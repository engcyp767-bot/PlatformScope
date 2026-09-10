"""
Platform Scope - Central License Manager
Single Authority for License State, 30-Day Trial Enforcement, Anti-Tamper Verification,
and Offline Activation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from platform_core.licensing import crypto, fingerprint
from platform_core.licensing.models import (
    DEFAULT_FEATURES,
    Entitlements,
    LicenseInfo,
    LicenseState,
    LicenseType,
    PlatformEdition,
)

_INTERNAL_MAC_KEY = b"PlatformScope_HMAC_Internal_Key_2026"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> datetime:
    try:
        s = s.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return _utcnow()


class LicenseManager:
    _instance: LicenseManager | None = None
    _lock = threading.RLock()

    def __init__(self, storage_dir: Path):
        self.storage_dir = Path(storage_dir).resolve()
        self.db_path = self.storage_dir / "license.sqlite3"
        self.installation_id = fingerprint.get_installation_id()
        self.instance_id = fingerprint.get_instance_id(self.storage_dir, self.installation_id)
        self._cached_info: LicenseInfo | None = None
        self._last_cache_update = 0.0
        self._cache_ttl = 30.0  # seconds
        self._init_db()
        self._evaluate_state()

    @classmethod
    def get_instance(cls, storage_dir: Path | None = None) -> LicenseManager:
        with cls._lock:
            if cls._instance is None:
                if storage_dir is None:
                    # Default storage path
                    storage_dir = Path(__file__).resolve().parent.parent.parent / "storage"
                cls._instance = cls(storage_dir)
            return cls._instance

    def _init_db(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS license_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    installation_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    license_type TEXT NOT NULL,
                    product TEXT NOT NULL,
                    edition TEXT NOT NULL,
                    customer_org TEXT NOT NULL,
                    license_id TEXT NOT NULL,
                    start_utc TEXT NOT NULL,
                    expires_utc TEXT NOT NULL,
                    grace_days INTEGER NOT NULL DEFAULT 0,
                    last_seen_utc TEXT NOT NULL,
                    entitlements_json TEXT NOT NULL,
                    raw_license_payload TEXT,
                    signature TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    record_mac TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS license_audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                );
            """)
            conn.commit()

    def _calc_record_mac(self, state: str, exp_utc: str, last_seen: str, l_type: str) -> str:
        data = f"{self.installation_id}:{state}:{exp_utc}:{last_seen}:{l_type}".encode("utf-8")
        return hmac.new(_INTERNAL_MAC_KEY, data, hashlib.sha256).hexdigest()

    def _record_audit(self, event_type: str, details: dict[str, Any]) -> None:
        now_str = _iso(_utcnow())
        details_str = json.dumps(details, ensure_ascii=True, sort_keys=True)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute("SELECT entry_hash FROM license_audit_events ORDER BY id DESC LIMIT 1;")
                row = cur.fetchone()
                prev_hash = row[0] if row else "GENESIS_HASH"
                entry_hash = hashlib.sha256(f"{prev_hash}:{event_type}:{now_str}:{details_str}".encode("utf-8")).hexdigest()
                conn.execute(
                    "INSERT INTO license_audit_events (event_type, timestamp_utc, details_json, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?);",
                    (event_type, now_str, details_str, prev_hash, entry_hash),
                )
                conn.commit()
        except Exception:
            pass

    def _evaluate_state(self) -> LicenseInfo:
        with self._lock:
            now = _utcnow()
            watermark = fingerprint.load_system_watermark(self.storage_dir)

            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.execute("SELECT * FROM license_state WHERE id = 1;")
                row = cur.fetchone()

            if not row:
                # Fresh database. Check if system watermark exists to prevent trial reset.
                if watermark and watermark.get("trial_consumed"):
                    orig_start = watermark.get("start_utc", _iso(now - timedelta(days=31)))
                    orig_exp = watermark.get("expires_utc", _iso(now - timedelta(days=1)))
                    orig_exp_dt = _parse_iso(orig_exp)
                    if now > orig_exp_dt:
                        return self._set_state(
                            LicenseState.TRIAL_EXPIRED,
                            LicenseType.TRIAL,
                            PlatformEdition.ENTERPRISE,
                            orig_start,
                            orig_exp,
                            0,
                            "انتهت فترة التجربة (30 يوماً). يرجى استيراد ملف ترخيص صالح لمتابعة العمل.",
                            is_valid=False,
                        )
                    else:
                        days_rem = max(0, (orig_exp_dt.date() - now.date()).days)
                        state = LicenseState.TRIAL_EXPIRING if days_rem <= 7 else LicenseState.TRIAL_ACTIVE
                        return self._set_state(
                            state,
                            LicenseType.TRIAL,
                            PlatformEdition.ENTERPRISE,
                            orig_start,
                            orig_exp,
                            0,
                            f"تمت استعادة فترة التجربة السابقة (متبقي {days_rem} يوماً).",
                            is_valid=True,
                        )
                # First run has not started yet
                return self._set_state(
                    LicenseState.UNINITIALIZED,
                    LicenseType.TRIAL,
                    PlatformEdition.ENTERPRISE,
                    _iso(now),
                    _iso(now + timedelta(days=30)),
                    0,
                    "المنصة جاهزة لبدء فترة التجربة المجانية (30 يوماً).",
                    is_valid=True,
                )

            # Record exists in DB
            state_str = row["state"]
            l_type_str = row["license_type"]
            edition_str = row["edition"]
            start_dt = _parse_iso(row["start_utc"])
            exp_dt = _parse_iso(row["expires_utc"])
            last_seen_dt = _parse_iso(row["last_seen_utc"])
            grace_days = int(row["grace_days"])
            entitlements = Entitlements.from_dict(json.loads(row["entitlements_json"]))
            record_mac = row["record_mac"]

            # 1. Anti-Tamper: Verify Record MAC
            expected_mac = self._calc_record_mac(state_str, row["expires_utc"], row["last_seen_utc"], l_type_str)
            if not hmac.compare_digest(record_mac, expected_mac):
                return self._set_state(
                    LicenseState.LICENSE_INVALID,
                    LicenseType(l_type_str),
                    PlatformEdition(edition_str),
                    row["start_utc"],
                    row["expires_utc"],
                    grace_days,
                    "تم كشف تلاعب غير مصرح به في بيانات سجل الترخيص.",
                    is_valid=False,
                )

            # 2. Clock Tampering: Monotonic check
            # Allow 300 seconds of tolerance for small NTP drift
            if now < last_seen_dt - timedelta(seconds=300):
                self._record_audit("CLOCK_ROLLBACK_DETECTED", {
                    "current_utc": _iso(now),
                    "last_seen_utc": _iso(last_seen_dt),
                })
                return self._set_state(
                    LicenseState.LICENSE_SUSPENDED,
                    LicenseType(l_type_str),
                    PlatformEdition(edition_str),
                    row["start_utc"],
                    row["expires_utc"],
                    grace_days,
                    "تم كشف تغيير في توقيت النظام إلى الوراء. يرجى ضبط ساعة النظام بشكل صحيح.",
                    is_valid=False,
                )

            # Update last_seen_dt if moving forward
            if now > last_seen_dt:
                with sqlite3.connect(self.db_path) as conn:
                    new_mac = self._calc_record_mac(state_str, row["expires_utc"], _iso(now), l_type_str)
                    conn.execute(
                        "UPDATE license_state SET last_seen_utc = ?, record_mac = ?, updated_at = ? WHERE id = 1;",
                        (_iso(now), new_mac, _iso(now)),
                    )
                    conn.commit()

            # 3. Calculate remaining days and active state transitions
            days_remaining = max(0, (exp_dt.date() - now.date()).days)

            # Check expiration
            if now > exp_dt:
                if l_type_str != LicenseType.TRIAL.value and now <= exp_dt + timedelta(days=grace_days):
                    new_state = LicenseState.LICENSE_GRACE_PERIOD
                    msg = f"الترخيص في فترة السماح (متبقي {max(0, ((exp_dt + timedelta(days=grace_days)).date() - now.date()).days)} أيام)."
                    is_valid = True
                else:
                    new_state = LicenseState.TRIAL_EXPIRED if l_type_str == LicenseType.TRIAL.value else LicenseState.LICENSE_EXPIRED
                    msg = "انتهت صلاحية الترخيص. يرجى تفعيل أو تجديد الترخيص."
                    is_valid = False
            else:
                if l_type_str == LicenseType.TRIAL.value:
                    new_state = LicenseState.TRIAL_EXPIRING if days_remaining <= 7 else LicenseState.TRIAL_ACTIVE
                    msg = f"فترة التجربة نشطة (متبقي {days_remaining} يوماً)."
                else:
                    new_state = LicenseState.LICENSE_ACTIVE
                    msg = f"الترخيص نشط وصالح (متبقي {days_remaining} يوماً)."
                is_valid = True

            # If state changed, update database
            if new_state.value != state_str:
                with sqlite3.connect(self.db_path) as conn:
                    new_mac = self._calc_record_mac(new_state.value, row["expires_utc"], _iso(now), l_type_str)
                    conn.execute(
                        "UPDATE license_state SET state = ?, record_mac = ?, updated_at = ? WHERE id = 1;",
                        (new_state.value, new_mac, _iso(now)),
                    )
                    conn.commit()
                self._record_audit("LICENSE_STATE_CHANGED", {"old_state": state_str, "new_state": new_state.value})

            info = LicenseInfo(
                state=new_state,
                license_type=LicenseType(l_type_str),
                product=row["product"],
                edition=PlatformEdition(edition_str),
                installation_id=self.installation_id,
                instance_id=self.instance_id,
                start_utc=row["start_utc"],
                expires_utc=row["expires_utc"],
                days_remaining=days_remaining,
                grace_days=grace_days,
                entitlements=entitlements,
                customer_org=row["customer_org"],
                license_id=row["license_id"],
                is_valid=is_valid,
                status_message=msg,
                last_verified_utc=_iso(now),
            )
            self._cached_info = info
            return info

    def _set_state(
        self,
        state: LicenseState,
        l_type: LicenseType,
        edition: PlatformEdition,
        start_utc: str,
        expires_utc: str,
        grace_days: int,
        msg: str,
        is_valid: bool,
        entitlements: Entitlements | None = None,
        customer_org: str = "Platform Scope Customer",
        license_id: str = "PS-TRIAL-30D",
        raw_payload: str = "",
        signature: str = "",
    ) -> LicenseInfo:
        now = _utcnow()
        ent = entitlements or Entitlements()
        exp_dt = _parse_iso(expires_utc)
        days_rem = max(0, (exp_dt.date() - now.date()).days)
        rec_mac = self._calc_record_mac(state.value, expires_utc, _iso(now), l_type.value)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO license_state (
                    id, installation_id, instance_id, state, license_type, product, edition,
                    customer_org, license_id, start_utc, expires_utc, grace_days, last_seen_utc,
                    entitlements_json, raw_license_payload, signature, created_at, updated_at, record_mac
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    state = excluded.state,
                    license_type = excluded.license_type,
                    product = excluded.product,
                    edition = excluded.edition,
                    customer_org = excluded.customer_org,
                    license_id = excluded.license_id,
                    start_utc = excluded.start_utc,
                    expires_utc = excluded.expires_utc,
                    grace_days = excluded.grace_days,
                    last_seen_utc = excluded.last_seen_utc,
                    entitlements_json = excluded.entitlements_json,
                    raw_license_payload = excluded.raw_license_payload,
                    signature = excluded.signature,
                    updated_at = excluded.updated_at,
                    record_mac = excluded.record_mac;
            """, (
                self.installation_id, self.instance_id, state.value, l_type.value, "Platform Scope", edition.value,
                customer_org, license_id, start_utc, expires_utc, grace_days, _iso(now),
                json.dumps(ent.to_dict()), raw_payload, signature, _iso(now), _iso(now), rec_mac,
            ))
            conn.commit()

        # Update system watermark
        fingerprint.save_system_watermark({
            "installation_id": self.installation_id,
            "trial_consumed": True if state in (LicenseState.TRIAL_ACTIVE, LicenseState.TRIAL_EXPIRING, LicenseState.TRIAL_EXPIRED) else False,
            "start_utc": start_utc,
            "expires_utc": expires_utc,
            "last_state": state.value,
            "updated_at": _iso(now),
        }, self.storage_dir)

        info = LicenseInfo(
            state=state,
            license_type=l_type,
            product="Platform Scope",
            edition=edition,
            installation_id=self.installation_id,
            instance_id=self.instance_id,
            start_utc=start_utc,
            expires_utc=expires_utc,
            days_remaining=days_rem,
            grace_days=grace_days,
            entitlements=ent,
            customer_org=customer_org,
            license_id=license_id,
            is_valid=is_valid,
            status_message=msg,
            last_verified_utc=_iso(now),
        )
        self._cached_info = info
        return info

    def initialize_trial(self) -> LicenseInfo:
        """Starts 30-Day Trial on First Actual Run."""
        with self._lock:
            current = self.get_license_info()
            if current.state != LicenseState.UNINITIALIZED:
                return current

            now = _utcnow()
            exp = now + timedelta(days=30)
            self._record_audit("TRIAL_STARTED", {
                "start_utc": _iso(now),
                "expires_utc": _iso(exp),
                "installation_id": self.installation_id,
            })
            return self._set_state(
                LicenseState.TRIAL_ACTIVE,
                LicenseType.TRIAL,
                PlatformEdition.ENTERPRISE,
                _iso(now),
                _iso(exp),
                grace_days=0,
                msg="تم بدء فترة التجربة المجانية (30 يوماً) بنجاح.",
                is_valid=True,
            )

    def get_license_info(self, force_refresh: bool = False) -> LicenseInfo:
        with self._lock:
            now_ts = datetime.now().timestamp()
            if not force_refresh and self._cached_info and (now_ts - self._last_cache_update < self._cache_ttl):
                return self._cached_info
            info = self._evaluate_state()
            self._last_cache_update = now_ts
            return info

    get_info = get_license_info

    def generate_activation_request(self) -> dict[str, Any]:
        """Generates an offline activation request payload."""
        now = _utcnow()
        payload = {
            "format": "PLATFORM_SCOPE_ACTIVATION_REQUEST_V1",
            "installation_id": self.installation_id,
            "instance_id": self.instance_id,
            "product": "Platform Scope",
            "requested_at": _iso(now),
        }
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload["request_hash"] = hashlib.sha256(raw).hexdigest()
        self._record_audit("ACTIVATION_REQUEST_GENERATED", payload)
        return payload

    def activate_license(self, license_envelope_text: str, custom_public_key: bytes | None = None) -> tuple[bool, str]:
        """Validates Ed25519 signature, checks hardware binding, and activates license."""
        with self._lock:
            is_valid, payload, msg = crypto.verify_license_envelope(license_envelope_text, custom_public_key)
            if not is_valid or not payload:
                self._record_audit("LICENSE_VALIDATION_FAILED", {"reason": msg})
                return False, msg

            # Validate Product
            if payload.get("product") != "Platform Scope":
                return False, "ملف الترخيص مخصص لمنتج آخر غير Platform Scope."

            # Validate Hardware Binding
            binding = payload.get("hardware_binding", {})
            target_inst_id = binding.get("installation_id")
            allow_migration = binding.get("allow_migration", False)
            if target_inst_id and target_inst_id != self.installation_id and not allow_migration:
                self._record_audit("LICENSE_VALIDATION_FAILED", {
                    "reason": "Installation ID Mismatch",
                    "expected": self.installation_id,
                    "target": target_inst_id,
                })
                return False, f"هذا الترخيص مخصص لجهاز آخر ({target_inst_id}) ولا يتطابق مع معرف هذا الجهاز ({self.installation_id})."

            # Parse validity
            validity = payload.get("validity", {})
            starts_at_str = validity.get("starts_at", _iso(_utcnow()))
            expires_at_str = validity.get("expires_at", "")
            if not expires_at_str:
                return False, "تاريخ انتهاء الترخيص غير محدد في الملف."

            exp_dt = _parse_iso(expires_at_str)
            grace_days = int(validity.get("grace_period_days", 14))
            l_type_str = validity.get("type", "SUBSCRIPTION")
            try:
                l_type = LicenseType(l_type_str)
            except ValueError:
                l_type = LicenseType.SUBSCRIPTION

            edition_str = payload.get("edition", "Enterprise")
            try:
                edition = PlatformEdition(edition_str)
            except ValueError:
                edition = PlatformEdition.ENTERPRISE

            customer = payload.get("customer", {})
            customer_org = customer.get("organization", "Licensed Enterprise")
            license_id = payload.get("license_id", "PS-LIC-CUSTOM")
            entitlements = Entitlements.from_dict(payload.get("entitlements"))

            now = _utcnow()
            if now > exp_dt + timedelta(days=grace_days):
                return False, "ملف الترخيص المقدم منتهي الصلاحية بالفعل."

            state = LicenseState.LICENSE_ACTIVE
            if now > exp_dt:
                state = LicenseState.LICENSE_GRACE_PERIOD

            self._set_state(
                state=state,
                l_type=l_type,
                edition=edition,
                start_utc=starts_at_str,
                expires_utc=expires_at_str,
                grace_days=grace_days,
                msg="تم تفعيل ترخيص Platform Scope بنجاح.",
                is_valid=True,
                entitlements=entitlements,
                customer_org=customer_org,
                license_id=license_id,
                raw_payload=json.dumps(payload),
                signature=json.loads(license_envelope_text).get("signature", ""),
            )

            self._record_audit("LICENSE_ACTIVATED", {
                "license_id": license_id,
                "customer_org": customer_org,
                "expires_at": expires_at_str,
            })
            return True, "تم تفعيل الترخيص بنجاح."

    def is_operation_allowed(self, operation: str) -> tuple[bool, str]:
        """
        Policy enforcement engine.
        Returns: (allowed: bool, reason_if_blocked: str)
        """
        # Always allowed administrative and monitoring routes
        allowed_free_ops = {"auth", "licensing", "health", "system_info", "audit_read"}
        if operation in allowed_free_ops:
            return True, ""

        info = self.get_license_info()
        if info.state in (
            LicenseState.TRIAL_ACTIVE,
            LicenseState.TRIAL_EXPIRING,
            LicenseState.LICENSE_ACTIVE,
            LicenseState.LICENSE_GRACE_PERIOD,
        ):
            # Check feature entitlement
            if operation not in info.entitlements.features and operation not in allowed_free_ops:
                # If feature is explicitly recognized but not licensed
                if operation in DEFAULT_FEATURES:
                    return False, f"الميزة المطلوبة ({operation}) غير مفعلة في ترخيص هذا الإصدار ({info.edition.value})."
            return True, ""

        # Otherwise operation is restricted
        if info.state == LicenseState.TRIAL_EXPIRED:
            return False, "انتهت فترة التجربة المجانية (30 يوماً). يرجى استيراد ترخيص صالح لتفعيل التحليل ومعالجة البيانات."
        elif info.state == LicenseState.LICENSE_EXPIRED:
            return False, "انتهت صلاحية ترخيص المنصة. يرجى تجديد الترخيص لمتابعة عمليات التحليل."
        elif info.state == LicenseState.LICENSE_SUSPENDED:
            return False, "تم تعليق وظائف المنصة لاكتشاف تلاعب في توقيت النظام. يرجى تصحيح ساعة النظام."
        elif info.state == LicenseState.UNINITIALIZED:
            # Auto-start trial on first sensitive operation!
            self.initialize_trial()
            return True, ""

        return False, "حالة الترخيص غير صالحة. يرجى مراجعة إدارة التراخيص."

