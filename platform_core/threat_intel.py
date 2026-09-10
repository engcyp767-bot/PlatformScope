"""Centralized Threat Intelligence & IOC Knowledge Base Engine.

Provides unified management for Indicators of Compromise (IOCs) across IP,
Domain, URL, Hash (MD5/SHA1/SHA256), and Certificate fingerprints.
Includes high-throughput O(1) in-memory cache, SQLite persistent storage,
MITRE ATT&CK v14.1 mapping, TLP taxonomy, CSV/JSON/STIX import/export,
and cross-correlation with LogScope, FlowScope, ThreatScope, and Incidents.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

from platform_core import audit_engine

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
STORAGE_DIR = WORKSPACE_ROOT / "storage"
DB_PATH = STORAGE_DIR / "threat_intel.sqlite3"

_LOCK = threading.RLock()

VALID_IOC_TYPES = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "certificate"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_TLP_LEVELS = {"white", "green", "amber", "red"}
VALID_THREAT_TYPES = {
    "c2", "malware", "phishing", "ransomware", "botnet",
    "scanner", "exploit", "apt", "crypto_miner", "suspicious"
}

MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def detect_hash_type(val: str) -> Optional[str]:
    """Detect hash algorithm from hex string length."""
    val = val.strip()
    if MD5_REGEX.match(val):
        return "hash_md5"
    if SHA1_REGEX.match(val):
        return "hash_sha1"
    if SHA256_REGEX.match(val):
        return "hash_sha256"
    return None


def normalize_ioc_value(ioc_type: str, value: str) -> Tuple[str, str]:
    """Normalize IOC value according to its type and validate format.
    
    Returns:
        Tuple of (detected_or_normalized_type, normalized_value)
    """
    val = str(value or "").strip()
    if not val:
        raise ValueError("قيمة مؤشر التهديد لا يمكن أن تكون فارغة.")

    # Auto-detect hash type if generic 'hash' is passed
    if ioc_type in {"hash", "file_hash"}:
        detected = detect_hash_type(val)
        if not detected:
            raise ValueError(f"صيغة التجزئة غير صالحة ({val}). يجب أن تكون MD5 (32 رمز) أو SHA-1 (40 رمز) أو SHA-256 (64 رمز).")
        return detected, val.lower()

    if ioc_type in {"hash_md5", "hash_sha1", "hash_sha256"}:
        val_lower = val.lower()
        if ioc_type == "hash_md5" and not MD5_REGEX.match(val_lower):
            raise ValueError(f"صيغة MD5 غير صالحة ({val}). يجب أن تكون 32 رمزاً سداسياً.")
        if ioc_type == "hash_sha1" and not SHA1_REGEX.match(val_lower):
            raise ValueError(f"صيغة SHA-1 غير صالحة ({val}). يجب أن تكون 40 رمزاً سداسياً.")
        if ioc_type == "hash_sha256" and not SHA256_REGEX.match(val_lower):
            raise ValueError(f"صيغة SHA-256 غير صالحة ({val}). يجب أن تكون 64 رمزاً سداسياً.")
        return ioc_type, val_lower

    if ioc_type == "ip":
        # Check single IP or CIDR
        if "/" in val:
            try:
                net = ipaddress.ip_network(val, strict=False)
                return "ip", str(net)
            except ValueError:
                raise ValueError(f"عنوان شبكة CIDR غير صالح ({val}).")
        else:
            try:
                ip_obj = ipaddress.ip_address(val)
                return "ip", str(ip_obj)
            except ValueError:
                raise ValueError(f"عنوان IP غير صالح ({val}).")

    if ioc_type == "domain":
        # Strip scheme if user pasted full URL
        if "://" in val:
            parsed = urlparse(val)
            val = parsed.netloc or parsed.path
        val = val.split("/")[0].split(":")[0].strip().lower().rstrip(".")
        if not DOMAIN_REGEX.match(val) and not val.endswith(".local"):
            # Check if valid domain or wildcard
            if not val.startswith("*.") or not DOMAIN_REGEX.match(val[2:]):
                raise ValueError(f"اسم نطاق غير صالح ({val}).")
        return "domain", val

    if ioc_type == "url":
        if "://" not in val:
            val = "http://" + val
        parsed = urlparse(val)
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        normalized = f"{scheme}://{netloc}{path}{query}"
        return "url", normalized

    if ioc_type == "certificate":
        # Fingerprint or serial
        clean_cert = re.sub(r"[\s:-]", "", val).lower()
        if not re.match(r"^[a-f0-9]{32,64}$", clean_cert):
            raise ValueError(f"بصمة شهادة غير صالحة ({val}).")
        return "certificate", clean_cert

    # Fallback
    return ioc_type, val


@dataclass
class IndicatorOfCompromise:
    """Core domain model for an Indicator of Compromise (IOC)."""
    id: str
    type: str
    value: str
    threat_type: str = "c2"
    severity: str = "high"
    confidence: int = 80
    source: str = "Internal SOC"
    first_seen: str = field(default_factory=_now_iso)
    last_seen: str = field(default_factory=_now_iso)
    tags: List[str] = field(default_factory=list)
    tlp: str = "amber"
    description: str = ""
    mitre_attack: Dict[str, Any] = field(default_factory=dict)
    related_threat_actor: str = ""
    is_active: bool = True
    hit_count: int = 0
    last_hit_at: Optional[str] = None
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    created_by: str = "system"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type_label_ar"] = {
            "ip": "عنوان IP",
            "domain": "اسم نطاق Domain",
            "url": "رابط ويب URL",
            "hash_md5": "تجزئة MD5",
            "hash_sha1": "تجزئة SHA-1",
            "hash_sha256": "تجزئة SHA-256",
            "certificate": "بصمة شهادة Certificate",
        }.get(self.type, self.type)
        d["severity_label_ar"] = {
            "critical": "حرج",
            "high": "مرتفع",
            "medium": "متوسط",
            "low": "منخفض",
            "info": "معلوماتي",
        }.get(self.severity, self.severity)
        d["threat_type_label_ar"] = {
            "c2": "خادم تحكم وسيطرة (C2)",
            "malware": "برمجية خبيثة (Malware)",
            "phishing": "تصيد احتيالي (Phishing)",
            "ransomware": "فدية وتشفير (Ransomware)",
            "botnet": "شبكة روبوتات (Botnet)",
            "scanner": "استطلاع ومسح (Scanner)",
            "exploit": "استغلال ثغرات (Exploit)",
            "apt": "هجوم متقدم موجه (APT)",
            "crypto_miner": "تعدين غير مصرح (CryptoMiner)",
            "suspicious": "نشاط مشبوه (Suspicious)",
        }.get(self.threat_type, self.threat_type)
        return d


@contextmanager
def db_session():
    """Thread-safe SQLite connection context with WAL mode."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


class ThreatIntelManager:
    """Central manager for Threat Intelligence, IOC storage, and fast O(1) matching."""

    _instance: Optional[ThreatIntelManager] = None
    _singleton_lock = threading.Lock()

    def __init__(self, db_file: Optional[Path] = None):
        self.db_path = db_file or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

        # In-Memory Fast Lookup Caches (O(1))
        self._ips: Dict[str, IndicatorOfCompromise] = {}
        self._ip_networks: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, IndicatorOfCompromise]] = []
        self._domains: Dict[str, IndicatorOfCompromise] = {}
        self._urls: Dict[str, IndicatorOfCompromise] = {}
        self._hashes: Dict[str, IndicatorOfCompromise] = {}
        self._certificates: Dict[str, IndicatorOfCompromise] = {}

        self._init_db()
        self.reload_cache()
        self._ensure_seed_iocs()

    @classmethod
    def get_instance(cls) -> ThreatIntelManager:
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def _init_db(self) -> None:
        with self._lock, db_session() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS iocs (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                threat_type TEXT NOT NULL DEFAULT 'c2',
                severity TEXT NOT NULL DEFAULT 'high',
                confidence INTEGER NOT NULL DEFAULT 80,
                source TEXT NOT NULL DEFAULT 'Internal SOC',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                tags_json TEXT NOT NULL DEFAULT '[]',
                tlp TEXT NOT NULL DEFAULT 'amber',
                description TEXT NOT NULL DEFAULT '',
                mitre_json TEXT NOT NULL DEFAULT '{}',
                threat_actor TEXT NOT NULL DEFAULT '',
                is_active INTEGER NOT NULL DEFAULT 1,
                hit_count INTEGER NOT NULL DEFAULT 0,
                last_hit_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                created_by TEXT NOT NULL DEFAULT 'system',
                UNIQUE(type, value)
            );

            CREATE INDEX IF NOT EXISTS idx_iocs_type_val ON iocs(type, value);
            CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(is_active);
            CREATE INDEX IF NOT EXISTS idx_iocs_threat_type ON iocs(threat_type);
            CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
            CREATE INDEX IF NOT EXISTS idx_iocs_tlp ON iocs(tlp);

            CREATE TABLE IF NOT EXISTS ioc_hits (
                id TEXT PRIMARY KEY,
                ioc_id TEXT NOT NULL,
                source_app TEXT NOT NULL,
                incident_id TEXT,
                job_id TEXT,
                event_data_json TEXT NOT NULL DEFAULT '{}',
                hit_timestamp TEXT NOT NULL,
                FOREIGN KEY(ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_ioc_hits_ioc_id ON ioc_hits(ioc_id);
            CREATE INDEX IF NOT EXISTS idx_ioc_hits_time ON ioc_hits(hit_timestamp);
            """)

    def reload_cache(self) -> None:
        """Reload active IOCs into in-memory dictionaries for O(1) matching."""
        with self._lock, db_session() as conn:
            rows = conn.execute("SELECT * FROM iocs WHERE is_active = 1").fetchall()

            new_ips: Dict[str, IndicatorOfCompromise] = {}
            new_ip_nets: List[Tuple[Any, IndicatorOfCompromise]] = []
            new_domains: Dict[str, IndicatorOfCompromise] = {}
            new_urls: Dict[str, IndicatorOfCompromise] = {}
            new_hashes: Dict[str, IndicatorOfCompromise] = {}
            new_certs: Dict[str, IndicatorOfCompromise] = {}

            for row in rows:
                ioc = self._row_to_ioc(row)
                t = ioc.type
                v = ioc.value

                if t == "ip":
                    if "/" in v:
                        try:
                            net = ipaddress.ip_network(v, strict=False)
                            new_ip_nets.append((net, ioc))
                        except Exception:
                            new_ips[v] = ioc
                    else:
                        new_ips[v] = ioc
                elif t == "domain":
                    new_domains[v] = ioc
                elif t == "url":
                    new_urls[v] = ioc
                elif t.startswith("hash_"):
                    new_hashes[v] = ioc
                elif t == "certificate":
                    new_certs[v] = ioc

            self._ips = new_ips
            self._ip_networks = new_ip_nets
            self._domains = new_domains
            self._urls = new_urls
            self._hashes = new_hashes
            self._certificates = new_certs

    def _row_to_ioc(self, row: sqlite3.Row) -> IndicatorOfCompromise:
        tags = []
        mitre = {}
        try:
            tags = json.loads(row["tags_json"] or "[]")
        except Exception:
            pass
        try:
            mitre = json.loads(row["mitre_json"] or "{}")
        except Exception:
            pass

        return IndicatorOfCompromise(
            id=row["id"],
            type=row["type"],
            value=row["value"],
            threat_type=row["threat_type"],
            severity=row["severity"],
            confidence=int(row["confidence"] or 80),
            source=row["source"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            tags=tags,
            tlp=row["tlp"],
            description=row["description"] or "",
            mitre_attack=mitre,
            related_threat_actor=row["threat_actor"] or "",
            is_active=bool(row["is_active"]),
            hit_count=int(row["hit_count"] or 0),
            last_hit_at=row["last_hit_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            created_by=row["created_by"],
        )

    def _ensure_seed_iocs(self) -> None:
        """Seed initial high-value curated IOC catalog if database is empty."""
        with self._lock, db_session() as conn:
            count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            if count > 0:
                return

        seeds = [
            {
                "type": "ip",
                "value": "198.51.100.44",
                "threat_type": "c2",
                "severity": "critical",
                "confidence": 95,
                "source": "ThreatFox / C2 Intel",
                "tags": ["cobalt_strike", "c2", "beacon"],
                "tlp": "amber",
                "description": "Active Cobalt Strike TeamServer C2 beacon endpoint.",
                "mitre_attack": {"tactics": ["Command and Control"], "techniques": ["T1071.001 - Web Protocols"]},
                "related_threat_actor": "FIN7",
            },
            {
                "type": "ip",
                "value": "203.0.113.195",
                "threat_type": "scanner",
                "severity": "medium",
                "confidence": 85,
                "source": "AbuseIPDB",
                "tags": ["scanner", "log4j", "exploit"],
                "tlp": "green",
                "description": "Mass scanning origin targeting Apache Log4Shell CVE-2021-44228.",
                "mitre_attack": {"tactics": ["Initial Access"], "techniques": ["T1190 - Exploit Public-Facing Application"]},
                "related_threat_actor": "Automated Botnet",
            },
            {
                "type": "domain",
                "value": "cdn-update-auth-telemetry.com",
                "threat_type": "phishing",
                "severity": "high",
                "confidence": 90,
                "source": "AlienVault OTX",
                "tags": ["m365", "phishing", "aitm"],
                "tlp": "amber",
                "description": "Adversary-in-the-Middle (AiTM) reverse proxy domain harvesting Microsoft 365 tokens.",
                "mitre_attack": {"tactics": ["Credential Access"], "techniques": ["T1566.002 - Spearphishing Link"]},
                "related_threat_actor": "Storm-1167",
            },
            {
                "type": "domain",
                "value": "secure-dns-resolver-sync.net",
                "threat_type": "c2",
                "severity": "critical",
                "confidence": 95,
                "source": "MISP Community",
                "tags": ["dns_tunnel", "c2", "apt29"],
                "tlp": "red",
                "description": "DNS Tunneling exfiltration domain associated with sophisticated state-sponsored operations.",
                "mitre_attack": {"tactics": ["Exfiltration"], "techniques": ["T1071.004 - DNS"]},
                "related_threat_actor": "APT29",
            },
            {
                "type": "url",
                "value": "http://185.220.101.5/bins/arm7.payload",
                "threat_type": "malware",
                "severity": "critical",
                "confidence": 95,
                "source": "MalwareBazaar",
                "tags": ["mirai", "iot", "dropper"],
                "tlp": "white",
                "description": "Mirai botnet Linux ARM payload dropper URL.",
                "mitre_attack": {"tactics": ["Execution"], "techniques": ["T1105 - Ingress Tool Transfer"]},
                "related_threat_actor": "Mirai Variant",
            },
            {
                "type": "hash_sha256",
                "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "threat_type": "malware",
                "severity": "high",
                "confidence": 85,
                "source": "Internal SOC",
                "tags": ["lockbit", "ransomware"],
                "tlp": "amber",
                "description": "LockBit 3.0 Ransomware encryptor binary signature.",
                "mitre_attack": {"tactics": ["Impact"], "techniques": ["T1486 - Data Encrypted for Impact"]},
                "related_threat_actor": "LockBit Gang",
            },
            {
                "type": "hash_sha256",
                "value": "7b8f9e2d1c3a4b5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e",
                "threat_type": "c2",
                "severity": "critical",
                "confidence": 95,
                "source": "VirusTotal",
                "tags": ["mimikatz", "credential_theft"],
                "tlp": "amber",
                "description": "Patched Mimikatz LSASS dumper binary.",
                "mitre_attack": {"tactics": ["Credential Access"], "techniques": ["T1003.001 - LSASS Memory"]},
                "related_threat_actor": "Generic Threat",
            }
        ]

        for s in seeds:
            try:
                self.add_ioc(
                    ioc_type=s["type"],
                    value=s["value"],
                    threat_type=s.get("threat_type", "c2"),
                    severity=s.get("severity", "high"),
                    confidence=s.get("confidence", 80),
                    source=s.get("source", "Internal SOC"),
                    tags=s.get("tags", []),
                    tlp=s.get("tlp", "amber"),
                    description=s.get("description", ""),
                    mitre_attack=s.get("mitre_attack", {}),
                    related_threat_actor=s.get("related_threat_actor", ""),
                    created_by="system_seed",
                )
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # CRUD Operations
    # -------------------------------------------------------------------------

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        threat_type: str = "c2",
        severity: str = "high",
        confidence: int = 80,
        source: str = "Internal SOC",
        tags: Optional[List[str]] = None,
        tlp: str = "amber",
        description: str = "",
        mitre_attack: Optional[Dict[str, Any]] = None,
        related_threat_actor: str = "",
        is_active: bool = True,
        created_by: str = "system",
    ) -> IndicatorOfCompromise:
        """Create a new IOC with normalization, duplicate prevention, and caching."""
        norm_type, norm_val = normalize_ioc_value(ioc_type, value)

        threat_type = threat_type.lower() if threat_type in VALID_THREAT_TYPES else "suspicious"
        severity = severity.lower() if severity in VALID_SEVERITIES else "medium"
        tlp = tlp.lower() if tlp in VALID_TLP_LEVELS else "amber"
        confidence = max(0, min(100, int(confidence)))
        tags_list = [str(t).strip().lower() for t in (tags or []) if str(t).strip()]
        mitre_dict = mitre_attack or {}
        now = _now_iso()

        ioc_id = f"IOC-{uuid.uuid4().hex[:12].upper()}"

        with self._lock, db_session() as conn:
            # Check duplicate
            existing = conn.execute("SELECT id FROM iocs WHERE type = ? AND value = ?", (norm_type, norm_val)).fetchone()
            if existing:
                raise ValueError(f"مؤشر التهديد ({norm_type}: {norm_val}) موجود مسبقاً برمز {existing['id']}.")

            conn.execute("""
            INSERT INTO iocs (
                id, type, value, threat_type, severity, confidence, source,
                first_seen, last_seen, tags_json, tlp, description, mitre_json,
                threat_actor, is_active, hit_count, last_hit_at, created_at, updated_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)
            """, (
                ioc_id, norm_type, norm_val, threat_type, severity, confidence, source,
                now, now, json.dumps(tags_list), tlp, description, json.dumps(mitre_dict),
                related_threat_actor, 1 if is_active else 0, now, now, created_by
            ))

        ioc = IndicatorOfCompromise(
            id=ioc_id,
            type=norm_type,
            value=norm_val,
            threat_type=threat_type,
            severity=severity,
            confidence=confidence,
            source=source,
            first_seen=now,
            last_seen=now,
            tags=tags_list,
            tlp=tlp,
            description=description,
            mitre_attack=mitre_dict,
            related_threat_actor=related_threat_actor,
            is_active=is_active,
            hit_count=0,
            last_hit_at=None,
            created_at=now,
            updated_at=now,
            created_by=created_by,
        )

        # Update cache
        self.reload_cache()

        # Audit
        audit_engine.record_engine_event(
            application="threat_intel",
            action="ioc_create",
            message=f"إضافة مؤشر تهديد جديد ({norm_type}): {norm_val}",
            category="threat_intelligence",
            details={"type": norm_type, "value": norm_val, "severity": severity, "threat_type": threat_type, "user": created_by},
        )

        return ioc

    def get_ioc(self, ioc_id: str) -> Optional[IndicatorOfCompromise]:
        with self._lock, db_session() as conn:
            row = conn.execute("SELECT * FROM iocs WHERE id = ?", (ioc_id,)).fetchone()
            if not row:
                return None
            return self._row_to_ioc(row)

    def update_ioc(self, ioc_id: str, actor: str = "system", **updates: Any) -> Optional[IndicatorOfCompromise]:
        with self._lock, db_session() as conn:
            row = conn.execute("SELECT * FROM iocs WHERE id = ?", (ioc_id,)).fetchone()
            if not row:
                return None

            allowed = {
                "threat_type", "severity", "confidence", "source", "last_seen",
                "tags", "tlp", "description", "mitre_attack", "related_threat_actor", "is_active"
            }
            fields_to_update = {}
            for k, v in updates.items():
                if k not in allowed or v is None:
                    continue
                if k == "threat_type" and v in VALID_THREAT_TYPES:
                    fields_to_update["threat_type"] = v.lower()
                elif k == "severity" and v in VALID_SEVERITIES:
                    fields_to_update["severity"] = v.lower()
                elif k == "confidence":
                    fields_to_update["confidence"] = max(0, min(100, int(v)))
                elif k == "source":
                    fields_to_update["source"] = str(v).strip()
                elif k == "tags":
                    fields_to_update["tags_json"] = json.dumps(v)
                elif k == "tlp" and v in VALID_TLP_LEVELS:
                    fields_to_update["tlp"] = v.lower()
                elif k == "description":
                    fields_to_update["description"] = str(v).strip()
                elif k == "mitre_attack":
                    fields_to_update["mitre_json"] = json.dumps(v)
                elif k == "related_threat_actor":
                    fields_to_update["threat_actor"] = str(v).strip()
                elif k == "is_active":
                    fields_to_update["is_active"] = 1 if v else 0

            if not fields_to_update:
                return self._row_to_ioc(row)

            fields_to_update["updated_at"] = _now_iso()

            set_clauses = ", ".join(f"{k} = ?" for k in fields_to_update.keys())
            values = list(fields_to_update.values()) + [ioc_id]

            conn.execute(f"UPDATE iocs SET {set_clauses} WHERE id = ?", values)

        self.reload_cache()

        audit_engine.record_engine_event(
            application="threat_intel",
            action="ioc_update",
            message=f"تحديث مؤشر تهديد: {ioc_id}",
            category="threat_intelligence",
            details={"ioc_id": ioc_id, "user": actor, **updates},
        )

        return self.get_ioc(ioc_id)

    def delete_ioc(self, ioc_id: str, actor: str = "system") -> bool:
        with self._lock, db_session() as conn:
            existing = conn.execute("SELECT id, type, value FROM iocs WHERE id = ?", (ioc_id,)).fetchone()
            if not existing:
                return False

            conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))

        self.reload_cache()

        audit_engine.record_engine_event(
            application="threat_intel",
            action="ioc_delete",
            message=f"حذف مؤشر تهديد: {ioc_id}",
            category="threat_intelligence",
            details={"ioc_id": ioc_id, "type": existing["type"], "value": existing["value"], "user": actor},
        )
        return True

    def list_iocs(
        self,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
        tlp: Optional[str] = None,
        is_active: Optional[bool] = None,
        query: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
    ) -> Tuple[List[IndicatorOfCompromise], int]:
        """Query IOCs with structured filters, full-text search, and pagination."""
        with self._lock, db_session() as conn:
            conditions = []
            params: List[Any] = []

            if ioc_type:
                if ioc_type == "hash":
                    conditions.append("type LIKE 'hash_%'")
                else:
                    conditions.append("type = ?")
                    params.append(ioc_type)

            if severity and severity != "all":
                conditions.append("severity = ?")
                params.append(severity.lower())

            if threat_type and threat_type != "all":
                conditions.append("threat_type = ?")
                params.append(threat_type.lower())

            if tlp and tlp != "all":
                conditions.append("tlp = ?")
                params.append(tlp.lower())

            if is_active is not None:
                conditions.append("is_active = ?")
                params.append(1 if is_active else 0)

            if query and query.strip():
                q = f"%{query.strip().lower()}%"
                conditions.append("(LOWER(value) LIKE ? OR LOWER(description) LIKE ? OR LOWER(threat_actor) LIKE ? OR LOWER(tags_json) LIKE ?)")
                params.extend([q, q, q, q])

            where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

            # Count total
            total = conn.execute(f"SELECT COUNT(*) FROM iocs{where_clause}", params).fetchone()[0]

            # Allowed sorts
            valid_sorts = {"updated_at", "created_at", "hit_count", "confidence", "severity", "value"}
            col = sort_by if sort_by in valid_sorts else "updated_at"
            order = "DESC" if str(sort_order).lower() == "desc" else "ASC"

            sql = f"SELECT * FROM iocs{where_clause} ORDER BY {col} {order} LIMIT ? OFFSET ?"
            query_params = list(params) + [limit, offset]
            rows = conn.execute(sql, query_params).fetchall()

            iocs = [self._row_to_ioc(r) for r in rows]
            return iocs, total

    def get_summary(self) -> Dict[str, Any]:
        """Generate high-level metrics for the Threat Intelligence dashboard."""
        with self._lock, db_session() as conn:
            total = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            active = conn.execute("SELECT COUNT(*) FROM iocs WHERE is_active = 1").fetchone()[0]
            total_hits = conn.execute("SELECT COALESCE(SUM(hit_count), 0) FROM iocs").fetchone()[0]

            by_type = {}
            for r in conn.execute("SELECT type, COUNT(*) as cnt FROM iocs GROUP BY type").fetchall():
                by_type[r["type"]] = r["cnt"]

            by_severity = {}
            for r in conn.execute("SELECT severity, COUNT(*) as cnt FROM iocs GROUP BY severity").fetchall():
                by_severity[r["severity"]] = r["cnt"]

            by_threat_type = {}
            for r in conn.execute("SELECT threat_type, COUNT(*) as cnt FROM iocs GROUP BY threat_type").fetchall():
                by_threat_type[r["threat_type"]] = r["cnt"]

            top_hits_rows = conn.execute(
                "SELECT id, type, value, threat_type, severity, hit_count, last_hit_at "
                "FROM iocs WHERE hit_count > 0 ORDER BY hit_count DESC LIMIT 5"
            ).fetchall()
            top_hits = [dict(r) for r in top_hits_rows]

            recent_added_rows = conn.execute(
                "SELECT id, type, value, threat_type, severity, created_at "
                "FROM iocs ORDER BY created_at DESC LIMIT 5"
            ).fetchall()
            recent_added = [dict(r) for r in recent_added_rows]

            return {
                "total_iocs": total,
                "active_iocs": active,
                "total_hits": total_hits,
                "by_type": by_type,
                "by_severity": by_severity,
                "by_threat_type": by_threat_type,
                "top_hits": top_hits,
                "recent_added": recent_added,
            }

    # -------------------------------------------------------------------------
    # Fast O(1) Matching & Lookup Engine
    # -------------------------------------------------------------------------

    def match_value(self, value: str, ioc_type: Optional[str] = None) -> List[IndicatorOfCompromise]:
        """Perform exact O(1) match on normalized value with in-memory indexes."""
        val = str(value or "").strip()
        if not val:
            return []

        val_lower = val.lower()
        matches: List[IndicatorOfCompromise] = []

        # 1. Direct Hash match
        if ioc_type is None or ioc_type.startswith("hash"):
            if val_lower in self._hashes:
                matches.append(self._hashes[val_lower])

        # 2. Direct IP match or subnet match
        if ioc_type is None or ioc_type == "ip":
            if val in self._ips:
                matches.append(self._ips[val])
            elif val_lower in self._ips:
                matches.append(self._ips[val_lower])
            else:
                try:
                    ip_obj = ipaddress.ip_address(val)
                    for net, ioc in self._ip_networks:
                        if ip_obj in net:
                            matches.append(ioc)
                except ValueError:
                    pass

        # 3. Direct Domain match
        if ioc_type is None or ioc_type == "domain":
            domain_val = val_lower.split(":")[0].rstrip(".")
            if domain_val in self._domains:
                matches.append(self._domains[domain_val])
            # Check domain wildcards or subdomains
            parts = domain_val.split(".")
            if len(parts) > 2:
                parent = ".".join(parts[1:])
                if parent in self._domains:
                    matches.append(self._domains[parent])
                wildcard = f"*.{parent}"
                if wildcard in self._domains:
                    matches.append(self._domains[wildcard])

        # 4. Direct URL match
        if ioc_type is None or ioc_type == "url":
            if val in self._urls:
                matches.append(self._urls[val])
            elif val_lower in self._urls:
                matches.append(self._urls[val_lower])

        # 5. Direct Certificate match
        if ioc_type is None or ioc_type == "certificate":
            clean_cert = re.sub(r"[\s:-]", "", val_lower)
            if clean_cert in self._certificates:
                matches.append(self._certificates[clean_cert])

        return matches

    def record_hit(
        self,
        ioc_id: str,
        source_app: str,
        incident_id: Optional[str] = None,
        job_id: Optional[str] = None,
        event_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Increment IOC hit counter and log telemetry hit record."""
        now = _now_iso()
        hit_id = f"HIT-{uuid.uuid4().hex[:12].upper()}"

        with self._lock, db_session() as conn:
            conn.execute(
                "UPDATE iocs SET hit_count = hit_count + 1, last_hit_at = ? WHERE id = ?",
                (now, ioc_id)
            )
            conn.execute("""
            INSERT INTO ioc_hits (id, ioc_id, source_app, incident_id, job_id, event_data_json, hit_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                hit_id, ioc_id, source_app, incident_id, job_id, json.dumps(event_data or {}), now
            ))

    def get_ioc_hits(self, ioc_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent historical hits and detections for a specific IOC."""
        with self._lock, db_session() as conn:
            rows = conn.execute(
                "SELECT id, ioc_id, source_app, incident_id, job_id, event_data_json, hit_timestamp "
                "FROM ioc_hits WHERE ioc_id = ? ORDER BY hit_timestamp DESC LIMIT ?",
                (ioc_id, max(1, min(500, limit)))
            ).fetchall()
            hits = []
            for r in rows:
                hit_dict = dict(r)
                try:
                    hit_dict["event_data"] = json.loads(hit_dict.pop("event_data_json", "{}"))
                except Exception:
                    hit_dict["event_data"] = {}
                hits.append(hit_dict)
            return hits

    def match_event(self, event: Any, source_app: str = "logscope") -> List[Dict[str, Any]]:
        """Scan a CanonicalEvent or log dictionary against all in-memory IOCs."""
        hits = []

        def _get_val(field_name: str) -> Optional[str]:
            if hasattr(event, field_name):
                return getattr(event, field_name)
            if isinstance(event, dict):
                return event.get(field_name)
            return None

        # Check Source IP
        src_ip = _get_val("source_ip") or _get_val("src_ip")
        if src_ip:
            matched = self.match_value(str(src_ip), ioc_type="ip")
            for m in matched:
                hits.append({"field": "source_ip", "value": src_ip, "ioc": m})

        # Check Destination IP
        dst_ip = _get_val("destination_ip") or _get_val("dst_ip")
        if dst_ip:
            matched = self.match_value(str(dst_ip), ioc_type="ip")
            for m in matched:
                hits.append({"field": "destination_ip", "value": dst_ip, "ioc": m})

        # Check Domain
        domain = _get_val("domain") or _get_val("host")
        if domain:
            matched = self.match_value(str(domain), ioc_type="domain")
            for m in matched:
                hits.append({"field": "domain", "value": domain, "ioc": m})

        # Check URL
        url = _get_val("url") or _get_val("request_url")
        if url:
            matched = self.match_value(str(url), ioc_type="url")
            for m in matched:
                hits.append({"field": "url", "value": url, "ioc": m})

        # Check Hashes in raw_fields or top-level
        raw = _get_val("raw_fields") or {}
        if isinstance(raw, dict):
            for k in ("hash", "file_hash", "md5", "sha1", "sha256", "imphash"):
                h_val = raw.get(k)
                if h_val:
                    matched = self.match_value(str(h_val))
                    for m in matched:
                        hits.append({"field": f"raw_fields.{k}", "value": str(h_val), "ioc": m})

        # Record hits
        for hit in hits:
            self.record_hit(hit["ioc"].id, source_app=source_app)

        return hits

    def lookup_batch(self, values: List[str]) -> List[Dict[str, Any]]:
        """Batch lookup for analysts to test multiple values at once."""
        results = []
        for raw in values:
            v = str(raw or "").strip()
            if not v:
                continue
            matched = self.match_value(v)
            results.append({
                "query": v,
                "matched": len(matched) > 0,
                "matches": [m.to_dict() for m in matched],
            })
        return results

    # -------------------------------------------------------------------------
    # Import / Export
    # -------------------------------------------------------------------------

    def import_csv(self, csv_content: str, on_duplicate: str = "skip", actor: str = "system") -> Dict[str, Any]:
        """Import IOCs from CSV content with automatic header mapping."""
        reader = csv.DictReader(io.StringIO(csv_content))
        imported = 0
        skipped = 0
        errors = []

        for idx, row in enumerate(reader, start=1):
            val = row.get("value") or row.get("indicator") or row.get("ioc")
            t = row.get("type") or row.get("ioc_type") or "ip"
            if not val:
                skipped += 1
                continue

            try:
                tags = [t.strip() for t in (row.get("tags") or "").split(",") if t.strip()]
                confidence = int(row.get("confidence") or 80)
                severity = row.get("severity") or "high"
                threat_type = row.get("threat_type") or "suspicious"
                source = row.get("source") or "CSV Import"
                tlp = row.get("tlp") or "amber"
                desc = row.get("description") or ""

                try:
                    self.add_ioc(
                        ioc_type=t,
                        value=val,
                        threat_type=threat_type,
                        severity=severity,
                        confidence=confidence,
                        source=source,
                        tags=tags,
                        tlp=tlp,
                        description=desc,
                        created_by=actor,
                    )
                    imported += 1
                except ValueError as ve:
                    if "موجود مسبقاً" in str(ve) and on_duplicate == "overwrite":
                        norm_t, norm_v = normalize_ioc_value(t, val)
                        with self._lock, db_session() as conn:
                            existing = conn.execute("SELECT id FROM iocs WHERE type=? AND value=?", (norm_t, norm_v)).fetchone()
                            if existing:
                                self.update_ioc(
                                    existing["id"],
                                    actor=actor,
                                    threat_type=threat_type,
                                    severity=severity,
                                    confidence=confidence,
                                    tags=tags,
                                    tlp=tlp,
                                    description=desc,
                                )
                                imported += 1
                    else:
                        skipped += 1
            except Exception as e:
                errors.append(f"السطر {idx}: {str(e)}")

        return {"imported": imported, "skipped": skipped, "errors": errors}

    def import_json(self, json_content: str, on_duplicate: str = "skip", actor: str = "system") -> Dict[str, Any]:
        """Import IOCs from JSON array or STIX-compatible indicator list."""
        data = json.loads(json_content)
        items = data if isinstance(data, list) else data.get("indicators") or data.get("iocs") or []
        imported = 0
        skipped = 0
        errors = []

        for idx, item in enumerate(items, start=1):
            val = item.get("value") or item.get("pattern")
            t = item.get("type") or "ip"

            # Handle STIX indicator pattern e.g. [ipv4-addr:value = '1.2.3.4']
            if val and "[" in val and "]" in val and ":" in val:
                m = re.search(r"([a-z0-9_-]+):value\s*=\s*'([^']+)'", val)
                if m:
                    stix_t, stix_v = m.group(1), m.group(2)
                    t = "ip" if "ip" in stix_t else "domain" if "domain" in stix_t else "url" if "url" in stix_t else "hash_sha256"
                    val = stix_v

            if not val:
                skipped += 1
                continue

            try:
                self.add_ioc(
                    ioc_type=t,
                    value=val,
                    threat_type=item.get("threat_type", "c2"),
                    severity=item.get("severity", "high"),
                    confidence=int(item.get("confidence", 80)),
                    source=item.get("source", "JSON Import"),
                    tags=item.get("tags", []),
                    tlp=item.get("tlp", "amber"),
                    description=item.get("description", ""),
                    mitre_attack=item.get("mitre_attack", {}),
                    related_threat_actor=item.get("related_threat_actor", ""),
                    created_by=actor,
                )
                imported += 1
            except ValueError as ve:
                if "موجود مسبقاً" in str(ve) and on_duplicate == "overwrite":
                    norm_t, norm_v = normalize_ioc_value(t, val)
                    with self._lock, db_session() as conn:
                        existing = conn.execute("SELECT id FROM iocs WHERE type=? AND value=?", (norm_t, norm_v)).fetchone()
                        if existing:
                            self.update_ioc(
                                existing["id"],
                                actor=actor,
                                threat_type=item.get("threat_type", "c2"),
                                severity=item.get("severity", "high"),
                                confidence=int(item.get("confidence", 80)),
                                tags=item.get("tags", []),
                                tlp=item.get("tlp", "amber"),
                                description=item.get("description", ""),
                            )
                            imported += 1
                else:
                    skipped += 1
            except Exception as e:
                errors.append(f"العنصر {idx}: {str(e)}")

        return {"imported": imported, "skipped": skipped, "errors": errors}

    def export_csv(self, ioc_type: Optional[str] = None) -> str:
        iocs, _ = self.list_iocs(ioc_type=ioc_type, limit=10000)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "type", "value", "threat_type", "severity", "confidence",
            "source", "first_seen", "last_seen", "tags", "tlp", "threat_actor",
            "is_active", "hit_count", "description"
        ])
        for i in iocs:
            writer.writerow([
                i.id, i.type, i.value, i.threat_type, i.severity, i.confidence,
                i.source, i.first_seen, i.last_seen, ",".join(i.tags), i.tlp,
                i.related_threat_actor, 1 if i.is_active else 0, i.hit_count, i.description
            ])
        return output.getvalue()

    def export_json(self, ioc_type: Optional[str] = None) -> str:
        iocs, _ = self.list_iocs(ioc_type=ioc_type, limit=10000)
        return json.dumps([i.to_dict() for i in iocs], indent=2, ensure_ascii=False)

    def export_stix(self, ioc_type: Optional[str] = None) -> str:
        """Export IOCs as a standardized STIX 2.1 JSON Bundle."""
        iocs, _ = self.list_iocs(ioc_type=ioc_type, limit=10000)
        objects = []

        for i in iocs:
            pattern = ""
            if i.type == "ip":
                is_v6 = ":" in i.value
                pattern = f"[{'ipv6-addr' if is_v6 else 'ipv4-addr'}:value = '{i.value}']"
            elif i.type == "domain":
                pattern = f"[domain-name:value = '{i.value}']"
            elif i.type == "url":
                pattern = f"[url:value = '{i.value}']"
            elif i.type == "hash_md5":
                pattern = f"[file:hashes.md5 = '{i.value}']"
            elif i.type == "hash_sha1":
                pattern = f"[file:hashes.sha1 = '{i.value}']"
            elif i.type == "hash_sha256":
                pattern = f"[file:hashes.sha256 = '{i.value}']"
            elif i.type == "certificate":
                pattern = f"[x509-certificate:hashes.sha256 = '{i.value}']"
            else:
                pattern = f"[custom-object:value = '{i.value}']"

            obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, i.id)}",
                "created": i.first_seen,
                "modified": i.last_seen,
                "name": f"{i.threat_type.upper()}: {i.value}",
                "description": i.description or f"IOC identifier {i.id} from source {i.source}",
                "indicator_types": [i.threat_type],
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": i.first_seen,
                "confidence": i.confidence,
                "labels": list(i.tags),
                "custom_properties": {
                    "x_platform_ioc_id": i.id,
                    "x_platform_severity": i.severity,
                    "x_platform_tlp": i.tlp,
                    "x_platform_hit_count": i.hit_count,
                    "x_platform_actor": i.related_threat_actor,
                }
            }
            objects.append(obj)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }
        return json.dumps(bundle, indent=2, ensure_ascii=False)


def init_db() -> None:
    """Initialize the threat intelligence database schema and seed data."""
    ThreatIntelManager.get_instance()._init_db()




# -----------------------------------------------------------------------------
# LogScope ThreatIntelDetector Integration
# -----------------------------------------------------------------------------

class ThreatIntelDetector:
    """Detection Engine adapter that triggers when events match central IOCs."""
    detector_name = "threat_intel_matcher"

    def __init__(self):
        self.manager = ThreatIntelManager.get_instance()
        self.detector_id = "threat_intel_matcher"
        self.name = "Central Threat Intelligence Matcher"

    def analyze_event(self, event: Any) -> list:
        """Analyze a single CanonicalEvent and return zero or more findings."""
        try:
            from logscope.canonical import DetectionFinding, ConclusionLevel
        except ImportError:
            return []

        hits = self.manager.match_event(event, source_app="logscope")
        findings = []

        sev_map = {
            "critical": 95,
            "high": 80,
            "medium": 55,
            "low": 30,
            "info": 15,
        }

        for hit in hits:
            ioc = hit["ioc"]
            sev_num = sev_map.get(ioc.severity, 75)
            conclusion = ConclusionLevel.CONFIRMED if ioc.confidence >= 85 else ConclusionLevel.SUSPICIOUS

            tactics = []
            techniques = []
            if isinstance(ioc.mitre_attack, dict):
                tactics = ioc.mitre_attack.get("tactics", [])
                techniques = ioc.mitre_attack.get("techniques", [])

            f = DetectionFinding(
                detection_id=f"DET-IOC-{ioc.id}",
                title_ar=f"مطابقة مؤشر اختراق ({ioc.threat_type.upper()}): {ioc.value}",
                description_ar=ioc.description or f"تم رصد مؤشر تهديد مسجل من مصدر {ioc.source}",
                base_severity=sev_num,
                confidence=ioc.confidence,
                conclusion_level=conclusion,
                mitre_tactics=list(tactics) if isinstance(tactics, (list, tuple)) else [],
                mitre_techniques=list(techniques) if isinstance(techniques, (list, tuple)) else [],
                threat_family=ioc.related_threat_actor or f"ThreatIntel-{ioc.threat_type.upper()}",
                evidence=[
                    f"حقل المطابقة: {hit['field']}",
                    f"القيمة المرصودة: {hit['value']}",
                    f"معرف المؤشر: {ioc.id}",
                    f"مستوى السرية: TLP:{ioc.tlp.upper()}",
                    f"المصدر: {ioc.source}"
                ],
                contributing_factors=[f"تطابق فوري مع قاعدة استخبارات التهديدات المركزية بموثوقية {ioc.confidence}%"]
            )
            findings.append(f)

        return findings

    def evaluate_event(self, event: Any) -> List[Dict[str, Any]]:
        """Evaluate event against in-memory Threat Intelligence."""
        hits = self.manager.match_event(event, source_app="logscope")
        detections = []

        for hit in hits:
            ioc = hit["ioc"]
            detections.append({
                "rule_id": f"IOC-MATCH-{ioc.id}",
                "rule_name": f"مطابقة مؤشر اختراق ({ioc.threat_type.upper()}): {ioc.value}",
                "severity": ioc.severity,
                "confidence": ioc.confidence,
                "category": "threat_intelligence",
                "matched_field": hit["field"],
                "matched_value": hit["value"],
                "description": ioc.description or f"تم رصد مؤشر تهديد مسجل من مصدر {ioc.source}",
                "mitre_attack": ioc.mitre_attack,
                "ioc_id": ioc.id,
                "ioc_type": ioc.type,
                "tlp": ioc.tlp,
            })

        return detections

