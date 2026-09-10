"""Append-only structured audit events emitted by Python analysis workers."""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = ROOT / "storage" / "audit"
_LOCK = threading.Lock()
_ENABLED = True
_LEVEL = "info"
_INCLUDE_DETAILS = True
_MAX_DETAIL_LENGTH = 500
_LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}
_LAST_HASH = "GENESIS_AUDIT_HASH_00000000000000000000000000000000000000000000000000000000"


def configure(*, enabled: bool = True, level: str = "info", include_details: bool = True, max_detail_length: int = 500, **_: Any) -> None:
    global _ENABLED, _LEVEL, _INCLUDE_DETAILS, _MAX_DETAIL_LENGTH
    _ENABLED = bool(enabled)
    _LEVEL = level if level in _LEVELS else "info"
    _INCLUDE_DETAILS = bool(include_details)
    _MAX_DETAIL_LENGTH = max(100, min(int(max_detail_length), 5000))


def _trim(value: Any) -> Any:
    if isinstance(value, str):
        return value[:_MAX_DETAIL_LENGTH]
    if isinstance(value, dict):
        return {str(key)[:80]: _trim(item) for key, item in list(value.items())[:100]}
    if isinstance(value, list):
        return [_trim(item) for item in value[:100]]
    return value


def _compute_hash(prev_hash: str, event_data: dict[str, Any]) -> str:
    """Compute deterministic SHA-256 hash for audit entry chained with prev_hash."""
    canonical = json.dumps(event_data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    content = f"{prev_hash}:{canonical}".encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def record_engine_event(
    *, application: str, action: str, message: str, job_id: str | None = None,
    level: str = "info", outcome: str = "success", category: str = "analysis",
    details: dict[str, Any] | None = None,
) -> None:
    """Persist one small event without ever interrupting the analysis itself."""
    """Persist one small event with cryptographic tamper-evident hash chain without interrupting analysis."""
    global _LAST_HASH
    if not _ENABLED or _LEVELS.get(level, 20) < _LEVELS.get(_LEVEL, 20):
        return
    try:
        timestamp = datetime.now(timezone.utc).isoformat()
        event = {
            "id": uuid.uuid4().hex,
            "timestamp": timestamp,
            "level": level,
            "outcome": outcome,
            "category": category,
            "action": action,
            "message": message,
            "application": application,
            "job_id": job_id,
            "details": _trim(details or {}) if _INCLUDE_DETAILS else {},
        }
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        target = AUDIT_DIR / f"engine-{timestamp[:10]}.jsonl"
        with _LOCK, target.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")

        with _LOCK:
            # Recover last hash if still at genesis and file exists
            if _LAST_HASH.startswith("GENESIS_AUDIT_HASH") and target.exists():
                try:
                    with target.open("r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                rec = json.loads(line)
                                if rec.get("entry_hash"):
                                    _LAST_HASH = rec["entry_hash"]
                except Exception:
                    pass

            event_core = {
                "id": uuid.uuid4().hex,
                "timestamp": timestamp,
                "level": level,
                "outcome": outcome,
                "category": category,
                "action": action,
                "message": message,
                "application": application,
                "job_id": job_id,
                "details": _trim(details or {}) if _INCLUDE_DETAILS else {},
                "prev_hash": _LAST_HASH,
            }
            entry_hash = _compute_hash(_LAST_HASH, event_core)
            event_core["entry_hash"] = entry_hash
            _LAST_HASH = entry_hash

            AUDIT_DIR.mkdir(parents=True, exist_ok=True)
            target = AUDIT_DIR / f"engine-{timestamp[:10]}.jsonl"
            with target.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(event_core, ensure_ascii=False, separators=(",", ":")) + "\n")
    except Exception:
        # Observability must never become a cause of analysis failure.
        return


def record_activity(
    *,
    action: str,
    message: str,
    user_id: str | None = None,
    username: str | None = None,
    category: str = "governance",
    outcome: str = "success",
    level: str = "info",
    client_ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Record sensitive platform governance operations into the cryptographic audit log."""
    det = details.copy() if details else {}
    if user_id:
        det["user_id"] = user_id
    if username:
        det["username"] = username
    if client_ip:
        det["client_ip"] = client_ip
    record_engine_event(
        application="platform",
        action=action,
        message=message,
        category=category,
        outcome=outcome,
        level=level,
        details=det,
    )


def verify_audit_integrity(file_path: Path | str | None = None) -> tuple[bool, str]:
    """Verify cryptographic hash chain integrity of an audit log file (or all files if None)."""
    if file_path is None:
        if not AUDIT_DIR.exists():
            return True, "Audit directory does not exist yet."
        audit_files = sorted(AUDIT_DIR.glob("*.jsonl"))
        if not audit_files:
            return True, "No audit log files present yet."
        for af in audit_files:
            ok, msg = verify_audit_integrity(af)
            if not ok:
                return False, f"{af.name}: {msg}"
        return True, f"All {len(audit_files)} audit log files verified successfully."

    path = Path(file_path)
    if not path.exists():
        return False, f"Audit file does not exist: {path.name}"

    current_expected_prev = "GENESIS_AUDIT_HASH_00000000000000000000000000000000000000000000000000000000"
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line_idx, line in enumerate(stream, start=1):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                recorded_hash = record.get("entry_hash")
                recorded_prev = record.get("prev_hash")

                if not recorded_hash:
                    # Legacy record before hash chain adoption
                    continue

                if line_idx == 1 or current_expected_prev == "GENESIS_AUDIT_HASH_00000000000000000000000000000000000000000000000000000000":
                    current_expected_prev = recorded_prev

                if recorded_prev != current_expected_prev:
                    return False, f"Broken chain at line {line_idx}: expected prev_hash {current_expected_prev}, got {recorded_prev}"

                # Recompute hash
                verification_data = {k: v for k, v in record.items() if k != "entry_hash"}
                computed_hash = _compute_hash(recorded_prev, verification_data)
                if computed_hash != recorded_hash:
                    return False, f"Tampered record at line {line_idx}: computed {computed_hash} != {recorded_hash}"

                current_expected_prev = recorded_hash

        return True, "Audit log integrity verified successfully."
    except Exception as exc:
        return False, f"Verification failed with exception: {exc}"


