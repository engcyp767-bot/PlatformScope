"""Unified Enterprise Incident Management Core Engine.

Manages the complete lifecycle, priority calculation, evidence vault,
timeline, and audit logging for security incidents across LogScope,
FlowScope, and ThreatScope without replacing underlying analysis engines.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from platform_core import audit_engine

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
STORAGE_DIR = WORKSPACE_ROOT / "storage"
DB_PATH = STORAGE_DIR / "incidents.sqlite3"
EVIDENCE_DIR = STORAGE_DIR / "evidence"

_LOCK = threading.RLock()

VALID_STATUSES = {"new", "triaged", "investigating", "contained", "resolved", "closed", "rejected"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_PRIORITIES = {"P1", "P2", "P3", "P4"}
VALID_EVIDENCE_TYPES = {"ip", "domain", "url", "hash", "file", "log_snippet", "pcap", "cve", "other"}

VALID_TRANSITIONS = {
    "new": {"triaged", "investigating", "rejected", "closed"},
    "triaged": {"investigating", "contained", "rejected", "closed"},
    "investigating": {"contained", "resolved", "rejected", "closed"},
    "contained": {"investigating", "resolved", "rejected", "closed"},
    "resolved": {"closed", "investigating"},
    "closed": {"investigating"},
    "rejected": {"investigating", "triaged"},
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def db_session():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
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


def get_evidence_file_path(rel_path: str) -> Path:
    return EVIDENCE_DIR / rel_path.replace("\\", "/")


def init_db() -> None:
    with _LOCK, db_session() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            correlation_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL,
            priority TEXT NOT NULL,
            asset_criticality TEXT DEFAULT 'medium',
            business_impact TEXT DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'new',
            source_app TEXT NOT NULL,
            source_job_id TEXT,
            assigned_to TEXT,
            mitre_tactics TEXT DEFAULT '[]',
            mitre_techniques TEXT DEFAULT '[]',
            entities TEXT DEFAULT '[]',
            detection_rule TEXT,
            confidence REAL DEFAULT 80.0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            closed_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
        CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(priority);
        CREATE INDEX IF NOT EXISTS idx_incidents_source_app ON incidents(source_app);
        CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to ON incidents(assigned_to);
        CREATE INDEX IF NOT EXISTS idx_incidents_correlation_id ON incidents(correlation_id);
        CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);

        CREATE TABLE IF NOT EXISTS incident_notes (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            author TEXT NOT NULL,
            note_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_notes_incident ON incident_notes(incident_id);

        CREATE TABLE IF NOT EXISTS incident_evidence (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            name TEXT NOT NULL,
            value TEXT,
            sha256 TEXT,
            size_bytes INTEGER DEFAULT 0,
            mime_type TEXT,
            file_path TEXT,
            notes TEXT,
            added_by TEXT NOT NULL,
            added_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_evidence_incident ON incident_evidence(incident_id);

        CREATE TABLE IF NOT EXISTS incident_timeline (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_timeline_incident ON incident_timeline(incident_id);

        CREATE TABLE IF NOT EXISTS incident_audit (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            before_state TEXT,
            after_state TEXT,
            reason TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_incident ON incident_audit(incident_id);
        """)


def calculate_priority(severity: str, asset_criticality: str = "medium", business_impact: str = "medium") -> str:
    sev_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity.lower(), 2)
    asset_weight = {"mission_critical": 3, "high": 2, "medium": 1, "low": 0}.get(asset_criticality.lower(), 1)
    impact_weight = {"high": 3, "medium": 2, "low": 1, "none": 0}.get(business_impact.lower(), 1)
    
    total = sev_weight + asset_weight + impact_weight
    if sev_weight == 4 and (asset_weight >= 2 or impact_weight >= 2):
        return "P1"
    if total >= 8:
        return "P1"
    if total >= 5:
        return "P2"
    if total >= 3:
        return "P3"
    return "P4"


def _generate_incident_id(conn: sqlite3.Connection) -> str:
    today_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    cursor = conn.execute(
        "SELECT id FROM incidents WHERE id LIKE ? ORDER BY id DESC LIMIT 1",
        (f"INC-{today_str}-%",)
    )
    row = cursor.fetchone()
    if row:
        last_id = row["id"]
        try:
            seq = int(last_id.split("-")[-1]) + 1
        except ValueError:
            seq = 1
    else:
        seq = 1
    return f"INC-{today_str}-{seq:04d}"


def _generate_correlation_id() -> str:
    return f"CORR-{uuid.uuid4().hex[:12].upper()}"


def _audit_and_timeline(
    conn: sqlite3.Connection,
    incident_id: str,
    actor: str,
    action: str,
    reason: str,
    before: Any = None,
    after: Any = None,
    details_str: str = "",
) -> None:
    now = _now_iso()
    audit_id = f"aud_{uuid.uuid4().hex[:12]}"
    conn.execute(
        """
        INSERT INTO incident_audit (id, incident_id, actor, action, timestamp, before_state, after_state, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            audit_id, incident_id, actor, action, now,
            json.dumps(before, ensure_ascii=False) if before is not None else None,
            json.dumps(after, ensure_ascii=False) if after is not None else None,
            reason,
        )
    )
    timeline_id = f"tl_{uuid.uuid4().hex[:12]}"
    conn.execute(
        """
        INSERT INTO incident_timeline (id, incident_id, action, actor, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (timeline_id, incident_id, action, actor, details_str or reason, now)
    )
    audit_engine.record_engine_event(
        application="soc",
        action=action,
        message=f"Incident {incident_id}: {action} by {actor} - {reason}",
        category="incident",
        details={"incident_id": incident_id, "actor": actor, "reason": reason}
    )


def create_incident(
    title: str,
    severity: str,
    source_app: str,
    description: str = "",
    source_job_id: str | None = None,
    correlation_id: str | None = None,
    asset_criticality: str = "medium",
    business_impact: str = "medium",
    assigned_to: str | None = None,
    mitre_tactics: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
    entities: list[str] | None = None,
    detection_rule: str | None = None,
    confidence: float = 80.0,
    actor: str = "system",
    reason: str = "Initial incident creation",
) -> dict:
    init_db()
    severity = severity.lower() if severity.lower() in VALID_SEVERITIES else "medium"
    priority = calculate_priority(severity, asset_criticality, business_impact)
    corr_id = correlation_id or _generate_correlation_id()
    now = _now_iso()

    with _LOCK, db_session() as conn:
        inc_id = _generate_incident_id(conn)
        conn.execute(
            """
            INSERT INTO incidents (
                id, correlation_id, title, description, severity, priority,
                asset_criticality, business_impact, status, source_app, source_job_id,
                assigned_to, mitre_tactics, mitre_techniques, entities, detection_rule,
                confidence, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                inc_id, corr_id, title, description, severity, priority,
                asset_criticality, business_impact, source_app, source_job_id,
                assigned_to, json.dumps(mitre_tactics or []), json.dumps(mitre_techniques or []),
                json.dumps(entities or []), detection_rule, confidence, now, now,
            )
        )
        _audit_and_timeline(
            conn, inc_id, actor, "incident.created", reason,
            before=None, after={"status": "new", "severity": severity, "priority": priority},
            details_str=f"تم إنشاء الحادث الأمني بعنوان: {title}"
        )

    return get_incident(inc_id) or {}


def get_incident(incident_id: str) -> dict | None:
    init_db()
    with _LOCK, db_session() as conn:
        cursor = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return None
        item = dict(row)
        item["mitre_tactics"] = json.loads(item.get("mitre_tactics") or "[]")
        item["mitre_techniques"] = json.loads(item.get("mitre_techniques") or "[]")
        item["entities"] = json.loads(item.get("entities") or "[]")

        n_cursor = conn.execute(
            "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at ASC",
            (incident_id,)
        )
        item["notes"] = [dict(r) for r in n_cursor.fetchall()]

        e_cursor = conn.execute(
            "SELECT * FROM incident_evidence WHERE incident_id = ? ORDER BY added_at DESC",
            (incident_id,)
        )
        item["evidence"] = [dict(r) for r in e_cursor.fetchall()]

        t_cursor = conn.execute(
            "SELECT * FROM incident_timeline WHERE incident_id = ? ORDER BY timestamp DESC",
            (incident_id,)
        )
        item["timeline"] = [dict(r) for r in t_cursor.fetchall()]

        a_cursor = conn.execute(
            "SELECT * FROM incident_audit WHERE incident_id = ? ORDER BY timestamp DESC",
            (incident_id,)
        )
        item["audit"] = [dict(r) for r in a_cursor.fetchall()]
        return item


def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    priority: str | None = None,
    source_app: str | None = None,
    assigned_to: str | None = None,
    search: str | None = None,
    limit: int = 25,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    init_db()
    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    conditions = []
    params: list[Any] = []

    if status and status.lower() in VALID_STATUSES:
        conditions.append("status = ?")
        params.append(status.lower())
    if severity and severity.lower() in VALID_SEVERITIES:
        conditions.append("severity = ?")
        params.append(severity.lower())
    if priority and priority.upper() in VALID_PRIORITIES:
        conditions.append("priority = ?")
        params.append(priority.upper())
    if source_app:
        conditions.append("source_app = ?")
        params.append(source_app.lower())
    if assigned_to:
        conditions.append("assigned_to = ?")
        params.append(assigned_to)
    if search:
        search_pattern = f"%{search.strip()}%"
        conditions.append("(id LIKE ? OR title LIKE ? OR description LIKE ? OR entities LIKE ? OR correlation_id LIKE ?)")
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern, search_pattern])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with _LOCK, db_session() as conn:
        count_query = f"SELECT count(*) FROM incidents {where_clause}"
        total = conn.execute(count_query, params).fetchone()[0]

        query = f"""
            SELECT * FROM incidents {where_clause}
            ORDER BY created_at DESC LIMIT ? OFFSET ?
        """
        rows = conn.execute(query, params + [limit, offset]).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["mitre_tactics"] = json.loads(d.get("mitre_tactics") or "[]")
            d["mitre_techniques"] = json.loads(d.get("mitre_techniques") or "[]")
            d["entities"] = json.loads(d.get("entities") or "[]")
            results.append(d)

    return results, total


def get_incidents_summary() -> dict:
    init_db()
    with _LOCK, db_session() as conn:
        total = conn.execute("SELECT count(*) FROM incidents").fetchone()[0]
        
        status_counts = {s: 0 for s in VALID_STATUSES}
        for row in conn.execute("SELECT status, count(*) as cnt FROM incidents GROUP BY status"):
            status_counts[row["status"]] = row["cnt"]

        severity_counts = {s: 0 for s in VALID_SEVERITIES}
        for row in conn.execute("SELECT severity, count(*) as cnt FROM incidents GROUP BY severity"):
            severity_counts[row["severity"]] = row["cnt"]

        priority_counts = {p: 0 for p in VALID_PRIORITIES}
        for row in conn.execute("SELECT priority, count(*) as cnt FROM incidents GROUP BY priority"):
            priority_counts[row["priority"]] = row["cnt"]

        assigned_count = conn.execute("SELECT count(*) FROM incidents WHERE assigned_to IS NOT NULL AND assigned_to != ''").fetchone()[0]
        unassigned_count = total - assigned_count

    return {
        "total": total,
        "by_status": status_counts,
        "by_severity": severity_counts,
        "by_priority": priority_counts,
        "assigned": assigned_count,
        "unassigned": unassigned_count,
    }


def update_status(incident_id: str, new_status: str, reason: str, actor: str) -> dict:
    init_db()
    new_status = new_status.lower()
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid status '{new_status}'. Allowed: {VALID_STATUSES}")
    if not reason or not reason.strip():
        raise ValueError("A reason is mandatory for any status change.")

    with _LOCK, db_session() as conn:
        inc = conn.execute("SELECT status FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            raise LookupError(f"Incident {incident_id} not found.")
        old_status = inc["status"]
        if old_status == new_status:
            return get_incident(incident_id) or {}

        allowed = VALID_TRANSITIONS.get(old_status, set())
        if new_status not in allowed:
            raise ValueError(f"Transition from '{old_status}' to '{new_status}' is not permitted. Allowed: {allowed}")

        now = _now_iso()
        closed_at = now if new_status in {"closed", "rejected"} else None

        conn.execute(
            """
            UPDATE incidents SET status = ?, updated_at = ?, closed_at = ?
            WHERE id = ?
            """,
            (new_status, now, closed_at, incident_id)
        )
        _audit_and_timeline(
            conn, incident_id, actor, "incident.status_changed", reason,
            before={"status": old_status}, after={"status": new_status},
            details_str=f"تم تغيير الحالة من [{old_status}] إلى [{new_status}]. السبب: {reason}"
        )

    return get_incident(incident_id) or {}


def assign_analyst(incident_id: str, username: str | None, actor: str, reason: str = "Analyst assignment") -> dict:
    init_db()
    with _LOCK, db_session() as conn:
        inc = conn.execute("SELECT assigned_to, status FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            raise LookupError(f"Incident {incident_id} not found.")
        old_assignee = inc["assigned_to"]
        target = username.strip() if username else None

        now = _now_iso()
        new_status = inc["status"]
        if inc["status"] == "new" and target:
            new_status = "triaged"

        conn.execute(
            "UPDATE incidents SET assigned_to = ?, status = ?, updated_at = ? WHERE id = ?",
            (target, new_status, now, incident_id)
        )
        _audit_and_timeline(
            conn, incident_id, actor, "incident.assigned", reason,
            before={"assigned_to": old_assignee, "status": inc["status"]},
            after={"assigned_to": target, "status": new_status},
            details_str=f"تم تعيين الحادث إلى: {target or 'غير معين'}"
        )

    return get_incident(incident_id) or {}


def update_priority(
    incident_id: str,
    severity: str | None = None,
    asset_criticality: str | None = None,
    business_impact: str | None = None,
    actor: str = "system",
    justification: str = "Severity/Priority update",
) -> dict:
    init_db()
    if not justification or not justification.strip():
        raise ValueError("A justification is mandatory for severity/priority modification.")

    with _LOCK, db_session() as conn:
        inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            raise LookupError(f"Incident {incident_id} not found.")

        old_state = {
            "severity": inc["severity"], "priority": inc["priority"],
            "asset_criticality": inc["asset_criticality"], "business_impact": inc["business_impact"]
        }

        new_sev = severity.lower() if severity and severity.lower() in VALID_SEVERITIES else inc["severity"]
        new_asset = asset_criticality.lower() if asset_criticality else inc["asset_criticality"]
        new_impact = business_impact.lower() if business_impact else inc["business_impact"]
        new_prio = calculate_priority(new_sev, new_asset, new_impact)

        now = _now_iso()
        conn.execute(
            """
            UPDATE incidents
            SET severity = ?, priority = ?, asset_criticality = ?, business_impact = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_sev, new_prio, new_asset, new_impact, now, incident_id)
        )
        new_state = {
            "severity": new_sev, "priority": new_prio,
            "asset_criticality": new_asset, "business_impact": new_impact
        }
        _audit_and_timeline(
            conn, incident_id, actor, "incident.priority_override", justification,
            before=old_state, after=new_state,
            details_str=f"تعديل مستوى الخطورة [{new_sev}] والأولوية [{new_prio}]. التبرير: {justification}"
        )

    return get_incident(incident_id) or {}


def add_note(incident_id: str, note_text: str, author: str) -> dict:
    init_db()
    if not note_text or not note_text.strip():
        raise ValueError("Note text cannot be empty.")

    note_id = f"not_{uuid.uuid4().hex[:12]}"
    now = _now_iso()

    with _LOCK, db_session() as conn:
        inc = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            raise LookupError(f"Incident {incident_id} not found.")

        conn.execute(
            """
            INSERT INTO incident_notes (id, incident_id, author, note_text, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (note_id, incident_id, author, note_text.strip(), now)
        )
        conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now, incident_id))
        _audit_and_timeline(
            conn, incident_id, author, "incident.note_added", "Added investigation note",
            before=None, after={"note_id": note_id},
            details_str=f"أضاف المحلل {author} ملاحظة تحقيق جديدة: {note_text[:100]}..."
        )

    return get_incident(incident_id) or {}


def add_evidence_record(
    incident_id: str,
    evidence_type: str,
    name: str,
    value: str | None = None,
    file_bytes: bytes | None = None,
    filename: str | None = None,
    mime_type: str | None = None,
    notes: str = "",
    added_by: str = "analyst",
) -> dict:
    init_db()
    evidence_type = evidence_type.lower()
    if evidence_type not in VALID_EVIDENCE_TYPES:
        raise ValueError(f"Invalid evidence type '{evidence_type}'. Allowed: {VALID_EVIDENCE_TYPES}")

    evidence_id = f"evi_{uuid.uuid4().hex[:12]}"
    now = _now_iso()
    file_rel_path = None
    sha256_hash = None
    size_bytes = 0

    if file_bytes is not None and len(file_bytes) > 0:
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        size_bytes = len(file_bytes)
        inc_vault = EVIDENCE_DIR / incident_id
        inc_vault.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", filename or name or "artifact")
        storage_filename = f"{sha256_hash[:12]}_{safe_name}"
        dest_file = inc_vault / storage_filename
        dest_file.write_bytes(file_bytes)
        file_rel_path = f"{incident_id}/{storage_filename}"
    elif value:
        sha256_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()

    with _LOCK, db_session() as conn:
        inc = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not inc:
            raise LookupError(f"Incident {incident_id} not found.")

        conn.execute(
            """
            INSERT INTO incident_evidence (
                id, incident_id, evidence_type, name, value, sha256, size_bytes,
                mime_type, file_path, notes, added_by, added_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id, incident_id, evidence_type, name, value, sha256_hash,
                size_bytes, mime_type or "text/plain", file_rel_path, notes, added_by, now
            )
        )
        conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now, incident_id))
        _audit_and_timeline(
            conn, incident_id, added_by, "incident.evidence_added", notes or f"Attached evidence {name}",
            before=None, after={"evidence_id": evidence_id, "name": name, "sha256": sha256_hash},
            details_str=f"تم إرفاق دليل أمني [{evidence_type}]: {name} (SHA-256: {sha256_hash or 'N/A'})"
        )

    return get_incident(incident_id) or {}


def remove_evidence_record(incident_id: str, evidence_id: str, actor: str, reason: str = "Evidence removed") -> dict:
    init_db()
    with _LOCK, db_session() as conn:
        row = conn.execute(
            "SELECT * FROM incident_evidence WHERE id = ? AND incident_id = ?",
            (evidence_id, incident_id)
        ).fetchone()
        if not row:
            raise LookupError(f"Evidence {evidence_id} not found in incident {incident_id}.")

        file_path = row["file_path"]
        if file_path:
            full_path = get_evidence_file_path(file_path)
            if full_path.is_file():
                try:
                    full_path.unlink()
                except OSError:
                    pass

        conn.execute("DELETE FROM incident_evidence WHERE id = ?", (evidence_id,))
        now = _now_iso()
        conn.execute("UPDATE incidents SET updated_at = ? WHERE id = ?", (now, incident_id))
        _audit_and_timeline(
            conn, incident_id, actor, "incident.evidence_removed", reason,
            before={"evidence_id": evidence_id, "name": row["name"]}, after=None,
            details_str=f"تم حذف الدليل الأمني [{row['evidence_type']}]: {row['name']}"
        )

    return get_incident(incident_id) or {}


def promote_detection_to_incident(
    source_app: str,
    source_job_id: str,
    detection_data: dict,
    actor: str = "system",
    reason: str = "Automatic promotion based on severity/correlation rules",
    auto: bool = False,
) -> dict:
    """Detection-to-Incident Promotion Logic."""
    severity = str(detection_data.get("severity") or "medium").lower()
    confidence = float(detection_data.get("confidence") or 80.0)
    risk_score = float(detection_data.get("risk_score") or 0.0)
    name = str(detection_data.get("name") or detection_data.get("title") or f"Security incident detected in {source_app.title()}")
    desc = str(detection_data.get("description") or detection_data.get("detail") or "")

    if auto:
        is_high_sev = severity in {"critical", "high"}
        is_high_risk = risk_score >= 75.0
        is_multi_stage = bool(detection_data.get("mitre_tactics") and len(detection_data.get("mitre_tactics")) > 1)
        if not (is_high_sev or is_high_risk or is_multi_stage):
            return {}

    corr_id = detection_data.get("correlation_id") or f"CORR-{source_job_id[:12].upper()}"

    entities = detection_data.get("entities") or []
    if not entities:
        if detection_data.get("src_ip"):
            entities.append(str(detection_data.get("src_ip")))
        if detection_data.get("dst_ip"):
            entities.append(str(detection_data.get("dst_ip")))
        if detection_data.get("event_source"):
            entities.append(str(detection_data.get("event_source")))

    mitre_tactics = detection_data.get("mitre_tactics") or []
    mitre_techniques = detection_data.get("mitre_techniques") or []

    inc = create_incident(
        title=name,
        severity=severity,
        source_app=source_app,
        description=desc,
        source_job_id=source_job_id,
        correlation_id=corr_id,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        entities=list(set(entities)),
        detection_rule=detection_data.get("rule_name") or detection_data.get("detection_rule"),
        confidence=confidence,
        actor=actor,
        reason=reason,
    )

    inc_id = inc["id"]
    for entity in entities:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(entity)):
            add_evidence_record(
                inc_id, evidence_type="ip", name=f"Observed IP: {entity}",
                value=str(entity), notes="Extracted from detection telemetry", added_by=actor
            )
        elif re.match(r"^[a-fA-F0-9]{32,64}$", str(entity)):
            add_evidence_record(
                inc_id, evidence_type="hash", name=f"Malicious Hash: {entity[:12]}...",
                value=str(entity), notes="Extracted from detection telemetry", added_by=actor
            )

    return get_incident(inc_id) or inc


def sync_all_existing_jobs() -> int:
    """Sync incidents from existing persisted analysis jobs into the unified store."""
    init_db()
    synced = 0
    with _LOCK, db_session() as conn:
        existing_job_ids = {
            row["source_job_id"] for row in conn.execute("SELECT source_job_id FROM incidents WHERE source_job_id IS NOT NULL")
        }

    for app in ("logscope", "flowscope", "threatscope"):
        jobs_dir = WORKSPACE_ROOT / app / "storage" / "jobs"
        if not jobs_dir.is_dir():
            continue
        for job_dir in jobs_dir.iterdir():
            if not job_dir.is_dir() or len(job_dir.name) != 32:
                continue
            if job_dir.name in existing_job_ids:
                continue
            analysis_file = job_dir / "analysis.json"
            if not analysis_file.is_file():
                continue
            try:
                data = json.loads(analysis_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue

            if app == "logscope" and data.get("incidents"):
                for inc_item in data["incidents"]:
                    corr_id = f"CORR-LS-{job_dir.name[:8].upper()}"
                    create_incident(
                        title=inc_item.get("name") or "Correlated SIEM Attack Incident",
                        severity=inc_item.get("severity") or "high",
                        source_app="logscope",
                        description=inc_item.get("description") or "Multi-stage correlated attack from LogScope",
                        source_job_id=job_dir.name,
                        correlation_id=corr_id,
                        mitre_tactics=inc_item.get("mitre_tactics") or [],
                        mitre_techniques=inc_item.get("mitre_techniques") or [],
                        entities=inc_item.get("entities") or [],
                        confidence=inc_item.get("confidence") or 85.0,
                        actor="logscope_sync",
                        reason="Imported from completed LogScope analysis job",
                    )
                    synced += 1
                    existing_job_ids.add(job_dir.name)

            elif app == "threatscope":
                summary = data.get("summary") or {}
                if summary.get("malicious_count", 0) > 0 or summary.get("high_risk", 0) > 0:
                    corr_id = f"CORR-TS-{job_dir.name[:8].upper()}"
                    create_incident(
                        title=f"ThreatScope Malware Detections: {summary.get('malicious_count', 0)} malicious hashes",
                        severity="critical" if summary.get("malicious_count", 0) > 3 else "high",
                        source_app="threatscope",
                        description=f"Automated threat detection found {summary.get('malicious_count')} confirmed malicious items and {summary.get('suspicious_count', 0)} suspicious files.",
                        source_job_id=job_dir.name,
                        correlation_id=corr_id,
                        entities=data.get("malicious_hashes") or [],
                        confidence=95.0,
                        actor="threatscope_sync",
                        reason="Imported from ThreatScope malware detections",
                    )
                    synced += 1
                    existing_job_ids.add(job_dir.name)

            elif app == "flowscope":
                summary = data.get("summary") or {}
                if summary.get("critical_count", 0) > 0 or summary.get("high_count", 0) > 0:
                    corr_id = f"CORR-FS-{job_dir.name[:8].upper()}"
                    create_incident(
                        title=f"FlowScope Anomaly & High-Transfer Alert ({job_dir.name[:8].upper()})",
                        severity="high" if summary.get("critical_count", 0) == 0 else "critical",
                        source_app="flowscope",
                        description=f"Network flow correlation detected {summary.get('critical_count', 0)} critical flows and {summary.get('high_count', 0)} high severity anomalies.",
                        source_job_id=job_dir.name,
                        correlation_id=corr_id,
                        entities=data.get("summary", {}).get("top_sources") or [],
                        confidence=85.0,
                        actor="flowscope_sync",
                        reason="Imported from FlowScope network anomaly analysis",
                    )
                    synced += 1
                    existing_job_ids.add(job_dir.name)

    return synced
