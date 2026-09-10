"""Centralized Asset Intelligence & Inventory Engine (Phase 5).

Provides enterprise asset lifecycle management, Identity Resolution,
Dynamic Risk Scoring, expanded SOC mesh relationships (Events, Detections,
Incidents, IOCs, Threat History), timeline tracking, Action Framework
for isolation/containment, and CMDB import/export.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from platform_core import audit_engine


def _log_audit(action: str, message: str, details: dict | None = None) -> None:
    try:
        audit_engine.record_engine_event(
            application="assets",
            action=action,
            message=message,
            category="asset",
            details=details or {}
        )
    except Exception:
        pass

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
STORAGE_DIR = WORKSPACE_ROOT / "storage"
DB_PATH = STORAGE_DIR / "assets.sqlite3"

_LOCK = threading.RLock()

VALID_ASSET_TYPES = {
    "server", "workstation", "domain_controller", "firewall",
    "database", "cloud_instance", "iot", "network_switch", "router", "other"
}
VALID_CRITICALITIES = {"mission_critical", "high", "medium", "low"}
VALID_STATUSES = {"unknown", "active", "maintenance", "isolated", "decommissioned"}
VALID_ENVIRONMENTS = {"production", "staging", "development", "dmz", "lab"}
VALID_CONTAINMENT_STATUSES = {"draft", "pending_approval", "dispatched", "confirmed", "revoked"}
VALID_CONTAINMENT_PROVIDERS = {"generic_webhook", "sentinel_one", "endpoint_central", "fortinet_firewall", "manual_playbook"}

MAC_CLEAN_REGEX = re.compile(r"[^0-9a-fA-F]")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_mac(mac: str | None) -> str:
    if not mac:
        return ""
    cleaned = MAC_CLEAN_REGEX.sub("", str(mac)).lower()
    if len(cleaned) == 12:
        return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))
    return cleaned


def normalize_hostname(name: str | None) -> str:
    if not name:
        return ""
    raw = str(name).strip()
    if "." in raw:
        raw = raw.split(".")[0]
    return raw.upper()


@contextmanager
def db_session(existing_conn: sqlite3.Connection | None = None):
    if existing_conn is not None:
        yield existing_conn
        return

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


def init_db() -> None:
    with _LOCK, db_session() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            normalized_hostname TEXT NOT NULL,
            primary_ip TEXT NOT NULL,
            ip_addresses TEXT NOT NULL DEFAULT '[]',
            mac_address TEXT DEFAULT '',
            os TEXT DEFAULT 'Unknown',
            asset_type TEXT NOT NULL DEFAULT 'server',
            criticality TEXT NOT NULL DEFAULT 'medium',
            status TEXT NOT NULL DEFAULT 'unknown',
            environment TEXT NOT NULL DEFAULT 'production',
            owner TEXT DEFAULT 'Unassigned',
            department TEXT DEFAULT 'IT Operations',
            risk_score INTEGER NOT NULL DEFAULT 10,
            confidence_score INTEGER NOT NULL DEFAULT 50,
            discovery_sources TEXT NOT NULL DEFAULT '[]',
            tags TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_deleted INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS asset_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT NOT NULL,
            alias_type TEXT NOT NULL,
            alias_value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS asset_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL DEFAULT 'info',
            actor TEXT NOT NULL DEFAULT 'system',
            metadata TEXT NOT NULL DEFAULT '{}',
            timestamp TEXT NOT NULL,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS asset_containment_actions (
            id TEXT PRIMARY KEY,
            asset_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            provider TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            dispatched_by TEXT,
            playbook_commands TEXT NOT NULL,
            payload TEXT NOT NULL DEFAULT '{}',
            execution_log TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_assets_id ON assets(id);
        CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(normalized_hostname);
        CREATE INDEX IF NOT EXISTS idx_assets_primary_ip ON assets(primary_ip);
        CREATE INDEX IF NOT EXISTS idx_assets_mac ON assets(mac_address);
        CREATE INDEX IF NOT EXISTS idx_assets_risk ON assets(risk_score);
        CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
        CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
        CREATE INDEX IF NOT EXISTS idx_assets_deleted ON assets(is_deleted);
        CREATE INDEX IF NOT EXISTS idx_aliases_asset ON asset_aliases(asset_id);
        CREATE INDEX IF NOT EXISTS idx_aliases_lookup ON asset_aliases(alias_type, alias_value);
        CREATE INDEX IF NOT EXISTS idx_timeline_asset ON asset_timeline(asset_id);
        CREATE INDEX IF NOT EXISTS idx_actions_asset ON asset_containment_actions(asset_id);
        """)


def _row_to_asset(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k in ("ip_addresses", "discovery_sources", "tags"):
        try:
            d[k] = json.loads(d.get(k) or "[]")
        except Exception:
            d[k] = []
    try:
        d["metadata"] = json.loads(d.get("metadata") or "{}")
    except Exception:
        d["metadata"] = {}
    d["is_deleted"] = bool(d.get("is_deleted", 0))
    return d


def resolve_asset_identity(
    mac: str | None = None,
    hostname: str | None = None,
    ip: str | None = None,
    conn: sqlite3.Connection | None = None
) -> Optional[dict]:
    """Identity Resolution Layer: Finds existing asset by MAC, Hostname, or IP."""
    clean_mac = normalize_mac(mac)
    norm_host = normalize_hostname(hostname)
    clean_ip = str(ip or "").strip()

    init_db()
    with _LOCK, db_session(conn) as session_conn:
        # Priority 1: Match by normalized MAC Address
        if clean_mac:
            row = session_conn.execute(
                "SELECT * FROM assets WHERE mac_address = ? AND is_deleted = 0 LIMIT 1",
                (clean_mac,)
            ).fetchone()
            if row:
                return _row_to_asset(row)
            # Check aliases
            alias = session_conn.execute(
                "SELECT asset_id FROM asset_aliases WHERE alias_type = 'mac' AND alias_value = ? LIMIT 1",
                (clean_mac,)
            ).fetchone()
            if alias:
                match = session_conn.execute("SELECT * FROM assets WHERE id = ? AND is_deleted = 0 LIMIT 1", (alias["asset_id"],)).fetchone()
                if match:
                    return _row_to_asset(match)

        # Priority 2: Match by Normalized Hostname
        if norm_host and norm_host not in {"UNKNOWN", "LOCALHOST", "NONE", "WIN", "DESKTOP"}:
            row = session_conn.execute(
                "SELECT * FROM assets WHERE normalized_hostname = ? AND is_deleted = 0 LIMIT 1",
                (norm_host,)
            ).fetchone()
            if row:
                return _row_to_asset(row)
            # Check aliases
            alias = session_conn.execute(
                "SELECT asset_id FROM asset_aliases WHERE alias_type IN ('hostname', 'fqdn', 'netbios') AND alias_value = ? LIMIT 1",
                (norm_host,)
            ).fetchone()
            if alias:
                match = session_conn.execute("SELECT * FROM assets WHERE id = ? AND is_deleted = 0 LIMIT 1", (alias["asset_id"],)).fetchone()
                if match:
                    return _row_to_asset(match)

        # Priority 3: Match by Primary IP or IP alias
        if clean_ip and clean_ip not in {"127.0.0.1", "::1", "0.0.0.0", "unknown"}:
            row = session_conn.execute(
                "SELECT * FROM assets WHERE primary_ip = ? AND is_deleted = 0 LIMIT 1",
                (clean_ip,)
            ).fetchone()
            if row:
                return _row_to_asset(row)
            alias = session_conn.execute(
                "SELECT asset_id FROM asset_aliases WHERE alias_type = 'ip' AND alias_value = ? LIMIT 1",
                (clean_ip,)
            ).fetchone()
            if alias:
                match = session_conn.execute("SELECT * FROM assets WHERE id = ? AND is_deleted = 0 LIMIT 1", (alias["asset_id"],)).fetchone()
                if match:
                    return _row_to_asset(match)

    return None


def calculate_dynamic_risk(asset: dict) -> int:
    """Calculates dynamic risk score (0-100) based on Criticality + Incidents + Threat Intel + Activity."""
    criticality = str(asset.get("criticality", "medium")).lower()
    crit_scores = {"mission_critical": 30, "high": 20, "medium": 10, "low": 5}
    base_crit = crit_scores.get(criticality, 10)

    # 1. Incidents Component
    incidents_score = 0
    hostname = asset.get("hostname", "")
    norm_host = asset.get("normalized_hostname", "")
    ips = set(asset.get("ip_addresses", []))
    if asset.get("primary_ip"):
        ips.add(asset["primary_ip"])

    try:
        from platform_core import incident_manager
        all_incidents = incident_manager.list_incidents().get("incidents", [])
        active_incidents = [
            inc for inc in all_incidents
            if inc.get("status") not in {"resolved", "closed", "rejected"}
        ]
        for inc in active_incidents:
            entities = inc.get("entities", [])
            source_ips = inc.get("source_ips", [])
            target_ips = inc.get("target_ips", [])
            match_found = False
            for ip in ips:
                if ip and (ip in source_ips or ip in target_ips or ip in entities):
                    match_found = True
                    break
            if not match_found and (hostname in entities or norm_host in entities):
                match_found = True

            if match_found:
                prio = str(inc.get("priority", "P3")).upper()
                if prio == "P1":
                    incidents_score += 35
                elif prio == "P2":
                    incidents_score += 20
                elif prio == "P3":
                    incidents_score += 10
                else:
                    incidents_score += 5
    except Exception:
        pass

    # 2. Threat Intel Component
    intel_score = 0
    try:
        from platform_core import threat_intel
        for ip in ips:
            if ip:
                matches = threat_intel.lookup_ioc(ip)
                if matches:
                    top_threat = matches[0].get("threat_type", "suspicious")
                    if top_threat in {"c2", "ransomware", "apt"}:
                        intel_score = max(intel_score, 35)
                    elif top_threat in {"malware", "botnet", "exploit"}:
                        intel_score = max(intel_score, 25)
                    else:
                        intel_score = max(intel_score, 15)
    except Exception:
        pass

    # 3. Activity Component (Status & Detections)
    activity_score = 0
    if asset.get("status") == "isolated":
        activity_score += 20
    elif asset.get("status") == "unknown":
        activity_score += 10

    total_risk = base_crit + min(50, incidents_score) + min(35, intel_score) + activity_score
    return max(5, min(100, total_risk))


def add_timeline_event(
    asset_id: str,
    event_type: str,
    title: str,
    description: str = "",
    severity: str = "info",
    actor: str = "system",
    metadata: dict | None = None,
    conn: sqlite3.Connection | None = None
) -> int:
    init_db()
    with _LOCK, db_session(conn) as session_conn:
        cur = session_conn.execute(
            """
            INSERT INTO asset_timeline (asset_id, event_type, title, description, severity, actor, metadata, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (asset_id, event_type, title, description, severity, actor, json.dumps(metadata or {}), _now_iso())
        )
        return cur.lastrowid


def create_or_update_asset(
    hostname: str,
    primary_ip: str,
    mac_address: str | None = None,
    ip_addresses: list[str] | None = None,
    os_name: str | None = None,
    asset_type: str = "server",
    criticality: str = "medium",
    status: str = "unknown",
    environment: str = "production",
    owner: str = "Unassigned",
    department: str = "IT Operations",
    confidence_score: int = 50,
    discovery_source: str = "manual",
    tags: list[str] | None = None,
    metadata: dict | None = None,
    actor: str = "system"
) -> dict:
    init_db()
    now = _now_iso()
    clean_mac = normalize_mac(mac_address)
    norm_host = normalize_hostname(hostname)
    clean_primary_ip = str(primary_ip or "0.0.0.0").strip()

    all_ips = set()
    if clean_primary_ip and clean_primary_ip != "0.0.0.0":
        all_ips.add(clean_primary_ip)
    if ip_addresses:
        for ip in ip_addresses:
            ip_str = str(ip or "").strip()
            if ip_str:
                all_ips.add(ip_str)

    with _LOCK, db_session() as conn:
        existing = resolve_asset_identity(mac=clean_mac, hostname=norm_host, ip=clean_primary_ip, conn=conn)

        if existing:
            asset_id = existing["id"]
            current_ips = set(existing.get("ip_addresses", []))
            combined_ips = list(current_ips.union(all_ips))

            sources = existing.get("discovery_sources", [])
            src_map = {s["source"]: s for s in sources if isinstance(s, dict) and "source" in s}
            if discovery_source in src_map:
                src_map[discovery_source]["last_seen"] = now
                src_map[discovery_source]["count"] = src_map[discovery_source].get("count", 1) + 1
            else:
                src_map[discovery_source] = {
                    "source": discovery_source,
                    "first_seen": now,
                    "last_seen": now,
                    "count": 1
                }
            merged_sources = list(src_map.values())

            new_conf = max(existing.get("confidence_score", 50), confidence_score)
            if len(merged_sources) > 1:
                new_conf = min(100, new_conf + 10)

            if clean_primary_ip and clean_primary_ip != existing.get("primary_ip"):
                add_timeline_event(
                    asset_id,
                    "ip_changed",
                    f"تغير عنوان الـ IP الرئيسي إلى {clean_primary_ip}",
                    f"العنوان السابق: {existing.get('primary_ip')}",
                    severity="low",
                    actor=actor,
                    conn=conn
                )
                conn.execute(
                    "INSERT INTO asset_aliases (asset_id, alias_type, alias_value, created_at) VALUES (?, 'ip', ?, ?)",
                    (asset_id, clean_primary_ip, now)
                )

            new_os = os_name if os_name and os_name != "Unknown" else existing.get("os", "Unknown")
            conn.execute(
                """
                UPDATE assets
                SET primary_ip = ?, ip_addresses = ?, os = ?, last_seen = ?, updated_at = ?,
                    confidence_score = ?, discovery_sources = ?, is_deleted = 0
                WHERE id = ?
                """,
                (clean_primary_ip, json.dumps(combined_ips), new_os, now, now, new_conf, json.dumps(merged_sources), asset_id)
            )

            if clean_mac and clean_mac != existing.get("mac_address"):
                conn.execute(
                    "UPDATE assets SET mac_address = ? WHERE id = ?",
                    (clean_mac, asset_id)
                )
                conn.execute(
                    "INSERT INTO asset_aliases (asset_id, alias_type, alias_value, created_at) VALUES (?, 'mac', ?, ?)",
                    (asset_id, clean_mac, now)
                )

            updated_row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
            asset_dict = _row_to_asset(updated_row)

            new_risk = calculate_dynamic_risk(asset_dict)
            conn.execute("UPDATE assets SET risk_score = ? WHERE id = ?", (new_risk, asset_id))
            asset_dict["risk_score"] = new_risk
            return asset_dict

        else:
            asset_id = f"AST-{uuid.uuid4().hex[:12].upper()}"
            initial_sources = [{
                "source": discovery_source,
                "first_seen": now,
                "last_seen": now,
                "count": 1
            }]
            ips_json = json.dumps(list(all_ips))
            tags_json = json.dumps(tags or [])
            meta_json = json.dumps(metadata or {})
            sources_json = json.dumps(initial_sources)

            conn.execute(
                """
                INSERT INTO assets (
                    id, hostname, normalized_hostname, primary_ip, ip_addresses, mac_address,
                    os, asset_type, criticality, status, environment, owner, department,
                    risk_score, confidence_score, discovery_sources, tags, metadata,
                    first_seen, last_seen, created_at, updated_at, is_deleted
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    asset_id, hostname, norm_host, clean_primary_ip, ips_json, clean_mac,
                    os_name or "Unknown", asset_type, criticality, status, environment,
                    owner, department, 10, confidence_score, sources_json, tags_json,
                    meta_json, now, now, now, now
                )
            )

            if norm_host:
                conn.execute("INSERT INTO asset_aliases (asset_id, alias_type, alias_value, created_at) VALUES (?, 'hostname', ?, ?)", (asset_id, norm_host, now))
            if clean_primary_ip:
                conn.execute("INSERT INTO asset_aliases (asset_id, alias_type, alias_value, created_at) VALUES (?, 'ip', ?, ?)", (asset_id, clean_primary_ip, now))
            if clean_mac:
                conn.execute("INSERT INTO asset_aliases (asset_id, alias_type, alias_value, created_at) VALUES (?, 'mac', ?, ?)", (asset_id, clean_mac, now))

            add_timeline_event(
                asset_id,
                "discovered",
                f"تم رصد واكتشاف الأصل عبر {discovery_source}",
                f"الاسم: {hostname} | العنوان: {clean_primary_ip}",
                severity="info",
                actor=actor,
                metadata={"discovery_source": discovery_source, "confidence": confidence_score},
                conn=conn
            )

            new_row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
            asset_dict = _row_to_asset(new_row)

            initial_risk = calculate_dynamic_risk(asset_dict)
            conn.execute("UPDATE assets SET risk_score = ? WHERE id = ?", (initial_risk, asset_id))
            asset_dict["risk_score"] = initial_risk

            _log_audit(
                "asset.created",
                f"Asset {asset_id} ({hostname}) created",
                {"asset_id": asset_id, "hostname": hostname, "primary_ip": clean_primary_ip, "criticality": criticality}
            )
            return asset_dict


def list_assets(
    search: str | None = None,
    criticality: str | None = None,
    asset_type: str | None = None,
    status: str | None = None,
    department: str | None = None,
    min_risk: int | None = None,
    limit: int = 50,
    offset: int = 0,
    sort_by: str = "risk_score",
    sort_order: str = "desc"
) -> dict:
    init_db()
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    where_clauses = ["is_deleted = 0"]
    params: list[Any] = []

    if search:
        s = f"%{search.strip()}%"
        where_clauses.append("(hostname LIKE ? OR primary_ip LIKE ? OR mac_address LIKE ? OR owner LIKE ? OR department LIKE ?)")
        params.extend([s, s, s, s, s])

    if criticality and criticality != "all":
        where_clauses.append("criticality = ?")
        params.append(criticality)

    if asset_type and asset_type != "all":
        where_clauses.append("asset_type = ?")
        params.append(asset_type)

    if status and status != "all":
        where_clauses.append("status = ?")
        params.append(status)

    if department and department != "all":
        where_clauses.append("department = ?")
        params.append(department)

    if min_risk is not None and min_risk > 0:
        where_clauses.append("risk_score >= ?")
        params.append(min_risk)

    where_sql = " AND ".join(where_clauses)
    allowed_sorts = {"risk_score", "hostname", "created_at", "last_seen", "criticality", "confidence_score"}
    sort_col = sort_by if sort_by in allowed_sorts else "risk_score"
    order_dir = "ASC" if str(sort_order).lower() == "asc" else "DESC"

    with _LOCK, db_session() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM assets WHERE {where_sql}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM assets WHERE {where_sql} ORDER BY {sort_col} {order_dir} LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()

    return {
        "assets": [_row_to_asset(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset
    }


def get_asset(asset_id: str) -> Optional[dict]:
    init_db()
    with _LOCK, db_session() as conn:
        row = conn.execute("SELECT * FROM assets WHERE id = ? AND is_deleted = 0", (asset_id,)).fetchone()
        if not row:
            return None
        asset = _row_to_asset(row)

        aliases = conn.execute("SELECT alias_type, alias_value, created_at FROM asset_aliases WHERE asset_id = ?", (asset_id,)).fetchall()
        asset["aliases"] = [dict(a) for a in aliases]

        timeline_rows = conn.execute(
            "SELECT * FROM asset_timeline WHERE asset_id = ? ORDER BY timestamp DESC LIMIT 50",
            (asset_id,)
        ).fetchall()
        timeline = []
        for tr in timeline_rows:
            item = dict(tr)
            try:
                item["metadata"] = json.loads(item.get("metadata") or "{}")
            except Exception:
                item["metadata"] = {}
            timeline.append(item)
        asset["timeline"] = timeline

        action_rows = conn.execute(
            "SELECT * FROM asset_containment_actions WHERE asset_id = ? ORDER BY created_at DESC",
            (asset_id,)
        ).fetchall()
        actions = []
        for ar in action_rows:
            item = dict(ar)
            try:
                item["playbook_commands"] = json.loads(item.get("playbook_commands") or "{}")
                item["payload"] = json.loads(item.get("payload") or "{}")
                item["execution_log"] = json.loads(item.get("execution_log") or "[]")
            except Exception:
                pass
            actions.append(item)
        asset["containment_actions"] = actions

        asset["related_incidents"] = []
        asset["matched_iocs"] = []
        try:
            from platform_core import incident_manager
            all_incidents = incident_manager.list_incidents().get("incidents", [])
            ips = set(asset.get("ip_addresses", []))
            if asset.get("primary_ip"):
                ips.add(asset["primary_ip"])
            host = asset.get("hostname", "")

            for inc in all_incidents:
                entities = inc.get("entities", [])
                source_ips = inc.get("source_ips", [])
                target_ips = inc.get("target_ips", [])
                if any(ip in source_ips or ip in target_ips or ip in entities for ip in ips) or host in entities:
                    asset["related_incidents"].append({
                        "id": inc.get("id"),
                        "title": inc.get("title"),
                        "severity": inc.get("severity"),
                        "priority": inc.get("priority"),
                        "status": inc.get("status"),
                        "created_at": inc.get("created_at")
                    })
        except Exception:
            pass

        try:
            from platform_core import threat_intel
            ips = set(asset.get("ip_addresses", []))
            if asset.get("primary_ip"):
                ips.add(asset["primary_ip"])
            for ip in ips:
                matches = threat_intel.lookup_ioc(ip)
                if matches:
                    for m in matches:
                        asset["matched_iocs"].append({
                            "type": m.get("type"),
                            "value": m.get("value"),
                            "threat_type": m.get("threat_type"),
                            "severity": m.get("severity"),
                            "confidence": m.get("confidence")
                        })
        except Exception:
            pass

        latest_risk = calculate_dynamic_risk(asset)
        if latest_risk != asset.get("risk_score"):
            conn.execute("UPDATE assets SET risk_score = ? WHERE id = ?", (latest_risk, asset_id))
            asset["risk_score"] = latest_risk

        return asset


def update_asset(asset_id: str, fields: dict, actor: str = "system") -> Optional[dict]:
    init_db()
    allowed_updates = {
        "hostname", "os", "asset_type", "criticality", "status",
        "environment", "owner", "department", "tags", "metadata"
    }

    with _LOCK, db_session() as conn:
        current = conn.execute("SELECT * FROM assets WHERE id = ? AND is_deleted = 0", (asset_id,)).fetchone()
        if not current:
            return None
        current_dict = _row_to_asset(current)

        updates = []
        params = []
        now = _now_iso()

        for k, v in fields.items():
            if k in allowed_updates:
                if k == "hostname":
                    norm = normalize_hostname(v)
                    updates.extend(["hostname = ?", "normalized_hostname = ?"])
                    params.extend([v, norm])
                    conn.execute("INSERT INTO asset_aliases (asset_id, alias_type, alias_value, created_at) VALUES (?, 'hostname', ?, ?)", (asset_id, norm, now))
                elif k in {"tags", "metadata"}:
                    updates.append(f"{k} = ?")
                    params.append(json.dumps(v))
                elif k == "criticality" and str(v).lower() in VALID_CRITICALITIES:
                    updates.append("criticality = ?")
                    params.append(str(v).lower())
                    add_timeline_event(asset_id, "criticality_changed", f"تعديل مستوى حرجية الأصل إلى {v}", actor=actor, conn=conn)
                elif k == "status" and str(v).lower() in VALID_STATUSES:
                    updates.append("status = ?")
                    params.append(str(v).lower())
                    add_timeline_event(asset_id, "status_changed", f"تعديل حالة الأصل إلى {v}", actor=actor, conn=conn)
                else:
                    updates.append(f"{k} = ?")
                    params.append(v)

        if not updates:
            return current_dict

        updates.append("updated_at = ?")
        params.append(now)
        params.append(asset_id)

        conn.execute(f"UPDATE assets SET {', '.join(updates)} WHERE id = ?", params)
        updated_row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        asset_dict = _row_to_asset(updated_row)

        new_risk = calculate_dynamic_risk(asset_dict)
        conn.execute("UPDATE assets SET risk_score = ? WHERE id = ?", (new_risk, asset_id))
        asset_dict["risk_score"] = new_risk

        _log_audit("asset.updated", f"Asset {asset_id} updated", {"asset_id": asset_id, "fields": list(fields.keys())})
        return asset_dict


def delete_asset(asset_id: str, actor: str = "system", hard_delete: bool = False) -> bool:
    init_db()
    with _LOCK, db_session() as conn:
        if hard_delete:
            conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        else:
            conn.execute("UPDATE assets SET is_deleted = 1, updated_at = ? WHERE id = ?", (_now_iso(), asset_id))
        _log_audit("asset.deleted", f"Asset {asset_id} deleted (hard={hard_delete})", {"asset_id": asset_id, "hard_delete": hard_delete})
        return True


def get_assets_summary() -> dict:
    init_db()
    with _LOCK, db_session() as conn:
        total = conn.execute("SELECT COUNT(*) FROM assets WHERE is_deleted = 0").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM assets WHERE is_deleted = 0 AND criticality = 'mission_critical'").fetchone()[0]
        high_risk = conn.execute("SELECT COUNT(*) FROM assets WHERE is_deleted = 0 AND risk_score >= 60").fetchone()[0]
        isolated = conn.execute("SELECT COUNT(*) FROM assets WHERE is_deleted = 0 AND status = 'isolated'").fetchone()[0]
        unknown = conn.execute("SELECT COUNT(*) FROM assets WHERE is_deleted = 0 AND status = 'unknown'").fetchone()[0]

        dept_rows = conn.execute("SELECT department, COUNT(*) as c FROM assets WHERE is_deleted = 0 GROUP BY department").fetchall()
        dept_dist = {r["department"]: r["c"] for r in dept_rows}

        type_rows = conn.execute("SELECT asset_type, COUNT(*) as c FROM assets WHERE is_deleted = 0 GROUP BY asset_type").fetchall()
        type_dist = {r["asset_type"]: r["c"] for r in type_rows}

    return {
        "total_assets": total,
        "mission_critical_count": critical,
        "high_risk_count": high_risk,
        "isolated_count": isolated,
        "unknown_status_count": unknown,
        "department_distribution": dept_dist,
        "type_distribution": type_dist
    }


# -------------------------------------------------------------------------
# Containment Action Framework
# -------------------------------------------------------------------------

def create_containment_action(
    asset_id: str,
    action_type: str = "network_isolation",
    provider: str = "manual_playbook",
    dispatched_by: str = "analyst",
    payload: dict | None = None
) -> dict:
    init_db()
    asset = get_asset(asset_id)
    if not asset:
        raise ValueError(f"Asset {asset_id} not found")

    action_id = f"ACT-{uuid.uuid4().hex[:12].upper()}"
    now = _now_iso()
    ip = asset.get("primary_ip", "")
    host = asset.get("hostname", "")
    mac = asset.get("mac_address", "")

    playbook = {
        "fortinet_cli": f"config firewall address\nedit \"QUARANTINE-{ip}\"\nset subnet {ip}/32\nnext\nend",
        "windows_netsh": f"netsh advfirewall firewall add rule name=\"SOC-ISOLATE-{ip}\" dir=in action=block remoteip={ip}",
        "linux_iptables": f"iptables -I INPUT -s {ip} -j DROP\niptables -I OUTPUT -d {ip} -j DROP",
        "sentinel_one_api": {
            "endpoint": "/web/api/v2.1/agents/actions/isolate",
            "payload": {"filter": {"computerName": host, "networkInterfacePhysical": mac}}
        },
        "endpoint_central": {
            "action": "isolate_computer",
            "computer_name": host,
            "ip_address": ip
        }
    }

    with _LOCK, db_session() as conn:
        conn.execute(
            """
            INSERT INTO asset_containment_actions (
                id, asset_id, action_type, provider, status, dispatched_by,
                playbook_commands, payload, execution_log, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, 'pending_approval', ?, ?, ?, ?, ?, ?)
            """,
            (
                action_id, asset_id, action_type, provider, dispatched_by,
                json.dumps(playbook), json.dumps(payload or {}),
                json.dumps([{"action": "created", "timestamp": now, "actor": dispatched_by}]),
                now, now
            )
        )

        add_timeline_event(
            asset_id,
            "containment_action",
            f"تم إنشاء خطة عزل أمني ({action_type})",
            f"المزود المقترح: {provider} | منفذ الطلب: {dispatched_by}",
            severity="high",
            actor=dispatched_by,
            metadata={"action_id": action_id, "provider": provider},
            conn=conn
        )

    _log_audit("asset.containment_created", f"Containment {action_id} created for {asset_id}", {"asset_id": asset_id, "action_id": action_id})
    return {
        "action_id": action_id,
        "asset_id": asset_id,
        "status": "pending_approval",
        "playbook": playbook
    }


def confirm_containment_action(action_id: str, actor: str = "analyst") -> dict:
    init_db()
    now = _now_iso()
    with _LOCK, db_session() as conn:
        row = conn.execute("SELECT * FROM asset_containment_actions WHERE id = ?", (action_id,)).fetchone()
        if not row:
            raise ValueError(f"Action {action_id} not found")
        asset_id = row["asset_id"]

        logs = json.loads(row["execution_log"] or "[]")
        logs.append({"action": "confirmed_and_dispatched", "timestamp": now, "actor": actor})

        conn.execute(
            "UPDATE asset_containment_actions SET status = 'confirmed', updated_at = ?, execution_log = ? WHERE id = ?",
            (now, json.dumps(logs), action_id)
        )
        conn.execute("UPDATE assets SET status = 'isolated', updated_at = ? WHERE id = ?", (now, asset_id))

        add_timeline_event(
            asset_id,
            "containment_action",
            "تم تأكيد عزل الأصل أمنياً (Confirmed Isolation)",
            f"تم تأكيد العزل بنجاح بواسطة {actor}",
            severity="critical",
            actor=actor,
            metadata={"action_id": action_id},
            conn=conn
        )

    _log_audit("asset.isolated", f"Asset {asset_id} isolated via {action_id}", {"asset_id": asset_id, "action_id": action_id})
    return {"action_id": action_id, "asset_id": asset_id, "status": "confirmed"}


def revoke_containment_action(action_id: str, actor: str = "analyst") -> dict:
    init_db()
    now = _now_iso()
    with _LOCK, db_session() as conn:
        row = conn.execute("SELECT * FROM asset_containment_actions WHERE id = ?", (action_id,)).fetchone()
        if not row:
            raise ValueError(f"Action {action_id} not found")
        asset_id = row["asset_id"]

        logs = json.loads(row["execution_log"] or "[]")
        logs.append({"action": "revoked", "timestamp": now, "actor": actor})

        conn.execute(
            "UPDATE asset_containment_actions SET status = 'revoked', updated_at = ?, execution_log = ? WHERE id = ?",
            (now, json.dumps(logs), action_id)
        )
        conn.execute("UPDATE assets SET status = 'active', updated_at = ? WHERE id = ?", (now, asset_id))

        add_timeline_event(
            asset_id,
            "containment_action",
            "تم إلغاء عزل الأصل وإعادته للعمل الطبيعي (Revoked Isolation)",
            f"تم فك العزل بواسطة {actor}",
            severity="medium",
            actor=actor,
            metadata={"action_id": action_id},
            conn=conn
        )

    _log_audit("asset.isolation_revoked", f"Asset {asset_id} isolation revoked via {action_id}", {"asset_id": asset_id, "action_id": action_id})
    return {"action_id": action_id, "asset_id": asset_id, "status": "revoked"}


# -------------------------------------------------------------------------
# CMDB Import / Export
# -------------------------------------------------------------------------

def export_assets(format: str = "json") -> str:
    res = list_assets(limit=5000)
    assets = res.get("assets", [])

    if format.lower() == "csv":
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow([
            "ID", "Hostname", "Primary IP", "MAC Address", "OS",
            "Type", "Criticality", "Status", "Owner", "Department",
            "Risk Score", "Confidence Score", "First Seen", "Last Seen"
        ])
        for a in assets:
            writer.writerow([
                a.get("id"), a.get("hostname"), a.get("primary_ip"),
                a.get("mac_address"), a.get("os"), a.get("asset_type"),
                a.get("criticality"), a.get("status"), a.get("owner"),
                a.get("department"), a.get("risk_score"), a.get("confidence_score"),
                a.get("first_seen"), a.get("last_seen")
            ])
        return out.getvalue()

    return json.dumps(assets, indent=2, ensure_ascii=False)


def import_assets(content: str, format: str = "json", dry_run: bool = False, actor: str = "cmdb_import") -> dict:
    created = 0
    updated = 0
    errors = []

    records = []
    if format.lower() == "csv":
        f = io.StringIO(content)
        reader = csv.DictReader(f)
        for row in reader:
            records.append({
                "hostname": row.get("Hostname") or row.get("hostname"),
                "primary_ip": row.get("Primary IP") or row.get("primary_ip") or row.get("IP"),
                "mac_address": row.get("MAC Address") or row.get("mac_address"),
                "os": row.get("OS") or row.get("os"),
                "asset_type": row.get("Type") or row.get("asset_type") or "server",
                "criticality": row.get("Criticality") or row.get("criticality") or "medium",
                "owner": row.get("Owner") or row.get("owner") or "Unassigned",
                "department": row.get("Department") or row.get("department") or "IT Operations"
            })
    else:
        try:
            records = json.loads(content)
            if isinstance(records, dict) and "assets" in records:
                records = records["assets"]
            if not isinstance(records, list):
                records = [records]
        except Exception as e:
            return {"success": False, "error": f"Invalid JSON content: {str(e)}"}

    for idx, r in enumerate(records):
        if not isinstance(r, dict):
            continue
        host = r.get("hostname")
        ip = r.get("primary_ip") or r.get("ip")
        if not host and not ip:
            errors.append(f"Row {idx+1}: Missing hostname and IP")
            continue

        existing = resolve_asset_identity(
            mac=r.get("mac_address"),
            hostname=host,
            ip=ip
        )
        if existing:
            updated += 1
        else:
            created += 1

        if not dry_run:
            try:
                create_or_update_asset(
                    hostname=host or ip,
                    primary_ip=ip or "0.0.0.0",
                    mac_address=r.get("mac_address"),
                    os_name=r.get("os"),
                    asset_type=r.get("asset_type", "server").lower(),
                    criticality=r.get("criticality", "medium").lower(),
                    status="active" if existing else "unknown",
                    owner=r.get("owner", "Unassigned"),
                    department=r.get("department", "IT Operations"),
                    confidence_score=100,
                    discovery_source="cmdb_import",
                    actor=actor
                )
            except Exception as e:
                errors.append(f"Row {idx+1} ({host}): {str(e)}")

    return {
        "success": True,
        "dry_run": dry_run,
        "total_records": len(records),
        "created_count": created,
        "updated_count": updated,
        "errors": errors
    }


def discover_assets_from_jobs(limit_jobs: int = 50) -> dict:
    """Discovers and updates assets from completed LogScope and FlowScope jobs."""
    init_db()
    discovered = 0
    updated = 0
    seen_keys: set[str] = set()

    for app in ("logscope", "flowscope", "threatscope"):
        for base_dir in [WORKSPACE_ROOT / app / "storage" / "jobs", WORKSPACE_ROOT / "storage" / f"{app}_jobs"]:
            if not base_dir.is_dir():
                continue
            for job_dir in base_dir.iterdir():
                if not job_dir.is_dir():
                    continue
                analysis_file = job_dir / "analysis.json"
                if not analysis_file.is_file():
                    continue
                try:
                    data = json.loads(analysis_file.read_text(encoding="utf-8"))
                except Exception:
                    continue

                candidates: list[tuple[str, str, str, int]] = []
                if app == "logscope":
                    for inc in data.get("incidents", []):
                        for dev in inc.get("devices", []):
                            candidates.append((dev, "", "windows_event", 90))
                        for ip in inc.get("source_ips", []):
                            if ip and not ip.startswith(("127.", "0.")):
                                candidates.append(("", ip, "windows_event", 80))
                        for ip in inc.get("target_ips", []):
                            if ip and not ip.startswith(("127.", "0.")):
                                candidates.append(("", ip, "windows_event", 85))

                if app == "flowscope":
                    for ep in data.get("top_talkers", []) or data.get("endpoints", []):
                        ip = ep.get("ip") or ep.get("address")
                        if ip and not ip.startswith(("127.", "0.")):
                            candidates.append(("", ip, "flow_analysis", 70))

                for host, ip, src, conf in candidates:
                    key = f"{host}|{ip}"
                    if key in seen_keys or (not host and not ip):
                        continue
                    seen_keys.add(key)
                    if len(seen_keys) > 5000:
                        break

                    existing = resolve_asset_identity(hostname=host, ip=ip)
                    if existing:
                        updated += 1
                    else:
                        discovered += 1

                    create_or_update_asset(
                        hostname=host or ip,
                        primary_ip=ip or "0.0.0.0",
                        status="active" if existing else "unknown",
                        confidence_score=conf,
                        discovery_source=src,
                        actor="job_auto_discovery"
                    )

    return {"success": True, "discovered": discovered, "updated": updated, "total_processed": len(seen_keys)}

