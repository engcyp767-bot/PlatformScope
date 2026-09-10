"""EndpointScope — Central Event Collector & Agent Manager.

Receives events from endpoint agents via REST API, processes them,
and forwards to LogScope/FlowScope for unified analysis.
Manages agent registration, heartbeats, and response actions.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from endpointscope.models import (
    AgentInfo,
    AgentState,
    EndpointEvent,
    EndpointEventType,
    EndpointPolicy,
    ResponseAction,
    ResponseActionType,
)

logger = logging.getLogger("endpointscope.collector")

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
STORAGE_DIR = WORKSPACE_ROOT / "storage"
DB_PATH = STORAGE_DIR / "endpointscope.sqlite3"

_LOCK = threading.RLock()

# Heartbeat timeout: if no heartbeat in this many seconds, mark agent offline
HEARTBEAT_TIMEOUT_SECONDS = 180


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _get_db(db_path: Path | None = None):
    target = db_path or DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), timeout=20.0, check_same_thread=False)
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


class EndpointCollector:
    """Central collector for endpoint agent events and management.

    Thread-safe singleton that:
    1. Registers and tracks endpoint agents
    2. Receives and processes endpoint events
    3. Manages response actions
    4. Integrates with the platform event bus
    """

    _instance: EndpointCollector | None = None
    _init_lock = threading.Lock()

    def __init__(self, db_path: Path | None = None):
        self._db_path = db_path or DB_PATH
        self._event_buffer: list[EndpointEvent] = []
        self._buffer_lock = threading.Lock()
        self._buffer_max = 1000
        self._stats: dict[str, int] = defaultdict(int)
        self._init_db()

    @classmethod
    def get_instance(cls, db_path: Path | None = None) -> EndpointCollector:
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls(db_path)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._init_lock:
            cls._instance = None

    def _init_db(self) -> None:
        with _get_db(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    os_type TEXT NOT NULL,
                    os_version TEXT NOT NULL DEFAULT '',
                    agent_version TEXT NOT NULL DEFAULT '1.0.0',
                    ip_addresses TEXT NOT NULL DEFAULT '[]',
                    mac_addresses TEXT NOT NULL DEFAULT '[]',
                    state TEXT NOT NULL DEFAULT 'online',
                    last_heartbeat TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    tags TEXT NOT NULL DEFAULT '[]',
                    agent_group TEXT NOT NULL DEFAULT 'default',
                    system_info TEXT NOT NULL DEFAULT '{}',
                    security_posture TEXT NOT NULL DEFAULT '{}',
                    policy_id TEXT NOT NULL DEFAULT 'default',
                    risk_score REAL NOT NULL DEFAULT 0.0,
                    active_alerts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS endpoint_events (
                    event_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'info',
                    event_data TEXT NOT NULL DEFAULT '{}',
                    matched_rules TEXT NOT NULL DEFAULT '[]',
                    processed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_agent
                ON endpoint_events(agent_id, timestamp DESC);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_type
                ON endpoint_events(event_type, timestamp DESC);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_severity
                ON endpoint_events(severity, timestamp DESC);
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS response_actions (
                    action_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    requested_by TEXT NOT NULL DEFAULT 'system',
                    requested_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    parameters TEXT NOT NULL DEFAULT '{}',
                    result TEXT NOT NULL DEFAULT '{}',
                    completed_at TEXT NOT NULL DEFAULT '',
                    error_message TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    policy_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    name_ar TEXT NOT NULL DEFAULT '',
                    version TEXT NOT NULL DEFAULT '1.0',
                    config TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
            conn.commit()

    # ── Agent Management ──────────────────────────────────────────────────

    def register_agent(self, agent_info: AgentInfo) -> dict[str, Any]:
        """Register a new endpoint agent or update an existing one."""
        now = _now_iso()
        with _LOCK:
            with _get_db(self._db_path) as conn:
                existing = conn.execute(
                    "SELECT agent_id FROM agents WHERE agent_id = ?;",
                    (agent_info.agent_id,),
                ).fetchone()

                if existing:
                    conn.execute("""
                        UPDATE agents SET
                            hostname = ?, os_type = ?, os_version = ?,
                            agent_version = ?, ip_addresses = ?, mac_addresses = ?,
                            state = ?, last_heartbeat = ?, updated_at = ?
                        WHERE agent_id = ?;
                    """, (
                        agent_info.hostname, agent_info.os_type, agent_info.os_version,
                        agent_info.agent_version,
                        json.dumps(agent_info.ip_addresses),
                        json.dumps(agent_info.mac_addresses),
                        AgentState.ONLINE.value, now, now,
                        agent_info.agent_id,
                    ))
                    self._stats["agents_updated"] += 1
                else:
                    conn.execute("""
                        INSERT INTO agents (
                            agent_id, hostname, os_type, os_version, agent_version,
                            ip_addresses, mac_addresses, state, last_heartbeat,
                            first_seen, tags, agent_group, policy_id, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        agent_info.agent_id, agent_info.hostname,
                        agent_info.os_type, agent_info.os_version,
                        agent_info.agent_version,
                        json.dumps(agent_info.ip_addresses),
                        json.dumps(agent_info.mac_addresses),
                        AgentState.ONLINE.value, now, now,
                        json.dumps(agent_info.tags),
                        agent_info.group, agent_info.policy_id,
                        now, now,
                    ))
                    self._stats["agents_registered"] += 1

                conn.commit()

        # Emit event
        try:
            from platform_core.plugins.hooks import HookPoint, event_bus
            event_bus().emit(HookPoint.ENDPOINT_CONNECTED, {
                "agent_id": agent_info.agent_id,
                "hostname": agent_info.hostname,
                "os_type": agent_info.os_type,
            })
        except Exception:
            pass

        logger.info("Agent registered: %s (%s)", agent_info.hostname, agent_info.agent_id)
        return {"status": "registered", "agent_id": agent_info.agent_id}

    def heartbeat(self, agent_id: str, system_metrics: dict[str, Any] | None = None) -> dict[str, Any]:
        """Process agent heartbeat and return pending actions."""
        now = _now_iso()
        with _LOCK:
            with _get_db(self._db_path) as conn:
                agent = conn.execute(
                    "SELECT agent_id FROM agents WHERE agent_id = ?;", (agent_id,)
                ).fetchone()
                if not agent:
                    return {"status": "error", "message": "Agent not registered"}

                update_fields = "state = ?, last_heartbeat = ?, updated_at = ?"
                params: list[Any] = [AgentState.ONLINE.value, now, now]

                if system_metrics:
                    update_fields += ", system_info = ?"
                    params.append(json.dumps(system_metrics))

                params.append(agent_id)
                conn.execute(
                    f"UPDATE agents SET {update_fields} WHERE agent_id = ?;",
                    params,
                )

                # Get pending response actions
                pending = conn.execute("""
                    SELECT action_id, action_type, parameters
                    FROM response_actions
                    WHERE agent_id = ? AND status = 'pending'
                    ORDER BY requested_at ASC;
                """, (agent_id,)).fetchall()

                pending_actions = [
                    {
                        "action_id": row["action_id"],
                        "action_type": row["action_type"],
                        "parameters": json.loads(row["parameters"]),
                    }
                    for row in pending
                ]

                # Mark as executing
                for action in pending_actions:
                    conn.execute(
                        "UPDATE response_actions SET status = 'executing' WHERE action_id = ?;",
                        (action["action_id"],),
                    )

                conn.commit()

        self._stats["heartbeats"] += 1
        return {
            "status": "ok",
            "pending_actions": pending_actions,
            "server_time": now,
        }

    def get_agent(self, agent_id: str) -> Optional[dict[str, Any]]:
        """Get agent information."""
        with _get_db(self._db_path) as conn:
            row = conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?;", (agent_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_agent_dict(row)

    def list_agents(
        self,
        state: str | None = None,
        group: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List all registered agents with optional filtering."""
        conditions: list[str] = []
        params: list[Any] = []

        if state:
            conditions.append("state = ?")
            params.append(state)
        if group:
            conditions.append("agent_group = ?")
            params.append(group)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with _get_db(self._db_path) as conn:
            count_row = conn.execute(
                f"SELECT COUNT(*) FROM agents {where_clause};", params
            ).fetchone()
            total = count_row[0] if count_row else 0

            params.extend([limit, offset])
            rows = conn.execute(
                f"SELECT * FROM agents {where_clause} ORDER BY last_heartbeat DESC LIMIT ? OFFSET ?;",
                params,
            ).fetchall()

            agents = [self._row_to_agent_dict(row) for row in rows]

        return {"agents": agents, "total": total, "limit": limit, "offset": offset}

    # ── Event Ingestion ───────────────────────────────────────────────────

    def ingest_events(self, events: list[EndpointEvent]) -> dict[str, Any]:
        """Ingest a batch of events from an endpoint agent."""
        now = _now_iso()
        accepted = 0
        rejected = 0

        with _LOCK:
            with _get_db(self._db_path) as conn:
                for event in events:
                    try:
                        conn.execute("""
                            INSERT OR IGNORE INTO endpoint_events (
                                event_id, agent_id, hostname, event_type,
                                timestamp, severity, event_data, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            event.event_id, event.agent_id, event.hostname,
                            event.event_type.value, event.timestamp,
                            event.severity, json.dumps(event.to_dict()), now,
                        ))
                        accepted += 1
                    except Exception as exc:
                        logger.warning("Failed to ingest event %s: %s", event.event_id, exc)
                        rejected += 1

                conn.commit()

        self._stats["events_ingested"] += accepted
        self._stats["events_rejected"] += rejected

        # Emit high-severity events to the event bus
        for event in events:
            if event.severity in ("high", "critical"):
                try:
                    from platform_core.plugins.hooks import HookPoint, event_bus
                    event_bus().emit(HookPoint.ENDPOINT_ALERT, event.to_dict())
                except Exception:
                    pass

        return {"accepted": accepted, "rejected": rejected}

    def get_events(
        self,
        agent_id: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        since: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Query endpoint events with filtering."""
        conditions: list[str] = []
        params: list[Any] = []

        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with _get_db(self._db_path) as conn:
            count_row = conn.execute(
                f"SELECT COUNT(*) FROM endpoint_events {where_clause};", params
            ).fetchone()
            total = count_row[0] if count_row else 0

            params.extend([limit, offset])
            rows = conn.execute(
                f"SELECT * FROM endpoint_events {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?;",
                params,
            ).fetchall()

            events = []
            for row in rows:
                try:
                    events.append(json.loads(row["event_data"]))
                except Exception:
                    events.append({"event_id": row["event_id"], "error": "parse_error"})

        return {"events": events, "total": total, "limit": limit, "offset": offset}

    # ── Response Actions ──────────────────────────────────────────────────

    def create_response_action(
        self,
        agent_id: str,
        action_type: ResponseActionType,
        requested_by: str = "admin",
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a response action to be executed by an agent."""
        action = ResponseAction(
            agent_id=agent_id,
            action_type=action_type,
            requested_by=requested_by,
            parameters=parameters or {},
        )

        with _LOCK:
            with _get_db(self._db_path) as conn:
                agent = conn.execute(
                    "SELECT state FROM agents WHERE agent_id = ?;", (agent_id,)
                ).fetchone()
                if not agent:
                    return {"error": "Agent not found"}

                conn.execute("""
                    INSERT INTO response_actions (
                        action_id, agent_id, action_type, requested_by,
                        requested_at, status, parameters
                    ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """, (
                    action.action_id, agent_id, action_type.value,
                    requested_by, action.requested_at, "pending",
                    json.dumps(parameters or {}),
                ))
                conn.commit()

        self._stats["actions_created"] += 1
        logger.info(
            "Response action created: %s → %s (%s)",
            action_type.value, agent_id, action.action_id,
        )
        return action.to_dict()

    def update_action_result(
        self,
        action_id: str,
        status: str,
        result: dict[str, Any] | None = None,
        error_message: str = "",
    ) -> dict[str, Any]:
        """Update the result of a response action (called by agent)."""
        now = _now_iso()
        with _LOCK:
            with _get_db(self._db_path) as conn:
                conn.execute("""
                    UPDATE response_actions SET
                        status = ?, result = ?, completed_at = ?, error_message = ?
                    WHERE action_id = ?;
                """, (status, json.dumps(result or {}), now, error_message, action_id))
                conn.commit()

        return {"status": "updated", "action_id": action_id}

    # ── Monitoring ────────────────────────────────────────────────────────

    def check_agent_health(self) -> dict[str, Any]:
        """Check all agents and mark stale ones as offline."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=HEARTBEAT_TIMEOUT_SECONDS)
        ).isoformat()

        with _LOCK:
            with _get_db(self._db_path) as conn:
                stale = conn.execute("""
                    UPDATE agents SET state = ?
                    WHERE state = ? AND last_heartbeat < ?;
                """, (AgentState.OFFLINE.value, AgentState.ONLINE.value, cutoff))
                stale_count = stale.rowcount

                stats = conn.execute("""
                    SELECT state, COUNT(*) as cnt FROM agents GROUP BY state;
                """).fetchall()
                conn.commit()

        state_counts = {row["state"]: row["cnt"] for row in stats}
        return {
            "stale_marked_offline": stale_count,
            "state_counts": state_counts,
            "checked_at": _now_iso(),
        }

    def get_dashboard_stats(self) -> dict[str, Any]:
        """Get dashboard statistics for EndpointScope."""
        with _get_db(self._db_path) as conn:
            agent_stats = conn.execute("""
                SELECT state, COUNT(*) as cnt FROM agents GROUP BY state;
            """).fetchall()

            total_events = conn.execute(
                "SELECT COUNT(*) FROM endpoint_events;"
            ).fetchone()

            recent_critical = conn.execute("""
                SELECT COUNT(*) FROM endpoint_events
                WHERE severity IN ('high', 'critical')
                AND timestamp >= datetime('now', '-24 hours');
            """).fetchone()

            pending_actions = conn.execute("""
                SELECT COUNT(*) FROM response_actions WHERE status = 'pending';
            """).fetchone()

        return {
            "agents": {row["state"]: row["cnt"] for row in agent_stats},
            "total_agents": sum(row["cnt"] for row in agent_stats),
            "total_events": total_events[0] if total_events else 0,
            "critical_events_24h": recent_critical[0] if recent_critical else 0,
            "pending_actions": pending_actions[0] if pending_actions else 0,
            "collector_stats": dict(self._stats),
        }

    # ── Helpers ───────────────────────────────────────────────────────────

    def _row_to_agent_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "agent_id": row["agent_id"],
            "hostname": row["hostname"],
            "os_type": row["os_type"],
            "os_version": row["os_version"],
            "agent_version": row["agent_version"],
            "ip_addresses": json.loads(row["ip_addresses"]),
            "mac_addresses": json.loads(row["mac_addresses"]),
            "state": row["state"],
            "last_heartbeat": row["last_heartbeat"],
            "first_seen": row["first_seen"],
            "tags": json.loads(row["tags"]),
            "group": row["agent_group"],
            "policy_id": row["policy_id"],
            "risk_score": row["risk_score"],
            "active_alerts": row["active_alerts"],
        }


def get_endpoint_collector(db_path: Path | None = None) -> EndpointCollector:
    """Get the singleton EndpointCollector instance."""
    return EndpointCollector.get_instance(db_path)

