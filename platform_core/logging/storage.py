"""SQLite-backed indexing and high-throughput query store for platform logs."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any

from .messages import translate_to_arabic_if_english


class PlatformLogStorage:
    """Thread-safe SQLite storage for platform logs with WAL mode and fast indexes."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is None:
            root = Path(__file__).resolve().parent.parent.parent
            self.db_path = root / "storage" / "platform_logs.db"
        else:
            self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._lock = threading.RLock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS platform_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    logger TEXT,
                    component TEXT NOT NULL,
                    event_type TEXT,
                    event_code TEXT,
                    message_ar TEXT,
                    message_en TEXT,
                    message TEXT NOT NULL,
                    request_id TEXT,
                    correlation_id TEXT,
                    job_id TEXT,
                    user_id TEXT,
                    duration_ms REAL,
                    error_code TEXT,
                    exception_type TEXT,
                    technical_details TEXT,
                    stack_trace TEXT,
                    raw_json TEXT NOT NULL
                );
                """
            )
            # Create indexing for fast UI queries
            conn.execute("CREATE INDEX IF NOT EXISTS idx_plogs_timestamp ON platform_logs(timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_plogs_level ON platform_logs(level);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_plogs_component ON platform_logs(component);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_plogs_corr_id ON platform_logs(correlation_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_plogs_req_id ON platform_logs(request_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_plogs_job_id ON platform_logs(job_id);")

            # Migrate legacy English messages to Arabic for known platform events
            try:
                conn.execute("""
                    UPDATE platform_logs
                    SET message_ar = 'بدء تشغيل خادم المنصة الموحد',
                        message = 'بدء تشغيل خادم المنصة الموحد'
                    WHERE (event_code = 'SYS_START' OR message = 'Unified backend server starting')
                      AND (message_ar IS NULL OR message_ar = 'Unified backend server starting' OR message_ar = 'test message');
                """)
                conn.execute("""
                    UPDATE platform_logs
                    SET message_ar = 'تم إيقاف خادم المنصة الموحد بنجاح',
                        message = 'تم إيقاف خادم المنصة الموحد بنجاح'
                    WHERE (event_code = 'SYS_SHUTDOWN' OR message = 'Unified backend server shutting down')
                      AND (message_ar IS NULL OR message_ar = 'Unified backend server shutting down');
                """)
            except Exception:
                pass
            conn.commit()

    def insert_batch(self, events: list[dict[str, Any]]) -> int:
        """Insert a batch of structured log events in a single transaction."""
        if not events:
            return 0
        conn = self._get_conn()
        records = []
        for e in events:
            raw_json = json.dumps(e, ensure_ascii=False, default=str)
            tech_details = json.dumps(e.get("technical_details"), ensure_ascii=False) if e.get("technical_details") else None
            records.append((
                e.get("timestamp"),
                e.get("level", "INFO").upper(),
                e.get("logger"),
                e.get("component", "platform"),
                e.get("event_type"),
                e.get("event_code"),
                e.get("message_ar"),
                e.get("message_en"),
                e.get("message", ""),
                e.get("request_id"),
                e.get("correlation_id"),
                e.get("job_id"),
                e.get("user_id"),
                e.get("duration_ms"),
                e.get("error_code"),
                e.get("exception_type"),
                tech_details,
                e.get("stack_trace"),
                raw_json,
            ))

        with self._lock:
            conn.executemany(
                """
                INSERT INTO platform_logs (
                    timestamp, level, logger, component, event_type, event_code,
                    message_ar, message_en, message, request_id, correlation_id,
                    job_id, user_id, duration_ms, error_code, exception_type,
                    technical_details, stack_trace, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                records,
            )
            conn.commit()
        return len(records)

    def query_logs(
        self,
        *,
        page: int = 1,
        limit: int = 50,
        level: str | None = None,
        component: str | None = None,
        event_type: str | None = None,
        event_code: str | None = None,
        search: str | None = None,
        correlation_id: str | None = None,
        request_id: str | None = None,
        job_id: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        sort_dir: str = "DESC",
    ) -> dict[str, Any]:
        """Search and paginate platform logs with filtering."""
        conn = self._get_conn()
        clauses = []
        params: list[Any] = []

        if level and level.lower() != "all":
            clauses.append("level = ?")
            params.append(level.upper())
        if component and component.lower() != "all":
            clauses.append("component = ?")
            params.append(component)
        if event_type and event_type.lower() != "all":
            clauses.append("event_type = ?")
            params.append(event_type)
        if event_code:
            clauses.append("event_code = ?")
            params.append(event_code)
        if correlation_id:
            clauses.append("correlation_id = ?")
            params.append(correlation_id)
        if request_id:
            clauses.append("request_id = ?")
            params.append(request_id)
        if job_id:
            clauses.append("job_id = ?")
            params.append(job_id)
        if date_from:
            clauses.append("timestamp >= ?")
            params.append(date_from)
        if date_to:
            clauses.append("timestamp <= ?")
            params.append(date_to)
        if search and search.strip():
            s = f"%{search.strip()}%"
            clauses.append(
                "(message_ar LIKE ? OR message_en LIKE ? OR message LIKE ? OR error_code LIKE ? OR component LIKE ? OR correlation_id LIKE ?)"
            )
            params.extend([s, s, s, s, s, s])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        order_dir = "ASC" if str(sort_dir).upper() == "ASC" else "DESC"

        # Count total
        count_query = f"SELECT COUNT(*) AS total FROM platform_logs {where_sql}"
        cursor = conn.execute(count_query, params)
        total = cursor.fetchone()["total"]

        # Fetch page
        offset = max(0, (page - 1) * limit)
        data_query = f"""
            SELECT id, timestamp, level, logger, component, event_type, event_code,
                   message_ar, message_en, message, request_id, correlation_id,
                   job_id, user_id, duration_ms, error_code, exception_type,
                   technical_details, stack_trace, raw_json
            FROM platform_logs
            {where_sql}
            ORDER BY timestamp {order_dir}, id {order_dir}
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(data_query, params + [limit, offset]).fetchall()

        logs = []
        for r in rows:
            tech = None
            if r["technical_details"]:
                try:
                    tech = json.loads(r["technical_details"])
                except Exception:
                    tech = r["technical_details"]

            raw_ar = r["message_ar"] or r["message"] or ""
            resolved_ar = translate_to_arabic_if_english(raw_ar)
            canonical = r["message"] or resolved_ar
            if not any("\u0600" <= c <= "\u06FF" for c in canonical):
                canonical = resolved_ar

            logs.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "level": r["level"],
                "logger": r["logger"],
                "component": r["component"],
                "event_type": r["event_type"],
                "event_code": r["event_code"],
                "message_ar": resolved_ar,
                "message_en": r["message_en"],
                "message": canonical,
                "request_id": r["request_id"],
                "correlation_id": r["correlation_id"],
                "job_id": r["job_id"],
                "user_id": r["user_id"],
                "duration_ms": r["duration_ms"],
                "error_code": r["error_code"],
                "exception_type": r["exception_type"],
                "technical_details": tech,
                "stack_trace": r["stack_trace"],
                "raw_json": r["raw_json"],
            })

        return {
            "total": total,
            "page": page,
            "limit": limit,
            "total_pages": max(1, (total + limit - 1) // limit),
            "logs": logs,
        }

    def get_kpis(self) -> dict[str, Any]:
        """Aggregate log level KPIs and component counts."""
        conn = self._get_conn()
        cursor = conn.execute(
            """
            SELECT 
                COUNT(*) AS total,
                SUM(CASE WHEN level = 'ERROR' THEN 1 ELSE 0 END) AS errors,
                SUM(CASE WHEN level = 'WARNING' THEN 1 ELSE 0 END) AS warnings,
                SUM(CASE WHEN level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN level = 'INFO' THEN 1 ELSE 0 END) AS info,
                COUNT(DISTINCT component) AS components_count
            FROM platform_logs
            """
        )
        row = cursor.fetchone()
        return {
            "total_events": row["total"] or 0,
            "errors": row["errors"] or 0,
            "warnings": row["warnings"] or 0,
            "critical": row["critical"] or 0,
            "info": row["info"] or 0,
            "components_count": row["components_count"] or 0,
        }

    def get_correlation_timeline(self, correlation_id: str) -> list[dict[str, Any]]:
        """Return full chronological execution timeline for a correlation ID."""
        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT id, timestamp, level, component, event_type, event_code,
                   message_ar, message_en, message, request_id, correlation_id,
                   job_id, duration_ms, error_code, exception_type, technical_details
            FROM platform_logs
            WHERE correlation_id = ?
            ORDER BY timestamp ASC, id ASC
            """,
            (correlation_id,),
        ).fetchall()

        timeline = []
        for r in rows:
            raw_ar = r["message_ar"] or r["message"] or ""
            resolved_ar = translate_to_arabic_if_english(raw_ar)
            canonical = r["message"] or resolved_ar
            if not any("\u0600" <= c <= "\u06FF" for c in canonical):
                canonical = resolved_ar

            timeline.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "level": r["level"],
                "component": r["component"],
                "event_type": r["event_type"],
                "event_code": r["event_code"],
                "message_ar": resolved_ar,
                "message_en": r["message_en"],
                "message": canonical,
                "request_id": r["request_id"],
                "correlation_id": r["correlation_id"],
                "job_id": r["job_id"],
                "duration_ms": r["duration_ms"],
                "error_code": r["error_code"],
                "exception_type": r["exception_type"],
            })
        return timeline

    def prune_older_than(self, days: int = 30) -> int:
        """Prune logs older than retention days."""
        conn = self._get_conn()
        cutoff_sec = time.time() - (max(1, days) * 86400)
        # Convert to ISO format prefix for pruning
        cutoff_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(cutoff_sec))
        with self._lock:
            cursor = conn.execute("DELETE FROM platform_logs WHERE timestamp < ?", (cutoff_iso,))
            deleted = cursor.rowcount
            conn.commit()
            return deleted

    def store_event(self, event: dict[str, Any]) -> int:
        """Convenience method to write a single structured event."""
        return self.insert_batch([event])

    def close(self) -> None:
        """Close SQLite database connection if open."""
        with self._lock:
            if hasattr(self._local, "conn") and self._local.conn is not None:
                try:
                    self._local.conn.close()
                except Exception:
                    pass
                self._local.conn = None



