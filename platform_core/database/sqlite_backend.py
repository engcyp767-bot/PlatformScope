"""
Unified Database Abstraction Layer (DAL) - SQLite Implementation.

Production-grade, zero-dependency, transactional SQLite engine operating with
WAL journal mode, thread-safe connection pooling, and built-in FTS5 full-text indexing.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, ContextManager, Generator, Sequence

from .base import (
    BaseAssetRepository,
    BaseIncidentRepository,
    BaseSearchRepository,
    BaseThreatIntelRepository,
    BaseTimeSeriesRepository,
    DatabaseBackend,
    DatabaseType,
)
from .config import DatabaseConfig


class SQLiteBackend(DatabaseBackend):
    """Encapsulates thread-local connections to local SQLite databases."""

    def __init__(self, db_path: Path | str, config: DatabaseConfig | None = None) -> None:
        self.db_path = Path(db_path)
        self.config = config or DatabaseConfig()
        self._local = threading.local()
        self._lock = threading.RLock()
        self._initialized = False

    @property
    def backend_type(self) -> DatabaseType:
        return DatabaseType.SQLITE

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=self.config.timeout_seconds,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            if self.config.wal_mode:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._local.conn = conn
        return self._local.conn

    def initialize(self) -> None:
        with self._lock:
            if self._initialized:
                return
            conn = self._get_connection()
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        applied_at TEXT NOT NULL
                    );
                    """
                )
            self._initialized = True

    def execute(self, query: str, params: tuple | list | dict = ()) -> int:
        conn = self._get_connection()
        if getattr(self._local, "in_manual_tx", False):
            cursor = conn.execute(query, params)
            return cursor.rowcount if cursor.rowcount > 0 else (cursor.lastrowid or 0)
        with conn:
            cursor = conn.execute(query, params)
            return cursor.rowcount if cursor.rowcount > 0 else (cursor.lastrowid or 0)

    def executescript(self, script: str) -> None:
        conn = self._get_connection()
        with conn:
            conn.executescript(script)

    def fetch_all(self, query: str, params: tuple | list | dict = ()) -> list[dict[str, Any]]:
        conn = self._get_connection()
        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    def fetch_one(self, query: str, params: tuple | list | dict = ()) -> dict[str, Any] | None:
        conn = self._get_connection()
        cursor = conn.execute(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None

    def execute_batch(self, query: str, params_seq: Sequence[tuple | list | dict]) -> int:
        conn = self._get_connection()
        if getattr(self._local, "in_manual_tx", False):
            cursor = conn.executemany(query, params_seq)
            return cursor.rowcount
        with conn:
            cursor = conn.executemany(query, params_seq)
            return cursor.rowcount

    @contextlib.contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        conn = self._get_connection()
        self._local.in_manual_tx = True
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._local.in_manual_tx = False

    def health_check(self) -> dict[str, Any]:
        start = time.perf_counter()
        try:
            conn = self._get_connection()
            cur = conn.execute("SELECT sqlite_version() as ver, 1 as ok;")
            row = cur.fetchone()
            latency = (time.perf_counter() - start) * 1000.0
            return {
                "status": "healthy",
                "backend": "sqlite",
                "version": row["ver"] if row else "unknown",
                "latency_ms": round(latency, 2),
                "db_path": str(self.db_path),
                "size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0,
            }
        except Exception as e:
            return {
                "status": "degraded",
                "backend": "sqlite",
                "error": str(e),
                "latency_ms": round((time.perf_counter() - start) * 1000.0, 2),
            }

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn is not None:
            try:
                self._local.conn.close()
            except Exception:
                pass
            self._local.conn = None


class SQLiteSearchRepository(BaseSearchRepository):
    """High-speed local full-text search engine leveraging SQLite FTS5 with fallback."""

    def __init__(self, backend: SQLiteBackend) -> None:
        self.backend = backend
        self._fts_available = self._check_and_init_fts()

    def _check_and_init_fts(self) -> bool:
        try:
            self.backend.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS search_documents USING fts5(
                    index_name,
                    doc_id,
                    content,
                    metadata_json UNINDEXED
                );
                """
            )
            return True
        except Exception:
            # Fallback to plain table if FTS5 extension was omitted in current python build
            self.backend.executescript(
                """
                CREATE TABLE IF NOT EXISTS search_documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    index_name TEXT NOT NULL,
                    doc_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata_json TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_search_doc ON search_documents(index_name, doc_id);
                """
            )
            return False

    def index_document(self, index_name: str, doc_id: str, document: dict[str, Any]) -> bool:
        content_parts = []
        for k, v in document.items():
            if isinstance(v, (str, int, float)):
                content_parts.append(str(v))
            elif isinstance(v, (list, dict)):
                content_parts.append(json.dumps(v, ensure_ascii=False))
        full_content = " ".join(content_parts)
        meta = json.dumps(document, ensure_ascii=False)

        if self._fts_available:
            self.backend.execute(
                "DELETE FROM search_documents WHERE index_name = ? AND doc_id = ?",
                (index_name, doc_id),
            )
            self.backend.execute(
                "INSERT INTO search_documents (index_name, doc_id, content, metadata_json) VALUES (?, ?, ?, ?)",
                (index_name, doc_id, full_content, meta),
            )
        else:
            self.backend.execute(
                "DELETE FROM search_documents WHERE index_name = ? AND doc_id = ?",
                (index_name, doc_id),
            )
            self.backend.execute(
                "INSERT INTO search_documents (index_name, doc_id, content, metadata_json) VALUES (?, ?, ?, ?)",
                (index_name, doc_id, full_content, meta),
            )
        return True

    def search(
        self,
        index_name: str,
        query_text: str,
        filters: dict[str, Any] | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        clean_q = query_text.strip()
        if not clean_q:
            return []

        if self._fts_available:
            # FTS5 MATCH query with rank ordering
            sql = """
                SELECT doc_id, content, metadata_json, rank
                FROM search_documents
                WHERE index_name = ? AND search_documents MATCH ?
                ORDER BY rank
                LIMIT ?
            """
            try:
                rows = self.backend.fetch_all(sql, (index_name, clean_q, limit))
                results = []
                for r in rows:
                    item = json.loads(r["metadata_json"]) if r.get("metadata_json") else {}
                    item["_doc_id"] = r["doc_id"]
                    item["_score"] = abs(float(r.get("rank", 0.0)))
                    results.append(item)
                return results
            except Exception:
                pass  # fallback to LIKE on syntax error

        # Fallback query
        sql = """
            SELECT doc_id, content, metadata_json
            FROM search_documents
            WHERE index_name = ? AND content LIKE ?
            LIMIT ?
        """
        rows = self.backend.fetch_all(sql, (index_name, f"%{clean_q}%", limit))
        results = []
        for r in rows:
            item = json.loads(r["metadata_json"]) if r.get("metadata_json") else {}
            item["_doc_id"] = r["doc_id"]
            item["_score"] = 1.0
            results.append(item)
        return results


class SQLiteTimeSeriesRepository(BaseTimeSeriesRepository):
    """High-throughput time-series event storage utilizing indexed row keys and payload JSON."""

    def __init__(self, backend: SQLiteBackend) -> None:
        self.backend = backend
        self._init_tables()

    def _init_tables(self) -> None:
        self.backend.executescript(
            """
            CREATE TABLE IF NOT EXISTS telemetry_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stream_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_telemetry_stream_time
            ON telemetry_events(stream_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_telemetry_time
            ON telemetry_events(timestamp);
            """
        )

    def insert_events_batch(self, stream_id: str, events: list[dict[str, Any]]) -> int:
        if not events:
            return 0
        records = []
        for ev in events:
            ts = str(ev.get("timestamp", ""))
            sev = str(ev.get("severity", "low"))
            ev_type = str(ev.get("event_type", "event"))
            records.append((stream_id, ts, sev, ev_type, json.dumps(ev, ensure_ascii=False)))

        sql = """
            INSERT INTO telemetry_events (stream_id, timestamp, severity, event_type, payload_json)
            VALUES (?, ?, ?, ?, ?)
        """
        return self.backend.execute_batch(sql, records)

    def query_events_window(
        self,
        stream_id: str,
        start_time: str,
        end_time: str,
        filters: dict[str, Any] | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        sql = """
            SELECT payload_json
            FROM telemetry_events
            WHERE stream_id = ? AND timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            LIMIT ?
        """
        rows = self.backend.fetch_all(sql, (stream_id, start_time, end_time, limit))
        return [json.loads(r["payload_json"]) for r in rows if r.get("payload_json")]
