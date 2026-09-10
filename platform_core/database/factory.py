"""
Unified Database Abstraction Layer (DAL) - Factory & DatabaseManager.

Provides thread-safe singleton access, graceful degradation to SQLite,
and unified repository dispatchers across all platform components.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from .base import (
    BaseAssetRepository,
    BaseIncidentRepository,
    BaseSearchRepository,
    BaseThreatIntelRepository,
    BaseTimeSeriesRepository,
    DatabaseBackend,
    DatabaseType,
)
from .config import ROOT_DIR, DatabaseConfig
from .opensearch_backend import OpenSearchBackend, OpenSearchRepository
from .postgres_backend import PostgreSQLBackend
from .sqlite_backend import (
    SQLiteBackend,
    SQLiteSearchRepository,
    SQLiteTimeSeriesRepository,
)

logger = logging.getLogger("platform.database")


class DatabaseManager:
    """Central manager providing connections and repositories to all platform modules."""

    _instance: DatabaseManager | None = None
    _lock = threading.RLock()

    def __init__(self, config: DatabaseConfig | None = None) -> None:
        self.config = config or DatabaseConfig.from_env_and_file()
        self._backend: DatabaseBackend | None = None
        self._search_repo: BaseSearchRepository | None = None
        self._timeseries_repo: BaseTimeSeriesRepository | None = None
        self._sqlite_default_backend: SQLiteBackend | None = None
        self._fallback_active = False
        self._fallback_reason = ""
        self._init_backend()

    @classmethod
    def get_instance(cls) -> DatabaseManager:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton for unit tests."""
        with cls._lock:
            if cls._instance:
                cls._instance.close()
            cls._instance = None

    def _init_backend(self) -> None:
        storage_dir = self.config.storage_dir
        storage_dir.mkdir(parents=True, exist_ok=True)
        default_sqlite_path = storage_dir / "platform_master.sqlite3"
        self._sqlite_default_backend = SQLiteBackend(default_sqlite_path, self.config)
        self._sqlite_default_backend.initialize()

        if self.config.db_type == DatabaseType.SQLITE:
            self._backend = self._sqlite_default_backend
            self._search_repo = SQLiteSearchRepository(self._sqlite_default_backend)
            self._timeseries_repo = SQLiteTimeSeriesRepository(self._sqlite_default_backend)
            return

        if self.config.db_type in (DatabaseType.POSTGRESQL, DatabaseType.TIMESCALEDB):
            pg_backend = PostgreSQLBackend(self.config)
            if pg_backend.is_driver_available():
                self._backend = pg_backend
                self._search_repo = SQLiteSearchRepository(self._sqlite_default_backend)
                self._timeseries_repo = SQLiteTimeSeriesRepository(self._sqlite_default_backend)
            else:
                self._fallback_active = True
                self._fallback_reason = "PostgreSQL driver (psycopg2) not present in environment. Gracefully fell back to SQLite."
                logger.warning(self._fallback_reason)
                self._backend = self._sqlite_default_backend
                self._search_repo = SQLiteSearchRepository(self._sqlite_default_backend)
                self._timeseries_repo = SQLiteTimeSeriesRepository(self._sqlite_default_backend)
            return

        if self.config.db_type == DatabaseType.OPENSEARCH:
            opensearch = OpenSearchBackend(self.config)
            health = opensearch.health_check()
            if health.get("status") == "healthy":
                self._backend = self._sqlite_default_backend
                self._search_repo = OpenSearchRepository(opensearch)
                self._timeseries_repo = SQLiteTimeSeriesRepository(self._sqlite_default_backend)
            else:
                self._fallback_active = True
                self._fallback_reason = "OpenSearch cluster unreachable. Gracefully fell back to local SQLite FTS5."
                self._backend = self._sqlite_default_backend
                self._search_repo = SQLiteSearchRepository(self._sqlite_default_backend)
                self._timeseries_repo = SQLiteTimeSeriesRepository(self._sqlite_default_backend)
            return

        # Default catch-all
        self._backend = self._sqlite_default_backend
        self._search_repo = SQLiteSearchRepository(self._sqlite_default_backend)
        self._timeseries_repo = SQLiteTimeSeriesRepository(self._sqlite_default_backend)

    def get_backend(self) -> DatabaseBackend:
        return self._backend or self._sqlite_default_backend  # type: ignore

    def get_sqlite_backend(self, db_name: str) -> SQLiteBackend:
        """Helper to get a specialized SQLite backend for individual subsystems."""
        path = self.config.storage_dir / db_name
        backend = SQLiteBackend(path, self.config)
        backend.initialize()
        return backend

    def get_search_repo(self) -> BaseSearchRepository:
        return self._search_repo or SQLiteSearchRepository(self._sqlite_default_backend)  # type: ignore

    def get_timeseries_repo(self) -> BaseTimeSeriesRepository:
        return self._timeseries_repo or SQLiteTimeSeriesRepository(self._sqlite_default_backend)  # type: ignore

    def get_status(self) -> dict[str, Any]:
        """Provides full health telemetry and capabilities matrix for all 4 database engines."""
        active_backend = self.get_backend()
        active_health = active_backend.health_check()

        pg_probe = PostgreSQLBackend(self.config).health_check()
        os_probe = OpenSearchBackend(self.config).health_check()

        return {
            "active_engine": active_backend.backend_type.value,
            "configured_engine": self.config.db_type.value,
            "is_fallback_active": self._fallback_active,
            "fallback_reason": self._fallback_reason or None,
            "health": active_health,
            "engines_matrix": {
                "sqlite": {
                    "status": "active" if active_backend.backend_type == DatabaseType.SQLITE else "standby",
                    "storage_dir": str(self.config.storage_dir),
                    "wal_mode": self.config.wal_mode,
                    "fts5_enabled": isinstance(self._search_repo, SQLiteSearchRepository) and self._search_repo._fts_available,
                },
                "postgresql": {
                    "status": pg_probe.get("status"),
                    "driver_available": pg_probe.get("driver") != "none (install psycopg2 to enable direct live connection)",
                    "target_host": f"{self.config.pg_host}:{self.config.pg_port}",
                    "target_db": self.config.pg_database,
                },
                "timescaledb": {
                    "status": "ready" if pg_probe.get("status") == "ready" else "driver_missing",
                    "hypertable_supported": True,
                    "target_interval": self.config.chunk_time_interval,
                },
                "opensearch": {
                    "status": os_probe.get("status"),
                    "target_url": self.config.opensearch_url,
                    "index_prefix": self.config.opensearch_index_prefix,
                },
            },
            "features": {
                "horizontal_readiness": True,
                "zero_frontend_change": True,
                "non_destructive_sqlite": True,
            },
        }

    def close(self) -> None:
        if self._sqlite_default_backend:
            self._sqlite_default_backend.close()
        if self._backend and self._backend != self._sqlite_default_backend:
            self._backend.close()
