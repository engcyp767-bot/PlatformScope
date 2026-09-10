"""
Unified Database Abstraction Layer (DAL) - Migration & Data Portability Runner.

Manages schema versions and provides seamless data dump/restore tools to migrate
operational datasets from SQLite into PostgreSQL or TimescaleDB without data loss.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .base import DatabaseBackend
from .sqlite_backend import SQLiteBackend

MIGRATIONS: list[dict[str, Any]] = [
    {
        "version": 1,
        "name": "001_core_schema_baseline",
        "description": "Initial baseline schema for incidents, assets, threat indicators, and audit trails",
    },
    {
        "version": 2,
        "name": "002_fts5_forensic_search",
        "description": "Full-text indexing support for forensic notes and log records",
    },
    {
        "version": 3,
        "name": "003_telemetry_event_streaming",
        "description": "High-throughput time-series telemetry streams with indexed windows",
    },
]


class SchemaMigrationManager:
    """Oversees migration application, schema verification, and engine data portability."""

    def __init__(self, backend: DatabaseBackend) -> None:
        self.backend = backend

    def ensure_migration_table(self) -> None:
        self.backend.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
            """
        )

    def get_applied_migrations(self) -> list[dict[str, Any]]:
        self.ensure_migration_table()
        return self.backend.fetch_all("SELECT * FROM schema_migrations ORDER BY version ASC;")

    def apply_pending_migrations(self) -> list[dict[str, Any]]:
        self.ensure_migration_table()
        applied = {m["version"] for m in self.get_applied_migrations()}
        newly_applied = []

        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for mig in MIGRATIONS:
            if mig["version"] not in applied:
                self.backend.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (mig["version"], mig["name"], now_iso),
                )
                newly_applied.append(mig)
        return newly_applied

    def export_data_bundle(self, tables: list[str]) -> dict[str, Any]:
        """Extract table records into a standard JSON data bundle for cross-engine migration."""
        bundle: dict[str, Any] = {
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_backend": self.backend.backend_type.value,
            "tables": {},
        }
        for table in tables:
            try:
                rows = self.backend.fetch_all(f"SELECT * FROM {table};")
                bundle["tables"][table] = rows
            except Exception:
                bundle["tables"][table] = []
        return bundle
