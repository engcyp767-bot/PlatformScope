"""
Unified Database Abstraction Layer (DAL) - Base Interfaces.

Provides generic, protocol-driven storage abstractions decoupling SOC domain logic
from specific database drivers (SQLite, PostgreSQL, TimescaleDB, OpenSearch).
"""

from __future__ import annotations

import abc
import enum
from typing import Any, ContextManager, Sequence


class DatabaseType(str, enum.Enum):
    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    TIMESCALEDB = "timescaledb"
    OPENSEARCH = "opensearch"


class DatabaseBackend(abc.ABC):
    """Abstract contract for relational and document backends."""

    @property
    @abc.abstractmethod
    def backend_type(self) -> DatabaseType:
        """Identifies the active database backend engine."""
        pass

    @abc.abstractmethod
    def initialize(self) -> None:
        """Create schemas, extensions, and tables if not already present."""
        pass

    @abc.abstractmethod
    def execute(self, query: str, params: tuple | list | dict = ()) -> int:
        """Execute a mutation statement (INSERT, UPDATE, DELETE) and return rows affected or last row id."""
        pass

    @abc.abstractmethod
    def fetch_all(self, query: str, params: tuple | list | dict = ()) -> list[dict[str, Any]]:
        """Execute a read query and return all matching records as dictionaries."""
        pass

    @abc.abstractmethod
    def fetch_one(self, query: str, params: tuple | list | dict = ()) -> dict[str, Any] | None:
        """Execute a read query and return the first matching record as a dictionary or None."""
        pass

    @abc.abstractmethod
    def execute_batch(self, query: str, params_seq: Sequence[tuple | list | dict]) -> int:
        """Execute a parameterized query across multiple parameter tuples in a single batch."""
        pass

    @abc.abstractmethod
    def transaction(self) -> ContextManager[Any]:
        """Provide a transactional context manager guaranteeing atomic commit/rollback."""
        pass

    @abc.abstractmethod
    def health_check(self) -> dict[str, Any]:
        """Perform a liveness check and report latency, connectivity status, and engine version."""
        pass

    @abc.abstractmethod
    def close(self) -> None:
        """Gracefully close all managed connections and return resources."""
        pass


class BaseIncidentRepository(abc.ABC):
    """Encapsulates transactional operations on SOC incidents and forensic artifacts."""

    @abc.abstractmethod
    def save_incident(self, incident_data: dict[str, Any]) -> dict[str, Any]:
        pass

    @abc.abstractmethod
    def get_incident_by_id(self, incident_id: str) -> dict[str, Any] | None:
        pass

    @abc.abstractmethod
    def list_incidents(
        self,
        filters: dict[str, Any] | None = None,
        limit: int = 50,
        offset: int = 0
    ) -> tuple[list[dict[str, Any]], int]:
        pass

    @abc.abstractmethod
    def add_audit_event(self, audit_entry: dict[str, Any]) -> None:
        pass


class BaseAssetRepository(abc.ABC):
    """Encapsulates operations on the Enterprise Asset Inventory."""

    @abc.abstractmethod
    def upsert_asset(self, asset_data: dict[str, Any]) -> dict[str, Any]:
        pass

    @abc.abstractmethod
    def get_asset_by_id(self, asset_id: str) -> dict[str, Any] | None:
        pass

    @abc.abstractmethod
    def list_assets(
        self,
        filters: dict[str, Any] | None = None,
        limit: int = 50,
        offset: int = 0
    ) -> tuple[list[dict[str, Any]], int]:
        pass

    @abc.abstractmethod
    def record_containment_action(self, action_data: dict[str, Any]) -> dict[str, Any]:
        pass


class BaseThreatIntelRepository(abc.ABC):
    """Encapsulates IOC storage and high-speed threat matching."""

    @abc.abstractmethod
    def save_indicator(self, indicator_data: dict[str, Any]) -> dict[str, Any]:
        pass

    @abc.abstractmethod
    def find_matches(self, value: str) -> list[dict[str, Any]]:
        pass

    @abc.abstractmethod
    def get_summary_stats(self) -> dict[str, Any]:
        pass


class BaseTimeSeriesRepository(abc.ABC):
    """Encapsulates high-velocity security telemetry and event ingestion."""

    @abc.abstractmethod
    def insert_events_batch(self, stream_id: str, events: list[dict[str, Any]]) -> int:
        pass

    @abc.abstractmethod
    def query_events_window(
        self,
        stream_id: str,
        start_time: str,
        end_time: str,
        filters: dict[str, Any] | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        pass


class BaseSearchRepository(abc.ABC):
    """Encapsulates full-text search across raw logs, forensic notes, and artifacts."""

    @abc.abstractmethod
    def index_document(self, index_name: str, doc_id: str, document: dict[str, Any]) -> bool:
        pass

    @abc.abstractmethod
    def search(
        self,
        index_name: str,
        query_text: str,
        filters: dict[str, Any] | None = None,
        limit: int = 50
    ) -> list[dict[str, Any]]:
        pass
