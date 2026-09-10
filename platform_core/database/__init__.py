"""
Unified Database Abstraction Layer (DAL).

Provides clean, enterprise-grade storage interfaces, connection management,
and smooth scalability across SQLite, PostgreSQL, TimescaleDB, and OpenSearch.
"""

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
from .factory import DatabaseManager
from .migration import SchemaMigrationManager
from .opensearch_backend import OpenSearchBackend, OpenSearchRepository
from .postgres_backend import PostgreSQLBackend
from .sqlite_backend import (
    SQLiteBackend,
    SQLiteSearchRepository,
    SQLiteTimeSeriesRepository,
)

__all__ = [
    "DatabaseType",
    "DatabaseBackend",
    "DatabaseConfig",
    "DatabaseManager",
    "BaseIncidentRepository",
    "BaseAssetRepository",
    "BaseThreatIntelRepository",
    "BaseTimeSeriesRepository",
    "BaseSearchRepository",
    "SQLiteBackend",
    "SQLiteSearchRepository",
    "SQLiteTimeSeriesRepository",
    "PostgreSQLBackend",
    "OpenSearchBackend",
    "OpenSearchRepository",
    "SchemaMigrationManager",
]
