"""
Unified Database Abstraction Layer (DAL) - Configuration Management.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .base import DatabaseType

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
_STORAGE_ENV = os.environ.get("PLATFORM_STORAGE_DIR") or os.environ.get("PLATFORM_SCOPE_DATA_DIR")
if _STORAGE_ENV:
    DEFAULT_STORAGE_DIR = Path(_STORAGE_ENV).resolve()
elif (ROOT_DIR / "storage").exists() or not os.name == "nt":
    DEFAULT_STORAGE_DIR = ROOT_DIR / "storage"
elif os.environ.get("ProgramData") and (str(ROOT_DIR).lower().startswith(r"c:\program files") or (Path(os.environ["ProgramData"]) / "PlatformScope").exists()):
    DEFAULT_STORAGE_DIR = Path(os.environ["ProgramData"]) / "PlatformScope"
else:
    DEFAULT_STORAGE_DIR = ROOT_DIR / "storage"

CONFIG_FILE = DEFAULT_STORAGE_DIR / "platform_config.json"


@dataclass
class DatabaseConfig:
    """Represents full connectivity and tuning configuration for all supported storage engines."""
    db_type: DatabaseType = DatabaseType.SQLITE
    storage_dir: Path = field(default_factory=lambda: DEFAULT_STORAGE_DIR)
    timeout_seconds: float = 30.0
    wal_mode: bool = True
    max_connections: int = 20

    # PostgreSQL / TimescaleDB parameters
    pg_host: str = "127.0.0.1"
    pg_port: int = 5432
    pg_database: str = "security_platform"
    pg_user: str = "postgres"
    pg_password: str = ""
    pg_sslmode: str = "prefer"

    # TimescaleDB parameters
    timescale_enabled: bool = False
    chunk_time_interval: str = "1 day"

    # OpenSearch parameters
    opensearch_url: str = "http://127.0.0.1:9200"
    opensearch_index_prefix: str = "platform_soc"
    opensearch_user: str = "admin"
    opensearch_password: str = ""
    opensearch_timeout: float = 10.0

    @classmethod
    def from_env_and_file(cls) -> DatabaseConfig:
        """Load configuration from storage/platform_config.json with environment variable overrides."""
        cfg = cls()

        # 1. Read JSON file if available
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                db_section = data.get("database", {})
                if "type" in db_section:
                    raw_type = str(db_section["type"]).lower()
                    if raw_type in [t.value for t in DatabaseType]:
                        cfg.db_type = DatabaseType(raw_type)
                if "pg_host" in db_section:
                    cfg.pg_host = str(db_section["pg_host"])
                if "pg_port" in db_section:
                    cfg.pg_port = int(db_section["pg_port"])
                if "pg_database" in db_section:
                    cfg.pg_database = str(db_section["pg_database"])
                if "pg_user" in db_section:
                    cfg.pg_user = str(db_section["pg_user"])
                if "timescale_enabled" in db_section:
                    cfg.timescale_enabled = bool(db_section["timescale_enabled"])
                if "opensearch_url" in db_section:
                    cfg.opensearch_url = str(db_section["opensearch_url"])
            except Exception:
                pass

        # 2. Environment variables override
        env_type = os.environ.get("PLATFORM_DB_TYPE", os.environ.get("DB_TYPE", "")).lower()
        if env_type in [t.value for t in DatabaseType]:
            cfg.db_type = DatabaseType(env_type)

        if "PLATFORM_PG_HOST" in os.environ:
            cfg.pg_host = os.environ["PLATFORM_PG_HOST"]
        if "PLATFORM_PG_PORT" in os.environ:
            try:
                cfg.pg_port = int(os.environ["PLATFORM_PG_PORT"])
            except ValueError:
                pass
        if "PLATFORM_PG_DB" in os.environ:
            cfg.pg_database = os.environ["PLATFORM_PG_DB"]
        if "PLATFORM_PG_USER" in os.environ:
            cfg.pg_user = os.environ["PLATFORM_PG_USER"]
        if "PLATFORM_PG_PASSWORD" in os.environ:
            cfg.pg_password = os.environ["PLATFORM_PG_PASSWORD"]

        if os.environ.get("PLATFORM_TIMESCALE_ENABLED", "").lower() in ("true", "1", "yes"):
            cfg.timescale_enabled = True

        if "PLATFORM_OPENSEARCH_URL" in os.environ:
            cfg.opensearch_url = os.environ["PLATFORM_OPENSEARCH_URL"]

        return cfg

    def to_dict(self) -> dict[str, Any]:
        """Export sanitized representation safe for API and audit logging."""
        return {
            "db_type": self.db_type.value,
            "wal_mode": self.wal_mode,
            "timeout_seconds": self.timeout_seconds,
            "max_connections": self.max_connections,
            "pg_host": self.pg_host,
            "pg_port": self.pg_port,
            "pg_database": self.pg_database,
            "pg_user": self.pg_user,
            "timescale_enabled": self.timescale_enabled,
            "opensearch_url": self.opensearch_url,
            "opensearch_index_prefix": self.opensearch_index_prefix,
        }
