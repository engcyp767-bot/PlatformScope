"""
Unified Enterprise Architecture - Multi-Tenancy & Data Isolation.

Provides tenant scoping, quotas, and data segregation ensuring enterprise clients
operate in securely isolated environments with zero cross-tenant data leakage.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Generator

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = ROOT_DIR / "storage"
DB_PATH = STORAGE_DIR / "tenants.sqlite3"

_THREAD_LOCAL = threading.local()


def get_current_tenant_id() -> str:
    """Retrieve the current thread or request tenant ID, defaulting to 'default'."""
    return getattr(_THREAD_LOCAL, "tenant_id", "default")


def set_current_tenant_id(tenant_id: str) -> None:
    """Set the active tenant context for the current execution thread."""
    _THREAD_LOCAL.tenant_id = tenant_id or "default"


@contextlib.contextmanager
def tenant_context(tenant_id: str) -> Generator[str, None, None]:
    """Scoped context manager ensuring clean isolation and reset of tenant context."""
    previous = get_current_tenant_id()
    set_current_tenant_id(tenant_id)
    try:
        yield tenant_id
    finally:
        set_current_tenant_id(previous)


TenantContext = tenant_context


@dataclass
class TenantQuotas:
    max_storage_mb: int = 10_240  # 10 GB default
    max_concurrent_jobs: int = 10
    max_incidents: int = 5_000
    max_users: int = 50


@dataclass
class Tenant:
    id: str
    name: str
    status: str = "active"  # active, suspended, archived
    quotas: TenantQuotas = field(default_factory=TenantQuotas)
    created_at: str = ""
    updated_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "quotas": asdict(self.quotas),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }


class TenantManager:
    """Central manager for tenant provisioning, quota monitoring, and query scoping."""

    _instance: TenantManager | None = None
    _lock = threading.RLock()

    def __init__(self, db_path: Path | str = DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._init_db()

    @classmethod
    def get_instance(cls) -> TenantManager:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._lock:
            cls._instance = None

    def _get_conn(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tenants (
                    id VARCHAR(64) PRIMARY KEY,
                    name VARCHAR(128) NOT NULL,
                    status VARCHAR(32) NOT NULL DEFAULT 'active',
                    quotas_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tenant_status ON tenants(status);
                """
            )
            # Seed default tenant if table is empty
            cur = conn.execute("SELECT COUNT(*) as cnt FROM tenants WHERE id = 'default';")
            if cur.fetchone()["cnt"] == 0:
                now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                default_quotas = json.dumps(asdict(TenantQuotas()))
                conn.execute(
                    """
                    INSERT INTO tenants (id, name, status, quotas_json, metadata_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    ("default", "المستأجر الافتراضي للمنصة (Default)", "active", default_quotas, "{}", now, now),
                )

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,))
            row = cur.fetchone()
            if not row:
                return None
            quotas_dict = json.loads(row["quotas_json"]) if row["quotas_json"] else {}
            meta_dict = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
            return Tenant(
                id=row["id"],
                name=row["name"],
                status=row["status"],
                quotas=TenantQuotas(**quotas_dict),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                metadata=meta_dict,
            )

    def list_tenants(self) -> list[Tenant]:
        with self._get_conn() as conn:
            cur = conn.execute("SELECT * FROM tenants ORDER BY created_at ASC;")
            tenants = []
            for row in cur.fetchall():
                quotas_dict = json.loads(row["quotas_json"]) if row["quotas_json"] else {}
                meta_dict = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
                tenants.append(
                    Tenant(
                        id=row["id"],
                        name=row["name"],
                        status=row["status"],
                        quotas=TenantQuotas(**quotas_dict),
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                        metadata=meta_dict,
                    )
                )
            return tenants

    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        quotas: TenantQuotas | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Tenant:
        clean_id = tenant_id.strip().lower()
        if not clean_id or not name.strip():
            raise ValueError("معرف المستأجر واسمه مطلوبان")

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        q = quotas or TenantQuotas()
        meta = metadata or {}

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO tenants (id, name, status, quotas_json, metadata_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (clean_id, name.strip(), "active", json.dumps(asdict(q)), json.dumps(meta), now, now),
            )

        return Tenant(
            id=clean_id,
            name=name.strip(),
            status="active",
            quotas=q,
            created_at=now,
            updated_at=now,
            metadata=meta,
        )

    def update_tenant_status(self, tenant_id: str, status: str) -> bool:
        if status not in ("active", "suspended", "archived"):
            raise ValueError(f"حالة غير صالحة: {status}")
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._get_conn() as conn:
            cur = conn.execute(
                "UPDATE tenants SET status = ?, updated_at = ? WHERE id = ?",
                (status, now, tenant_id),
            )
            return cur.rowcount > 0
