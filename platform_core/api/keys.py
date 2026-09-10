"""API Key Management for Platform Scope Public API.

Provides cryptographically secure API key generation, prefix-based indexing,
SHA-256 hash validation, role-based scoping (read, write, admin, ingest),
automatic expiration, and per-key rate limiting.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


KEY_PREFIX = "psk_"
LIVE_PREFIX = "psk_live_"
TEST_PREFIX = "psk_test_"


class APIScope:
    """Standard API scopes."""
    READ = "read"
    WRITE = "write"
    INGEST = "ingest"
    ADMIN = "admin"
    ALL = [READ, WRITE, INGEST, ADMIN]

    @classmethod
    def contains(cls, granted_scope: str, required_scope: str) -> bool:
        """Check if granted scope satisfies the required scope."""
        if granted_scope == cls.ADMIN:
            return True
        if granted_scope == cls.WRITE and required_scope in (cls.READ, cls.INGEST, cls.WRITE):
            return True
        if granted_scope == cls.INGEST and required_scope in (cls.READ, cls.INGEST):
            return True
        return granted_scope == required_scope


@dataclass
class APIKeyRecord:
    """Represents a stored API Key record (without raw secret)."""
    key_id: str
    key_prefix: str  # First 12 chars for display / identification
    key_hash: str    # SHA-256 hex digest of full key
    name: str
    scope: str = APIScope.READ
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    rate_limit_rpm: int = 120  # requests per minute
    is_active: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > exp
        except Exception:
            return False

    def to_dict(self, include_hash: bool = False) -> dict[str, Any]:
        d = {
            "key_id": self.key_id,
            "key_prefix": self.key_prefix,
            "name": self.name,
            "scope": self.scope,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_used_at": self.last_used_at,
            "rate_limit_rpm": self.rate_limit_rpm,
            "is_active": self.is_active,
            "is_expired": self.is_expired(),
            "metadata": self.metadata,
        }
        if include_hash:
            d["key_hash"] = self.key_hash
        return d


class APIKeyManager:
    """Manages API Keys in an SQLite database with caching and thread safety."""

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        if db_path is None:
            self._db_path = Path.home() / ".platform_scope" / "api_keys.db"
        else:
            self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._rate_limits: dict[str, list[float]] = {}  # key_id -> timestamps
        self._init_db()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(str(self._db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    key_prefix TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'read',
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used_at TEXT,
                    rate_limit_rpm INTEGER NOT NULL DEFAULT 120,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_key_hash ON api_keys(key_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_key_prefix ON api_keys(key_prefix)")
            conn.commit()

    @staticmethod
    def _hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def generate_key(
        self,
        name: str,
        scope: str = APIScope.READ,
        expires_in_days: Optional[int] = None,
        rate_limit_rpm: int = 120,
        is_test: bool = False,
        metadata: Optional[dict[str, Any]] = None,
    ) -> tuple[str, APIKeyRecord]:
        """Generate a new cryptographically secure API key.
        
        Returns:
            (raw_key, APIKeyRecord) -- raw_key is only returned ONCE upon creation!
        """
        prefix = TEST_PREFIX if is_test else LIVE_PREFIX
        random_part = secrets.token_urlsafe(32)
        raw_key = f"{prefix}{random_part}"
        
        key_id = f"key_{secrets.token_hex(8)}"
        key_prefix = raw_key[:12] + "..."
        key_hash = self._hash_key(raw_key)
        now_iso = datetime.now(timezone.utc).isoformat()
        
        expires_at = None
        if expires_in_days is not None and expires_in_days > 0:
            exp_ts = time.time() + (expires_in_days * 86400)
            expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()

        record = APIKeyRecord(
            key_id=key_id,
            key_prefix=key_prefix,
            key_hash=key_hash,
            name=name,
            scope=scope,
            created_at=now_iso,
            expires_at=expires_at,
            rate_limit_rpm=rate_limit_rpm,
            is_active=True,
            metadata=metadata or {},
        )

        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO api_keys (
                    key_id, key_prefix, key_hash, name, scope,
                    created_at, expires_at, last_used_at,
                    rate_limit_rpm, is_active, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.key_id,
                    record.key_prefix,
                    record.key_hash,
                    record.name,
                    record.scope,
                    record.created_at,
                    record.expires_at,
                    record.last_used_at,
                    record.rate_limit_rpm,
                    1 if record.is_active else 0,
                    json.dumps(record.metadata),
                ),
            )
            conn.commit()

        return raw_key, record

    def validate_key(self, raw_key: str, required_scope: Optional[str] = None) -> Optional[APIKeyRecord]:
        """Validate a raw API key. Returns record if valid, None if invalid or expired."""
        if not raw_key or not isinstance(raw_key, str):
            return None

        key_hash = self._hash_key(raw_key.strip())
        
        with self._lock, self._get_conn() as conn:
            cur = conn.execute(
                "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1",
                (key_hash,),
            )
            row = cur.fetchone()
            if not row:
                return None

            record = APIKeyRecord(
                key_id=row["key_id"],
                key_prefix=row["key_prefix"],
                key_hash=row["key_hash"],
                name=row["name"],
                scope=row["scope"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                last_used_at=row["last_used_at"],
                rate_limit_rpm=row["rate_limit_rpm"],
                is_active=bool(row["is_active"]),
                metadata=json.loads(row["metadata_json"] or "{}"),
            )

            if record.is_expired():
                return None

            if required_scope and not APIScope.contains(record.scope, required_scope):
                return None

            # Update last_used_at
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE key_id = ?",
                (now_iso, record.key_id),
            )
            conn.commit()
            record.last_used_at = now_iso

            return record

    def check_rate_limit(self, key_id: str, limit_rpm: int = 120) -> tuple[bool, int, int]:
        """Check if request is within rate limit.
        
        Returns:
            (allowed: bool, remaining: int, reset_seconds: int)
        """
        now = time.time()
        window = 60.0  # 1 minute

        with self._lock:
            timestamps = self._rate_limits.get(key_id, [])
            # Filter out timestamps older than window
            timestamps = [t for t in timestamps if now - t < window]
            
            if len(timestamps) >= limit_rpm:
                self._rate_limits[key_id] = timestamps
                oldest = timestamps[0]
                reset_sec = max(1, int(window - (now - oldest)))
                return False, 0, reset_sec

            timestamps.append(now)
            self._rate_limits[key_id] = timestamps
            remaining = max(0, limit_rpm - len(timestamps))
            return True, remaining, int(window)

    def list_keys(self) -> list[APIKeyRecord]:
        """List all registered API keys."""
        with self._lock, self._get_conn() as conn:
            cur = conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC")
            records = []
            for row in cur.fetchall():
                records.append(
                    APIKeyRecord(
                        key_id=row["key_id"],
                        key_prefix=row["key_prefix"],
                        key_hash=row["key_hash"],
                        name=row["name"],
                        scope=row["scope"],
                        created_at=row["created_at"],
                        expires_at=row["expires_at"],
                        last_used_at=row["last_used_at"],
                        rate_limit_rpm=row["rate_limit_rpm"],
                        is_active=bool(row["is_active"]),
                        metadata=json.loads(row["metadata_json"] or "{}"),
                    )
                )
            return records

    def revoke_key(self, key_id: str) -> bool:
        """Revoke (deactivate) an API key."""
        with self._lock, self._get_conn() as conn:
            cur = conn.execute(
                "UPDATE api_keys SET is_active = 0 WHERE key_id = ?",
                (key_id,),
            )
            conn.commit()
            return cur.rowcount > 0

    def delete_key(self, key_id: str) -> bool:
        """Permanently delete an API key record."""
        with self._lock, self._get_conn() as conn:
            cur = conn.execute("DELETE FROM api_keys WHERE key_id = ?", (key_id,))
            conn.commit()
            return cur.rowcount > 0


_manager_instance: Optional[APIKeyManager] = None
_manager_lock = threading.Lock()


def get_api_key_manager() -> APIKeyManager:
    """Get or create singleton APIKeyManager."""
    global _manager_instance
    if _manager_instance is None:
        with _manager_lock:
            if _manager_instance is None:
                _manager_instance = APIKeyManager()
    return _manager_instance
