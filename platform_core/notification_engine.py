"""
Unified Enterprise Architecture - Central Notification & Alerting Engine.

Provides durable in-app notifications, operational alerts, security broadcasts,
and unread badge state tracking stored in SQLite (WAL mode).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger("platform.notifications")
ROOT_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = ROOT_DIR / "storage"

_local_storage = threading.local()


def _get_db_path() -> Path:
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return STORAGE_DIR / "notifications.db"


def _get_db_conn() -> sqlite3.Connection:
    if not hasattr(_local_storage, "conn") or _local_storage.conn is None:
        conn = sqlite3.connect(str(_get_db_path()), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        _local_storage.conn = conn
    return _local_storage.conn


def _init_db() -> None:
    conn = _get_db_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'system',
            severity TEXT NOT NULL DEFAULT 'info',
            target_user TEXT NOT NULL DEFAULT '*',
            link TEXT,
            is_read INTEGER NOT NULL DEFAULT 0,
            read_at TEXT,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_target ON notifications(target_user);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_read ON notifications(is_read);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_created ON notifications(created_at DESC);")
    conn.commit()


_init_db()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    meta = {}
    try:
        if row["metadata_json"]:
            meta = json.loads(row["metadata_json"])
    except Exception:
        pass
    return {
        "id": row["id"],
        "title": row["title"],
        "message": row["message"],
        "category": row["category"],
        "severity": row["severity"],
        "target_user": row["target_user"],
        "link": row["link"],
        "is_read": bool(row["is_read"]),
        "read_at": row["read_at"],
        "created_at": row["created_at"],
        "metadata": meta,
    }


def create_notification(
    title: str,
    message: str,
    category: str = "system",
    severity: str = "info",
    target_user: str = "*",
    link: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Creates a new notification record."""
    notif_id = f"notif_{uuid.uuid4().hex[:12]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    meta_str = json.dumps(metadata or {}, ensure_ascii=False)

    conn = _get_db_conn()
    conn.execute("""
        INSERT INTO notifications (
            id, title, message, category, severity, target_user, link,
            is_read, read_at, created_at, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?)
    """, (
        notif_id,
        title,
        message,
        category,
        severity,
        target_user,
        link,
        now_iso,
        meta_str,
    ))
    conn.commit()

    return {
        "id": notif_id,
        "title": title,
        "message": message,
        "category": category,
        "severity": severity,
        "target_user": target_user,
        "link": link,
        "is_read": False,
        "read_at": None,
        "created_at": now_iso,
        "metadata": metadata or {},
    }


def list_notifications(
    user: str = "*",
    unread_only: bool = False,
    category: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Lists notifications for a specific user and general broadcasts."""
    conn = _get_db_conn()
    query = "SELECT * FROM notifications WHERE (target_user = ? OR target_user = '*')"
    params: list[Any] = [user]

    if unread_only:
        query += " AND is_read = 0"
    if category:
        query += " AND category = ?"
        params.append(category)

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cur = conn.execute(query, params)
    rows = cur.fetchall()
    return [_row_to_dict(r) for r in rows]


def get_unread_count(user: str = "*") -> int:
    """Returns the count of unread notifications for a user."""
    conn = _get_db_conn()
    cur = conn.execute(
        "SELECT COUNT(*) as cnt FROM notifications WHERE (target_user = ? OR target_user = '*') AND is_read = 0",
        (user,),
    )
    row = cur.fetchone()
    return int(row["cnt"]) if row else 0


def mark_as_read(notification_id: str, user: str = "*") -> bool:
    """Marks a single notification as read."""
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn = _get_db_conn()
    cur = conn.execute(
        "UPDATE notifications SET is_read = 1, read_at = ? WHERE id = ? AND (target_user = ? OR target_user = '*')",
        (now_iso, notification_id, user),
    )
    conn.commit()
    return cur.rowcount > 0


def mark_all_as_read(user: str = "*") -> int:
    """Marks all notifications for a user as read."""
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn = _get_db_conn()
    cur = conn.execute(
        "UPDATE notifications SET is_read = 1, read_at = ? WHERE (target_user = ? OR target_user = '*') AND is_read = 0",
        (now_iso, user),
    )
    conn.commit()
    return cur.rowcount


def delete_notification(notification_id: str) -> bool:
    conn = _get_db_conn()
    cur = conn.execute("DELETE FROM notifications WHERE id = ?", (notification_id,))
    conn.commit()
    return cur.rowcount > 0

