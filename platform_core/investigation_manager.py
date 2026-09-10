"""Centralized SOC Investigation Workspace Engine.

Manages unified investigation cases bundling Incidents, Assets, IOCs,
Evidence, Timelines, Notes, and Collaborative Hypotheses.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from platform_core import audit_engine

logger = logging.getLogger("platform.investigation_manager")

ROOT = Path(__file__).resolve().parent.parent
STORAGE_DIR = ROOT / "storage"
DB_PATH = STORAGE_DIR / "investigations.sqlite3"

_LOCK = threading.RLock()

VALID_STATUSES = {"open", "active_triage", "in_depth_analysis", "containment", "closed"}
VALID_PRIORITIES = {"P1", "P2", "P3", "P4"}
VALID_ITEM_TYPES = {"incident", "asset", "ioc", "evidence", "log_snippet"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_db(db_path: Path | None = None):
    target = db_path or DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), timeout=20.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


class InvestigationManager:
    _instance: InvestigationManager | None = None

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_PATH
        self.init_db()

    @classmethod
    def get_instance(cls) -> InvestigationManager:
        if cls._instance is None:
            with _LOCK:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def init_db(self) -> None:
        with _LOCK, get_db(self.db_path) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'open',
                priority TEXT DEFAULT 'P2',
                lead_analyst TEXT DEFAULT 'Unassigned',
                tags TEXT,
                hypothesis TEXT,
                conclusion TEXT,
                created_by TEXT DEFAULT 'system',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                closed_at TEXT
            );
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS investigation_items (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                item_type TEXT NOT NULL,
                item_id TEXT NOT NULL,
                title TEXT NOT NULL,
                metadata TEXT,
                added_by TEXT DEFAULT 'system',
                added_at TEXT NOT NULL,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            );
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS investigation_notes (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                author TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            );
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS investigation_timeline (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_status ON investigations(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_priority ON investigations(priority);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inv_items ON investigation_items(investigation_id);")

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        if "tags" in d and isinstance(d["tags"], str):
            try:
                d["tags"] = json.loads(d["tags"])
            except Exception:
                d["tags"] = []
        return d

    def create_investigation(
        self,
        title: str,
        description: str = "",
        priority: str = "P2",
        lead_analyst: str = "Unassigned",
        tags: list[str] | None = None,
        hypothesis: str = "",
        actor: str = "system",
    ) -> dict[str, Any]:
        with _LOCK, get_db(self.db_path) as conn:
            inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
            now = _now_iso()
            prio = priority.upper() if priority.upper() in VALID_PRIORITIES else "P2"
            tags_json = json.dumps(tags or [], ensure_ascii=False)

            conn.execute("""
            INSERT INTO investigations (
                id, title, description, status, priority, lead_analyst,
                tags, hypothesis, conclusion, created_by, created_at, updated_at
            ) VALUES (?, ?, ?, 'open', ?, ?, ?, ?, '', ?, ?, ?)
            """, (inv_id, title, description, prio, lead_analyst, tags_json, hypothesis, actor, now, now))

            tl_id = f"tl_{uuid.uuid4().hex[:10]}"
            conn.execute("""
            INSERT INTO investigation_timeline (id, investigation_id, actor, action, details, timestamp)
            VALUES (?, ?, ?, 'created', 'تم إنشاء ملف التحقيق الأمني', ?)
            """, (tl_id, inv_id, actor, now))

        audit_engine.record_engine_event(
            application="investigations",
            action="investigation_created",
            message=f"تم إنشاء ملف تحقيق أمني جديد: {inv_id} ({title})",
            category="investigation",
            details={"investigation_id": inv_id, "title": title, "priority": prio, "actor": actor},
        )

        return self.get_investigation(inv_id) or {}

    def list_investigations(
        self,
        status: str | None = None,
        priority: str | None = None,
        lead_analyst: str | None = None,
        search: str | None = None,
        limit: int = 25,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        limit = max(1, min(limit, 100))
        offset = max(0, offset)
        where_clauses = []
        params: list[Any] = []

        if status and status.lower() in VALID_STATUSES:
            where_clauses.append("status = ?")
            params.append(status.lower())

        if priority and priority.upper() in VALID_PRIORITIES:
            where_clauses.append("priority = ?")
            params.append(priority.upper())

        if lead_analyst:
            where_clauses.append("lead_analyst LIKE ?")
            params.append(f"%{lead_analyst.strip()}%")

        if search:
            s = f"%{search.strip()}%"
            where_clauses.append("(id LIKE ? OR title LIKE ? OR description LIKE ? OR hypothesis LIKE ?)")
            params.extend([s, s, s, s])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        with _LOCK, get_db(self.db_path) as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM investigations {where_sql}", params).fetchone()[0]

            rows = conn.execute(f"""
            SELECT * FROM investigations {where_sql}
            ORDER BY created_at DESC LIMIT ? OFFSET ?
            """, params + [limit, offset]).fetchall()

            items = [self._row_to_dict(r) for r in rows]

            # Attach item counts
            for item in items:
                count_row = conn.execute(
                    "SELECT COUNT(*) FROM investigation_items WHERE investigation_id = ?",
                    (item["id"],)
                ).fetchone()
                item["items_count"] = count_row[0] if count_row else 0

                notes_row = conn.execute(
                    "SELECT COUNT(*) FROM investigation_notes WHERE investigation_id = ?",
                    (item["id"],)
                ).fetchone()
                item["notes_count"] = notes_row[0] if notes_row else 0

        return items, total

    def get_investigation(self, investigation_id: str) -> dict[str, Any] | None:
        with _LOCK, get_db(self.db_path) as conn:
            row = conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
            if not row:
                return None
            inv = self._row_to_dict(row)

            # Items
            item_rows = conn.execute(
                "SELECT * FROM investigation_items WHERE investigation_id = ? ORDER BY added_at DESC",
                (investigation_id,)
            ).fetchall()
            items = []
            for ir in item_rows:
                d = dict(ir)
                if d.get("metadata"):
                    try:
                        d["metadata"] = json.loads(d["metadata"])
                    except Exception:
                        d["metadata"] = {}
                items.append(d)
            inv["items"] = items

            # Notes
            note_rows = conn.execute(
                "SELECT * FROM investigation_notes WHERE investigation_id = ? ORDER BY created_at ASC",
                (investigation_id,)
            ).fetchall()
            inv["notes"] = [dict(nr) for nr in note_rows]

            # Timeline
            tl_rows = conn.execute(
                "SELECT * FROM investigation_timeline WHERE investigation_id = ? ORDER BY timestamp DESC",
                (investigation_id,)
            ).fetchall()
            inv["timeline"] = [dict(tl) for tl in tl_rows]

        return inv

    def update_investigation(self, investigation_id: str, updates: dict[str, Any], actor: str = "system") -> dict[str, Any] | None:
        allowed = {"title", "description", "status", "priority", "lead_analyst", "hypothesis", "conclusion", "tags"}
        fields: dict[str, Any] = {}

        for k, v in updates.items():
            if k not in allowed or v is None:
                continue
            if k == "status" and str(v).lower() in VALID_STATUSES:
                fields["status"] = str(v).lower()
                if str(v).lower() == "closed":
                    fields["closed_at"] = _now_iso()
                else:
                    fields["closed_at"] = None
            elif k == "priority" and str(v).upper() in VALID_PRIORITIES:
                fields["priority"] = str(v).upper()
            elif k == "tags" and isinstance(v, list):
                fields["tags"] = json.dumps(v, ensure_ascii=False)
            elif isinstance(v, str):
                fields[k] = v.strip()

        if not fields:
            return self.get_investigation(investigation_id)

        now = _now_iso()
        fields["updated_at"] = now

        set_clause = ", ".join(f"{col} = ?" for col in fields.keys())
        values = list(fields.values()) + [investigation_id]

        with _LOCK, get_db(self.db_path) as conn:
            conn.execute(f"UPDATE investigations SET {set_clause} WHERE id = ?", values)

            tl_id = f"tl_{uuid.uuid4().hex[:10]}"
            conn.execute("""
            INSERT INTO investigation_timeline (id, investigation_id, actor, action, details, timestamp)
            VALUES (?, ?, ?, 'updated', ?, ?)
            """, (tl_id, investigation_id, actor, f"تحديث الحقول: {', '.join(fields.keys())}", now))

        audit_engine.record_engine_event(
            application="investigations",
            action="investigation_updated",
            message=f"تحديث ملف التحقيق الأمني: {investigation_id}",
            category="investigation",
            details={"investigation_id": investigation_id, "updated_fields": list(fields.keys()), "actor": actor},
        )

        return self.get_investigation(investigation_id)

    def add_item(
        self,
        investigation_id: str,
        item_type: str,
        item_id: str,
        title: str,
        metadata: dict[str, Any] | None = None,
        actor: str = "system",
    ) -> dict[str, Any]:
        norm_type = item_type.lower() if item_type.lower() in VALID_ITEM_TYPES else "evidence"
        entry_id = f"itm_{uuid.uuid4().hex[:10]}"
        now = _now_iso()
        meta_json = json.dumps(metadata or {}, ensure_ascii=False)

        with _LOCK, get_db(self.db_path) as conn:
            # Check duplicate item in investigation
            existing = conn.execute(
                "SELECT id FROM investigation_items WHERE investigation_id = ? AND item_type = ? AND item_id = ?",
                (investigation_id, norm_type, item_id)
            ).fetchone()
            if existing:
                return dict(existing)

            conn.execute("""
            INSERT INTO investigation_items (id, investigation_id, item_type, item_id, title, metadata, added_by, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (entry_id, investigation_id, norm_type, item_id, title, meta_json, actor, now))

            tl_id = f"tl_{uuid.uuid4().hex[:10]}"
            conn.execute("""
            INSERT INTO investigation_timeline (id, investigation_id, actor, action, details, timestamp)
            VALUES (?, ?, ?, 'item_added', ?, ?)
            """, (tl_id, investigation_id, actor, f"إضافة عنصر مرتبط: [{norm_type.upper()}] {title}", now))

            conn.execute("UPDATE investigations SET updated_at = ? WHERE id = ?", (now, investigation_id))

        audit_engine.record_engine_event(
            application="investigations",
            action="item_added",
            message=f"تم ربط عنصر ({norm_type}) بالتحقيق {investigation_id}: {title}",
            category="investigation",
            details={"investigation_id": investigation_id, "item_type": norm_type, "item_id": item_id, "actor": actor},
        )

        return {
            "id": entry_id,
            "investigation_id": investigation_id,
            "item_type": norm_type,
            "item_id": item_id,
            "title": title,
            "metadata": metadata or {},
            "added_by": actor,
            "added_at": now,
        }

    def remove_item(self, investigation_id: str, item_entry_id: str, actor: str = "system") -> bool:
        with _LOCK, get_db(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM investigation_items WHERE investigation_id = ? AND (id = ? OR item_id = ?)",
                (investigation_id, item_entry_id, item_entry_id)
            ).fetchone()
            if not row:
                return False

            conn.execute(
                "DELETE FROM investigation_items WHERE id = ?",
                (row["id"],)
            )

            now = _now_iso()
            tl_id = f"tl_{uuid.uuid4().hex[:10]}"
            conn.execute("""
            INSERT INTO investigation_timeline (id, investigation_id, actor, action, details, timestamp)
            VALUES (?, ?, ?, 'item_removed', ?, ?)
            """, (tl_id, investigation_id, actor, f"إزالة عنصر: {row['title']}", now))

            conn.execute("UPDATE investigations SET updated_at = ? WHERE id = ?", (now, investigation_id))

        audit_engine.record_engine_event(
            application="investigations",
            action="item_removed",
            message=f"تم فك ربط العنصر من التحقيق {investigation_id}: {row['title']}",
            category="investigation",
            details={"investigation_id": investigation_id, "item_id": row["item_id"], "actor": actor},
        )

        return True

    def add_note(self, investigation_id: str, content: str, author: str = "system") -> dict[str, Any]:
        note_id = f"not_{uuid.uuid4().hex[:10]}"
        now = _now_iso()

        with _LOCK, get_db(self.db_path) as conn:
            conn.execute("""
            INSERT INTO investigation_notes (id, investigation_id, author, content, created_at)
            VALUES (?, ?, ?, ?, ?)
            """, (note_id, investigation_id, author, content, now))

            tl_id = f"tl_{uuid.uuid4().hex[:10]}"
            conn.execute("""
            INSERT INTO investigation_timeline (id, investigation_id, actor, action, details, timestamp)
            VALUES (?, ?, ?, 'note_added', ?, ?)
            """, (tl_id, investigation_id, author, f"إضافة ملاحظة تحليلية جديدة بواسطة {author}", now))

            conn.execute("UPDATE investigations SET updated_at = ? WHERE id = ?", (now, investigation_id))

        audit_engine.record_engine_event(
            application="investigations",
            action="note_added",
            message=f"إضافة ملاحظة في ملف التحقيق {investigation_id}",
            category="investigation",
            details={"investigation_id": investigation_id, "note_id": note_id, "author": author},
        )

        return {
            "id": note_id,
            "investigation_id": investigation_id,
            "author": author,
            "content": content,
            "created_at": now,
        }

    def get_summary(self) -> dict[str, Any]:
        with _LOCK, get_db(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
            open_cases = conn.execute("SELECT COUNT(*) FROM investigations WHERE status != 'closed'").fetchone()[0]
            p1_count = conn.execute("SELECT COUNT(*) FROM investigations WHERE priority = 'P1' AND status != 'closed'").fetchone()[0]
            closed_cases = conn.execute("SELECT COUNT(*) FROM investigations WHERE status = 'closed'").fetchone()[0]

            by_status = {}
            for r in conn.execute("SELECT status, COUNT(*) as cnt FROM investigations GROUP BY status").fetchall():
                by_status[r["status"]] = r["cnt"]

            by_priority = {}
            for r in conn.execute("SELECT priority, COUNT(*) as cnt FROM investigations GROUP BY priority").fetchall():
                by_priority[r["priority"]] = r["cnt"]

        return {
            "total_investigations": total,
            "open_cases": open_cases,
            "critical_p1_cases": p1_count,
            "closed_cases": closed_cases,
            "by_status": by_status,
            "by_priority": by_priority,
        }
