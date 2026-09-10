import sqlite3
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Iterable
from pathlib import Path

logger = logging.getLogger(__name__)

class ResultSink(ABC):
    @abstractmethod
    def add(self, record: dict[str, Any]) -> None:
        pass

    @abstractmethod
    def finalize(self) -> None:
        pass

    @abstractmethod
    def get_records(self) -> list[dict[str, Any]]:
        pass


class MemoryResultSink(ResultSink):
    """Legacy in-memory list sink."""
    def __init__(self):
        self.records: list[dict[str, Any]] = []

    def add(self, record: dict[str, Any]) -> None:
        self.records.append(record)

    def finalize(self) -> None:
        pass

    def get_records(self) -> list[dict[str, Any]]:
        return self.records


class SQLiteResultSink(ResultSink):
    """Stream records to SQLite to avoid RAM amplification."""
    def __init__(self, db_path: Path, batch_size: int = 5000):
        self.db_path = db_path
        self.batch_size = batch_size
        self._batch: list[tuple[int, str]] = []
        self._count = 0
        
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Fast write performance
        self.conn = sqlite3.connect(self.db_path, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_db()

    def _init_db(self):
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            row_index INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_records_row_index ON records(row_index)")
        self._cursor = self.conn.cursor()
        self._cursor.execute("BEGIN TRANSACTION")

    def add(self, record: dict[str, Any]) -> None:
        self._batch.append((self._count, json.dumps(record, ensure_ascii=False)))
        self._count += 1
        
        if len(self._batch) >= self.batch_size:
            self._flush_batch()

    def _flush_batch(self):
        if not self._batch:
            return
        try:
            self._cursor.executemany(
                "INSERT INTO records (row_index, payload_json) VALUES (?, ?)", 
                self._batch
            )
            self._batch.clear()
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Failed to flush batch to SQLite: {e}")
            raise

    def finalize(self) -> None:
        if self._batch:
            self._flush_batch()
        self._cursor.execute("COMMIT")
        self.conn.close()

    def get_records(self) -> list[dict[str, Any]]:
        # This is purely for fallback in places that haven't migrated to Reader yet
        raise NotImplementedError("SQLiteResultSink does not support returning all records at once in memory.")


class ResultReader(ABC):
    @abstractmethod
    def count(self) -> int:
        pass

    @abstractmethod
    def iter_records(self, sort_by: str = None, limit: int = None) -> Iterable[dict[str, Any]]:
        pass

    @abstractmethod
    def get_paginated_records(self, cursor: int, limit: int, query: str = None) -> tuple[list[dict[str, Any]], int | None]:
        """Returns (records_list, next_cursor)."""
        pass
        
    @abstractmethod
    def close(self) -> None:
        pass


class MemoryResultReader(ResultReader):
    def __init__(self, records: list[dict[str, Any]]):
        self.records = records

    def count(self) -> int:
        return len(self.records)

    def iter_records(self, sort_by: str = None, limit: int = None) -> Iterable[dict[str, Any]]:
        records = self.records
        if sort_by == "risk_score_desc":
            records = sorted(records, key=lambda r: int(r.get("risk_score") or 0), reverse=True)
        if limit is not None:
            return records[:limit]
        return records

    def get_paginated_records(self, cursor: int, limit: int, query: str = None) -> tuple[list[dict[str, Any]], int | None]:
        if query:
            q_lower = query.lower()
            filtered = []
            for i, r in enumerate(self.records):
                # Basic sub-string match across values for legacy support
                match = False
                for v in r.values():
                    if isinstance(v, str) and q_lower in v.lower():
                        match = True
                        break
                    elif isinstance(v, dict):
                        for sub_v in v.values():
                            if isinstance(sub_v, str) and q_lower in sub_v.lower():
                                match = True
                                break
                        if match:
                            break
                if match:
                    # Inject source index for UI
                    r_copy = dict(r)
                    r_copy["_sourceIndex"] = i
                    filtered.append(r_copy)
            results_pool = filtered
        else:
            results_pool = []
            for i, r in enumerate(self.records):
                r_copy = dict(r)
                r_copy["_sourceIndex"] = i
                results_pool.append(r_copy)
            
        start = cursor
        end = start + limit
        results = results_pool[start:end]
        next_cursor = end if end < len(results_pool) else None
        return results, next_cursor
        
    def close(self) -> None:
        pass


class SQLiteResultReader(ResultReader):
    def __init__(self, db_path: Path):
        self.db_path = db_path
        # Use a read-only connection for concurrent reads
        self.conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        self.conn.row_factory = sqlite3.Row

    def count(self) -> int:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(id) FROM records")
        return cursor.fetchone()[0]

    def iter_records(self, sort_by: str = None, limit: int = None) -> Iterable[dict[str, Any]]:
        cursor = self.conn.cursor()
        sql = "SELECT payload_json FROM records"
        
        if sort_by == "risk_score_desc":
            # Very fast with small LIMIT, decent for full table scan compared to memory
            sql += " ORDER BY CAST(json_extract(payload_json, '$.risk_score') AS INTEGER) DESC"
        else:
            sql += " ORDER BY row_index ASC"
            
        params = []
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
            
        cursor.execute(sql, params)
        for row in cursor:
            yield json.loads(row["payload_json"])

    def get_paginated_records(self, cursor: int, limit: int, query: str = None) -> tuple[list[dict[str, Any]], int | None]:
        db_cursor = self.conn.cursor()
        
        sql = "SELECT row_index, payload_json FROM records WHERE row_index >= ?"
        params = [cursor]
        
        if query:
            sql += " AND payload_json LIKE ?"
            # SQLite LIKE is case-insensitive for ASCII by default
            # Add wildcards to query
            params.append(f"%{query}%")
            
        sql += " ORDER BY row_index ASC LIMIT ?"
        params.append(limit)
        
        db_cursor.execute(sql, tuple(params))
        
        results = []
        last_index = cursor
        for row in db_cursor:
            last_index = row["row_index"]
            rec = json.loads(row["payload_json"])
            rec["_sourceIndex"] = last_index
            results.append(rec)
            
        next_cursor = last_index + 1 if len(results) == limit else None
        return results, next_cursor

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def get_page(self, limit: int = 100, cursor_val: int = -1) -> list[dict[str, Any]]:
        if not self.db_path.is_file():
            return []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT payload_json FROM records WHERE row_index > ? ORDER BY row_index LIMIT ?",
                (cursor_val, limit)
            )
            return [json.loads(row[0]) for row in cursor]
