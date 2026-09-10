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
    def get_paginated_records(self, cursor: int, limit: int, query: str = None, filters: dict[str, str] = None) -> tuple[list[dict[str, Any]], int | None]:
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

    def get_paginated_records(self, cursor: int, limit: int, query: str = None, filters: dict[str, str] = None) -> tuple[list[dict[str, Any]], int | None]:
        results_pool = []
        q_lower = query.lower() if query else None

        for i, r in enumerate(self.records):
            # 1. Query text filter
            if q_lower:
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
                if not match:
                    continue

            # 2. Structured filters
            if filters:
                if filters.get("severity") and str(r.get("severity")) != filters["severity"]:
                    continue
                if filters.get("incident_id") and str(r.get("incident_id")) != filters["incident_id"]:
                    continue
                if filters.get("event_id") and str(r.get("event_id")) != str(filters["event_id"]):
                    continue
                if filters.get("action") and str(r.get("action", "")).lower() != str(filters["action"]).lower():
                    continue
                if filters.get("conclusion_level") and str(r.get("conclusion_level", "")).lower() != str(filters["conclusion_level"]).lower():
                    continue
                if filters.get("user") and str(r.get("user_account")) != filters["user"]:
                    continue
                if filters.get("ip") and str(r.get("src_ip")) != filters["ip"] and str(r.get("destination")) != filters["ip"]:
                    continue
                if filters.get("device") and str(r.get("device")) != filters["device"]:
                    continue

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

    def get_paginated_records(self, cursor: int, limit: int, query: str = None, filters: dict[str, str] = None) -> tuple[list[dict[str, Any]], int | None]:
        db_cursor = self.conn.cursor()
        
        sql = "SELECT row_index, payload_json FROM records WHERE row_index >= ?"
        params: list[Any] = [cursor]
        
        if query:
            sql += " AND payload_json LIKE ?"
            params.append(f"%{query}%")

        if filters:
            if filters.get("severity"):
                sql += " AND json_extract(payload_json, '$.severity') = ?"
                params.append(filters["severity"])
            if filters.get("incident_id"):
                sql += " AND json_extract(payload_json, '$.incident_id') = ?"
                params.append(filters["incident_id"])
            if filters.get("event_id"):
                sql += " AND json_extract(payload_json, '$.event_id') = ?"
                params.append(str(filters["event_id"]))
            if filters.get("action"):
                sql += " AND LOWER(json_extract(payload_json, '$.action')) = LOWER(?)"
                params.append(filters["action"])
            if filters.get("conclusion_level"):
                sql += " AND LOWER(json_extract(payload_json, '$.conclusion_level')) = LOWER(?)"
                params.append(filters["conclusion_level"])
            if filters.get("user"):
                sql += " AND json_extract(payload_json, '$.user_account') = ?"
                params.append(filters["user"])
            if filters.get("ip"):
                sql += " AND (json_extract(payload_json, '$.src_ip') = ? OR json_extract(payload_json, '$.destination') = ?)"
                params.extend([filters["ip"], filters["ip"]])
            if filters.get("device"):
                sql += " AND json_extract(payload_json, '$.device') = ?"
                params.append(filters["device"])
            
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

    def get_entity_profile(self, entity_type: str, entity_value: str) -> dict[str, Any]:
        cursor = self.conn.cursor()
        if entity_type == "ip":
            sql = "SELECT payload_json FROM records WHERE json_extract(payload_json, '$.src_ip') = ? OR json_extract(payload_json, '$.destination') = ? LIMIT 500"
            params: tuple[Any, ...] = (entity_value, entity_value)
        elif entity_type == "user":
            sql = "SELECT payload_json FROM records WHERE json_extract(payload_json, '$.user_account') = ? LIMIT 500"
            params = (entity_value,)
        elif entity_type == "device":
            sql = "SELECT payload_json FROM records WHERE json_extract(payload_json, '$.device') = ? LIMIT 500"
            params = (entity_value,)
        else:
            sql = "SELECT payload_json FROM records WHERE payload_json LIKE ? LIMIT 500"
            params = (f"%{entity_value}%",)

        cursor.execute(sql, params)
        events_count = 0
        critical_count = 0
        high_count = 0
        destinations = set()
        ports = set()
        detection_ids = set()
        incident_ids = set()
        first_seen = ""
        last_seen = ""

        for row in cursor:
            events_count += 1
            rec = json.loads(row["payload_json"])
            sev = rec.get("severity")
            if sev == "حرج":
                critical_count += 1
            elif sev == "مرتفع":
                high_count += 1
            t = rec.get("event_time") or ""
            if t:
                if not first_seen or t < first_seen:
                    first_seen = t
                if not last_seen or t > last_seen:
                    last_seen = t
            if rec.get("destination") and rec["destination"] != "-":
                destinations.add(rec["destination"])
            if rec.get("dst_port"):
                ports.add(str(rec["dst_port"]))
            for d in rec.get("detection_ids") or []:
                detection_ids.add(d)
            if rec.get("incident_id"):
                incident_ids.add(rec["incident_id"])

        return {
            "type": entity_type,
            "value": entity_value,
            "total_events": events_count,
            "critical_events": critical_count,
            "high_events": high_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "destinations": sorted(destinations)[:20],
            "ports": sorted(ports)[:20],
            "detection_ids": sorted(detection_ids),
            "incident_ids": sorted(incident_ids),
        }

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
