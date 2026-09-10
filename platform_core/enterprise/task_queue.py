"""
Unified Enterprise Architecture - Distributed Workers & Asynchronous Task Queue.

Provides priority scheduling, worker concurrency control, automatic exponential retries,
and full observability into heavy background forensic workloads.
durable SQLite WAL persistence, real-time progress tracking, and cooperative cancellation.
"""

from __future__ import annotations

import enum
import heapq
import json
import logging
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("platform.task_queue")
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = ROOT_DIR / "storage"

_local_storage = threading.local()


def _get_db_path() -> Path:
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return STORAGE_DIR / "tasks.db"


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
        CREATE TABLE IF NOT EXISTS enterprise_tasks (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            priority TEXT NOT NULL,
            priority_level INTEGER NOT NULL,
            status TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0,
            step_message TEXT NOT NULL DEFAULT '',
            cancellation_requested INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT,
            error TEXT,
            retries INTEGER NOT NULL DEFAULT 0,
            max_retries INTEGER NOT NULL DEFAULT 3,
            tenant_id TEXT NOT NULL DEFAULT 'default',
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            duration_ms REAL NOT NULL DEFAULT 0.0
        );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON enterprise_tasks(status);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_tenant ON enterprise_tasks(tenant_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_created ON enterprise_tasks(created_at DESC);")
    conn.commit()


class TaskPriority(enum.IntEnum):
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4


class TaskStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


@dataclass(order=True)
class PriorityItem:
    priority: int
    created_at_epoch: float
    task_id: str = field(compare=False)


@dataclass
class EnterpriseTask:
    id: str
    name: str
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.QUEUED
    progress: int = 0
    step_message: str = ""
    cancellation_requested: bool = False
    payload: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None
    retries: int = 0
    max_retries: int = 3
    tenant_id: str = "default"
    created_at: str = ""
    started_at: str | None = None
    completed_at: str | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "priority": self.priority.name,
            "priority_level": self.priority.value,
            "status": self.status.value,
            "progress": self.progress,
            "step_message": self.step_message,
            "cancellation_requested": self.cancellation_requested,
            "payload": self.payload,
            "result": self.result,
            "error": self.error,
            "retries": self.retries,
            "max_retries": self.max_retries,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": round(self.duration_ms, 2),
        }


class EnterpriseTaskQueue:
    """Thread-safe, priority-driven asynchronous task queue with worker pools."""
    """Thread-safe, priority-driven asynchronous task queue with durable SQLite persistence."""

    _instance: EnterpriseTaskQueue | None = None
    _singleton_lock = threading.RLock()

    def __init__(self, num_workers: int = 3) -> None:
        self.num_workers = num_workers
        self._heap: list[PriorityItem] = []
        self._tasks: dict[str, EnterpriseTask] = {}
        self._handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {}
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._shutdown_event = threading.Event()
        self._workers: list[threading.Thread] = []
        self._processed_count = 0
        self._failed_count = 0
        _init_db()
        self._start_workers()

    @classmethod
    def get_instance(cls) -> EnterpriseTaskQueue:
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._singleton_lock:
            if cls._instance:
                cls._instance.shutdown()
            cls._instance = None

    def register_handler(self, task_name: str, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        """Register a handler function corresponding to a task name."""
        with self._lock:
            self._handlers[task_name] = handler

    def _start_workers(self) -> None:
        for idx in range(self.num_workers):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"EnterpriseWorker-{idx + 1}",
                daemon=True,
            )
            t.start()
            self._workers.append(t)

    def _persist_task(self, task: EnterpriseTask) -> None:
        try:
            conn = _get_db_conn()
            conn.execute("""
                INSERT OR REPLACE INTO enterprise_tasks (
                    id, name, priority, priority_level, status, progress, step_message,
                    cancellation_requested, payload_json, result_json, error, retries,
                    max_retries, tenant_id, created_at, started_at, completed_at, duration_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task.id,
                task.name,
                task.priority.name,
                task.priority.value,
                task.status.value,
                task.progress,
                task.step_message,
                1 if task.cancellation_requested else 0,
                json.dumps(task.payload, ensure_ascii=False),
                json.dumps(task.result, ensure_ascii=False) if task.result is not None else None,
                task.error,
                task.retries,
                task.max_retries,
                task.tenant_id,
                task.created_at,
                task.started_at,
                task.completed_at,
                task.duration_ms,
            ))
            conn.commit()
        except Exception as e:
            logger.warning("Failed to persist task %s: %s", task.id, e)

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        payload = {}
        try:
            payload = json.loads(row["payload_json"]) if row["payload_json"] else {}
        except Exception:
            pass
        result = None
        try:
            result = json.loads(row["result_json"]) if row["result_json"] else None
        except Exception:
            pass
        return {
            "id": row["id"],
            "name": row["name"],
            "priority": row["priority"],
            "priority_level": row["priority_level"],
            "status": row["status"],
            "progress": row["progress"],
            "step_message": row["step_message"],
            "cancellation_requested": bool(row["cancellation_requested"]),
            "payload": payload,
            "result": result,
            "error": row["error"],
            "retries": row["retries"],
            "max_retries": row["max_retries"],
            "tenant_id": row["tenant_id"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "duration_ms": round(row["duration_ms"], 2),
        }

    def _load_task_from_db(self, task_id: str) -> EnterpriseTask | None:
        try:
            conn = _get_db_conn()
            cur = conn.execute("SELECT * FROM enterprise_tasks WHERE id = ?", (task_id,))
            row = cur.fetchone()
            if not row:
                return None
            d = self._row_to_dict(row)
            return EnterpriseTask(
                id=d["id"],
                name=d["name"],
                priority=TaskPriority[d["priority"]],
                status=TaskStatus(d["status"]),
                progress=d["progress"],
                step_message=d["step_message"],
                cancellation_requested=d["cancellation_requested"],
                payload=d["payload"],
                result=d["result"],
                error=d["error"],
                retries=d["retries"],
                max_retries=d["max_retries"],
                tenant_id=d["tenant_id"],
                created_at=d["created_at"],
                started_at=d["started_at"],
                completed_at=d["completed_at"],
                duration_ms=d["duration_ms"],
            )
        except Exception:
            return None

    def submit(
        self,
        name: str,
        payload: dict[str, Any] | None = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        max_retries: int = 3,
        tenant_id: str = "default",
    ) -> str:
        task_id = f"task_{uuid.uuid4().hex[:12]}"
        now_epoch = time.time()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_epoch))

        task = EnterpriseTask(
            id=task_id,
            name=name,
            priority=priority,
            status=TaskStatus.QUEUED,
            progress=0,
            step_message="Queued for worker pickup",
            payload=payload or {},
            max_retries=max_retries,
            tenant_id=tenant_id,
            created_at=now_iso,
        )

        with self._lock:
            self._tasks[task_id] = task
            heapq.heappush(self._heap, PriorityItem(priority.value, now_epoch, task_id))
            self._persist_task(task)
            self._condition.notify()

        return task_id

    def get_task(self, task_id: str) -> EnterpriseTask | None:
        with self._lock:
            return self._tasks.get(task_id)
            task = self._tasks.get(task_id)
            if task:
                return task
            return self._load_task_from_db(task_id)

    def list_tasks(
        self,
        tenant_id: str | None = None,
        status: TaskStatus | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with self._lock:
            results = []
            for t in sorted(self._tasks.values(), key=lambda x: x.created_at, reverse=True):
                if tenant_id and t.tenant_id != tenant_id:
                    continue
                if status and t.status != status:
                    continue
                results.append(t.to_dict())
                if len(results) >= limit:
                    break
            return results
        try:
            conn = _get_db_conn()
            query = "SELECT * FROM enterprise_tasks WHERE 1=1"
            params: list[Any] = []
            if tenant_id:
                query += " AND tenant_id = ?"
                params.append(tenant_id)
            if status:
                query += " AND status = ?"
                params.append(status.value if isinstance(status, TaskStatus) else str(status))
            if search:
                query += " AND (name LIKE ? OR id LIKE ? OR step_message LIKE ?)"
                term = f"%{search}%"
                params.extend([term, term, term])
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cur = conn.execute(query, params)
            rows = cur.fetchall()
            return [self._row_to_dict(r) for r in rows]
        except Exception:
            with self._lock:
                results = []
                for t in sorted(self._tasks.values(), key=lambda x: x.created_at, reverse=True):
                    if tenant_id and t.tenant_id != tenant_id:
                        continue
                    if status and t.status != status:
                        continue
                    if search and (search.lower() not in t.name.lower() and search.lower() not in t.id.lower()):
                        continue
                    results.append(t.to_dict())
                return results[offset : offset + limit]

    def count_tasks(
        self,
        tenant_id: str | None = None,
        status: TaskStatus | None = None,
        search: str | None = None,
    ) -> int:
        try:
            conn = _get_db_conn()
            query = "SELECT COUNT(*) as cnt FROM enterprise_tasks WHERE 1=1"
            params: list[Any] = []
            if tenant_id:
                query += " AND tenant_id = ?"
                params.append(tenant_id)
            if status:
                query += " AND status = ?"
                params.append(status.value if isinstance(status, TaskStatus) else str(status))
            if search:
                query += " AND (name LIKE ? OR id LIKE ? OR step_message LIKE ?)"
                term = f"%{search}%"
                params.extend([term, term, term])
            cur = conn.execute(query, params)
            row = cur.fetchone()
            return int(row["cnt"]) if row else 0
        except Exception:
            return len(self._tasks)

    def cancel_task(self, task_id: str) -> bool:
        """Cooperatively cancels a queued or running task."""
        with self._lock:
            task = self._tasks.get(task_id)
            task = self._tasks.get(task_id) or self._load_task_from_db(task_id)
            if not task:
                return False
            if task.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED):
                return False
            task.cancellation_requested = True
            task.step_message = "Cancellation requested by operator"
            if task.status == TaskStatus.QUEUED:
                task.status = TaskStatus.CANCELLED
                task.completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                return True
            return False
            self._tasks[task_id] = task
            self._persist_task(task)
            return True

    def retry_task(self, task_id: str) -> bool:
        """Re-enqueues a failed or cancelled task for immediate execution."""
        with self._lock:
            task = self._tasks.get(task_id) or self._load_task_from_db(task_id)
            if not task:
                return False
            if task.status not in (TaskStatus.FAILED, TaskStatus.CANCELLED):
                return False
            task.status = TaskStatus.QUEUED
            task.cancellation_requested = False
            task.error = None
            task.progress = 0
            task.step_message = "Re-queued by operator"
            task.started_at = None
            task.completed_at = None
            self._tasks[task_id] = task
            self._persist_task(task)
            heapq.heappush(self._heap, PriorityItem(task.priority.value, time.time(), task.id))
            self._condition.notify()
            return True

    def update_progress(self, task_id: str, progress: int, step_message: str = "") -> bool:
        """Updates runtime completion percentage (0-100) and step description."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False
            task.progress = max(0, min(100, int(progress)))
            if step_message:
                task.step_message = step_message
            self._persist_task(task)
            return True

    def is_cancellation_requested(self, task_id: str) -> bool:
        with self._lock:
            task = self._tasks.get(task_id)
            return bool(task and task.cancellation_requested)

    def _worker_loop(self) -> None:
        while not self._shutdown_event.is_set():
            with self._lock:
                while not self._heap and not self._shutdown_event.is_set():
                    self._condition.wait(timeout=1.0)
                if self._shutdown_event.is_set():
                    break
                if not self._heap:
                    continue

                item = heapq.heappop(self._heap)
                task = self._tasks.get(item.task_id)
                if not task:
                    continue
                if task.status == TaskStatus.CANCELLED or task.cancellation_requested:
                    task.status = TaskStatus.CANCELLED
                    task.completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    self._persist_task(task)
                    continue

                task.status = TaskStatus.RUNNING
                if task.progress < 10:
                    task.progress = 10
                if not task.step_message or task.step_message == "Queued for worker pickup":
                    task.step_message = "Processing started"
                task.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                self._persist_task(task)

            handler = self._handlers.get(task.name)
            start_t = time.perf_counter()
            try:
                if handler:
                    res = handler(task.payload)
                    task.result = res
                else:
                    # Default dummy processing if no specific handler registered
                    task.result = {"message": f"Task '{task.name}' completed via standard processor"}
                task.status = TaskStatus.COMPLETED
                
                with self._lock:
                    if task.cancellation_requested:
                        task.status = TaskStatus.CANCELLED
                        task.step_message = "Task cancelled during execution"
                    else:
                        task.status = TaskStatus.COMPLETED
                        task.progress = 100
                        task.step_message = "Execution completed successfully"
                        self._processed_count += 1

                task.duration_ms = (time.perf_counter() - start_t) * 1000.0
                task.completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                with self._lock:
                    self._processed_count += 1
                self._persist_task(task)
            except Exception as exc:
                task.duration_ms = (time.perf_counter() - start_t) * 1000.0
                task.error = str(exc)
                if task.cancellation_requested:
                    task.status = TaskStatus.CANCELLED
                    task.step_message = "Cancelled by operator"
                    task.completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    self._persist_task(task)
                elif task.retries < task.max_retries:
                    task.retries += 1
                    task.status = TaskStatus.RETRYING
                    task.step_message = f"Retrying attempt {task.retries}/{task.max_retries}"
                    self._persist_task(task)
                    with self._lock:
                        # Re-enqueue with lower priority or slight delay
                        heapq.heappush(self._heap, PriorityItem(task.priority.value, time.time() + 0.1, task.id))
                else:
                    task.status = TaskStatus.FAILED
                    task.step_message = f"Failed: {str(exc)[:100]}"
                    task.completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    self._persist_task(task)
                    with self._lock:
                        self._failed_count += 1

    def get_metrics(self) -> dict[str, Any]:
        with self._lock:
            queued = sum(1 for t in self._tasks.values() if t.status == TaskStatus.QUEUED)
            running = sum(1 for t in self._tasks.values() if t.status == TaskStatus.RUNNING)
            completed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.COMPLETED)
            failed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.FAILED)
        try:
            conn = _get_db_conn()
            cur = conn.execute("SELECT status, COUNT(*) as cnt FROM enterprise_tasks GROUP BY status")
            counts = {row["status"]: row["cnt"] for row in cur.fetchall()}
            total = sum(counts.values())
            return {
                "active_workers": self.num_workers,
                "queued_tasks": queued,
                "running_tasks": running,
                "completed_tasks": completed,
                "failed_tasks": failed,
                "total_submitted": len(self._tasks),
                "broker": "in_memory_priority_queue (Redis/RabbitMQ adapter ready)",
                "queued_tasks": counts.get("queued", 0),
                "running_tasks": counts.get("running", 0),
                "completed_tasks": counts.get("completed", 0),
                "failed_tasks": counts.get("failed", 0),
                "cancelled_tasks": counts.get("cancelled", 0),
                "total_submitted": total,
                "broker": "sqlite_priority_queue (storage/tasks.db WAL mode)",
            }
        except Exception:
            with self._lock:
                queued = sum(1 for t in self._tasks.values() if t.status == TaskStatus.QUEUED)
                running = sum(1 for t in self._tasks.values() if t.status == TaskStatus.RUNNING)
                completed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.COMPLETED)
                failed = sum(1 for t in self._tasks.values() if t.status == TaskStatus.FAILED)
                return {
                    "active_workers": self.num_workers,
                    "queued_tasks": queued,
                    "running_tasks": running,
                    "completed_tasks": completed,
                    "failed_tasks": failed,
                    "total_submitted": len(self._tasks),
                    "broker": "in_memory_fallback",
                }

    def shutdown(self) -> None:
        self._shutdown_event.set()
        with self._lock:
            self._condition.notify_all()
        for w in self._workers:
            if w.is_alive():
                w.join(timeout=1.0)
