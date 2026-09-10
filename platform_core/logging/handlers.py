"""Non-blocking asynchronous log handler with queue worker and backpressure policy."""

from __future__ import annotations

from pathlib import Path
import queue
import threading
import time
from typing import Any

from .metrics import get_metrics
from .rotation import RotatingLogWriter
from .storage import PlatformLogStorage


class AsyncLogHandler:
    """High-throughput, non-blocking asynchronous log handler."""

    def __init__(
        self,
        log_dir: Path | str,
        storage: PlatformLogStorage | None = None,
        *,
        queue_size: int = 10000,
        max_size_mb: int = 100,
        retention_days: int = 30,
        compression: bool = True,
        batch_size: int = 50,
        flush_interval: float = 0.25,
    ) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=max(1, queue_size))
        self.storage = storage or PlatformLogStorage()
        self.metrics = get_metrics()
        self.batch_size = max(1, batch_size)
        self.flush_interval = max(0.01, flush_interval)


        # Writers for main application and error logs
        self.app_writer = RotatingLogWriter(
            self.log_dir / "platform" / "application.log",
            max_size_mb=max_size_mb,
            retention_days=retention_days,
            compression=compression,
        )
        self.error_writer = RotatingLogWriter(
            self.log_dir / "platform" / "error.log",
            max_size_mb=max_size_mb,
            retention_days=retention_days,
            compression=compression,
        )

        self._running = True
        self._worker = threading.Thread(target=self._process_queue, name="PlatformLogWorker", daemon=True)
        self._worker.start()

    def is_alive(self) -> bool:
        """Check if background worker thread is alive."""
        return bool(self._running and self._worker.is_alive())

    def enqueue(self, event: dict[str, Any]) -> bool:
        """Enqueue event non-blockingly with backpressure policy."""
        if not self._running:
            return False

        level = str(event.get("level", "INFO")).upper()
        self.metrics.set_queue_depth(self.queue.qsize())

        # Backpressure policy implementation
        if self.queue.full():
            if level == "CRITICAL":
                # CRITICAL: Never drop. Attempt short wait, fallback to direct sync write if still full
                try:
                    self.queue.put(event, block=True, timeout=0.1)
                    return True
                except queue.Full:
                    self._write_direct_emergency(event)
                    return True

            elif level == "ERROR":
                # ERROR: Prefer keep. Attempt short wait
                try:
                    self.queue.put(event, block=True, timeout=0.03)
                    return True
                except queue.Full:
                    self.metrics.record_dropped(level)
                    return False

            elif level in ("DEBUG", "TRACE"):
                # DEBUG/TRACE: Drop first
                self.metrics.record_dropped(level)
                return False

            else:
                # INFO/WARNING: Drop under extreme pressure
                self.metrics.record_dropped(level)
                return False

        try:
            self.queue.put_nowait(event)
            return True
        except queue.Full:
            self.metrics.record_dropped(level)
            return False

    def _write_direct_emergency(self, event: dict[str, Any]) -> None:
        """Emergency synchronous write path for CRITICAL events when queue is completely full."""
        import json
        line = json.dumps(event, ensure_ascii=False, default=str)
        self.app_writer.write_line(line)
        self.error_writer.write_line(line)
        try:
            self.storage.insert_batch([event])
        except Exception:
            pass
        self.metrics.record_written(event.get("level", "CRITICAL"), event.get("component", "platform"))

    def _process_queue(self) -> None:
        """Background worker thread consuming and batching writes."""
        import json
        batch: list[dict[str, Any]] = []
        last_flush = time.time()

        try:
            while self._running or not self.queue.empty():
                try:
                    timeout = max(0.01, min(0.05, self.flush_interval))
                    item = self.queue.get(timeout=timeout)
                    if item is None:
                        # Sentinel received
                        break
                    if isinstance(item, tuple) and len(item) == 2 and item[0] == "__FLUSH__":
                        if batch:
                            self._flush_batch(batch)
                            batch.clear()
                            last_flush = time.time()
                        item[1].set()
                        continue
                    batch.append(item)
                except queue.Empty:
                    pass

                now = time.time()
                if (len(batch) >= self.batch_size) or (batch and (now - last_flush >= self.flush_interval)):
                    self._flush_batch(batch)
                    batch.clear()
                    last_flush = now
                    self.metrics.set_queue_depth(self.queue.qsize())
        finally:
            if batch:
                self._flush_batch(batch)
                batch.clear()
            try:
                self.storage.close()
            except Exception:
                pass

    def _flush_batch(self, batch: list[dict[str, Any]]) -> None:
        """Write batch to rotation files and SQLite storage."""
        import json
        for event in batch:
            line = json.dumps(event, ensure_ascii=False, default=str)
            self.app_writer.write_line(line)
            level = str(event.get("level", "INFO")).upper()
            if level in ("ERROR", "CRITICAL"):
                self.error_writer.write_line(line)
            self.metrics.record_written(level, event.get("component", "platform"))

        try:
            self.storage.insert_batch(batch)
        except Exception:
            # Observability must never crash the application
            pass

    def flush(self, timeout: float = 3.0) -> None:
        """Flush all pending writes through worker and sync to disk/storage."""
        if not self._running:
            self.app_writer.flush()
            self.error_writer.flush()
            return
        flush_event = threading.Event()
        try:
            self.queue.put(("__FLUSH__", flush_event), timeout=timeout)
            flush_event.wait(timeout=timeout)
        except Exception:
            pass
        self.app_writer.flush()
        self.error_writer.flush()


    def close(self, timeout: float = 3.0) -> None:
        """Gracefully stop worker thread and close writers."""
        if not self._running:
            return
        self._running = False
        try:
            self.queue.put_nowait(None)
        except queue.Full:
            pass
        if self._worker.is_alive():
            self._worker.join(timeout=timeout)
        self.app_writer.close()
        self.error_writer.close()
        try:
            self.storage.close()
        except Exception:
            pass

    stop = close


