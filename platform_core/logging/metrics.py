"""Observability metrics tracking for the platform logging system."""

from __future__ import annotations

import threading
import time
from typing import Any


class LoggingMetrics:
    """Thread-safe performance and telemetry tracker for platform logging operations."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with getattr(self, "_lock", threading.Lock()):
            self.logs_written_total: dict[str, int] = {
                "TRACE": 0, "DEBUG": 0, "INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0
            }
            self.logs_dropped_total: dict[str, int] = {
                "TRACE": 0, "DEBUG": 0, "INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0
            }
            self.queue_depth: int = 0
            self.active_components: set[str] = set()
            self.started_at = time.time()
            self.last_event_time = 0.0

    def record_written(self, level: str, component: str) -> None:
        with self._lock:
            lvl = level.upper()
            self.logs_written_total[lvl] = self.logs_written_total.get(lvl, 0) + 1
            self.active_components.add(component)
            self.last_event_time = time.time()

    def record_dropped(self, level: str) -> None:
        with self._lock:
            lvl = level.upper()
            self.logs_dropped_total[lvl] = self.logs_dropped_total.get(lvl, 0) + 1

    def set_queue_depth(self, depth: int) -> None:
        with self._lock:
            self.queue_depth = depth

    def get_snapshot(self) -> dict[str, Any]:
        with self._lock:
            total_written = sum(self.logs_written_total.values())
            total_dropped = sum(self.logs_dropped_total.values())
            uptime = max(1.0, time.time() - self.started_at)
            return {
                "logs_written_total": dict(self.logs_written_total),
                "logs_dropped_total": dict(self.logs_dropped_total),
                "written_total": total_written,
                "dropped_total": total_dropped,
                "total_written": total_written,
                "total_dropped": total_dropped,
                "total_errors": self.logs_written_total.get("ERROR", 0),
                "total_warnings": self.logs_written_total.get("WARNING", 0),
                "total_critical": self.logs_written_total.get("CRITICAL", 0),
                "queue_depth": self.queue_depth,
                "active_components_count": len(self.active_components),
                "active_components": sorted(list(self.active_components)),
                "logs_per_minute": round((total_written / uptime) * 60.0, 2),
                "uptime_seconds": round(uptime, 2),
            }

    snapshot = get_snapshot


_METRICS = LoggingMetrics()


def get_metrics() -> LoggingMetrics:
    return _METRICS

