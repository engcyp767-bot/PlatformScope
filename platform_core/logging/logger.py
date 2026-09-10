"""Central Platform Logger implementing unified API, dynamic levels, and structured events."""

from __future__ import annotations

import logging
from pathlib import Path
import threading
from typing import Any

from .context import get_current_context
from .formatter import StructuredLogFormatter
from .handlers import AsyncLogHandler
from .storage import PlatformLogStorage

LEVELS: dict[str, int] = {
    "TRACE": 5,
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

_CURRENT_LEVEL: int = LEVELS["INFO"]
_CURRENT_LEVEL_NAME: str = "INFO"
_GLOBAL_HANDLER: AsyncLogHandler | None = None
_GLOBAL_STORAGE: PlatformLogStorage | None = None
_GLOBAL_FORMATTER: StructuredLogFormatter | None = None
_REGISTRY_LOCK = threading.RLock()
_LOGGER_CACHE: dict[str, PlatformLogger] = {}


def set_platform_log_level(level_name: str) -> None:
    """Dynamically change active logging level without restarting platform."""
    global _CURRENT_LEVEL, _CURRENT_LEVEL_NAME
    lvl = level_name.upper().strip()
    if lvl in LEVELS:
        _CURRENT_LEVEL = LEVELS[lvl]
        _CURRENT_LEVEL_NAME = lvl


def get_platform_log_level() -> str:
    """Return active log level name."""
    return _CURRENT_LEVEL_NAME


def init_platform_logging(
    log_dir: Path | str | None = None,
    storage: PlatformLogStorage | None = None,
    *,
    level: str = "INFO",
    async_enabled: bool = True,
    queue_size: int = 10000,
    max_size_mb: int = 100,
    retention_days: int = 30,
    compression: bool = True,
    redaction_enabled: bool = True,
) -> AsyncLogHandler:
    """Initialize central platform logging subsystem."""
    global _GLOBAL_HANDLER, _GLOBAL_STORAGE, _GLOBAL_FORMATTER

    with _REGISTRY_LOCK:
        set_platform_log_level(level)
        if log_dir is None:
            root = Path(__file__).resolve().parent.parent.parent
            log_dir = root / "logs"

        _GLOBAL_STORAGE = storage or PlatformLogStorage()
        _GLOBAL_FORMATTER = StructuredLogFormatter(redact=redaction_enabled)
        _GLOBAL_HANDLER = AsyncLogHandler(
            log_dir=log_dir,
            storage=_GLOBAL_STORAGE,
            queue_size=queue_size,
            max_size_mb=max_size_mb,
            retention_days=retention_days,
            compression=compression,
        )
        return _GLOBAL_HANDLER


def get_log_storage() -> PlatformLogStorage:
    """Return platform log storage repository."""
    global _GLOBAL_STORAGE
    if _GLOBAL_STORAGE is None:
        _GLOBAL_STORAGE = PlatformLogStorage()
    return _GLOBAL_STORAGE


def get_log_handler() -> AsyncLogHandler:
    """Return central log handler, initializing default if needed."""
    global _GLOBAL_HANDLER
    if _GLOBAL_HANDLER is None:
        init_platform_logging()
    return _GLOBAL_HANDLER


class PlatformLogger:
    """Unified logger providing structured observability events with context and redaction."""

    def __init__(self, component: str, name: str | None = None) -> None:
        self.component = component
        self.name = name or f"platform.{component}"

    def is_enabled_for(self, level: str) -> bool:
        lvl = LEVELS.get(level.upper(), 20)
        return lvl >= _CURRENT_LEVEL

    def _log(
        self,
        level: str,
        message: str | None,
        event_code: str = "GENERAL_EVENT",
        event_type: str | None = None,
        duration_ms: float | None = None,
        error_code: str | None = None,
        exception: BaseException | None = None,
        stack_trace: str | None = None,
        technical_details: dict[str, Any] | None = None,
        metrics: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if not self.is_enabled_for(level):
            return

        # Blend thread/async context with explicit kwargs
        ctx = get_current_context()
        req_id = kwargs.pop("request_id", ctx.get("request_id"))
        corr_id = kwargs.pop("correlation_id", ctx.get("correlation_id"))
        job_id = kwargs.pop("job_id", ctx.get("job_id"))
        user_id = kwargs.pop("user_id", ctx.get("user_id"))

        comp = kwargs.pop("component", self.component)
        ev_type = event_type or kwargs.pop("event_type", f"{comp}.event")

        global _GLOBAL_FORMATTER
        if _GLOBAL_FORMATTER is None:
            _GLOBAL_FORMATTER = StructuredLogFormatter()

        event = _GLOBAL_FORMATTER.format_event(
            level=level,
            logger_name=self.name,
            component=comp,
            event_type=ev_type,
            event_code=event_code,
            message=message,
            request_id=req_id,
            correlation_id=corr_id,
            job_id=job_id,
            user_id=user_id,
            duration_ms=duration_ms,
            error_code=error_code,
            exception=exception,
            stack_trace=stack_trace,
            technical_details=technical_details,
            metrics=metrics,
            **kwargs,
        )

        handler = get_log_handler()
        handler.enqueue(event)

    def trace(self, message: str, event_code: str = "GENERAL_EVENT", **kwargs: Any) -> None:
        self._log("TRACE", message, event_code=event_code, **kwargs)

    def debug(self, message: str, event_code: str = "GENERAL_EVENT", **kwargs: Any) -> None:
        self._log("DEBUG", message, event_code=event_code, **kwargs)

    def info(self, message: str, event_code: str = "GENERAL_EVENT", **kwargs: Any) -> None:
        self._log("INFO", message, event_code=event_code, **kwargs)

    def warning(self, message: str, event_code: str = "GENERAL_EVENT", **kwargs: Any) -> None:
        self._log("WARNING", message, event_code=event_code, **kwargs)

    def error(self, message: str, event_code: str = "GENERAL_EVENT", **kwargs: Any) -> None:
        self._log("ERROR", message, event_code=event_code, **kwargs)

    def critical(self, message: str, event_code: str = "GENERAL_EVENT", **kwargs: Any) -> None:
        self._log("CRITICAL", message, event_code=event_code, **kwargs)

    def exception(
        self,
        message: str,
        exception: BaseException | None = None,
        event_code: str = "GENERAL_EVENT",
        error_code: str | None = None,
        operation: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Standardized error logging with full exception details and stack trace."""
        tech = kwargs.pop("technical_details", {}) or {}
        if operation:
            tech["operation"] = operation
        self._log(
            "ERROR",
            message,
            event_code=event_code,
            error_code=error_code,
            exception=exception,
            technical_details=tech,
            **kwargs,
        )

    def log_performance(
        self,
        operation: str,
        duration_ms: float,
        events_processed: int | None = None,
        event_code: str = "GENERAL_EVENT",
        **kwargs: Any,
    ) -> None:
        """Standardized performance logging."""
        metrics = kwargs.pop("metrics", {}) or {}
        metrics["operation"] = operation
        metrics["duration_ms"] = duration_ms
        if events_processed is not None:
            metrics["events_processed"] = events_processed
            if duration_ms > 0:
                metrics["events_per_second"] = round((events_processed / (duration_ms / 1000.0)), 2)
        self._log(
            "INFO",
            f"Operation {operation} completed in {duration_ms:.2f}ms",
            event_code=event_code,
            event_type=f"{self.component}.performance",
            duration_ms=duration_ms,
            metrics=metrics,
            **kwargs,
        )


def get_logger(component: str) -> PlatformLogger:
    """Return unified PlatformLogger instance for a given component."""
    with _REGISTRY_LOCK:
        if component not in _LOGGER_CACHE:
            _LOGGER_CACHE[component] = PlatformLogger(component=component)
        return _LOGGER_CACHE[component]
