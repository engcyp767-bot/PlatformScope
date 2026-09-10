"""Structured JSON formatter for platform observability events."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import traceback
from typing import Any

from .messages import get_message
from .redaction import redact_data


class StructuredLogFormatter:
    """Formats platform log records into schema-compliant, sanitized JSON strings."""

    def __init__(self, *, redact: bool = True) -> None:
        self.redact = redact

    def format_event(
        self,
        *,
        level: str,
        logger_name: str,
        component: str,
        event_type: str,
        event_code: str = "GENERAL_EVENT",
        message: str | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
        job_id: str | None = None,
        user_id: str | None = None,
        duration_ms: float | None = None,
        error_code: str | None = None,
        exception: BaseException | None = None,
        stack_trace: str | None = None,
        technical_details: dict[str, Any] | None = None,
        metrics: dict[str, Any] | None = None,
        timestamp: str | None = None,
        **message_params: Any,
    ) -> dict[str, Any]:
        """Produce structured event dictionary adhering to platform schema."""
        now_ts = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # Resolve bilingual messages
        params = dict(message_params)
        if message:
            params.setdefault("message", message)
        if component:
            params.setdefault("component", component)
        if job_id:
            params.setdefault("job_id", job_id)
        if duration_ms is not None:
            params.setdefault("duration_ms", f"{duration_ms:.2f}")

        msg_ar = get_message(event_code, lang="ar", **params)
        msg_en = get_message(event_code, lang="en", **params)
        canonical_msg = msg_ar or message or event_code

        # Exception & Stack trace resolution
        exc_type: str | None = None
        if exception is not None:
            exc_type = type(exception).__name__
            if not stack_trace:
                stack_trace = "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
            if not error_code:
                error_code = getattr(exception, "code", exc_type)

        details = dict(technical_details or {})
        if exc_type and "exception_type" not in details:
            details["exception_type"] = exc_type

        event: dict[str, Any] = {
            "timestamp": now_ts,
            "level": level.upper(),
            "logger": logger_name,
            "component": component,
            "event_type": event_type,
            "event_code": event_code,
            "message_ar": msg_ar,
            "message_en": msg_en,
            "message": canonical_msg,
            "request_id": request_id,
            "correlation_id": correlation_id,
            "job_id": job_id,
            "user_id": user_id,
            "duration_ms": round(duration_ms, 2) if duration_ms is not None else None,
            "error_code": error_code,
            "exception_type": exc_type,
            "technical_details": details if details else None,
            "stack_trace": stack_trace,
            "metrics": metrics if metrics else None,
        }

        if self.redact:
            return redact_data(event)
        return event

    def to_json(self, event: dict[str, Any]) -> str:
        """Serialize structured event to single-line JSON."""
        return json.dumps(event, ensure_ascii=False, default=str)

