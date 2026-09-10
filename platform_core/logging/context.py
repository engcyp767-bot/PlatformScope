"""Context management for platform logging using contextvars for thread-safe and async-safe propagation."""

from __future__ import annotations

import contextlib
import contextvars
from typing import Any, Generator


_REQUEST_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)
_CORRELATION_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar("correlation_id", default=None)
_JOB_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar("job_id", default=None)
_USER_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar("user_id", default=None)
_CLIENT_IP: contextvars.ContextVar[str | None] = contextvars.ContextVar("client_ip", default=None)
_COMPONENT: contextvars.ContextVar[str | None] = contextvars.ContextVar("component", default=None)


def get_current_context() -> dict[str, Any]:
    """Return dictionary of all currently active context fields."""
    ctx: dict[str, Any] = {}
    req_id = _REQUEST_ID.get()
    if req_id:
        ctx["request_id"] = req_id
    corr_id = _CORRELATION_ID.get()
    if corr_id:
        ctx["correlation_id"] = corr_id
    job_id = _JOB_ID.get()
    if job_id:
        ctx["job_id"] = job_id
    user_id = _USER_ID.get()
    if user_id:
        ctx["user_id"] = user_id
    client_ip = _CLIENT_IP.get()
    if client_ip:
        ctx["client_ip"] = client_ip
    comp = _COMPONENT.get()
    if comp:
        ctx["component"] = comp
    return ctx


def set_context(
    *,
    request_id: str | None = None,
    correlation_id: str | None = None,
    job_id: str | None = None,
    user_id: str | None = None,
    client_ip: str | None = None,
    component: str | None = None,
) -> None:
    """Set context variables manually."""
    if request_id is not None:
        _REQUEST_ID.set(request_id)
    if correlation_id is not None:
        _CORRELATION_ID.set(correlation_id)
    if job_id is not None:
        _JOB_ID.set(job_id)
    if user_id is not None:
        _USER_ID.set(user_id)
    if client_ip is not None:
        _CLIENT_IP.set(client_ip)
    if component is not None:
        _COMPONENT.set(component)


def clear_context() -> None:
    """Reset all context variables to None."""
    _REQUEST_ID.set(None)
    _CORRELATION_ID.set(None)
    _JOB_ID.set(None)
    _USER_ID.set(None)
    _CLIENT_IP.set(None)
    _COMPONENT.set(None)


@contextlib.contextmanager
def log_context(
    *,
    request_id: str | None = None,
    correlation_id: str | None = None,
    job_id: str | None = None,
    user_id: str | None = None,
    client_ip: str | None = None,
    component: str | None = None,
) -> Generator[dict[str, Any], None, None]:
    """Context manager scoping log context for an operation or request."""
    tokens = []
    if request_id is not None:
        tokens.append((_REQUEST_ID, _REQUEST_ID.set(request_id)))
    if correlation_id is not None:
        tokens.append((_CORRELATION_ID, _CORRELATION_ID.set(correlation_id)))
    if job_id is not None:
        tokens.append((_JOB_ID, _JOB_ID.set(job_id)))
    if user_id is not None:
        tokens.append((_USER_ID, _USER_ID.set(user_id)))
    if client_ip is not None:
        tokens.append((_CLIENT_IP, _CLIENT_IP.set(client_ip)))
    if component is not None:
        tokens.append((_COMPONENT, _COMPONENT.set(component)))

    try:
        yield get_current_context()
    finally:
        for var, token in reversed(tokens):
            var.reset(token)

