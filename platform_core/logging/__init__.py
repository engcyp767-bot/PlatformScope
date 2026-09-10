"""Platform Logging & Observability Subsystem."""

from .context import clear_context, get_current_context, log_context, set_context
from .logger import (
    PlatformLogger,
    get_log_handler,
    get_log_storage,
    get_logger,
    get_platform_log_level,
    init_platform_logging,
    set_platform_log_level,
)
from .metrics import get_metrics
from .redaction import redact_data, redact_string
from .storage import PlatformLogStorage

__all__ = [
    "PlatformLogger",
    "get_logger",
    "init_platform_logging",
    "get_log_storage",
    "get_log_handler",
    "set_platform_log_level",
    "get_platform_log_level",
    "log_context",
    "set_context",
    "clear_context",
    "get_current_context",
    "redact_data",
    "redact_string",
    "get_metrics",
    "PlatformLogStorage",
]

