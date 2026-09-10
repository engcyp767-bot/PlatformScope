"""Platform Scope — Event Bus & Hook System.

Central pub/sub event bus for plugin and platform-internal communication.
Supports:
- Typed hook points (pre/post processing)
- Priority ordering
- Synchronous and async dispatch
- Dead letter queue for failed handlers
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("platform.plugins.hooks")


class HookPoint(str, Enum):
    """Well-defined hook points in the platform lifecycle.

    Plugins register handlers on these hook points to extend behavior.
    """
    # Analysis lifecycle
    PRE_ANALYSIS = "pre_analysis"           # Before any analysis starts
    POST_ANALYSIS = "post_analysis"         # After analysis completes
    ON_DETECTION = "on_detection"           # When a detection rule matches
    ON_ENRICHMENT = "on_enrichment"         # When enrichment data arrives

    # Incident lifecycle
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_CLOSED = "incident_closed"
    INCIDENT_ESCALATED = "incident_escalated"

    # Threat Intelligence
    IOC_ADDED = "ioc_added"
    IOC_MATCHED = "ioc_matched"
    THREAT_INTEL_UPDATED = "threat_intel_updated"

    # Asset events
    ASSET_CREATED = "asset_created"
    ASSET_RISK_CHANGED = "asset_risk_changed"
    ASSET_ISOLATED = "asset_isolated"

    # Endpoint events (for EndpointScope)
    ENDPOINT_CONNECTED = "endpoint_connected"
    ENDPOINT_DISCONNECTED = "endpoint_disconnected"
    ENDPOINT_ALERT = "endpoint_alert"
    ENDPOINT_PROCESS_CREATED = "endpoint_process_created"
    ENDPOINT_FILE_MODIFIED = "endpoint_file_modified"
    ENDPOINT_NETWORK_CONNECTION = "endpoint_network_connection"

    # System events
    PLATFORM_STARTUP = "platform_startup"
    PLATFORM_SHUTDOWN = "platform_shutdown"
    LICENSE_CHANGED = "license_changed"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    BACKUP_COMPLETED = "backup_completed"

    # Correlation
    ATTACK_CHAIN_DETECTED = "attack_chain_detected"
    LATERAL_MOVEMENT_DETECTED = "lateral_movement_detected"


@dataclass
class HookRegistration:
    """A registered hook handler."""
    hook: HookPoint
    handler: Callable[..., Any]
    source: str        # plugin_id or "platform"
    priority: int      # lower = earlier execution (default 100)
    description: str
    registered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class HookEvent:
    """Event payload dispatched to hook handlers."""
    hook: HookPoint
    data: dict[str, Any]
    source: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_id: str = ""

    def __post_init__(self) -> None:
        if not self.event_id:
            import uuid
            self.event_id = str(uuid.uuid4())


class EventBus:
    """Central event bus for the platform.

    Thread-safe singleton that manages hook registrations and event dispatch.
    """

    _instance: EventBus | None = None
    _init_lock = threading.Lock()

    def __init__(self) -> None:
        self._handlers: dict[HookPoint, list[HookRegistration]] = defaultdict(list)
        self._lock = threading.RLock()
        self._dead_letters: list[dict[str, Any]] = []
        self._max_dead_letters = 100
        self._stats: dict[str, int] = defaultdict(int)

    @classmethod
    def get_instance(cls) -> EventBus:
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton — for testing only."""
        with cls._init_lock:
            cls._instance = None

    def register(
        self,
        hook: HookPoint,
        handler: Callable[..., Any],
        source: str = "platform",
        priority: int = 100,
        description: str = "",
    ) -> HookRegistration:
        """Register a handler for a hook point."""
        reg = HookRegistration(
            hook=hook,
            handler=handler,
            source=source,
            priority=priority,
            description=description or f"{source}:{hook.value}",
        )
        with self._lock:
            self._handlers[hook].append(reg)
            # Sort by priority (lower first)
            self._handlers[hook].sort(key=lambda r: r.priority)
        logger.debug("Registered hook handler: %s from %s (priority=%d)", hook.value, source, priority)
        return reg

    def unregister(self, hook: HookPoint, source: str) -> int:
        """Unregister all handlers for a hook from a specific source. Returns count removed."""
        with self._lock:
            before = len(self._handlers[hook])
            self._handlers[hook] = [r for r in self._handlers[hook] if r.source != source]
            removed = before - len(self._handlers[hook])
        if removed:
            logger.debug("Unregistered %d handler(s) for %s from %s", removed, hook.value, source)
        return removed

    def unregister_all(self, source: str) -> int:
        """Unregister all handlers from a specific source (e.g., when unloading a plugin)."""
        total = 0
        with self._lock:
            for hook in list(self._handlers.keys()):
                before = len(self._handlers[hook])
                self._handlers[hook] = [r for r in self._handlers[hook] if r.source != source]
                total += before - len(self._handlers[hook])
        if total:
            logger.info("Unregistered %d total handler(s) from source '%s'", total, source)
        return total

    def emit(self, hook: HookPoint, data: dict[str, Any], source: str = "platform") -> list[Any]:
        """Dispatch an event to all registered handlers for a hook point.

        Returns a list of results from handlers. Exceptions are caught and
        logged (sent to dead letter queue) to prevent one bad handler from
        blocking others.
        """
        event = HookEvent(hook=hook, data=data, source=source)
        results: list[Any] = []

        with self._lock:
            handlers = list(self._handlers.get(hook, []))

        self._stats[hook.value] += 1

        for reg in handlers:
            try:
                result = reg.handler(event)
                results.append(result)
            except Exception as exc:
                logger.error(
                    "Hook handler error: %s from %s on %s: %s",
                    reg.description, reg.source, hook.value, exc,
                )
                dead_letter = {
                    "event_id": event.event_id,
                    "hook": hook.value,
                    "handler_source": reg.source,
                    "handler_desc": reg.description,
                    "error": str(exc),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self._dead_letters.append(dead_letter)
                if len(self._dead_letters) > self._max_dead_letters:
                    self._dead_letters = self._dead_letters[-self._max_dead_letters:]

        return results

    def get_handlers(self, hook: HookPoint) -> list[dict[str, Any]]:
        """Get info about registered handlers for a hook (for introspection)."""
        with self._lock:
            return [
                {
                    "source": r.source,
                    "priority": r.priority,
                    "description": r.description,
                    "registered_at": r.registered_at,
                }
                for r in self._handlers.get(hook, [])
            ]

    def get_all_hooks(self) -> dict[str, int]:
        """Get all hook points and their handler counts."""
        with self._lock:
            return {hook.value: len(handlers) for hook, handlers in self._handlers.items() if handlers}

    def get_stats(self) -> dict[str, int]:
        """Get dispatch statistics."""
        return dict(self._stats)

    def get_dead_letters(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get recent dead letter entries (failed handler dispatches)."""
        return self._dead_letters[-limit:]


# Global event bus accessor
def event_bus() -> EventBus:
    """Get the global EventBus singleton."""
    return EventBus.get_instance()
