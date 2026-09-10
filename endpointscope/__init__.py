"""EndpointScope — Endpoint Detection & Response Module.

Lightweight agent-based endpoint monitoring and real-time threat detection.
Collects system events from Windows/Linux endpoints and streams them to
LogScope and FlowScope for unified correlation and analysis.

Architecture:
    EndpointScope Agent (on each endpoint)
        ↓ (REST API / WebSocket)
    EndpointScope Server (central collector)
        ↓ (event pipeline)
    LogScope / FlowScope / Detection Engine

Components:
    - Agent: Lightweight data collector for endpoints
    - Collector: Central event receiver and processor
    - Monitor: Real-time process/file/network monitoring
    - Responder: Remote response actions (isolate, kill, quarantine)
"""

from .collector import EndpointCollector
from .monitor import EndpointMonitor, MonitorConfig
from .models import (
    AgentInfo,
    AgentState,
    EndpointEvent,
    EndpointEventType,
    ResponseAction,
    ResponseActionType,
)

__all__ = [
    "EndpointCollector",
    "EndpointMonitor",
    "MonitorConfig",
    "AgentInfo",
    "AgentState",
    "EndpointEvent",
    "EndpointEventType",
    "ResponseAction",
    "ResponseActionType",
]
