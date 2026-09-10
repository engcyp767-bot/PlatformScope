"""EndpointScope — Data Models for Endpoint Detection & Response.

Defines the core data structures for endpoint agents, events, and response actions.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class AgentState(str, Enum):
    """State of an endpoint agent."""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    ISOLATED = "isolated"
    INSTALLING = "installing"
    UPDATING = "updating"
    ERROR = "error"


class EndpointEventType(str, Enum):
    """Types of events collected from endpoints."""
    # Process events
    PROCESS_CREATED = "process_created"
    PROCESS_TERMINATED = "process_terminated"
    PROCESS_INJECTED = "process_injected"

    # File events
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    FILE_RENAMED = "file_renamed"
    FILE_PERMISSION_CHANGED = "file_permission_changed"

    # Network events
    NETWORK_CONNECTION_ESTABLISHED = "network_connection_established"
    NETWORK_CONNECTION_CLOSED = "network_connection_closed"
    NETWORK_DNS_QUERY = "network_dns_query"
    NETWORK_LISTEN = "network_listen"

    # Registry events (Windows)
    REGISTRY_KEY_CREATED = "registry_key_created"
    REGISTRY_VALUE_SET = "registry_value_set"
    REGISTRY_KEY_DELETED = "registry_key_deleted"

    # Authentication events
    AUTH_LOGIN_SUCCESS = "auth_login_success"
    AUTH_LOGIN_FAILED = "auth_login_failed"
    AUTH_PRIVILEGE_ESCALATION = "auth_privilege_escalation"
    AUTH_USER_CREATED = "auth_user_created"

    # Service events
    SERVICE_INSTALLED = "service_installed"
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    SERVICE_MODIFIED = "service_modified"

    # Scheduled tasks
    SCHEDULED_TASK_CREATED = "scheduled_task_created"
    SCHEDULED_TASK_MODIFIED = "scheduled_task_modified"

    # Driver/Module events
    DRIVER_LOADED = "driver_loaded"
    MODULE_LOADED = "module_loaded"

    # System events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    SYSTEM_SLEEP = "system_sleep"
    SYSTEM_USB_DEVICE = "system_usb_device"

    # Agent heartbeat
    HEARTBEAT = "heartbeat"


class ResponseActionType(str, Enum):
    """Types of remote response actions."""
    ISOLATE_ENDPOINT = "isolate_endpoint"
    UNISOLATE_ENDPOINT = "unisolate_endpoint"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    COLLECT_ARTIFACT = "collect_artifact"
    RUN_SCAN = "run_scan"
    UPDATE_AGENT = "update_agent"
    RESTART_AGENT = "restart_agent"
    COLLECT_MEMORY_DUMP = "collect_memory_dump"
    EXECUTE_SCRIPT = "execute_script"


@dataclass
class AgentInfo:
    """Information about an endpoint agent."""
    agent_id: str
    hostname: str
    os_type: str                    # "windows", "linux", "macos"
    os_version: str
    agent_version: str
    ip_addresses: list[str] = field(default_factory=list)
    mac_addresses: list[str] = field(default_factory=list)
    state: AgentState = AgentState.ONLINE
    last_heartbeat: str = ""
    first_seen: str = ""
    tags: list[str] = field(default_factory=list)
    group: str = "default"
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    installed_software: list[str] = field(default_factory=list)
    running_services: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    # Security posture
    antivirus_enabled: bool = False
    firewall_enabled: bool = False
    encryption_enabled: bool = False
    auto_update_enabled: bool = False
    # Policy
    policy_id: str = "default"
    policy_version: str = ""
    # Risk
    risk_score: float = 0.0
    active_alerts: int = 0

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["state"] = self.state.value
        return result


@dataclass
class EndpointEvent:
    """A single event collected from an endpoint agent."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    hostname: str = ""
    event_type: EndpointEventType = EndpointEventType.HEARTBEAT
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    severity: str = "info"          # info, low, medium, high, critical
    # Process context
    process_name: str = ""
    process_id: int = 0
    parent_process_name: str = ""
    parent_process_id: int = 0
    command_line: str = ""
    user: str = ""
    # File context
    file_path: str = ""
    file_hash_sha256: str = ""
    file_size: int = 0
    # Network context
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    dns_query: str = ""
    # Registry context (Windows)
    registry_key: str = ""
    registry_value: str = ""
    # Raw data
    raw_data: dict[str, Any] = field(default_factory=dict)
    # Detection context
    matched_rules: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["event_type"] = self.event_type.value
        return result

    def to_canonical_log(self) -> dict[str, Any]:
        """Convert to a format compatible with LogScope's canonical event model."""
        return {
            "timestamp": self.timestamp,
            "source": f"endpointscope:{self.hostname}",
            "source_type": "endpoint",
            "event_id": str(self.event_type.value),
            "severity": self.severity,
            "hostname": self.hostname,
            "username": self.user,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "parent_process_name": self.parent_process_name,
            "command_line": self.command_line,
            "file_path": self.file_path,
            "file_hash": self.file_hash_sha256,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "dns_query": self.dns_query,
            "raw_message": str(self.raw_data) if self.raw_data else "",
            "raw_fields": self.raw_data,
        }


@dataclass
class ResponseAction:
    """A response action to execute on an endpoint."""
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    action_type: ResponseActionType = ResponseActionType.RUN_SCAN
    requested_by: str = ""
    requested_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "pending"        # pending, executing, completed, failed
    parameters: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    completed_at: str = ""
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["action_type"] = self.action_type.value
        return result


@dataclass
class EndpointPolicy:
    """Security policy applied to endpoint agents."""
    policy_id: str = "default"
    name: str = "Default Policy"
    name_ar: str = "السياسة الافتراضية"
    description: str = ""
    version: str = "1.0"
    # Collection settings
    collect_process_events: bool = True
    collect_file_events: bool = True
    collect_network_events: bool = True
    collect_registry_events: bool = True
    collect_auth_events: bool = True
    collect_service_events: bool = True
    # Filter settings
    exclude_processes: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    exclude_extensions: list[str] = field(default_factory=list)
    # Performance settings
    heartbeat_interval_seconds: int = 60
    batch_size: int = 100
    max_events_per_minute: int = 5000
    cpu_limit_percent: float = 5.0
    memory_limit_mb: int = 128
    # Response settings
    auto_isolate_on_critical: bool = False
    auto_quarantine_malware: bool = True
    # Retention
    local_log_retention_hours: int = 24

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
