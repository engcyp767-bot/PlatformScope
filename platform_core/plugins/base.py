"""Platform Scope — Plugin Base Classes & Models.

Defines the abstract base class for all plugins and the data models
for plugin metadata, capabilities, and lifecycle state.
"""

from __future__ import annotations

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("platform.plugins")


class PluginType(str, Enum):
    """Classification of plugin types."""
    CONNECTOR = "connector"        # Data source connector (Splunk, ELK, etc.)
    DETECTOR = "detector"          # Custom detection logic
    ENRICHMENT = "enrichment"      # IOC/event enrichment provider
    REPORT = "report"              # Report template/generator
    RESPONSE = "response"          # Automated response action
    DASHBOARD = "dashboard"        # Custom dashboard widget
    INTEGRATION = "integration"    # External system integration
    ANALYSIS = "analysis"          # Custom analysis module


class PluginState(str, Enum):
    """Plugin lifecycle state."""
    DISCOVERED = "discovered"
    VALIDATED = "validated"
    LOADED = "loaded"
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"
    UNLOADED = "unloaded"


class PluginCapability(str, Enum):
    """Capabilities a plugin can request (security permission model)."""
    READ_EVENTS = "read_events"          # Read analysis events/results
    WRITE_EVENTS = "write_events"        # Create/modify events
    READ_INCIDENTS = "read_incidents"    # Read incident data
    WRITE_INCIDENTS = "write_incidents"  # Create/modify incidents
    READ_ASSETS = "read_assets"          # Read asset inventory
    WRITE_ASSETS = "write_assets"        # Modify assets
    READ_IOCS = "read_iocs"             # Read threat intelligence
    WRITE_IOCS = "write_iocs"           # Add/modify IOCs
    NETWORK_ACCESS = "network_access"    # Make outbound network calls
    FILE_READ = "file_read"              # Read files from filesystem
    FILE_WRITE = "file_write"            # Write files to plugin storage
    EXECUTE_COMMAND = "execute_command"   # Run system commands (restricted)
    SEND_NOTIFICATION = "send_notification"  # Send user notifications


@dataclass
class PluginInfo:
    """Plugin metadata loaded from plugin.json manifest."""
    id: str
    name: str
    name_ar: str
    version: str
    description: str
    description_ar: str
    author: str
    author_url: str = ""
    license: str = "MIT"
    plugin_type: PluginType = PluginType.INTEGRATION
    capabilities: list[PluginCapability] = field(default_factory=list)
    min_platform_version: str = "1.0.0"
    entry_point: str = "plugin.py"
    config_schema: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    icon: str = ""
    # Computed fields
    path: Path = field(default_factory=lambda: Path("."))
    state: PluginState = PluginState.DISCOVERED
    error_message: str = ""
    loaded_at: str = ""
    integrity_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["plugin_type"] = self.plugin_type.value
        result["capabilities"] = [c.value for c in self.capabilities]
        result["state"] = self.state.value
        result["path"] = str(self.path)
        return result

    @classmethod
    def from_manifest(cls, manifest: dict[str, Any], plugin_path: Path) -> PluginInfo:
        """Parse plugin.json manifest into PluginInfo."""
        caps = []
        for c in manifest.get("capabilities", []):
            try:
                caps.append(PluginCapability(c))
            except ValueError:
                logger.warning("Unknown capability '%s' in plugin '%s'", c, manifest.get("id"))

        try:
            ptype = PluginType(manifest.get("type", "integration"))
        except ValueError:
            ptype = PluginType.INTEGRATION

        # Calculate integrity hash of the manifest
        manifest_str = json.dumps(manifest, sort_keys=True, ensure_ascii=False)
        integrity = hashlib.sha256(manifest_str.encode("utf-8")).hexdigest()

        return cls(
            id=manifest.get("id", plugin_path.name),
            name=manifest.get("name", plugin_path.name),
            name_ar=manifest.get("name_ar", manifest.get("name", plugin_path.name)),
            version=manifest.get("version", "0.0.0"),
            description=manifest.get("description", ""),
            description_ar=manifest.get("description_ar", ""),
            author=manifest.get("author", "Unknown"),
            author_url=manifest.get("author_url", ""),
            license=manifest.get("license", "MIT"),
            plugin_type=ptype,
            capabilities=caps,
            min_platform_version=manifest.get("min_platform_version", "1.0.0"),
            entry_point=manifest.get("entry_point", "plugin.py"),
            config_schema=manifest.get("config_schema", {}),
            tags=manifest.get("tags", []),
            icon=manifest.get("icon", ""),
            path=plugin_path,
            integrity_hash=integrity,
        )


class PluginContext:
    """Sandboxed context passed to plugins for controlled platform access.

    Plugins interact with the platform exclusively through this context,
    which enforces capability-based access control.
    """

    def __init__(self, plugin_info: PluginInfo, storage_dir: Path):
        self._info = plugin_info
        self._storage_dir = storage_dir / "plugin_data" / plugin_info.id
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._config: dict[str, Any] = {}

    @property
    def plugin_id(self) -> str:
        return self._info.id

    @property
    def plugin_version(self) -> str:
        return self._info.version

    @property
    def storage_path(self) -> Path:
        """Plugin-specific storage directory (sandboxed)."""
        return self._storage_dir

    @property
    def config(self) -> dict[str, Any]:
        return self._config

    def set_config(self, config: dict[str, Any]) -> None:
        self._config = config

    def has_capability(self, cap: PluginCapability) -> bool:
        return cap in self._info.capabilities

    def _require_capability(self, cap: PluginCapability) -> None:
        if not self.has_capability(cap):
            raise PermissionError(
                f"Plugin '{self._info.id}' does not have capability '{cap.value}'. "
                f"Declared capabilities: {[c.value for c in self._info.capabilities]}"
            )

    def read_events(self, source: str, limit: int = 100, **filters: Any) -> list[dict[str, Any]]:
        """Read analysis events (requires READ_EVENTS capability)."""
        self._require_capability(PluginCapability.READ_EVENTS)
        # Delegate to platform internals (deferred import to avoid circular deps)
        return []  # Placeholder — wired in PluginManager

    def create_incident(self, title: str, severity: str, **kwargs: Any) -> dict[str, Any]:
        """Create a security incident (requires WRITE_INCIDENTS capability)."""
        self._require_capability(PluginCapability.WRITE_INCIDENTS)
        return {}  # Placeholder

    def add_ioc(self, ioc_type: str, value: str, **kwargs: Any) -> dict[str, Any]:
        """Add an IOC to threat intelligence (requires WRITE_IOCS capability)."""
        self._require_capability(PluginCapability.WRITE_IOCS)
        return {}  # Placeholder

    def send_notification(self, title: str, message: str, severity: str = "info") -> None:
        """Send a notification to the user (requires SEND_NOTIFICATION capability)."""
        self._require_capability(PluginCapability.SEND_NOTIFICATION)
        # Placeholder

    def log(self, message: str, level: str = "info") -> None:
        """Log a message from the plugin."""
        getattr(logger, level, logger.info)(f"[Plugin:{self._info.id}] {message}")


class PluginBase(ABC):
    """Abstract base class for all PlatformScope plugins.

    Every plugin must subclass this and implement at minimum:
    - activate(context): Called when the plugin is loaded
    - deactivate(): Called when the plugin is unloaded

    Example:
        class MyPlugin(PluginBase):
            def activate(self, context: PluginContext) -> None:
                self.ctx = context
                context.log("MyPlugin activated!")

            def deactivate(self) -> None:
                self.ctx.log("MyPlugin deactivated.")

            def on_event(self, event: dict) -> dict | None:
                # Optional: process events
                return None
    """

    @abstractmethod
    def activate(self, context: PluginContext) -> None:
        """Called when the plugin is loaded and ready to operate."""
        ...

    @abstractmethod
    def deactivate(self) -> None:
        """Called when the plugin is being unloaded."""
        ...

    def on_event(self, event: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Optional: Handle incoming analysis events. Return enriched event or None."""
        return None

    def on_incident(self, incident: dict[str, Any]) -> None:
        """Optional: React to incident state changes."""
        pass

    def on_detection(self, detection: dict[str, Any]) -> None:
        """Optional: React to new detections."""
        pass

    def on_schedule(self) -> None:
        """Optional: Periodic callback (called every N minutes by scheduler)."""
        pass

    def get_status(self) -> dict[str, Any]:
        """Optional: Return plugin health/status for the dashboard."""
        return {"status": "ok"}
