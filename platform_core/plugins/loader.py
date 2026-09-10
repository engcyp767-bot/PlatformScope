"""Platform Scope — Plugin Loader & Manager.

Handles plugin discovery, validation, loading, and lifecycle management.
Plugins are discovered from:
1. {PLATFORM_ROOT}/plugins/ — user-installed plugins
2. Plugin storage directory (for marketplace downloads)
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from platform_core.plugins.base import (
    PluginBase,
    PluginCapability,
    PluginContext,
    PluginInfo,
    PluginState,
    PluginType,
)
from platform_core.plugins.hooks import EventBus, HookPoint, event_bus

logger = logging.getLogger("platform.plugins.loader")

PLATFORM_ROOT = Path(__file__).resolve().parent.parent.parent
PLUGINS_DIR = PLATFORM_ROOT / "plugins"
PLATFORM_VERSION = "1.0.0"


class PluginLoader:
    """Discovers and validates plugins from the filesystem."""

    def __init__(self, plugins_dir: Path | None = None):
        self._plugins_dir = plugins_dir or PLUGINS_DIR

    def discover(self) -> list[PluginInfo]:
        """Scan the plugins directory for valid plugin packages."""
        plugins: list[PluginInfo] = []
        if not self._plugins_dir.is_dir():
            logger.info("Plugins directory does not exist: %s", self._plugins_dir)
            return plugins

        for entry in sorted(self._plugins_dir.iterdir()):
            if not entry.is_dir():
                continue
            if entry.name.startswith((".", "_")):
                continue

            manifest_path = entry / "plugin.json"
            if not manifest_path.is_file():
                logger.warning("Plugin directory '%s' missing plugin.json, skipping.", entry.name)
                continue

            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest = json.load(f)

                info = PluginInfo.from_manifest(manifest, entry)
                info.state = PluginState.DISCOVERED
                plugins.append(info)
                logger.info("Discovered plugin: %s v%s (%s)", info.name, info.version, info.id)
            except Exception as exc:
                logger.error("Failed to parse plugin manifest '%s': %s", manifest_path, exc)

        return plugins

    def validate(self, info: PluginInfo) -> tuple[bool, str]:
        """Validate a discovered plugin before loading."""
        # Check entry point exists
        entry_path = info.path / info.entry_point
        if not entry_path.is_file():
            return False, f"Entry point '{info.entry_point}' not found at {entry_path}"

        # Check platform version compatibility
        # Simple major version check
        try:
            required_parts = [int(x) for x in info.min_platform_version.split(".")]
            current_parts = [int(x) for x in PLATFORM_VERSION.split(".")]
            if required_parts[0] > current_parts[0]:
                return False, (
                    f"Plugin requires platform v{info.min_platform_version} "
                    f"but current is v{PLATFORM_VERSION}"
                )
        except (ValueError, IndexError):
            pass

        # Validate manifest integrity
        manifest_path = info.path / "plugin.json"
        if manifest_path.is_file():
            with open(manifest_path, "r", encoding="utf-8") as f:
                content = f.read()
            computed_hash = hashlib.sha256(
                json.dumps(json.loads(content), sort_keys=True, ensure_ascii=False).encode()
            ).hexdigest()
            if info.integrity_hash and computed_hash != info.integrity_hash:
                return False, "Manifest integrity check failed (SHA-256 mismatch)"

        # Check for dangerous capabilities
        dangerous_caps = {PluginCapability.EXECUTE_COMMAND, PluginCapability.FILE_WRITE}
        declared_dangerous = set(info.capabilities) & dangerous_caps
        if declared_dangerous:
            logger.warning(
                "Plugin '%s' requests dangerous capabilities: %s",
                info.id,
                [c.value for c in declared_dangerous],
            )

        return True, "OK"


class PluginManager:
    """Manages the complete plugin lifecycle.

    Thread-safe singleton that handles loading, activation, deactivation,
    and unloading of plugins.
    """

    _instance: PluginManager | None = None
    _init_lock = threading.Lock()

    def __init__(self, plugins_dir: Path | None = None, storage_dir: Path | None = None):
        self._plugins_dir = plugins_dir or PLUGINS_DIR
        self._storage_dir = storage_dir or (PLATFORM_ROOT / "storage")
        self._loader = PluginLoader(self._plugins_dir)
        self._plugins: dict[str, PluginInfo] = {}
        self._instances: dict[str, PluginBase] = {}
        self._contexts: dict[str, PluginContext] = {}
        self._lock = threading.RLock()

    @classmethod
    def get_instance(cls, plugins_dir: Path | None = None, storage_dir: Path | None = None) -> PluginManager:
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls(plugins_dir, storage_dir)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton — for testing only."""
        with cls._init_lock:
            cls._instance = None

    def discover_plugins(self) -> list[PluginInfo]:
        """Discover all available plugins."""
        discovered = self._loader.discover()
        with self._lock:
            for info in discovered:
                if info.id not in self._plugins:
                    self._plugins[info.id] = info
        return discovered

    def load_plugin(self, plugin_id: str) -> tuple[bool, str]:
        """Load and activate a specific plugin."""
        with self._lock:
            info = self._plugins.get(plugin_id)
            if info is None:
                return False, f"Plugin '{plugin_id}' not found"

            if plugin_id in self._instances:
                return True, "Plugin already loaded"

            # Validate
            valid, message = self._loader.validate(info)
            if not valid:
                info.state = PluginState.ERROR
                info.error_message = message
                return False, message

            info.state = PluginState.VALIDATED

            # Load module
            try:
                entry_path = info.path / info.entry_point
                spec = importlib.util.spec_from_file_location(
                    f"plugins.{plugin_id}",
                    str(entry_path),
                )
                if spec is None or spec.loader is None:
                    info.state = PluginState.ERROR
                    info.error_message = "Failed to create module spec"
                    return False, "Failed to create module spec"

                module = importlib.util.module_from_spec(spec)
                sys.modules[f"plugins.{plugin_id}"] = module
                spec.loader.exec_module(module)  # type: ignore[union-attr]

                # Find PluginBase subclass
                plugin_class: Type[PluginBase] | None = None
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, PluginBase)
                        and attr is not PluginBase
                    ):
                        plugin_class = attr
                        break

                if plugin_class is None:
                    info.state = PluginState.ERROR
                    info.error_message = "No PluginBase subclass found"
                    return False, "No PluginBase subclass found in plugin entry point"

                info.state = PluginState.LOADED

                # Create instance and context
                instance = plugin_class()
                context = PluginContext(info, self._storage_dir)
                instance.activate(context)

                self._instances[plugin_id] = instance
                self._contexts[plugin_id] = context
                info.state = PluginState.ACTIVE
                info.loaded_at = __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ).isoformat()

                logger.info("Plugin '%s' v%s loaded and activated.", info.name, info.version)
                event_bus().emit(HookPoint.PLATFORM_STARTUP, {
                    "event": "plugin_loaded",
                    "plugin_id": plugin_id,
                    "plugin_name": info.name,
                    "version": info.version,
                })
                return True, "OK"

            except Exception as exc:
                info.state = PluginState.ERROR
                info.error_message = str(exc)
                logger.error("Failed to load plugin '%s': %s", plugin_id, exc)
                return False, str(exc)

    def unload_plugin(self, plugin_id: str) -> tuple[bool, str]:
        """Deactivate and unload a plugin."""
        with self._lock:
            instance = self._instances.get(plugin_id)
            info = self._plugins.get(plugin_id)

            if instance is None:
                return False, f"Plugin '{plugin_id}' is not loaded"

            try:
                instance.deactivate()
            except Exception as exc:
                logger.warning("Error during plugin '%s' deactivation: %s", plugin_id, exc)

            # Unregister all hooks
            event_bus().unregister_all(plugin_id)

            # Cleanup
            del self._instances[plugin_id]
            self._contexts.pop(plugin_id, None)
            sys.modules.pop(f"plugins.{plugin_id}", None)

            if info:
                info.state = PluginState.UNLOADED

            logger.info("Plugin '%s' unloaded.", plugin_id)
            return True, "OK"

    def load_all(self) -> dict[str, tuple[bool, str]]:
        """Discover and load all available plugins."""
        self.discover_plugins()
        results: dict[str, tuple[bool, str]] = {}
        with self._lock:
            for plugin_id in list(self._plugins.keys()):
                if plugin_id not in self._instances:
                    results[plugin_id] = self.load_plugin(plugin_id)
        return results

    def unload_all(self) -> None:
        """Unload all loaded plugins."""
        with self._lock:
            for plugin_id in list(self._instances.keys()):
                self.unload_plugin(plugin_id)

    def get_plugin_info(self, plugin_id: str) -> Optional[PluginInfo]:
        """Get info about a specific plugin."""
        return self._plugins.get(plugin_id)

    def list_plugins(self) -> list[dict[str, Any]]:
        """List all known plugins with their status."""
        with self._lock:
            return [info.to_dict() for info in self._plugins.values()]

    def get_loaded_plugins(self) -> list[str]:
        """Get IDs of all currently loaded plugins."""
        with self._lock:
            return list(self._instances.keys())

    def dispatch_event(self, event_data: dict[str, Any]) -> None:
        """Dispatch an analysis event to all loaded plugins."""
        with self._lock:
            instances = list(self._instances.items())

        for plugin_id, instance in instances:
            try:
                instance.on_event(event_data)
            except Exception as exc:
                logger.error("Plugin '%s' error handling event: %s", plugin_id, exc)

    def dispatch_incident(self, incident_data: dict[str, Any]) -> None:
        """Dispatch incident updates to all loaded plugins."""
        with self._lock:
            instances = list(self._instances.items())

        for plugin_id, instance in instances:
            try:
                instance.on_incident(incident_data)
            except Exception as exc:
                logger.error("Plugin '%s' error handling incident: %s", plugin_id, exc)

    def dispatch_detection(self, detection_data: dict[str, Any]) -> None:
        """Dispatch detection events to all loaded plugins."""
        with self._lock:
            instances = list(self._instances.items())

        for plugin_id, instance in instances:
            try:
                instance.on_detection(detection_data)
            except Exception as exc:
                logger.error("Plugin '%s' error handling detection: %s", plugin_id, exc)

    def run_schedules(self) -> None:
        """Run scheduled callbacks for all loaded plugins."""
        with self._lock:
            instances = list(self._instances.items())

        for plugin_id, instance in instances:
            try:
                instance.on_schedule()
            except Exception as exc:
                logger.error("Plugin '%s' schedule error: %s", plugin_id, exc)


_plugin_manager_instance: Optional[PluginManager] = None
_plugin_manager_lock = threading.Lock()


def get_plugin_manager(plugins_dir: Optional[Path] = None) -> PluginManager:
    """Get or create singleton PluginManager."""
    global _plugin_manager_instance
    if _plugin_manager_instance is None:
        with _plugin_manager_lock:
            if _plugin_manager_instance is None:
                _plugin_manager_instance = PluginManager(plugins_dir=plugins_dir)
    return _plugin_manager_instance

