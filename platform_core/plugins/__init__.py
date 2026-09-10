"""Platform Scope — Plugin System.

Provides extensibility through a plugin architecture that allows:
1. Community plugins (loaded from plugins/ directory)
2. Custom integrations (user-developed)
3. Marketplace plugins (downloaded from PlatformScope Marketplace)

Plugin Lifecycle:
    Discover → Validate → Load → Initialize → Run → Unload

Security:
    - Plugins run in restricted scope (no direct DB access)
    - Manifest validation with SHA-256 integrity
    - Permission model: plugins declare required capabilities
"""

from .base import (
    PluginBase,
    PluginCapability,
    PluginInfo,
    PluginState,
    PluginType,
)
from .hooks import EventBus, HookPoint, event_bus
from .loader import PluginLoader, PluginManager, get_plugin_manager

__all__ = [
    "PluginBase",
    "PluginCapability",
    "PluginInfo",
    "PluginState",
    "PluginType",
    "PluginLoader",
    "PluginManager",
    "get_plugin_manager",
    "EventBus",
    "HookPoint",
    "event_bus",
]
