"""Tests for Plugin System (base, hooks, loader)."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from platform_core.plugins.base import (
    PluginBase,
    PluginCapability,
    PluginContext,
    PluginInfo,
    PluginState,
    PluginType,
)
from platform_core.plugins.hooks import EventBus, HookEvent, HookPoint
from platform_core.plugins.loader import PluginLoader, PluginManager


class TestPluginInfo(unittest.TestCase):
    def test_from_manifest(self):
        manifest = {
            "id": "test-plugin",
            "name": "Test Plugin",
            "name_ar": "إضافة تجريبية",
            "version": "1.0.0",
            "description": "A test plugin",
            "description_ar": "إضافة للاختبار",
            "author": "TestAuthor",
            "type": "detector",
            "capabilities": ["read_events", "write_incidents"],
            "entry_point": "plugin.py",
        }
        info = PluginInfo.from_manifest(manifest, Path("/tmp/test-plugin"))
        self.assertEqual(info.id, "test-plugin")
        self.assertEqual(info.name, "Test Plugin")
        self.assertEqual(info.name_ar, "إضافة تجريبية")
        self.assertEqual(info.plugin_type, PluginType.DETECTOR)
        self.assertIn(PluginCapability.READ_EVENTS, info.capabilities)
        self.assertIn(PluginCapability.WRITE_INCIDENTS, info.capabilities)
        self.assertTrue(info.integrity_hash)

    def test_to_dict(self):
        info = PluginInfo(
            id="my-plugin", name="My Plugin", name_ar="إضافتي",
            version="2.0.0", description="desc", description_ar="وصف",
            author="me", plugin_type=PluginType.CONNECTOR,
            capabilities=[PluginCapability.NETWORK_ACCESS],
        )
        d = info.to_dict()
        self.assertEqual(d["id"], "my-plugin")
        self.assertEqual(d["plugin_type"], "connector")
        self.assertEqual(d["capabilities"], ["network_access"])
        self.assertEqual(d["state"], "discovered")

    def test_unknown_capability_skipped(self):
        manifest = {
            "id": "x", "name": "X", "version": "1.0",
            "description": "", "author": "a",
            "capabilities": ["read_events", "nonexistent_cap"],
        }
        info = PluginInfo.from_manifest(manifest, Path("."))
        self.assertEqual(len(info.capabilities), 1)


class TestPluginContext(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.info = PluginInfo(
            id="ctx-test", name="Context Test", name_ar="اختبار",
            version="1.0", description="", description_ar="",
            author="test",
            capabilities=[PluginCapability.READ_EVENTS, PluginCapability.SEND_NOTIFICATION],
        )
        self.ctx = PluginContext(self.info, Path(self.tmpdir))

    def test_plugin_id(self):
        self.assertEqual(self.ctx.plugin_id, "ctx-test")

    def test_storage_path_created(self):
        self.assertTrue(self.ctx.storage_path.is_dir())
        self.assertIn("ctx-test", str(self.ctx.storage_path))

    def test_has_capability(self):
        self.assertTrue(self.ctx.has_capability(PluginCapability.READ_EVENTS))
        self.assertFalse(self.ctx.has_capability(PluginCapability.EXECUTE_COMMAND))

    def test_require_capability_raises(self):
        with self.assertRaises(PermissionError):
            self.ctx._require_capability(PluginCapability.EXECUTE_COMMAND)

    def test_config(self):
        self.ctx.set_config({"key": "value"})
        self.assertEqual(self.ctx.config["key"], "value")


class TestEventBus(unittest.TestCase):
    def setUp(self):
        EventBus.reset_instance()
        self.bus = EventBus()

    def test_register_and_emit(self):
        results = []
        def handler(event: HookEvent):
            results.append(event.data)
            return "handled"

        self.bus.register(HookPoint.INCIDENT_CREATED, handler, "test")
        returns = self.bus.emit(HookPoint.INCIDENT_CREATED, {"id": "INC-001"})

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "INC-001")
        self.assertEqual(returns, ["handled"])

    def test_priority_ordering(self):
        order = []
        self.bus.register(HookPoint.IOC_ADDED, lambda e: order.append("third"), "c", priority=300)
        self.bus.register(HookPoint.IOC_ADDED, lambda e: order.append("first"), "a", priority=10)
        self.bus.register(HookPoint.IOC_ADDED, lambda e: order.append("second"), "b", priority=100)

        self.bus.emit(HookPoint.IOC_ADDED, {})
        self.assertEqual(order, ["first", "second", "third"])

    def test_handler_error_does_not_block_others(self):
        results = []
        def bad_handler(event: HookEvent):
            raise RuntimeError("boom")

        def good_handler(event: HookEvent):
            results.append("ok")

        self.bus.register(HookPoint.ON_DETECTION, bad_handler, "bad", priority=1)
        self.bus.register(HookPoint.ON_DETECTION, good_handler, "good", priority=2)

        self.bus.emit(HookPoint.ON_DETECTION, {})
        self.assertEqual(results, ["ok"])

    def test_dead_letter_on_error(self):
        def bad_handler(event: HookEvent):
            raise ValueError("test error")

        self.bus.register(HookPoint.ON_DETECTION, bad_handler, "bad")
        self.bus.emit(HookPoint.ON_DETECTION, {})

        dead_letters = self.bus.get_dead_letters()
        self.assertEqual(len(dead_letters), 1)
        self.assertIn("test error", dead_letters[0]["error"])

    def test_unregister_by_source(self):
        self.bus.register(HookPoint.IOC_ADDED, lambda e: None, "plugin-a")
        self.bus.register(HookPoint.IOC_ADDED, lambda e: None, "plugin-b")

        removed = self.bus.unregister(HookPoint.IOC_ADDED, "plugin-a")
        self.assertEqual(removed, 1)

        handlers = self.bus.get_handlers(HookPoint.IOC_ADDED)
        self.assertEqual(len(handlers), 1)
        self.assertEqual(handlers[0]["source"], "plugin-b")

    def test_unregister_all(self):
        self.bus.register(HookPoint.IOC_ADDED, lambda e: None, "plugin-x")
        self.bus.register(HookPoint.ON_DETECTION, lambda e: None, "plugin-x")
        self.bus.register(HookPoint.ON_DETECTION, lambda e: None, "platform")

        removed = self.bus.unregister_all("plugin-x")
        self.assertEqual(removed, 2)

    def test_get_all_hooks(self):
        self.bus.register(HookPoint.IOC_ADDED, lambda e: None, "test")
        self.bus.register(HookPoint.ON_DETECTION, lambda e: None, "test")
        hooks = self.bus.get_all_hooks()
        self.assertIn("ioc_added", hooks)
        self.assertIn("on_detection", hooks)

    def test_stats(self):
        self.bus.register(HookPoint.PLATFORM_STARTUP, lambda e: None, "test")
        self.bus.emit(HookPoint.PLATFORM_STARTUP, {})
        self.bus.emit(HookPoint.PLATFORM_STARTUP, {})
        stats = self.bus.get_stats()
        self.assertEqual(stats.get("platform_startup"), 2)

    def test_endpoint_hooks_registered(self):
        """Verify EndpointScope hook points are defined."""
        endpoint_hooks = [
            HookPoint.ENDPOINT_CONNECTED,
            HookPoint.ENDPOINT_DISCONNECTED,
            HookPoint.ENDPOINT_ALERT,
            HookPoint.ENDPOINT_PROCESS_CREATED,
            HookPoint.ENDPOINT_FILE_MODIFIED,
            HookPoint.ENDPOINT_NETWORK_CONNECTION,
        ]
        for hook in endpoint_hooks:
            self.assertIsInstance(hook, HookPoint)

    def test_thread_safety(self):
        counter = {"count": 0}
        lock = threading.Lock()

        def handler(event: HookEvent):
            with lock:
                counter["count"] += 1

        self.bus.register(HookPoint.ON_DETECTION, handler, "test")

        threads = [
            threading.Thread(target=lambda: self.bus.emit(HookPoint.ON_DETECTION, {}))
            for _ in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(counter["count"], 20)


class TestPluginLoader(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.plugins_dir = Path(self.tmpdir) / "plugins"
        self.plugins_dir.mkdir()

    def test_discover_empty(self):
        loader = PluginLoader(self.plugins_dir)
        plugins = loader.discover()
        self.assertEqual(len(plugins), 0)

    def test_discover_valid_plugin(self):
        # Create a valid plugin directory
        plugin_dir = self.plugins_dir / "my-plugin"
        plugin_dir.mkdir()
        manifest = {
            "id": "my-plugin",
            "name": "My Plugin",
            "version": "1.0.0",
            "description": "Test plugin",
            "author": "Test",
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
        (plugin_dir / "plugin.py").write_text("pass", encoding="utf-8")

        loader = PluginLoader(self.plugins_dir)
        plugins = loader.discover()
        self.assertEqual(len(plugins), 1)
        self.assertEqual(plugins[0].id, "my-plugin")

    def test_skip_hidden_dirs(self):
        (self.plugins_dir / ".hidden").mkdir()
        (self.plugins_dir / "_private").mkdir()
        loader = PluginLoader(self.plugins_dir)
        plugins = loader.discover()
        self.assertEqual(len(plugins), 0)

    def test_skip_without_manifest(self):
        (self.plugins_dir / "no-manifest").mkdir()
        loader = PluginLoader(self.plugins_dir)
        plugins = loader.discover()
        self.assertEqual(len(plugins), 0)

    def test_validate_missing_entry_point(self):
        info = PluginInfo(
            id="bad", name="Bad", name_ar="", version="1.0",
            description="", description_ar="", author="test",
            entry_point="missing.py",
            path=self.plugins_dir / "bad",
        )
        (self.plugins_dir / "bad").mkdir()
        loader = PluginLoader(self.plugins_dir)
        valid, msg = loader.validate(info)
        self.assertFalse(valid)
        self.assertIn("not found", msg)


class TestPluginManager(unittest.TestCase):
    def setUp(self):
        PluginManager.reset_instance()
        self.tmpdir = tempfile.mkdtemp()
        self.plugins_dir = Path(self.tmpdir) / "plugins"
        self.plugins_dir.mkdir()
        self.storage_dir = Path(self.tmpdir) / "storage"
        self.storage_dir.mkdir()

    def _create_test_plugin(self, plugin_id: str = "test-plugin"):
        plugin_dir = self.plugins_dir / plugin_id
        plugin_dir.mkdir()
        manifest = {
            "id": plugin_id,
            "name": "Test Plugin",
            "name_ar": "إضافة اختبار",
            "version": "1.0.0",
            "description": "Test",
            "description_ar": "اختبار",
            "author": "Tester",
            "capabilities": [],
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
        plugin_code = '''
from platform_core.plugins.base import PluginBase, PluginContext

class TestPlugin(PluginBase):
    def activate(self, context):
        self.ctx = context
        context.log("Test plugin activated")

    def deactivate(self):
        pass

    def get_status(self):
        return {"status": "ok", "plugin": "test"}
'''
        (plugin_dir / "plugin.py").write_text(plugin_code, encoding="utf-8")
        return plugin_dir

    def test_discover_and_load(self):
        self._create_test_plugin()
        manager = PluginManager(self.plugins_dir, self.storage_dir)

        plugins = manager.discover_plugins()
        self.assertEqual(len(plugins), 1)

        success, msg = manager.load_plugin("test-plugin")
        self.assertTrue(success, f"Load failed: {msg}")
        self.assertIn("test-plugin", manager.get_loaded_plugins())

    def test_list_plugins(self):
        self._create_test_plugin("plugin-a")
        self._create_test_plugin("plugin-b")
        manager = PluginManager(self.plugins_dir, self.storage_dir)
        manager.discover_plugins()

        plugins = manager.list_plugins()
        self.assertEqual(len(plugins), 2)

    def test_unload_plugin(self):
        self._create_test_plugin()
        manager = PluginManager(self.plugins_dir, self.storage_dir)
        manager.discover_plugins()
        manager.load_plugin("test-plugin")

        success, msg = manager.unload_plugin("test-plugin")
        self.assertTrue(success)
        self.assertNotIn("test-plugin", manager.get_loaded_plugins())

    def test_load_nonexistent(self):
        manager = PluginManager(self.plugins_dir, self.storage_dir)
        success, msg = manager.load_plugin("does-not-exist")
        self.assertFalse(success)

    def test_unload_not_loaded(self):
        manager = PluginManager(self.plugins_dir, self.storage_dir)
        success, msg = manager.unload_plugin("not-loaded")
        self.assertFalse(success)


if __name__ == "__main__":
    unittest.main()
