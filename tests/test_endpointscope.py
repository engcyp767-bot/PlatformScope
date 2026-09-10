"""Tests for EndpointScope module."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from endpointscope.models import (
    AgentInfo,
    AgentState,
    EndpointEvent,
    EndpointEventType,
    EndpointPolicy,
    ResponseAction,
    ResponseActionType,
)
from endpointscope.collector import EndpointCollector
from endpointscope.monitor import EndpointMonitor, MonitorConfig


class TestEndpointModels(unittest.TestCase):
    """Test EndpointScope data models."""

    def test_agent_info_to_dict(self):
        agent = AgentInfo(
            agent_id="agent-abc123",
            hostname="workstation-01",
            os_type="windows",
            os_version="10.0.19045",
            agent_version="1.0.0",
            ip_addresses=["192.168.1.10"],
            state=AgentState.ONLINE,
        )
        d = agent.to_dict()
        self.assertEqual(d["agent_id"], "agent-abc123")
        self.assertEqual(d["state"], "online")
        self.assertEqual(d["hostname"], "workstation-01")

    def test_endpoint_event_to_dict(self):
        event = EndpointEvent(
            agent_id="agent-1",
            hostname="host-1",
            event_type=EndpointEventType.PROCESS_CREATED,
            severity="high",
            process_name="powershell.exe",
            process_id=1234,
            command_line="powershell -enc AAAA",
        )
        d = event.to_dict()
        self.assertEqual(d["event_type"], "process_created")
        self.assertEqual(d["severity"], "high")
        self.assertEqual(d["process_name"], "powershell.exe")

    def test_endpoint_event_to_canonical_log(self):
        event = EndpointEvent(
            agent_id="agent-1",
            hostname="host-1",
            event_type=EndpointEventType.PROCESS_CREATED,
            severity="high",
            process_name="cmd.exe",
            process_id=5678,
            user="DOMAIN\\admin",
            dst_ip="10.0.0.1",
            dst_port=443,
        )
        log = event.to_canonical_log()
        self.assertEqual(log["source"], "endpointscope:host-1")
        self.assertEqual(log["source_type"], "endpoint")
        self.assertEqual(log["hostname"], "host-1")
        self.assertEqual(log["username"], "DOMAIN\\admin")
        self.assertEqual(log["process_name"], "cmd.exe")

    def test_response_action_to_dict(self):
        action = ResponseAction(
            agent_id="agent-1",
            action_type=ResponseActionType.ISOLATE_ENDPOINT,
            requested_by="admin",
            parameters={"reason": "Suspicious activity"},
        )
        d = action.to_dict()
        self.assertEqual(d["action_type"], "isolate_endpoint")
        self.assertEqual(d["status"], "pending")
        self.assertEqual(d["parameters"]["reason"], "Suspicious activity")

    def test_all_event_types_defined(self):
        """Verify we have comprehensive event type coverage."""
        event_types = list(EndpointEventType)
        self.assertGreater(len(event_types), 25)
        # Check key categories exist
        type_values = [t.value for t in event_types]
        self.assertIn("process_created", type_values)
        self.assertIn("file_created", type_values)
        self.assertIn("network_connection_established", type_values)
        self.assertIn("auth_login_failed", type_values)
        self.assertIn("registry_key_created", type_values)
        self.assertIn("service_installed", type_values)
        self.assertIn("driver_loaded", type_values)

    def test_all_response_action_types(self):
        actions = list(ResponseActionType)
        self.assertGreater(len(actions), 5)
        action_values = [a.value for a in actions]
        self.assertIn("isolate_endpoint", action_values)
        self.assertIn("kill_process", action_values)
        self.assertIn("quarantine_file", action_values)
        self.assertIn("collect_memory_dump", action_values)

    def test_endpoint_policy_defaults(self):
        policy = EndpointPolicy()
        self.assertTrue(policy.collect_process_events)
        self.assertTrue(policy.collect_file_events)
        self.assertTrue(policy.collect_network_events)
        self.assertEqual(policy.heartbeat_interval_seconds, 60)
        self.assertEqual(policy.cpu_limit_percent, 5.0)
        self.assertEqual(policy.memory_limit_mb, 128)

    def test_agent_state_transitions(self):
        for state in AgentState:
            self.assertIsInstance(state.value, str)


class TestEndpointCollector(unittest.TestCase):
    """Test EndpointScope central collector."""

    def setUp(self):
        EndpointCollector.reset_instance()
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test_endpoint.sqlite3"
        self.collector = EndpointCollector(self.db_path)

    def test_register_agent(self):
        agent = AgentInfo(
            agent_id="agent-test-001",
            hostname="test-host",
            os_type="windows",
            os_version="10.0",
            agent_version="1.0.0",
        )
        result = self.collector.register_agent(agent)
        self.assertEqual(result["status"], "registered")

    def test_get_agent(self):
        agent = AgentInfo(
            agent_id="agent-get-001",
            hostname="get-host",
            os_type="linux",
            os_version="6.1",
            agent_version="1.0.0",
            ip_addresses=["10.0.0.5"],
        )
        self.collector.register_agent(agent)
        retrieved = self.collector.get_agent("agent-get-001")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["hostname"], "get-host")
        self.assertEqual(retrieved["os_type"], "linux")

    def test_list_agents(self):
        for i in range(5):
            agent = AgentInfo(
                agent_id=f"agent-list-{i:03d}",
                hostname=f"host-{i}",
                os_type="windows",
                os_version="10.0",
                agent_version="1.0.0",
            )
            self.collector.register_agent(agent)

        result = self.collector.list_agents()
        self.assertEqual(result["total"], 5)
        self.assertEqual(len(result["agents"]), 5)

    def test_heartbeat(self):
        agent = AgentInfo(
            agent_id="agent-hb-001",
            hostname="hb-host",
            os_type="windows",
            os_version="10.0",
            agent_version="1.0.0",
        )
        self.collector.register_agent(agent)

        result = self.collector.heartbeat("agent-hb-001", {"cpu": 25.5, "mem": 60.0})
        self.assertEqual(result["status"], "ok")
        self.assertIn("pending_actions", result)

    def test_heartbeat_unknown_agent(self):
        result = self.collector.heartbeat("nonexistent-agent")
        self.assertEqual(result["status"], "error")

    def test_ingest_events(self):
        agent = AgentInfo(
            agent_id="agent-evt-001",
            hostname="evt-host",
            os_type="windows",
            os_version="10.0",
            agent_version="1.0.0",
        )
        self.collector.register_agent(agent)

        events = [
            EndpointEvent(
                agent_id="agent-evt-001",
                hostname="evt-host",
                event_type=EndpointEventType.PROCESS_CREATED,
                severity="info",
                process_name="notepad.exe",
                process_id=100 + i,
            )
            for i in range(10)
        ]
        result = self.collector.ingest_events(events)
        self.assertEqual(result["accepted"], 10)
        self.assertEqual(result["rejected"], 0)

    def test_get_events_filtered(self):
        agent = AgentInfo(
            agent_id="agent-qry-001",
            hostname="qry-host",
            os_type="windows",
            os_version="10.0",
            agent_version="1.0.0",
        )
        self.collector.register_agent(agent)

        events = [
            EndpointEvent(
                agent_id="agent-qry-001", hostname="qry-host",
                event_type=EndpointEventType.PROCESS_CREATED, severity="info",
            ),
            EndpointEvent(
                agent_id="agent-qry-001", hostname="qry-host",
                event_type=EndpointEventType.NETWORK_CONNECTION_ESTABLISHED, severity="high",
            ),
        ]
        self.collector.ingest_events(events)

        result = self.collector.get_events(severity="high")
        self.assertEqual(result["total"], 1)

    def test_create_response_action(self):
        agent = AgentInfo(
            agent_id="agent-rsp-001",
            hostname="rsp-host",
            os_type="windows",
            os_version="10.0",
            agent_version="1.0.0",
        )
        self.collector.register_agent(agent)

        result = self.collector.create_response_action(
            agent_id="agent-rsp-001",
            action_type=ResponseActionType.ISOLATE_ENDPOINT,
            requested_by="admin",
            parameters={"reason": "Ransomware detected"},
        )
        self.assertIn("action_id", result)
        self.assertEqual(result["action_type"], "isolate_endpoint")

    def test_heartbeat_returns_pending_actions(self):
        agent = AgentInfo(
            agent_id="agent-pa-001",
            hostname="pa-host",
            os_type="windows",
            os_version="10.0",
            agent_version="1.0.0",
        )
        self.collector.register_agent(agent)

        self.collector.create_response_action(
            "agent-pa-001", ResponseActionType.KILL_PROCESS,
            parameters={"pid": 1234},
        )

        result = self.collector.heartbeat("agent-pa-001")
        self.assertEqual(len(result["pending_actions"]), 1)
        self.assertEqual(result["pending_actions"][0]["action_type"], "kill_process")

    def test_dashboard_stats(self):
        agent = AgentInfo(
            agent_id="agent-dash-001",
            hostname="dash-host",
            os_type="windows",
            os_version="10.0",
            agent_version="1.0.0",
        )
        self.collector.register_agent(agent)

        stats = self.collector.get_dashboard_stats()
        self.assertIn("agents", stats)
        self.assertIn("total_agents", stats)
        self.assertIn("total_events", stats)
        self.assertEqual(stats["total_agents"], 1)

    def test_agent_health_check(self):
        result = self.collector.check_agent_health()
        self.assertIn("state_counts", result)
        self.assertIn("checked_at", result)


class TestEndpointMonitor(unittest.TestCase):
    """Test EndpointScope local monitor."""

    def test_agent_id_deterministic(self):
        m1 = EndpointMonitor()
        m2 = EndpointMonitor()
        self.assertEqual(m1.agent_id, m2.agent_id)

    def test_agent_info(self):
        monitor = EndpointMonitor()
        info = monitor.get_agent_info()
        self.assertTrue(info.agent_id.startswith("agent-"))
        self.assertTrue(info.hostname)
        self.assertIn(info.os_type, ("windows", "linux", "darwin"))

    def test_config_defaults(self):
        config = MonitorConfig()
        self.assertTrue(config.monitor_processes)
        self.assertTrue(config.monitor_files)
        self.assertTrue(config.monitor_network)
        self.assertEqual(config.max_events_per_minute, 5000)
        self.assertEqual(config.batch_size, 100)

    def test_collect_events_empty(self):
        monitor = EndpointMonitor()
        events = monitor.collect_events()
        self.assertEqual(events, [])

    def test_severity_assessment_powershell(self):
        monitor = EndpointMonitor()
        severity = monitor._assess_process_severity({
            "name": "powershell.exe",
            "cmdline": "powershell.exe -NoProfile -Command Get-Date",
        })
        self.assertEqual(severity, "high")

    def test_severity_assessment_encoded_command(self):
        monitor = EndpointMonitor()
        severity = monitor._assess_process_severity({
            "name": "powershell.exe",
            "cmdline": "powershell.exe -enc AAAA==",
        })
        self.assertEqual(severity, "critical")

    def test_severity_assessment_normal(self):
        monitor = EndpointMonitor()
        severity = monitor._assess_process_severity({
            "name": "notepad.exe",
            "cmdline": "notepad.exe readme.txt",
        })
        self.assertEqual(severity, "info")

    def test_severity_assessment_mimikatz(self):
        monitor = EndpointMonitor()
        severity = monitor._assess_process_severity({
            "name": "mimikatz.exe",
            "cmdline": "mimikatz.exe privilege::debug",
        })
        self.assertEqual(severity, "high")

    def test_connection_severity_c2_port(self):
        monitor = EndpointMonitor()
        severity = monitor._assess_connection_severity({"dport": "4444"})
        self.assertEqual(severity, "high")

    def test_connection_severity_normal(self):
        monitor = EndpointMonitor()
        severity = monitor._assess_connection_severity({"dport": "443"})
        self.assertEqual(severity, "info")

    def test_system_snapshot(self):
        monitor = EndpointMonitor()
        snapshot = monitor.collect_system_snapshot()
        self.assertIn("timestamp", snapshot)
        self.assertIn("hostname", snapshot)
        self.assertIn("os", snapshot)
        self.assertIn("processes", snapshot)


if __name__ == "__main__":
    unittest.main()
