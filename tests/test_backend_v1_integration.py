"""Integration test for Unified Backend Server v1 API routing and dispatching."""

from __future__ import annotations

import io
import json
import unittest
from unittest.mock import MagicMock

from backend_server import UnifiedAPIHandler, v1_api_router
from endpointscope.collector import get_endpoint_collector
from endpointscope.models import AgentInfo, AgentState
from platform_core.api.keys import APIScope, get_api_key_manager
from platform_core.feature_gate import PlatformEdition, get_feature_gate


class TestBackendV1Integration(unittest.TestCase):
    """Verify backend_server.py routes /api/v1/* requests through APIRouter."""

    def setUp(self):
        self.gate = get_feature_gate()
        self._orig_get_edition = self.gate._get_edition
        self.gate._get_edition = lambda: PlatformEdition.ENTERPRISE

        # Generate an admin API key for integration tests
        self.km = get_api_key_manager()
        self.admin_api_key, self.admin_rec = self.km.generate_key("Integration Test Admin Key", scope=APIScope.ADMIN)

        # Pre-register an agent in the collector for response action tests
        self.collector = get_endpoint_collector()
        self.collector.register_agent(AgentInfo(
            agent_id="AGT-INTEG-001",
            hostname="SERVER-PROD-01",
            os_type="windows",
            os_version="11.0",
            agent_version="1.0.0",
            ip_addresses=["192.168.1.50"],
            mac_addresses=["00:11:22:33:44:55"],
        ))

    def tearDown(self):
        self.gate._get_edition = self._orig_get_edition

    def _invoke_handler(self, method: str, path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
        """Simulate an HTTP request handled by UnifiedAPIHandler."""
        headers_dict = {
            "Host": "127.0.0.1:8082",
            "Content-Type": "application/json",
            "X-API-Key": self.admin_api_key,
            **(headers or {}),
        }
        body_bytes = json.dumps(body).encode("utf-8") if body is not None else b""
        if body_bytes:
            headers_dict["Content-Length"] = str(len(body_bytes))

        handler = UnifiedAPIHandler.__new__(UnifiedAPIHandler)
        handler.client_address = ("127.0.0.1", 54321)
        handler.headers = MagicMock()
        handler.headers.get = lambda k, default=None: headers_dict.get(k, headers_dict.get(k.lower(), default))
        handler.headers.items = lambda: headers_dict.items()
        handler.path = path
        handler.rfile = io.BytesIO(body_bytes)
        
        status_holder = []
        payload_holder = []

        def mock_json(status: int, payload: dict, *args, **kwargs):
            status_holder.append(status)
            payload_holder.append(payload)

        handler._json = mock_json

        if method == "GET":
            handler.do_GET()
        elif method == "POST":
            handler.do_POST()
        elif method == "PUT":
            handler.do_PUT()
        elif method == "DELETE":
            handler.do_DELETE()
        else:
            raise ValueError(f"Unsupported method: {method}")

        self.assertTrue(len(status_holder) > 0, f"Handler did not send response for {method} {path}")
        return status_holder[0], payload_holder[0]

    def test_get_edition_via_handler(self):
        status, res = self._invoke_handler("GET", "/api/v1/edition")
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("data", {}).get("edition"), "Enterprise")

    def test_get_features_via_handler(self):
        status, res = self._invoke_handler("GET", "/api/v1/features")
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertIn("edition_comparison", res.get("data", {}))

    def test_get_endpoint_agents_via_handler(self):
        status, res = self._invoke_handler("GET", "/api/v1/endpoint/agents")
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertIn("agents", res.get("data", {}))

    def test_post_endpoint_telemetry_via_handler(self):
        event_payload = {
            "events": [
                {
                    "agent_id": "AGT-INTEG-001",
                    "hostname": "SERVER-PROD-01",
                    "event_type": "process_start",
                    "severity": "medium",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass",
                }
            ]
        }
        status, res = self._invoke_handler("POST", "/api/v1/endpoint/events", body=event_payload)
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("data", {}).get("accepted"), 1)

    def test_endpoint_isolate_action_via_handler(self):
        action_payload = {
            "agent_id": "AGT-INTEG-001",
            "isolate": True,
            "reason": "Suspicious PowerShell execution detected by SOC Analyst",
        }
        status, res = self._invoke_handler("POST", "/api/v1/endpoint/actions/isolate", body=action_payload)
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("data", {}).get("action_type"), "isolate_endpoint")

    def test_get_plugins_via_handler(self):
        status, res = self._invoke_handler("GET", "/api/v1/plugins")
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertIsInstance(res.get("data"), list)

    def test_unauthorized_request_rejected(self):
        status, res = self._invoke_handler(
            "POST",
            "/api/v1/endpoint/actions/isolate",
            body={"agent_id": "AGT-001"},
            headers={"X-API-Key": "psk_live_invalid_key_999"},
        )
        self.assertEqual(status, 401)
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "UNAUTHORIZED")

    def test_v1_not_found_handled_properly(self):
        status, res = self._invoke_handler("GET", "/api/v1/non_existent_resource")
        self.assertEqual(status, 404)
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
