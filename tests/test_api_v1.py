"""Unit tests for Public API v1, API Keys, and Router."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from endpointscope.collector import EndpointCollector
from endpointscope.monitor import EndpointMonitor
from platform_core.api.keys import APIKeyManager, APIScope
from platform_core.api.router import (
    APIRoute,
    APIRouter,
    APIResponse,
    error_response,
    success_response,
)
from platform_core.api.v1.routes import register_v1_routes
from platform_core.feature_gate import FeatureGate, FeatureID, PlatformEdition


class TestAPIKeys(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_api_keys.db"
        self.km = APIKeyManager(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generate_and_validate_key(self):
        raw_key, rec = self.km.generate_key(
            name="Test Ingestion Key",
            scope=APIScope.INGEST,
            rate_limit_rpm=60,
        )
        self.assertTrue(raw_key.startswith("psk_live_"))
        self.assertEqual(rec.scope, APIScope.INGEST)
        self.assertEqual(rec.rate_limit_rpm, 60)
        self.assertTrue(rec.is_active)

        # Validate with valid key
        validated = self.km.validate_key(raw_key)
        self.assertIsNotNone(validated)
        self.assertEqual(validated.key_id, rec.key_id)
        self.assertEqual(validated.name, "Test Ingestion Key")

        # Validate with wrong key
        bad = self.km.validate_key("psk_live_wrongrandomkey123")
        self.assertIsNone(bad)

    def test_scope_hierarchy(self):
        _, admin_rec = self.km.generate_key("Admin", scope=APIScope.ADMIN)
        raw_admin = f"psk_live_raw_admin_{time.time()}"
        # Store custom hash for direct test
        admin_raw, admin_rec = self.km.generate_key("AdminKey", scope=APIScope.ADMIN)
        write_raw, write_rec = self.km.generate_key("WriteKey", scope=APIScope.WRITE)
        read_raw, read_rec = self.km.generate_key("ReadKey", scope=APIScope.READ)

        # Admin key satisfies all scopes
        self.assertIsNotNone(self.km.validate_key(admin_raw, required_scope=APIScope.READ))
        self.assertIsNotNone(self.km.validate_key(admin_raw, required_scope=APIScope.WRITE))
        self.assertIsNotNone(self.km.validate_key(admin_raw, required_scope=APIScope.INGEST))
        self.assertIsNotNone(self.km.validate_key(admin_raw, required_scope=APIScope.ADMIN))

        # Write key satisfies write, ingest, read, but not admin
        self.assertIsNotNone(self.km.validate_key(write_raw, required_scope=APIScope.READ))
        self.assertIsNotNone(self.km.validate_key(write_raw, required_scope=APIScope.WRITE))
        self.assertIsNone(self.km.validate_key(write_raw, required_scope=APIScope.ADMIN))

        # Read key satisfies only read
        self.assertIsNotNone(self.km.validate_key(read_raw, required_scope=APIScope.READ))
        self.assertIsNone(self.km.validate_key(read_raw, required_scope=APIScope.WRITE))
        self.assertIsNone(self.km.validate_key(read_raw, required_scope=APIScope.ADMIN))

    def test_key_revocation(self):
        raw_key, rec = self.km.generate_key("Revocable")
        self.assertIsNotNone(self.km.validate_key(raw_key))

        ok = self.km.revoke_key(rec.key_id)
        self.assertTrue(ok)

        # Now validation should fail
        self.assertIsNone(self.km.validate_key(raw_key))

    def test_key_expiration(self):
        # Create expired key record
        raw_key, rec = self.km.generate_key("Expired", expires_in_days=0)
        # Directly update expiry to past
        with self.km._get_conn() as conn:
            conn.execute(
                "UPDATE api_keys SET expires_at = '2020-01-01T00:00:00+00:00' WHERE key_id = ?",
                (rec.key_id,),
            )
            conn.commit()

        self.assertIsNone(self.km.validate_key(raw_key))

    def test_rate_limit(self):
        raw_key, rec = self.km.generate_key("RateLimited", rate_limit_rpm=3)
        
        # 1st request
        allowed, rem, _ = self.km.check_rate_limit(rec.key_id, limit_rpm=3)
        self.assertTrue(allowed)
        self.assertEqual(rem, 2)

        # 2nd request
        allowed, rem, _ = self.km.check_rate_limit(rec.key_id, limit_rpm=3)
        self.assertTrue(allowed)
        self.assertEqual(rem, 1)

        # 3rd request
        allowed, rem, _ = self.km.check_rate_limit(rec.key_id, limit_rpm=3)
        self.assertTrue(allowed)
        self.assertEqual(rem, 0)

        # 4th request -> blocked
        allowed, rem, reset_s = self.km.check_rate_limit(rec.key_id, limit_rpm=3)
        self.assertFalse(allowed)
        self.assertEqual(rem, 0)
        self.assertGreater(reset_s, 0)


class TestAPIRouter(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_api_keys.db"
        self.km = APIKeyManager(self.db_path)
        
        # Feature gate in Community mode
        self.gate = FeatureGate(storage_dir=Path(self.temp_dir.name))
        self.router = APIRouter(prefix="/api/v1", key_manager=self.km, feature_gate=self.gate)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_route_matching_and_path_params(self):
        @self.router.get("/users/{user_id}/posts/{post_id}")
        def get_user_post(user_id: str, post_id: str):
            return {"user": user_id, "post": post_id}

        resp = self.router.dispatch("GET", "/api/v1/users/alice/posts/42")
        self.assertEqual(resp.status_code, 200)
        data = resp.to_dict()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["user"], "alice")
        self.assertEqual(data["data"]["post"], "42")
        self.assertIn("timestamp", data["meta"])

    def test_query_params_and_body_dispatch(self):
        @self.router.post("/items")
        def create_item(body: dict, query: dict):
            return {"received_body": body, "filter": query.get("filter")}

        body_bytes = json.dumps({"name": "Sensor", "price": 99}).encode("utf-8")
        resp = self.router.dispatch("POST", "/api/v1/items?filter=active", body_bytes=body_bytes)
        self.assertEqual(resp.status_code, 200)
        data = resp.to_dict()["data"]
        self.assertEqual(data["received_body"]["name"], "Sensor")
        self.assertEqual(data["filter"], "active")

    def test_not_found(self):
        resp = self.router.dispatch("GET", "/api/v1/nonexistent/path")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.to_dict()["error"]["code"], "NOT_FOUND")

    def test_invalid_json(self):
        @self.router.post("/test")
        def handler(body: dict):
            return body

        resp = self.router.dispatch("POST", "/api/v1/test", body_bytes=b"invalid json{{{")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.to_dict()["error"]["code"], "INVALID_JSON")

    def test_scope_authorization_enforcement(self):
        @self.router.get("/admin/metrics", required_scope=APIScope.ADMIN)
        def admin_metrics():
            return {"secret": 123}

        # No key -> 401
        resp = self.router.dispatch("GET", "/api/v1/admin/metrics")
        self.assertEqual(resp.status_code, 401)

        # Read key -> 401
        read_key, _ = self.km.generate_key("Reader", scope=APIScope.READ)
        resp = self.router.dispatch("GET", "/api/v1/admin/metrics", headers={"X-API-Key": read_key})
        self.assertEqual(resp.status_code, 401)

        # Admin key -> 200
        admin_key, _ = self.km.generate_key("AdminUser", scope=APIScope.ADMIN)
        resp = self.router.dispatch("GET", "/api/v1/admin/metrics", headers={"X-API-Key": admin_key})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.to_dict()["data"]["secret"], 123)

    def test_feature_gate_enforcement(self):
        # Register route that requires AIRGAP_MODE (Enterprise)
        @self.router.get("/airgap/export", required_feature=FeatureID.AIRGAP_MODE)
        def airgap_export():
            return {"exported": True}

        # Mock Community edition
        with patch.object(FeatureGate, "_get_edition", return_value=PlatformEdition.COMMUNITY):
            resp = self.router.dispatch("GET", "/api/v1/airgap/export")
            self.assertEqual(resp.status_code, 403)
            err = resp.to_dict()["error"]
            self.assertEqual(err["code"], "FEATURE_LOCKED")
            self.assertEqual(err["details"]["feature"], FeatureID.AIRGAP_MODE.value)

    def test_openapi_spec_generation(self):
        @self.router.get("/assets/{asset_id}", summary="Get asset", tags=["Assets"])
        def get_asset(asset_id: str):
            return {"id": asset_id}

        spec = self.router.generate_openapi_spec()
        self.assertEqual(spec["openapi"], "3.0.3")
        self.assertIn("/api/v1/assets/{asset_id}", spec["paths"])
        op = spec["paths"]["/api/v1/assets/{asset_id}"]["get"]
        self.assertEqual(op["summary"], "Get asset")
        self.assertEqual(op["tags"], ["Assets"])
        self.assertEqual(op["parameters"][0]["name"], "asset_id")


class TestV1Routes(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        base = Path(self.temp_dir.name)
        self.km = APIKeyManager(base / "keys.db")
        self.collector = EndpointCollector(db_path=base / "endpoints.db")
        self.monitor = EndpointMonitor()
        self.gate = FeatureGate(storage_dir=base)
        # Unlock professional features for full integration route testing
        self.gate._get_edition = lambda: PlatformEdition.PROFESSIONAL
        self.router = APIRouter(prefix="/api/v1", key_manager=self.km, feature_gate=self.gate)
        register_v1_routes(self.router, self.collector, self.monitor, self.km, self.gate)

        # Generate admin API key for tests
        self.admin_key, _ = self.km.generate_key("AdminKey", scope=APIScope.ADMIN)
        self.headers = {"X-API-Key": self.admin_key}

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_edition_and_features_endpoints(self):
        resp = self.router.dispatch("GET", "/api/v1/edition")
        self.assertEqual(resp.status_code, 200)
        data = resp.to_dict()["data"]
        self.assertEqual(data["edition"].lower(), "professional")
        self.assertTrue(data["gcc_compliance"]["nca_ecc"])

        resp2 = self.router.dispatch("GET", "/api/v1/features")
        self.assertEqual(resp2.status_code, 200)
        features_data = resp2.to_dict()["data"]
        self.assertIn("usage_summary", features_data)

    def test_endpoint_agent_registration_and_heartbeat(self):
        reg_body = {
            "agent_id": "test-srv-01",
            "hostname": "PROD-DB-01",
            "os_family": "windows",
            "ip_addresses": ["10.0.0.5"],
            "version": "1.2.0",
        }
        resp = self.router.dispatch(
            "POST",
            "/api/v1/endpoint/register",
            headers=self.headers,
            body_bytes=json.dumps(reg_body).encode("utf-8"),
        )
        self.assertEqual(resp.status_code, 201)
        agent_data = resp.to_dict()["data"]
        self.assertEqual(agent_data["agent_id"], "test-srv-01")

        # Heartbeat
        hb_body = {
            "agent_id": "test-srv-01",
            "metrics": {"cpu_percent": 14.5, "memory_percent": 42.0},
        }
        resp_hb = self.router.dispatch(
            "POST",
            "/api/v1/endpoint/heartbeat",
            headers=self.headers,
            body_bytes=json.dumps(hb_body).encode("utf-8"),
        )
        self.assertEqual(resp_hb.status_code, 200)
        self.assertEqual(resp_hb.to_dict()["data"]["status"], "ok")

    def test_endpoint_events_ingestion_and_details(self):
        # First register agent
        from endpointscope.models import AgentInfo
        self.collector.register_agent(
            AgentInfo(
                agent_id="srv-web-01",
                hostname="WEB-01",
                os_type="windows",
                os_version="10.0",
                agent_version="1.0.0",
            )
        )

        events_body = {
            "events": [
                {
                    "event_id": "evt-001",
                    "agent_id": "srv-web-01",
                    "event_type": "process_created",
                    "timestamp": "2026-09-10T00:00:00Z",
                    "severity": "medium",
                    "process_name": "powershell.exe",
                    "details": {"cmdline": "powershell.exe Get-Process"},
                }
            ]
        }
        resp = self.router.dispatch(
            "POST",
            "/api/v1/endpoint/events",
            headers=self.headers,
            body_bytes=json.dumps(events_body).encode("utf-8"),
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.to_dict()["data"]["accepted"], 1)

        # Get agent details
        resp_details = self.router.dispatch(
            "GET",
            "/api/v1/endpoint/agents/srv-web-01",
            headers=self.headers,
        )
        self.assertEqual(resp_details.status_code, 200)
        det_data = resp_details.to_dict()["data"]
        self.assertEqual(det_data["agent"]["agent_id"], "srv-web-01")
        self.assertEqual(len(det_data["recent_events"]), 1)

    def test_stats_and_host_scan(self):
        resp_stats = self.router.dispatch("GET", "/api/v1/endpoint/stats", headers=self.headers)
        self.assertEqual(resp_stats.status_code, 200)

        resp_scan = self.router.dispatch("POST", "/api/v1/endpoint/monitor/scan", headers=self.headers)
        self.assertEqual(resp_scan.status_code, 200)
        self.assertIn("os", resp_scan.to_dict()["data"])

    def test_key_management_via_api(self):
        # Create key
        create_body = {
            "name": "Integration Key",
            "scope": "ingest",
            "rate_limit_rpm": 300,
        }
        resp = self.router.dispatch(
            "POST",
            "/api/v1/keys",
            headers=self.headers,
            body_bytes=json.dumps(create_body).encode("utf-8"),
        )
        self.assertEqual(resp.status_code, 201)
        key_id = resp.to_dict()["data"]["key"]["key_id"]
        raw_key = resp.to_dict()["data"]["raw_key"]
        self.assertTrue(raw_key.startswith("psk_live_"))

        # List keys
        resp_list = self.router.dispatch("GET", "/api/v1/keys", headers=self.headers)
        self.assertEqual(resp_list.status_code, 200)
        self.assertTrue(any(k["key_id"] == key_id for k in resp_list.to_dict()["data"]))

        # Delete key
        resp_del = self.router.dispatch("DELETE", f"/api/v1/keys/{key_id}", headers=self.headers)
        self.assertEqual(resp_del.status_code, 200)

    def test_mailscope_api_endpoints(self):
        # 1. Get mail stats
        resp_stats = self.router.dispatch("GET", "/api/v1/mail/stats", headers=self.headers)
        self.assertEqual(resp_stats.status_code, 200)
        self.assertIn("total_analyzed", resp_stats.to_dict()["data"])

        # 2. Analyze mail payload
        raw_eml = """From: "CEO John" <ceo@evil-domain.com>
To: accountant@mycorp.com
Subject: Urgent Payment Request
Date: Mon, 10 Sep 2026 12:00:00 +0300
Authentication-Results: mx.mycorp.com; spf=fail; dmarc=fail

Please initiate an urgent wire transfer to our new supplier.
"""
        resp_analyze = self.router.dispatch(
            "POST",
            "/api/v1/mail/analyze",
            headers=self.headers,
            body_bytes=json.dumps({"raw_eml": raw_eml}).encode("utf-8"),
        )
        self.assertEqual(resp_analyze.status_code, 200)
        data = resp_analyze.to_dict()["data"]
        report_id = data["id"]
        self.assertIn(data["verdict"], ["bec_fraud", "phishing", "suspicious"])

        # 3. Get single report
        resp_rep = self.router.dispatch("GET", f"/api/v1/mail/reports/{report_id}", headers=self.headers)
        self.assertEqual(resp_rep.status_code, 200)
        self.assertEqual(resp_rep.to_dict()["data"]["id"], report_id)

        # 4. List reports
        resp_list = self.router.dispatch("GET", "/api/v1/mail/reports", headers=self.headers)
        self.assertEqual(resp_list.status_code, 200)
        self.assertTrue(len(resp_list.to_dict()["data"]) >= 1)

        # 5. Quarantine mail
        resp_quar = self.router.dispatch(
            "POST",
            f"/api/v1/mail/quarantine/{report_id}",
            headers=self.headers,
            body_bytes=json.dumps({"quarantine": True}).encode("utf-8"),
        )
        self.assertEqual(resp_quar.status_code, 200)
        self.assertTrue(resp_quar.to_dict()["data"]["quarantined"])


if __name__ == "__main__":
    unittest.main()

