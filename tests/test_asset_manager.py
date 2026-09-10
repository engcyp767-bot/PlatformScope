"""Unit tests for Centralized Asset Intelligence Engine (Phase 5)."""

import json
import unittest
from platform_core import asset_manager


class AssetManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        asset_manager.init_db()

    def test_identity_resolution_prevents_duplicates_by_mac(self):
        # Create initial asset with MAC
        a1 = asset_manager.create_or_update_asset(
            hostname="WS-CORP-101",
            primary_ip="192.168.10.101",
            mac_address="00:1A:2B:3C:4D:5E",
            criticality="high",
            status="unknown",
            discovery_source="windows_event"
        )
        self.assertTrue(a1["id"].startswith("AST-"))
        self.assertEqual(a1["status"], "unknown")
        self.assertEqual(a1["criticality"], "high")

        # Same asset appears under a different IP (e.g. DHCP change), but same MAC
        a2 = asset_manager.create_or_update_asset(
            hostname="WS-CORP-101.corp.local",
            primary_ip="192.168.10.199",
            mac_address="00-1A-2B-3C-4D-5E",
            discovery_source="flow_analysis"
        )
        # MUST resolve to same asset ID!
        self.assertEqual(a1["id"], a2["id"])
        self.assertEqual(a2["primary_ip"], "192.168.10.199")
        self.assertIn("192.168.10.101", a2["ip_addresses"])
        self.assertIn("192.168.10.199", a2["ip_addresses"])
        # Confidence score should have increased due to multi-source discovery
        self.assertGreaterEqual(a2["confidence_score"], a1["confidence_score"])

    def test_identity_resolution_by_normalized_hostname(self):
        # Create server by hostname
        srv1 = asset_manager.create_or_update_asset(
            hostname="SRV-DATABASE-01",
            primary_ip="10.0.5.20",
            asset_type="database",
            criticality="mission_critical",
            department="Engineering"
        )
        # Update using FQDN lowercase without MAC
        srv2 = asset_manager.create_or_update_asset(
            hostname="srv-database-01.internal.network",
            primary_ip="10.0.5.20",
            os_name="Ubuntu 22.04 LTS"
        )
        self.assertEqual(srv1["id"], srv2["id"])
        self.assertEqual(srv2["os"], "Ubuntu 22.04 LTS")

    def test_dynamic_risk_score_calculation(self):
        ast = asset_manager.create_or_update_asset(
            hostname="DC-PROD-PRIMARY",
            primary_ip="10.0.0.1",
            criticality="mission_critical",
            status="unknown"
        )
        # Mission critical base = 30, unknown status = +10 -> Total at least 40
        self.assertGreaterEqual(ast["risk_score"], 40)

    def test_containment_action_framework(self):
        ast = asset_manager.create_or_update_asset(
            hostname="COMPROMISED-HOST",
            primary_ip="192.168.50.77",
            mac_address="AA:BB:CC:DD:EE:FF",
            criticality="medium"
        )
        asset_id = ast["id"]

        # Create containment action
        action = asset_manager.create_containment_action(
            asset_id=asset_id,
            action_type="network_isolation",
            provider="sentinel_one",
            dispatched_by="security_analyst"
        )
        action_id = action["action_id"]
        self.assertTrue(action_id.startswith("ACT-"))
        self.assertEqual(action["status"], "pending_approval")
        self.assertIn("windows_netsh", action["playbook"])
        self.assertIn("fortinet_cli", action["playbook"])

        # Confirm containment
        confirmed = asset_manager.confirm_containment_action(action_id, actor="lead_analyst")
        self.assertEqual(confirmed["status"], "confirmed")

        # Verify asset status is now isolated
        updated_ast = asset_manager.get_asset(asset_id)
        self.assertEqual(updated_ast["status"], "isolated")
        self.assertGreaterEqual(len(updated_ast["timeline"]), 2)

        # Revoke containment
        revoked = asset_manager.revoke_containment_action(action_id, actor="lead_analyst")
        self.assertEqual(revoked["status"], "revoked")
        reverted_ast = asset_manager.get_asset(asset_id)
        self.assertEqual(reverted_ast["status"], "active")

    def test_cmdb_export_and_import(self):
        # Export as JSON
        json_export = asset_manager.export_assets(format="json")
        self.assertTrue(len(json_export) > 0)
        parsed = json.loads(json_export)
        self.assertIsInstance(parsed, list)

        # Export as CSV
        csv_export = asset_manager.export_assets(format="csv")
        self.assertIn("Hostname", csv_export)
        self.assertIn("Primary IP", csv_export)

        # Import mock CMDB CSV
        mock_csv = """Hostname,Primary IP,MAC Address,Type,Criticality,Department
FW-EDGE-01,10.0.0.254,00:50:56:11:22:33,firewall,mission_critical,Network Security
WS-HR-002,192.168.20.45,00:50:56:44:55:66,workstation,low,Human Resources
"""
        res = asset_manager.import_assets(mock_csv, format="csv", dry_run=False)
        self.assertTrue(res["success"])
        self.assertGreaterEqual(res["created_count"] + res["updated_count"], 2)


if __name__ == "__main__":
    unittest.main()
