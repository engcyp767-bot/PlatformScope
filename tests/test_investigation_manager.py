"""Unit tests for platform_core/investigation_manager.py."""

import tempfile
import unittest
from pathlib import Path

from platform_core.investigation_manager import InvestigationManager


class TestInvestigationManager(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.tmp_dir.name) / "test_investigations.sqlite3"
        self.manager = InvestigationManager(db_path=self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_create_and_get_investigation(self):
        inv = self.manager.create_investigation(
            title="Suspicious C2 Beaconing Activity",
            description="Investigating recurrent HTTPS requests to dynamic DNS host.",
            priority="P1",
            lead_analyst="soc_lead",
            tags=["c2", "cobalt_strike"],
            hypothesis="Endpoint is compromised with reflective loader.",
            actor="analyst_1",
        )
        self.assertIn("id", inv)
        self.assertEqual(inv["title"], "Suspicious C2 Beaconing Activity")
        self.assertEqual(inv["priority"], "P1")
        self.assertEqual(inv["status"], "open")
        self.assertEqual(inv["lead_analyst"], "soc_lead")

        fetched = self.manager.get_investigation(inv["id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["id"], inv["id"])
        self.assertEqual(len(fetched["timeline"]), 1)

    def test_list_investigations_filtering(self):
        self.manager.create_investigation("Case Alpha", priority="P1", lead_analyst="omar")
        self.manager.create_investigation("Case Beta", priority="P2", lead_analyst="ali")
        self.manager.create_investigation("Case Gamma", priority="P3", lead_analyst="omar")

        # All
        items, total = self.manager.list_investigations()
        self.assertEqual(total, 3)

        # By Priority
        items_p1, total_p1 = self.manager.list_investigations(priority="P1")
        self.assertEqual(total_p1, 1)
        self.assertEqual(items_p1[0]["priority"], "P1")

        # By Analyst
        items_omar, total_omar = self.manager.list_investigations(lead_analyst="omar")
        self.assertEqual(total_omar, 2)

    def test_items_and_notes_lifecycle(self):
        inv = self.manager.create_investigation("Incident Bundle Case")
        inv_id = inv["id"]

        # Add Incident Item
        item = self.manager.add_item(
            investigation_id=inv_id,
            item_type="incident",
            item_id="INC-1001",
            title="Critical Data Exfiltration Alert",
            metadata={"source": "ThreatScope", "severity": "critical"},
            actor="analyst_2",
        )
        self.assertIn("id", item)
        self.assertEqual(item["item_id"], "INC-1001")

        # Add Asset Item
        self.manager.add_item(
            investigation_id=inv_id,
            item_type="asset",
            item_id="AST-9002",
            title="DC01-Primary.domain.local",
            actor="analyst_2",
        )

        # Add Note
        note = self.manager.add_note(
            investigation_id=inv_id,
            content="Memory dump acquired from DC01 shows suspicious injected thread.",
            author="dfir_specialist",
        )
        self.assertIn("id", note)

        # Fetch and verify relations
        full_inv = self.manager.get_investigation(inv_id)
        self.assertEqual(len(full_inv["items"]), 2)
        self.assertEqual(len(full_inv["notes"]), 1)
        self.assertEqual(full_inv["notes"][0]["content"], note["content"])

        # Remove Item
        removed = self.manager.remove_item(inv_id, item["id"])
        self.assertTrue(removed)

        updated_inv = self.manager.get_investigation(inv_id)
        self.assertEqual(len(updated_inv["items"]), 1)

    def test_update_and_summary(self):
        inv = self.manager.create_investigation("Case Delta", priority="P1")
        inv_id = inv["id"]

        updated = self.manager.update_investigation(
            inv_id,
            {"status": "closed", "conclusion": "Malicious payload neutralized."},
            actor="incident_commander",
        )
        self.assertEqual(updated["status"], "closed")
        self.assertIsNotNone(updated["closed_at"])

        summary = self.manager.get_summary()
        self.assertEqual(summary["total_investigations"], 1)
        self.assertEqual(summary["closed_cases"], 1)
        self.assertEqual(summary["open_cases"], 0)


if __name__ == "__main__":
    unittest.main()
