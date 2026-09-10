import os
import shutil
import tempfile
import unittest
from pathlib import Path

from platform_core import incident_manager


class TestIncidentManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.orig_db = incident_manager.DB_PATH
        self.orig_evidence = incident_manager.EVIDENCE_DIR

        incident_manager.DB_PATH = self.temp_dir / "incidents.sqlite3"
        incident_manager.EVIDENCE_DIR = self.temp_dir / "evidence"
        incident_manager.init_db()

    def tearDown(self):
        incident_manager.DB_PATH = self.orig_db
        incident_manager.EVIDENCE_DIR = self.orig_evidence
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_priority_calculation(self):
        self.assertEqual(incident_manager.calculate_priority("critical", "mission_critical", "high"), "P1")
        self.assertEqual(incident_manager.calculate_priority("critical", "high", "medium"), "P1")
        self.assertEqual(incident_manager.calculate_priority("high", "high", "medium"), "P2")
        self.assertEqual(incident_manager.calculate_priority("medium", "medium", "low"), "P3")
        self.assertEqual(incident_manager.calculate_priority("low", "low", "none"), "P4")

    def test_incident_creation_and_fields(self):
        inc = incident_manager.create_incident(
            title="Suspicious Ransomware Outbreak",
            severity="critical",
            source_app="threatscope",
            description="Mass file encryption observed",
            source_job_id="12345678123456781234567812345678",
            asset_criticality="mission_critical",
            business_impact="high",
            assigned_to="admin",
            entities=["10.0.0.15", "SRV-FINANCE"],
            actor="test_user",
            reason="Confirmed critical alert",
        )

        self.assertTrue(inc["id"].startswith("INC-"))
        self.assertTrue(inc["correlation_id"].startswith("CORR-"))
        self.assertEqual(inc["title"], "Suspicious Ransomware Outbreak")
        self.assertEqual(inc["severity"], "critical")
        self.assertEqual(inc["priority"], "P1")
        self.assertEqual(inc["status"], "new")
        self.assertEqual(inc["source_app"], "threatscope")
        self.assertEqual(inc["assigned_to"], "admin")
        self.assertIn("10.0.0.15", inc["entities"])

        # Check audit entry
        self.assertEqual(len(inc["audit"]), 1)
        audit_entry = inc["audit"][0]
        self.assertEqual(audit_entry["actor"], "test_user")
        self.assertEqual(audit_entry["action"], "incident.created")
        self.assertEqual(audit_entry["reason"], "Confirmed critical alert")

    def test_lifecycle_transitions_and_rejection(self):
        inc = incident_manager.create_incident(
            title="Suspicious Login Activity",
            severity="medium",
            source_app="logscope",
            actor="analyst1",
        )
        inc_id = inc["id"]

        # Move new -> triaged
        updated = incident_manager.update_status(inc_id, "triaged", "Initial review complete", "analyst1")
        self.assertEqual(updated["status"], "triaged")

        # Move triaged -> investigating
        updated = incident_manager.update_status(inc_id, "investigating", "Starting deep forensic analysis", "analyst1")
        self.assertEqual(updated["status"], "investigating")

        # Move investigating -> rejected (False Positive)
        updated = incident_manager.update_status(inc_id, "rejected", "Confirmed false positive: scheduled IT test", "analyst1")
        self.assertEqual(updated["status"], "rejected")
        self.assertIsNotNone(updated["closed_at"])

        # Reopen rejected -> investigating
        updated = incident_manager.update_status(inc_id, "investigating", "Reopening incident upon new evidence", "analyst2")
        self.assertEqual(updated["status"], "investigating")

        # Invalid transition: investigating -> new should fail
        with self.assertRaises(ValueError):
            incident_manager.update_status(inc_id, "new", "Invalid jump backwards", "analyst1")

    def test_analyst_assignment_and_notes(self):
        inc = incident_manager.create_incident(title="Port Scan Alert", severity="low", source_app="flowscope")
        inc_id = inc["id"]

        assigned = incident_manager.assign_analyst(inc_id, "soc_analyst_1", "manager", "Routine investigation")
        self.assertEqual(assigned["assigned_to"], "soc_analyst_1")
        self.assertEqual(assigned["status"], "triaged")

        # Add notes
        incident_manager.add_note(inc_id, "Checked firewall logs. Traffic originated from scanner IP.", "soc_analyst_1")
        incident_manager.add_note(inc_id, "Verified internal IP is safe.", "soc_analyst_1")

        refreshed = incident_manager.get_incident(inc_id)
        self.assertEqual(len(refreshed["notes"]), 2)
        self.assertEqual(refreshed["notes"][0]["author"], "soc_analyst_1")

    def test_evidence_storage_separation_and_integrity(self):
        inc = incident_manager.create_incident(title="Malware Drop", severity="high", source_app="threatscope")
        inc_id = inc["id"]

        # 1. Text / IOC evidence
        incident_manager.add_evidence_record(
            inc_id, evidence_type="ip", name="C2 IP Address", value="198.51.100.25",
            notes="Active command and control server", added_by="analyst"
        )

        # 2. File evidence (saved outside SQLite with SHA256)
        file_content = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        incident_manager.add_evidence_record(
            inc_id, evidence_type="file", name="dropper.bin",
            file_bytes=file_content, filename="dropper.bin", mime_type="application/octet-stream",
            notes="Extracted dropper payload", added_by="analyst"
        )

        refreshed = incident_manager.get_incident(inc_id)
        self.assertEqual(len(refreshed["evidence"]), 2)

        file_evidence = next(e for e in refreshed["evidence"] if e["evidence_type"] == "file")
        self.assertEqual(file_evidence["size_bytes"], len(file_content))
        self.assertIsNotNone(file_evidence["sha256"])

        # Check physical file on disk
        real_file = incident_manager.get_evidence_file_path(file_evidence["file_path"])
        self.assertTrue(real_file.is_file())
        self.assertEqual(real_file.read_bytes(), file_content)

        # Remove evidence
        incident_manager.remove_evidence_record(inc_id, file_evidence["id"], "analyst", "Purging test evidence")
        self.assertFalse(real_file.is_file())

    def test_server_side_pagination_and_summary(self):
        for i in range(12):
            sev = "critical" if i % 3 == 0 else "high" if i % 3 == 1 else "low"
            incident_manager.create_incident(
                title=f"Incident #{i + 1}",
                severity=sev,
                source_app="logscope" if i % 2 == 0 else "flowscope",
                actor="test",
            )

        items, total = incident_manager.list_incidents(limit=5, offset=0)
        self.assertEqual(total, 12)
        self.assertEqual(len(items), 5)

        items_p2, total2 = incident_manager.list_incidents(limit=5, offset=5)
        self.assertEqual(total2, 12)
        self.assertEqual(len(items_p2), 5)
        self.assertNotEqual(items[0]["id"], items_p2[0]["id"])

        summary = incident_manager.get_incidents_summary()
        self.assertEqual(summary["total"], 12)
        self.assertEqual(summary["by_status"]["new"], 12)
        self.assertEqual(summary["by_severity"]["critical"], 4)


if __name__ == "__main__":
    unittest.main()
