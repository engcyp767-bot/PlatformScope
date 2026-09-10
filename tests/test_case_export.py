"""Tests for Security Case Export and Forensic SHA-256 Integrity Verification."""

import io
import json
import unittest
import zipfile

from platform_core import incident_manager
from platform_core.case_export import SecurityCaseExporter, SecurityCaseVerifier


class TestCaseExport(unittest.TestCase):

    def setUp(self):
        incident_manager.init_db()
        # Create a test incident
        self.inc = incident_manager.create_incident(
            title="اختبار هجوم فدية وتسلل شبكي C2",
            description="رصد اتصال بخادم تحكم C2 خارجي ومحاولة حذف نسخ الظل",
            severity="critical",
            source_app="ThreatScope",
            mitre_tactics=["TA0002", "TA0011"],
            mitre_techniques=["T1059", "T1071"],
            entities=["185.220.101.5", "powershell.exe", "user_victim"],
            asset_criticality="high",
            business_impact="high",
            actor="analyst_test",
        )
        self.inc_id = self.inc["id"]

        # Add notes
        incident_manager.add_note(
            self.inc_id,
            "تم عزل الجهاز والتأكد من إيقاف حركة المرور الشبكية.",
            author="lead_analyst"
        )

        # Add evidence
        incident_manager.add_evidence_record(
            self.inc_id,
            evidence_type="ip",
            name="C2 Server IP",
            value="185.220.101.5",
            notes="Active Cobalt Strike listener",
            added_by="analyst_test"
        )
        incident_manager.add_evidence_record(
            self.inc_id,
            evidence_type="hash",
            name="Malware Payload Hash",
            value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            notes="Dropper binary SHA256",
            added_by="analyst_test"
        )
        incident_manager.add_evidence_record(
            self.inc_id,
            evidence_type="log_snippet",
            name="Encoded PowerShell Log",
            value="powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAA=",
            notes="Event 4688 commandline",
            added_by="analyst_test"
        )

    def test_export_security_case_zip_structure(self):
        zip_bytes, filename = SecurityCaseExporter.export_case(self.inc_id, actor="test_runner")
        self.assertTrue(filename.startswith(f"{self.inc_id}_forensic_case"))
        self.assertTrue(len(zip_bytes) > 0)

        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            self.assertIn("metadata.json", names)
            self.assertIn("timeline.json", names)
            self.assertIn("events.json", names)
            self.assertIn("iocs.json", names)
            self.assertIn("analyst_notes.json", names)
            self.assertIn("reports/case_summary.json", names)
            self.assertIn("reports/case_report.md", names)
            self.assertIn("manifest.sha256", names)
            self.assertIn("integrity_seal.json", names)

            # Check metadata
            meta = json.loads(zf.read("metadata.json").decode("utf-8"))
            self.assertEqual(meta["case_id"], self.inc_id)
            self.assertEqual(meta["severity"], "critical")
            self.assertEqual(meta["exported_by"], "test_runner")

            # Check iocs
            iocs = json.loads(zf.read("iocs.json").decode("utf-8"))
            self.assertTrue(any(i.get("value") == "185.220.101.5" for i in iocs))

            # Check manifest format
            manifest_text = zf.read("manifest.sha256").decode("utf-8")
            lines = [line.strip() for line in manifest_text.strip().splitlines() if line.strip()]
            self.assertTrue(len(lines) >= 7)
            for line in lines:
                parts = line.split(maxsplit=1)
                self.assertEqual(len(parts), 2)
                self.assertEqual(len(parts[0]), 64) # 64-char sha256

    def test_verify_valid_security_case(self):
        zip_bytes, _ = SecurityCaseExporter.export_case(self.inc_id, actor="test_runner")
        res = SecurityCaseVerifier.verify_case(zip_bytes)
        self.assertTrue(res["valid"])
        self.assertEqual(res["case_id"], self.inc_id)
        self.assertEqual(res["mismatches_count"], 0)
        self.assertEqual(res["missing_count"], 0)
        self.assertTrue(res["seal_valid"])
        self.assertGreater(res["verified_files_count"], 5)

    def test_detect_tampered_file_in_case(self):
        zip_bytes, _ = SecurityCaseExporter.export_case(self.inc_id, actor="test_runner")
        
        # Tamper with metadata.json inside the zip
        orig_zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        tampered_buffer = io.BytesIO()
        with zipfile.ZipFile(tampered_buffer, "w", compression=zipfile.ZIP_DEFLATED) as new_zf:
            for item in orig_zf.infolist():
                if item.filename == "metadata.json":
                    # Tamper data
                    new_zf.writestr(item.filename, b'{"case_id": "TAMPERED"}')
                else:
                    new_zf.writestr(item.filename, orig_zf.read(item.filename))
        
        tampered_bytes = tampered_buffer.getvalue()
        res = SecurityCaseVerifier.verify_case(tampered_bytes)
        self.assertFalse(res["valid"])
        self.assertGreaterEqual(res["mismatches_count"], 1)
        self.assertTrue(any(m["path"] == "metadata.json" for m in res["mismatches"]))

    def test_detect_missing_file_in_case(self):
        zip_bytes, _ = SecurityCaseExporter.export_case(self.inc_id, actor="test_runner")
        
        # Remove timeline.json
        orig_zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        tampered_buffer = io.BytesIO()
        with zipfile.ZipFile(tampered_buffer, "w", compression=zipfile.ZIP_DEFLATED) as new_zf:
            for item in orig_zf.infolist():
                if item.filename != "timeline.json":
                    new_zf.writestr(item.filename, orig_zf.read(item.filename))
        
        tampered_bytes = tampered_buffer.getvalue()
        res = SecurityCaseVerifier.verify_case(tampered_bytes)
        self.assertFalse(res["valid"])
        self.assertIn("timeline.json", res["missing"])

    def test_detect_untracked_injected_file(self):
        zip_bytes, _ = SecurityCaseExporter.export_case(self.inc_id, actor="test_runner")
        
        # Inject an unauthorized file
        orig_zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        tampered_buffer = io.BytesIO()
        with zipfile.ZipFile(tampered_buffer, "w", compression=zipfile.ZIP_DEFLATED) as new_zf:
            for item in orig_zf.infolist():
                new_zf.writestr(item.filename, orig_zf.read(item.filename))
            new_zf.writestr("injected_backdoor.bin", b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        
        tampered_bytes = tampered_buffer.getvalue()
        res = SecurityCaseVerifier.verify_case(tampered_bytes)
        self.assertFalse(res["valid"])
        self.assertIn("injected_backdoor.bin", res["untracked"])

    def test_ed25519_signature_and_iso_compliance(self):
        zip_bytes, _ = SecurityCaseExporter.export_case(self.inc_id, actor="lead_forensic_analyst")
        res = SecurityCaseVerifier.verify_case(zip_bytes)
        self.assertTrue(res["valid"])
        self.assertTrue(res["signature_valid"])
        self.assertTrue(res["seal_valid"])
        self.assertFalse(res["tamper_detected"])
        self.assertEqual(res["integrity_status"], "SEALED_AND_VERIFIED_AUTHENTIC")
        self.assertTrue(any("ISO/IEC 27037" in s for s in res["standard_compliance"]))
        self.assertTrue(any("NIST SP 800-86" in s for s in res["standard_compliance"]))

    def test_detect_tampered_signature_or_manifest(self):
        zip_bytes, _ = SecurityCaseExporter.export_case(self.inc_id, actor="lead_forensic_analyst")
        
        # Tamper with manifest.sig
        orig_zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        tampered_buffer = io.BytesIO()
        with zipfile.ZipFile(tampered_buffer, "w", compression=zipfile.ZIP_DEFLATED) as new_zf:
            for item in orig_zf.infolist():
                if item.filename == "manifest.sig":
                    # Corrupted signature
                    new_zf.writestr(item.filename, b"00" * 64)
                else:
                    new_zf.writestr(item.filename, orig_zf.read(item.filename))
        
        tampered_bytes = tampered_buffer.getvalue()
        res = SecurityCaseVerifier.verify_case(tampered_bytes)
        self.assertFalse(res["valid"])
        self.assertFalse(res["signature_valid"])
        self.assertTrue(res["tamper_detected"])
        self.assertEqual(res["integrity_status"], "TAMPERED_OR_INVALID")


if __name__ == "__main__":
    unittest.main()
