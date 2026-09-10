"""Comprehensive unit test suite for Threat Intelligence & Central IOC Knowledge Base."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from platform_core import threat_intel
from platform_core.threat_intel import (
    ThreatIntelManager,
    ThreatIntelDetector,
    normalize_ioc_value,
    detect_hash_type,
    IndicatorOfCompromise,
)
from logscope.canonical import CanonicalEvent, ActionDisposition, ConclusionLevel


class TestThreatIntelModule(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.orig_db = threat_intel.DB_PATH

        self.test_db_path = self.temp_dir / "threat_intel_test.sqlite3"
        threat_intel.DB_PATH = self.test_db_path

        # Reset singleton instance for test isolation
        ThreatIntelManager._instance = None
        self.mgr = ThreatIntelManager.get_instance()

    def tearDown(self):
        threat_intel.DB_PATH = self.orig_db
        ThreatIntelManager._instance = None
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_normalization_and_hash_detection(self):
        # IP normalization
        t, v = normalize_ioc_value("ip", "  198.51.100.44  ")
        self.assertEqual(t, "ip")
        self.assertEqual(v, "198.51.100.44")

        # CIDR normalization
        t, v = normalize_ioc_value("ip", "10.0.0.1/24")
        self.assertEqual(t, "ip")
        self.assertEqual(v, "10.0.0.0/24")

        # Domain normalization
        t, v = normalize_ioc_value("domain", "  https://EVIL-DOMAIN.COM:8080/path?query=1  ")
        self.assertEqual(t, "domain")
        self.assertEqual(v, "evil-domain.com")

        # URL normalization
        t, v = normalize_ioc_value("url", "HTTP://Evil.com/Payload.exe?ID=1#anchor")
        self.assertEqual(t, "url")
        self.assertEqual(v, "http://evil.com/Payload.exe?ID=1")

        # Hash detection
        md5_val = "7b8f9e2d1c3a4b5e6f7a8b9c0d1e2f3a"
        sha1_val = "7b8f9e2d1c3a4b5e6f7a8b9c0d1e2f3a4b5c6d7e"
        sha256_val = "7b8f9e2d1c3a4b5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e"

        self.assertEqual(detect_hash_type(md5_val), "hash_md5")
        self.assertEqual(detect_hash_type(sha1_val), "hash_sha1")
        self.assertEqual(detect_hash_type(sha256_val), "hash_sha256")
        self.assertIsNone(detect_hash_type("invalid_hash"))

    def test_crud_and_duplicate_prevention(self):
        # Initial seeds exist
        iocs, total = self.mgr.list_iocs()
        self.assertGreater(total, 0)

        # Add new custom IOC
        ioc = self.mgr.add_ioc(
            ioc_type="ip",
            value="192.0.2.100",
            threat_type="c2",
            severity="critical",
            confidence=95,
            source="SOC Investigation",
            tags=["unit_test", "c2"],
            tlp="amber",
            description="Test C2 Endpoint",
            related_threat_actor="APT-X",
        )
        self.assertIsNotNone(ioc.id)
        self.assertEqual(ioc.value, "192.0.2.100")
        self.assertEqual(ioc.severity, "critical")
        self.assertEqual(ioc.confidence, 95)
        self.assertIn("unit_test", ioc.tags)

        # Duplicate addition should raise ValueError
        with self.assertRaises(ValueError):
            self.mgr.add_ioc(ioc_type="ip", value="192.0.2.100")

        # Retrieve IOC
        fetched = self.mgr.get_ioc(ioc.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.value, "192.0.2.100")

        # Update IOC
        updated = self.mgr.update_ioc(
            ioc.id,
            severity="medium",
            confidence=60,
            description="Updated description",
            is_active=False,
        )
        self.assertEqual(updated.severity, "medium")
        self.assertEqual(updated.confidence, 60)
        self.assertFalse(updated.is_active)

        # Delete IOC
        deleted = self.mgr.delete_ioc(ioc.id)
        self.assertTrue(deleted)
        self.assertIsNone(self.mgr.get_ioc(ioc.id))

    def test_fast_in_memory_matching(self):
        # Add test indicators for all modalities
        self.mgr.add_ioc(ioc_type="ip", value="198.18.0.1", threat_type="c2", severity="high")
        self.mgr.add_ioc(ioc_type="ip", value="10.200.0.0/16", threat_type="scanner", severity="medium")
        self.mgr.add_ioc(ioc_type="domain", value="malware-download-cdn.org", threat_type="malware", severity="critical")
        self.mgr.add_ioc(ioc_type="url", value="http://malware-download-cdn.org/dropper.sh", threat_type="malware", severity="critical")
        self.mgr.add_ioc(ioc_type="hash_sha256", value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", threat_type="ransomware")

        # 1. Direct IP matching
        matches = self.mgr.match_value("198.18.0.1")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].value, "198.18.0.1")

        # 2. CIDR subnet matching
        matches = self.mgr.match_value("10.200.45.99")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].value, "10.200.0.0/16")

        # Clean IP should not match
        self.assertEqual(len(self.mgr.match_value("1.1.1.1")), 0)

        # 3. Domain matching (case insensitive)
        matches = self.mgr.match_value("MALWARE-DOWNLOAD-CDN.ORG")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].threat_type, "malware")

        # 4. URL matching
        matches = self.mgr.match_value("http://malware-download-cdn.org/dropper.sh")
        self.assertEqual(len(matches), 1)

        # 5. Hash matching
        matches = self.mgr.match_value("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        self.assertEqual(len(matches), 1)

    def test_event_matching_and_detector(self):
        # Seed IOC
        ioc = self.mgr.add_ioc(
            ioc_type="ip",
            value="198.51.100.99",
            threat_type="c2",
            severity="critical",
            confidence=90,
            source="Firewall Alert",
            mitre_attack={"tactics": ["Command and Control"], "techniques": ["T1071.001"]},
        )

        evt = CanonicalEvent(
            event_id="EVT-001",
            event_time="2026-09-05T12:00:00Z",
            source_ip="198.51.100.99",
            destination_ip="10.0.0.5",
            action="ALLOW",
            action_disposition=ActionDisposition.ALLOW,
        )

        detector = ThreatIntelDetector()
        findings = detector.analyze_event(evt)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertIn(ioc.id, finding.detection_id)
        self.assertEqual(finding.confidence, 90)
        self.assertEqual(finding.mitre_tactics, ["Command and Control"])
        self.assertEqual(finding.mitre_techniques, ["T1071.001"])

        # Check hit counter incremented
        hits = self.mgr.get_ioc_hits(ioc.id)
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["source_app"], "logscope")

    def test_import_and_export_csv_json_stix(self):
        # CSV Import
        csv_data = """value,type,threat_type,severity,confidence,source
192.0.2.201,ip,c2,high,85,CSV Test
test-phish-domain.org,domain,phishing,critical,95,CSV Test
"""
        res = self.mgr.import_csv(csv_data)
        self.assertEqual(res["imported"], 2)
        self.assertEqual(res["skipped"], 0)

        # Export CSV
        exported_csv = self.mgr.export_csv()
        self.assertIn("192.0.2.201", exported_csv)
        self.assertIn("test-phish-domain.org", exported_csv)

        # JSON Export & Import
        exported_json = self.mgr.export_json()
        parsed = json.loads(exported_json)
        self.assertIsInstance(parsed, list)
        self.assertGreater(len(parsed), 0)

        # STIX 2.1 Export & Import
        exported_stix = self.mgr.export_stix()
        stix_bundle = json.loads(exported_stix)
        self.assertEqual(stix_bundle["type"], "bundle")
        self.assertIn("objects", stix_bundle)
        self.assertGreater(len(stix_bundle["objects"]), 0)

        # Test STIX indicator pattern structure
        ind = stix_bundle["objects"][0]
        self.assertEqual(ind["type"], "indicator")
        self.assertEqual(ind["spec_version"], "2.1")
        self.assertTrue(ind["pattern"].startswith("["))

    def test_summary_metrics(self):
        summary = self.mgr.get_summary()
        self.assertIn("total_iocs", summary)
        self.assertIn("active_iocs", summary)
        self.assertIn("by_type", summary)
        self.assertIn("by_severity", summary)
        self.assertIn("by_threat_type", summary)
        self.assertIn("top_hits", summary)
        self.assertIn("recent_added", summary)
        self.assertGreater(summary["total_iocs"], 0)


if __name__ == "__main__":
    unittest.main()
