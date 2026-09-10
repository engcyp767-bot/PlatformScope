"""Unit tests for CanonicalEvent, DetectionFinding, and Incident data structures."""

import unittest
from datetime import datetime
from logscope.canonical import (
    CanonicalEvent,
    DetectionFinding,
    Incident,
    ConclusionLevel,
    ActionDisposition,
    RiskExplanation,
)


class CanonicalModelTests(unittest.TestCase):
    def test_canonical_event_defaults_and_projection(self):
        event = CanonicalEvent(
            event_time="2026-09-03 12:00:00",
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            source_port=54321,
            destination_port=443,
            protocol="TCP",
            service_name="HTTPS",
            username="admin",
            hostname="DC01",
            device="Firewall-01",
            event_id="4625",
            action="block",
            action_disposition=ActionDisposition.BLOCK,
            status="Failure",
            priority="High",
            message="An account failed to log on",
            log_source="Windows Security",
            raw_fields={"OriginalEvent": "4625", "SubStatus": "0xC000006A"},
        )
        event.extracted_ips.add("192.168.1.50")
        event.extracted_ips.add("10.0.0.1")
        event.risk_score = 85
        event.confidence_score = 90
        event.severity = "مرتفع"
        event.conclusion_level = ConclusionLevel.LIKELY_MALICIOUS
        event.description_ar = "محاولة تسجيل دخول فاشلة"
        event.action_ar = "حظر"
        event.threat_family = "وصول أولي (Initial Access)"
        event.detection_ids.append("DET-WIN-4625")

        projected = event.to_dict()

        # UI & Storage Contract Assertions
        self.assertEqual(projected["event_time"], "2026-09-03 12:00:00")
        self.assertEqual(projected["src_ip"], "192.168.1.50")
        self.assertEqual(projected["destination"], "10.0.0.1")
        self.assertEqual(projected["src_port"], "54321")
        self.assertEqual(projected["dst_port"], "443")
        self.assertEqual(projected["protocol"], "TCP")
        self.assertEqual(projected["service_name"], "HTTPS")
        self.assertEqual(projected["user_account"], "admin")
        self.assertEqual(projected["device"], "Firewall-01")
        self.assertEqual(projected["event_id"], "4625")
        self.assertEqual(projected["action"], "block")
        self.assertEqual(projected["action_ar"], "حظر")
        self.assertEqual(projected["risk_score"], 85)
        self.assertEqual(projected["confidence_score"], 90)
        self.assertEqual(projected["severity"], "مرتفع")
        self.assertEqual(projected["conclusion_level"], "likely_malicious")
        self.assertEqual(projected["raw_fields"]["SubStatus"], "0xC000006A")
        self.assertIn("192.168.1.50", projected["extracted_ips"])

    def test_action_disposition_helper(self):
        self.assertEqual(ActionDisposition.from_string("DROP"), ActionDisposition.BLOCK)
        self.assertEqual(ActionDisposition.from_string("Permit"), ActionDisposition.ALLOW)
        self.assertEqual(ActionDisposition.from_string("Alert"), ActionDisposition.ALERT)
        self.assertEqual(ActionDisposition.from_string("Unknown"), ActionDisposition.UNKNOWN)

    def test_detection_finding_and_incident(self):
        finding = DetectionFinding(
            detection_id="DET-WIN-BRUTEFORCE-001",
            title_ar="هجوم تخمين كلمات المرور",
            description_ar="محاولات متكررة من نفس العنوان",
            base_severity=80,
            confidence=85,
            conclusion_level=ConclusionLevel.CORRELATED_SUSPICIOUS,
            mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
            mitre_techniques=["T1110.001 - Password Guessing"],
        )
        self.assertEqual(finding.detection_id, "DET-WIN-BRUTEFORCE-001")
        self.assertEqual(finding.conclusion_level, ConclusionLevel.CORRELATED_SUSPICIOUS)

        incident = Incident(
            incident_id="INC-2026-0001",
            title_ar="اشتباه هجوم تخمين ثم تصعيد صلاحيات",
            description_ar="تسلسل أحداث بدءاً من محاولات فاشلة حتى إنشاء خدمة",
            source_ips=["192.168.1.100"],
            event_count=35,
            detection_ids=["DET-WIN-BRUTEFORCE-001", "DET-WIN-PERSIST-001"],
            risk_score=95,
            confidence_score=92,
            conclusion_level=ConclusionLevel.CONFIRMED,
        )
        self.assertEqual(incident.incident_id, "INC-2026-0001")
        self.assertEqual(incident.event_count, 35)
        self.assertEqual(incident.conclusion_level, ConclusionLevel.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
