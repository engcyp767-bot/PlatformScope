"""Unit tests for decoupled Risk, Confidence, and Explainability."""

import unittest
from logscope.canonical import (
    CanonicalEvent,
    DetectionFinding,
    ActionDisposition,
    ConclusionLevel,
)
from logscope.risk_engine import RiskEngine


class RiskEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = RiskEngine()

    def test_high_risk_low_confidence_scenario(self):
        # Critical priority from unknown source, no IPs, no actor
        event = CanonicalEvent(priority="Critical", message="Unidentified emergency alarm")
        self.engine.evaluate(event)

        self.assertGreaterEqual(event.risk_score, 70)  # High Risk
        self.assertLessEqual(event.confidence_score, 45)  # Low Confidence!
        self.assertEqual(event.conclusion_level, ConclusionLevel.OBSERVED)

    def test_high_risk_high_confidence_scenario(self):
        # Specific finding, complete IPs, active Incident
        event = CanonicalEvent(
            source_ip="10.0.0.5",
            destination_ip="192.168.1.1",
            incident_id="INC-AUTH-00001",
            findings=[
                DetectionFinding(
                    detection_id="DET-WIN-RANSOM-001",
                    title_ar="حذف النسخ الاحتياطية",
                    description_ar="vssadmin shadowcopy delete",
                    base_severity=95,
                    confidence=90,
                    conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                )
            ]
        )
        self.engine.evaluate(event)

        self.assertGreaterEqual(event.risk_score, 90)  # High Risk
        self.assertGreaterEqual(event.confidence_score, 90)  # High Confidence
        self.assertEqual(event.severity, "حرج")
        self.assertEqual(event.conclusion_level, ConclusionLevel.CONFIRMED)

    def test_mitigation_by_blocking(self):
        # Finding with base_severity=80, but ActionDisposition.BLOCK
        event = CanonicalEvent(
            action="block",
            action_disposition=ActionDisposition.BLOCK,
            findings=[
                DetectionFinding(
                    detection_id="DET-TEST-001",
                    title_ar="تجربة هجوم",
                    description_ar="اختبار",
                    base_severity=80,
                    confidence=85,
                )
            ]
        )
        self.engine.evaluate(event)

        # Risk was reduced due to block
        self.assertEqual(event.risk_score, 65)  # 80 - 15 = 65
        self.assertTrue(any("إحباط ومنع" in r for r in event.risk_explanation.reasons_for_decrease))

    def test_escalation_by_allowing(self):
        # Finding with base_severity=80, but ActionDisposition.ALLOW
        event = CanonicalEvent(
            action="allow",
            action_disposition=ActionDisposition.ALLOW,
            findings=[
                DetectionFinding(
                    detection_id="DET-TEST-001",
                    title_ar="تجربة هجوم",
                    description_ar="اختبار",
                    base_severity=80,
                    confidence=85,
                )
            ]
        )
        self.engine.evaluate(event)

        # Risk was increased due to allow
        self.assertEqual(event.risk_score, 95)  # 80 + 15 = 95
        self.assertTrue(any("السماح بمرور" in r for r in event.risk_explanation.reasons_for_increase))

    def test_explainability_structure(self):
        event = CanonicalEvent(
            source_ip="1.2.3.4",
            destination_ip="5.6.7.8",
            findings=[
                DetectionFinding(
                    detection_id="DET-EXPLAIN-001",
                    title_ar="كشف قابل للتفسير",
                    description_ar="تجربة",
                    base_severity=70,
                    confidence=80,
                )
            ]
        )
        self.engine.evaluate(event)

        exp = event.risk_explanation
        self.assertIsNotNone(exp)
        self.assertIn("DET-EXPLAIN-001", exp.matched_rules)
        self.assertTrue(len(exp.reasons_for_increase) > 0)
        self.assertTrue(len(exp.confidence_factors) > 0)


if __name__ == "__main__":
    unittest.main()
