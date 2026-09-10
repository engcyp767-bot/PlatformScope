"""Unit tests for WindowsDetector and False Positive verification."""

import unittest
from logscope.canonical import CanonicalEvent, ConclusionLevel
from logscope.detectors.windows import WindowsDetector


class WindowsDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = WindowsDetector()

    def test_audit_log_cleared_1102(self):
        event = CanonicalEvent(event_id="1102", message="The audit log was cleared")
        findings = self.detector.analyze_event(event)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detection_id, "DET-WIN-EVASION-001")
        self.assertEqual(findings[0].base_severity, 95)
        self.assertEqual(findings[0].conclusion_level, ConclusionLevel.LIKELY_MALICIOUS)

    def test_failed_logon_substatus_locked_out(self):
        event = CanonicalEvent(event_id="4625", username="admin", raw_fields={"SubStatus": "0xC0000234"})
        findings = self.detector.analyze_event(event)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detection_id, "DET-WIN-AUTH-003")
        self.assertIn("مغلق", findings[0].description_ar)

    def test_ransomware_shadow_copy_deletion(self):
        event = CanonicalEvent(
            event_id="4688",
            message="Process created",
            raw_fields={"CommandLine": "vssadmin.exe delete shadows /all /quiet"}
        )
        findings = self.detector.analyze_event(event)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detection_id, "DET-WIN-RANSOM-001")
        self.assertEqual(findings[0].base_severity, 95)

    def test_suspicious_encoded_powershell(self):
        event = CanonicalEvent(
            event_id="4688",
            message="Process created",
            raw_fields={"CommandLine": "powershell.exe -nop -w hidden -encodedcommand SQBFAFgA..."}
        )
        findings = self.detector.analyze_event(event)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detection_id, "DET-WIN-EXEC-001")
        self.assertEqual(findings[0].conclusion_level, ConclusionLevel.LIKELY_MALICIOUS)

    def test_false_positive_benign_powershell(self):
        # Legitimate administrative PowerShell execution must NOT trigger alert!
        event = CanonicalEvent(
            event_id="4688",
            message="Process created",
            raw_fields={"CommandLine": "powershell.exe Get-Service -Name Spooler"}
        )
        findings = self.detector.analyze_event(event)
        self.assertEqual(len(findings), 0)

    def test_false_positive_benign_interactive_logon(self):
        # Normal interactive logon must be marked Observed, not Suspicious or Malicious
        event = CanonicalEvent(
            event_id="4624",
            username="jdoe",
            raw_fields={"LogonType": "2"}
        )
        findings = self.detector.analyze_event(event)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detection_id, "DET-WIN-LOGON-001")
        self.assertEqual(findings[0].conclusion_level, ConclusionLevel.OBSERVED)
        self.assertLessEqual(findings[0].base_severity, 30)


if __name__ == "__main__":
    unittest.main()
