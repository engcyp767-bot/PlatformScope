"""Unit tests for SourceDetector ground-truth accuracy and evidence checking."""

import unittest
from logscope.source_detector import SourceDetector


class SourceDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = SourceDetector()

    def test_windows_ad_detection(self):
        headers = ["Event ID", "TimeGenerated", "Account Name", "Logon Type", "Workstation Name"]
        sample_rows = [["4625", "2026-09-03", "Administrator", "10", "WORKSTATION-1"]]
        res = self.detector.detect(headers, sample_rows)
        self.assertEqual(res.source_id, "windows_active_directory")
        self.assertGreaterEqual(res.confidence, 85)
        self.assertTrue(len(res.evidence) >= 2)
        self.assertEqual(res.analysis_mode, "full")

    def test_classified1_firewall_detection(self):
        headers = ["Time", "Device", "Source IP", "Destination IP", "Attack Name", "Action", "Application", "Source Zone", "Transmission Protocol", "Message"]
        sample_rows = [[
            "8/31/2026 0:00", "10.47.15.5", "10.221.118.180", "114.114.114.114", "Virus", "Block", "DNS", "trust", "UDP",
            'CID=0x814f041e;An intrusion was detected. (SyslogId=31037711, SrcIp=10.221.118.180)'
        ]]
        res = self.detector.detect(headers, sample_rows)
        self.assertEqual(res.source_id, "firewall_utm")
        self.assertGreaterEqual(res.confidence, 88)
        self.assertTrue(any("CID" in e or "SyslogId" in e for e in res.evidence))

    def test_linux_syslog_detection(self):
        headers = ["timestamp", "host", "ident", "message"]
        sample_rows = [["Sep 3 12:00:00", "server1", "sshd[1234]", "Failed password for root from 192.168.1.5"]]
        res = self.detector.detect(headers, sample_rows)
        self.assertEqual(res.source_id, "linux_syslog")
        self.assertGreaterEqual(res.confidence, 78)

    def test_unknown_partial_analysis(self):
        headers = ["col1", "col2", "col3"]
        sample_rows = [["10.0.0.1", "valA", "valB"]]
        res = self.detector.detect(headers, sample_rows)
        self.assertEqual(res.source_id, "unknown_generic")
        self.assertEqual(res.analysis_mode, "partial")
        self.assertTrue(len(res.evidence) >= 1)


if __name__ == "__main__":
    unittest.main()
