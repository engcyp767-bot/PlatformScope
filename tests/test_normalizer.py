"""Unit tests for FieldNormalizer and Ground Truth Mapping Accuracy."""

import unittest
from logscope.normalizer import FieldNormalizer
from logscope.canonical import ActionDisposition


class FieldNormalizerTests(unittest.TestCase):
    def test_field_mapping_with_varied_headers(self):
        headers = ["ClientIP", "DestIP", "Sport", "Dport", "Proto", "UserAccount", "EventID", "Operation", "Details"]
        normalizer = FieldNormalizer(headers)

        row = ["192.168.10.50", "10.0.0.5", "50123", "443", "tcp", "jdoe", "4624", "Permit", "Successful logon"]
        evt = normalizer.normalize_row(row)

        self.assertEqual(evt.source_ip, "192.168.10.50")
        self.assertEqual(evt.destination_ip, "10.0.0.5")
        self.assertEqual(evt.source_port, 50123)
        self.assertEqual(evt.destination_port, 443)
        self.assertEqual(evt.service_name, "HTTPS")
        self.assertEqual(evt.protocol, "TCP")
        self.assertEqual(evt.username, "jdoe")
        self.assertEqual(evt.event_id, "4624")
        self.assertEqual(evt.action, "Permit")
        self.assertEqual(evt.action_disposition, ActionDisposition.ALLOW)
        self.assertEqual(evt.message, "Successful logon")
        self.assertIn("ClientIP", evt.raw_fields)

    def test_classified1_firewall_syslog_stream_compatibility(self):
        # Exact headers from المصنف1.csv
        headers = ["Time", "Device", "Source IP", "Destination IP", "Attack Name", "Action", "Application", "Source Zone", "Transmission Protocol", "Message"]
        normalizer = FieldNormalizer(headers)

        row = [
            "8/31/2026 0:00", "10.47.15.5", "10.221.118.180", "114.114.114.114", "Virus", "Block", "DNS", "trust", "UDP",
            'CID=0x814f041e;An intrusion was detected. (SyslogId=31037711, SrcIp=10.221.118.180, DstIp=114.114.114.114, SrcPort=45123, DstPort=53, User="unknown", Protocol=UDP, Action=Block)'
        ]
        evt = normalizer.normalize_row(row)

        self.assertEqual(evt.source_ip, "10.221.118.180")
        self.assertEqual(evt.destination_ip, "114.114.114.114")
        self.assertEqual(evt.event_id, "31037711")
        self.assertEqual(evt.action, "Block")
        self.assertEqual(evt.action_disposition, ActionDisposition.BLOCK)
        self.assertEqual(evt.source_port, 45123)
        self.assertEqual(evt.destination_port, 53)
        self.assertEqual(evt.service_name, "DNS")
        self.assertEqual(evt.username, "")  # "unknown" cleaned
        self.assertEqual(len(evt.raw_fields), 10)


if __name__ == "__main__":
    unittest.main()
