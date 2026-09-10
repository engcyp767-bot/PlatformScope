"""Unit tests for universal file parser (CSV, XLSX, JSON, JSONL, Syslog, TXT)."""

import unittest
from logscope.file_parser import read_file


class UniversalFileParserTests(unittest.TestCase):
    def test_json_array_parsing(self):
        json_content = b"""[
            {"timestamp": "2026-09-03 10:00:00", "host": "srv1", "ip": "10.0.0.1", "action": "allow"},
            {"timestamp": "2026-09-03 10:00:01", "host": "srv2", "ip": "10.0.0.2", "action": "block"}
        ]"""
        parsed = read_file(json_content, filename="logs.json")
        self.assertEqual(parsed.source_format, "JSON")
        self.assertEqual(parsed.total_rows, 2)
        self.assertIn("ip", parsed.headers)
        rows = list(parsed.rows)
        self.assertEqual(len(rows), 2)
        ip_idx = parsed.headers.index("ip")
        self.assertEqual(rows[0][ip_idx], "10.0.0.1")

    def test_jsonl_parsing(self):
        jsonl_content = b"""{"event_id": "4624", "user": "alice"}\n{"event_id": "4625", "user": "bob"}"""
        parsed = read_file(jsonl_content, filename="events.jsonl")
        self.assertEqual(parsed.source_format, "JSONL")
        self.assertEqual(parsed.total_rows, 2)
        self.assertIn("event_id", parsed.headers)
        rows = list(parsed.rows)
        self.assertEqual(len(rows), 2)
        user_idx = parsed.headers.index("user")
        self.assertEqual(rows[1][user_idx], "bob")

    def test_raw_syslog_parsing(self):
        syslog_content = b"""Sep  3 14:15:20 firewall01 sshd[9876]: Failed password for root from 192.168.1.100 port 45212 ssh2
Sep  3 14:15:21 firewall01 sshd[9877]: Failed password for root from 192.168.1.100 port 45214 ssh2
Sep  3 14:15:22 firewall01 sshd[9878]: Failed password for root from 192.168.1.100 port 45216 ssh2
Sep  3 14:15:23 firewall01 sshd[9879]: Failed password for root from 192.168.1.100 port 45218 ssh2"""
        parsed = read_file(syslog_content, filename="auth.log")
        self.assertEqual(parsed.source_format, "Syslog")
        self.assertIn("Host", parsed.headers)
        self.assertIn("Process", parsed.headers)
        rows = list(parsed.rows)
        self.assertEqual(len(rows), 4)
        host_idx = parsed.headers.index("Host")
        self.assertEqual(rows[0][host_idx], "firewall01")

    def test_csv_backward_compatibility(self):
        csv_content = b"Time,Source IP,Action\n8/31/2026 0:00,10.0.0.1,Block\n8/31/2026 0:01,10.0.0.2,Allow"
        parsed = read_file(csv_content, filename="test.csv")
        self.assertEqual(parsed.source_format, "CSV")
        self.assertEqual(parsed.headers, ["Time", "Source IP", "Action"])
        rows = list(parsed.rows)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][1], "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
