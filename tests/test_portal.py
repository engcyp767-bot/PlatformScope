from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from platform_core import history


class PortalHistoryTests(unittest.TestCase):
    def test_history_combines_apps_and_separates_refresh_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flow_job = root / "flowscope" / "storage" / "jobs" / ("a" * 32)
            threat_job = root / "threatscope" / "storage" / "jobs" / ("b" * 32)
            log_job = root / "logscope" / "storage" / "jobs" / ("c" * 32)
            flow_job.mkdir(parents=True)
            threat_job.mkdir(parents=True)
            log_job.mkdir(parents=True)
            (flow_job / "analysis.json").write_text(json.dumps({
                "metadata": {"filename": "private.csv", "analyzed_at": "2026-08-24T09:00:00+00:00", "data_type": "flows"},
                "analysis": {"status": "completed"},
                "summary": {"records": 10, "unique_ips": 3},
                "records": [],
                "enrichment": {"status": "not_started"},
            }), encoding="utf-8")
            (threat_job / "analysis.json").write_text(json.dumps({
                "metadata": {"filename": "secret.xlsx", "analyzed_at": "2026-08-24T10:00:00+00:00", "sheet": "CSV"},
                "summary": {"records": 5, "unique_hashes": 4},
                "records": [],
                "enrichment": {
                    "status": "completed", "force_refresh": True,
                    "completed_at": "2026-08-24T10:05:00+00:00",
                    "checked": 4, "total": 4, "cached": 0, "new": 4,
                },
            }), encoding="utf-8")
            (log_job / "analysis.json").write_text(json.dumps({
                "metadata": {"analyzed_at": "2026-08-24T11:00:00+00:00", "data_type": "siem_logs"},
                "analysis": {"status": "completed"},
                "total_records": 7, "unique_ips_count": 2,
                "records": [], "events": [], "enrichment": {"status": "not_started"},
            }), encoding="utf-8")

            operations = history.operation_history(root)

        self.assertEqual(len(operations), 4)
        self.assertEqual({item["application"] for item in operations}, {"flowscope", "threatscope", "logscope"})
        self.assertIn("refresh", {item["operation"] for item in operations})
        self.assertNotIn("filename", json.dumps(operations))
        self.assertTrue(all("?job=" not in item["target_url"] for item in operations))
        self.assertTrue(all(item["target_url"].count("/") == 2 for item in operations))
        self.assertTrue(any(item["target_url"].endswith("a" * 32) for item in operations))
        self.assertTrue(any(item["target_url"].endswith("b" * 32) for item in operations))
        self.assertTrue(any(item["target_url"].endswith("c" * 32) for item in operations))
        self.assertTrue(any(item["application"] == "logscope" and item["records"] == 7 and item["indicators"] == 2 for item in operations))
        self.assertTrue(all(item["source_system"] == "unspecified" for item in operations))
        self.assertTrue(all(item["source_system_label"] == "غير محدد — ملف سابق" for item in operations))
        self.assertGreaterEqual(operations[0]["timestamp"], operations[-1]["timestamp"])


if __name__ == "__main__":
    unittest.main()
