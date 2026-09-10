from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from platform_core import learning_engine


class LearningEngineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.store_patch = patch.object(
            learning_engine, "STORE", Path(self.temporary.name) / "learning.sqlite3"
        )
        self.store_patch.start()

    def tearDown(self):
        self.store_patch.stop()
        self.temporary.cleanup()

    @staticmethod
    def _flow_record(event_type="DNSQUERY", transfer="Transferred: 1 MiB", source="10.0.0.1"):
        return {
            "event_type": event_type, "priority": "LOW", "protocol": "UDP",
            "dst_port": "53", "src_port": "50000", "event_source": source,
            "event_targets": ["8.8.8.8"], "detail": transfer, "attributes": "",
        }

    def test_history_is_learned_once_and_outlier_is_explained(self):
        baseline = {"metadata": {"source_system": "flow_1"}, "records": [self._flow_record() for _ in range(30)]}
        learning_engine.annotate_analysis("flowscope", "a" * 32, baseline)
        first_status = learning_engine.model_status()["flowscope"]
        self.assertEqual(first_status["learned_observations"], 30)

        duplicate = {"metadata": {"source_system": "flow_1"}, "records": [self._flow_record() for _ in range(30)]}
        learning_engine.annotate_analysis("flowscope", "b" * 32, duplicate)
        second_status = learning_engine.model_status()["flowscope"]
        self.assertEqual(second_status["learned_observations"], 30)
        self.assertFalse(duplicate["learning"]["dataset_learned"])

        unusual = {"metadata": {"source_system": "flow_1"}, "records": [self._flow_record(
            event_type="EXFILTRATION", transfer="Transferred: 8 GiB", source="203.0.113.90"
        )]}
        learning_engine.annotate_analysis("flowscope", "c" * 32, unusual)
        assessment = unusual["records"][0]["ai_assessment"]
        self.assertGreaterEqual(assessment["score"], 40)
        self.assertEqual(assessment["mode"], "shadow")
        self.assertTrue(assessment["reasons"])

        other_system = {"metadata": {"source_system": "flow_2"}, "records": [self._flow_record(
            event_type="EXFILTRATION", transfer="Transferred: 8 GiB", source="203.0.113.90"
        )]}
        learning_engine.annotate_analysis("flowscope", "e" * 32, other_system)
        self.assertEqual(other_system["records"][0]["ai_assessment"]["confidence"], "warming_up")
        self.assertEqual(other_system["learning"]["source_system"], "flow_2")

    def test_analyst_feedback_is_persisted_and_enables_feedback_model(self):
        analysis = {"metadata": {"source_system": "flow_1"}, "records": [
            self._flow_record(event_type="MALWARE" if index < 15 else "DNSQUERY", source=f"10.0.0.{index}")
            for index in range(30)
        ]}
        job_id = "d" * 32
        learning_engine.annotate_analysis("flowscope", job_id, analysis)
        for index in range(30):
            label = "confirmed_threat" if index < 15 else "benign"
            saved = learning_engine.save_feedback("flowscope", job_id, index, label)
            self.assertEqual(saved["label"], label)
        status = learning_engine.model_status()["flowscope"]
        self.assertTrue(status["feedback_model_ready"])
        self.assertEqual(status["feedback"]["confirmed_threat"], 15)

    def test_logscope_records_are_learned_with_siem_features(self):
        analysis = {"metadata": {"source_system": "manageengine"}, "records": [{
            "event_id": "4625", "priority": "High", "severity": "مرتفع",
            "event_source": "Windows Security", "src_ip": "8.8.8.8",
            "user_account": "analyst", "description": "Repeated failed logon",
            "extracted_ips": ["8.8.8.8"], "risk_score": 70,
        }]}
        learning_engine.annotate_analysis("logscope", "f" * 32, analysis)

        self.assertEqual(analysis["learning"]["source_system"], "manageengine")
        self.assertIn("ai_assessment", analysis["records"][0])
        self.assertEqual(learning_engine.model_status()["logscope"]["learned_observations"], 1)


if __name__ == "__main__":
    unittest.main()
