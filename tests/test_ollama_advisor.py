from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from platform_core import ollama_advisor


class OllamaAdvisorTests(unittest.TestCase):
    def sample(self) -> dict:
        return {
            "metadata": {
                "filename": "must-not-leave.csv",
                "source_system": "flow_1",
                "source_system_label": "C-IN",
                "data_type": "ads_events",
            },
            "summary": {"records": 2, "critical": 0, "high": 1},
            "records": [
                {
                    "event_type": "BLACKLIST", "event_source": "192.168.1.5",
                    "event_targets": ["8.8.8.8"], "risk_score": 70,
                    "severity": "مرتفع", "bytes": 19000000,
                },
                {
                    "event_type": "Allowed traffic", "event_source": "192.168.1.8",
                    "event_targets": ["1.1.1.1"], "risk_score": 10,
                    "severity": "منخفض", "bytes": 2048,
                },
            ],
            "enrichment": {
                "status": "completed",
                "results": {
                    "8.8.8.8": {"virustotal": {"verdict": "malicious", "malicious": 4}}
                },
            },
        }

    def test_payload_is_bounded_and_hides_filename(self):
        payload, indices = ollama_advisor.build_payload("flowscope", self.sample())
        rendered = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("must-not-leave.csv", rendered)
        self.assertEqual(indices, {0, 1})
        self.assertEqual(payload["selected_records"][0]["record_index"], 0)
        self.assertIn("source_reputation", payload["selected_records"][0])

    def test_validation_rejects_unknown_indices_and_caps_confidence(self):
        raw = {
            "executive_summary_ar": "تشير الأدلة إلى حدث مرتفع الخطورة يحتاج إلى تحقق.",
            "overall_assessment": "مرتفع الخطورة",
            "confidence": 100,
            "patterns": ["ارتبطت الخطورة بنتيجة سمعة مثبتة."],
            "findings": [
                {"record_index": 99, "assessment_ar": "غير صالح", "rationale_ar": "غير صالح", "recommended_action_ar": "غير صالح"},
                {"record_index": 0, "assessment_ar": "حدث مهم", "rationale_ar": "درجة الخطورة مدعومة بنتيجة السمعة.", "recommended_action_ar": "راجع السجلات واعزل المصدر عند ثبوت النشاط."},
            ],
            "recommendations": ["مراجعة سجل الاتصالات المرتبط بالحدث."],
        }
        result = ollama_advisor._validate_result(raw, {0, 1})
        self.assertEqual(result["confidence"], 95)
        self.assertEqual([item["record_index"] for item in result["findings"]], [0])

    def test_schedule_fails_safely_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "model_analysis.json"
            with patch.object(ollama_advisor, "analyze", side_effect=ConnectionError("offline")):
                status = ollama_advisor.schedule("flowscope", "a" * 32, self.sample(), output)
                self.assertEqual(status, "queued")
                deadline = time.time() + 2
                while time.time() < deadline:
                    result = ollama_advisor.read_sidecar(output) or {}
                    if result.get("status") == "skipped":
                        break
                    time.sleep(0.02)
            self.assertEqual(result["status"], "skipped")
            self.assertEqual(result["reason"], "model_unavailable")

    def test_external_ai_provider_is_used_before_ollama(self):
        raw = {
            "executive_summary_ar": "تشير الأدلة إلى نشاط يحتاج إلى مراجعة أمنية.",
            "overall_assessment": "مرتفع الخطورة", "confidence": 82,
            "patterns": ["ظهر ارتباط بين درجة الخطورة ونتيجة السمعة."],
            "findings": [{"record_index": 0, "assessment_ar": "حدث مهم", "rationale_ar": "تدعمه نتيجة سمعة سلبية.", "recommended_action_ar": "راجع الاتصالات المرتبطة واعزل المصدر عند التأكد."}],
            "recommendations": ["مراجعة السجلات وربطها زمنيًا."],
        }
        provider = {"name": "Internal AI", "model": "secure-model", "priority": 1}
        with patch.object(ollama_advisor, "_external_ai_providers", return_value=[provider]), patch.object(
            ollama_advisor, "_external_chat", return_value=(raw, "secure-model")
        ), patch.object(ollama_advisor, "service_status") as ollama_status:
            result = ollama_advisor.analyze("flowscope", self.sample())
        self.assertEqual(result["provider"], "Internal AI")
        self.assertEqual(result["model"], "secure-model")
        ollama_status.assert_not_called()


if __name__ == "__main__":
    unittest.main()
