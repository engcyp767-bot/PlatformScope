import unittest
from platform_core import incident_manager, threat_intel
from platform_core.ai_copilot import (
    SecurityCopilotEngine,
    get_copilot_status,
    DeterministicCopilotFallback,
    SecurityContextEnricher,
)


class TestSecurityCopilot(unittest.TestCase):
    def setUp(self):
        # Create a test incident
        self.inc = incident_manager.create_incident(
            title="اختراق خادم قواعد البيانات عبر هجوم Brute Force واتصال C2",
            severity="critical",
            source_app="ThreatScope",
            mitre_tactics=["Initial Access", "Execution", "Command and Control"],
            mitre_techniques=["T1110", "T1059", "T1071"],
            entities=["185.220.101.5", "SRV-DB-01", "powershell.exe", "admin_sa"],
            asset_criticality="mission_critical",
            business_impact="high",
            actor="test_analyst",
        )
        self.inc_id = self.inc["id"]

        # Add evidence
        incident_manager.add_evidence_record(
            self.inc_id,
            evidence_type="ip",
            name="C2 Server IP",
            value="185.220.101.5",
            notes="Active Cobalt Strike server",
            added_by="test_analyst",
        )
        incident_manager.add_evidence_record(
            self.inc_id,
            evidence_type="log_snippet",
            name="PowerShell Execution Log",
            value="powershell.exe -enc VwByAGkAdABl...",
            notes="Base64 encoded execution",
            added_by="test_analyst",
        )

    def test_copilot_status(self):
        status = get_copilot_status(force_check=True)
        self.assertIsInstance(status, dict)
        self.assertIn("status", status)
        self.assertIn("mode", status)
        self.assertTrue(status.get("fallback_ready"))
        self.assertIn("active_model", status)

    def test_copilot_explain_severity(self):
        res = SecurityCopilotEngine.investigate(
            self.inc_id,
            intent="explain_severity",
            actor="lead_investigator",
        )
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("incident_id"), self.inc_id)
        self.assertEqual(res.get("intent"), "explain_severity")
        self.assertIn("تفسير مستوى الخطورة", res.get("investigation_title_ar", ""))
        self.assertTrue(len(res.get("summary_ar", "")) > 20)
        self.assertTrue(len(res.get("grounded_facts", [])) > 0)
        self.assertTrue(len(res.get("recommended_actions", [])) > 0)
        self.assertGreaterEqual(res.get("confidence", 0), 80)
        self.assertIn("disclaimer_ar", res)

    def test_copilot_attack_sequence(self):
        res = SecurityCopilotEngine.investigate(
            self.inc_id,
            intent="attack_sequence",
            actor="lead_investigator",
        )
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("intent"), "attack_sequence")
        self.assertIn("سلسلة القتل", res.get("investigation_title_ar", ""))
        self.assertTrue(len(res.get("summary_ar", "")) > 20)
        self.assertTrue(len(res.get("grounded_facts", [])) > 0)
        self.assertTrue(len(res.get("mitre_matrix", [])) > 0)

    def test_copilot_recommended_actions(self):
        res = SecurityCopilotEngine.investigate(
            self.inc_id,
            intent="recommended_actions",
            actor="lead_investigator",
        )
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("intent"), "recommended_actions")
        self.assertIn("خطة الاستجابة", res.get("investigation_title_ar", ""))
        actions = res.get("recommended_actions", [])
        self.assertTrue(len(actions) >= 3)
        phases = {a.get("phase") for a in actions}
        self.assertIn("containment", phases)
        self.assertIn("eradication", phases)

    def test_copilot_custom_query(self):
        res = SecurityCopilotEngine.investigate(
            self.inc_id,
            intent="custom_query",
            custom_query="ما هي خطة احتواء عنوان IP المشبوه؟",
            actor="lead_investigator",
        )
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("intent"), "custom_query")
        self.assertIn("نتيجة التحقيق الجنائي", res.get("investigation_title_ar", ""))
        self.assertTrue(len(res.get("grounded_facts", [])) > 0)

    def test_copilot_apply_recommendation_as_note(self):
        inc = SecurityCopilotEngine.apply_recommendation_as_note(
            self.inc_id,
            "يوصى بقطع الاتصال بالخادم 185.220.101.5 فوراً.",
            actor="soc_lead",
        )
        self.assertIsInstance(inc, dict)
        notes = inc.get("notes", [])
        self.assertTrue(any("🤖" in n.get("note_text", "") for n in notes))
        self.assertTrue(any("185.220.101.5" in n.get("note_text", "") for n in notes))

        # Verify it appears in incident
        inc_reloaded = incident_manager.get_incident(self.inc_id)
        notes_reloaded = inc_reloaded.get("notes", [])
        self.assertTrue(any("185.220.101.5" in n.get("note_text", "") for n in notes_reloaded))

    def test_copilot_invalid_incident(self):
        with self.assertRaises(ValueError):
            SecurityCopilotEngine.investigate("INC-NON-EXISTENT-9999")


if __name__ == "__main__":
    unittest.main()
