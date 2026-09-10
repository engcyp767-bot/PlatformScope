"""Unit and integration tests for Declarative Detection Engine and Correlation Layer."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from logscope.canonical import CanonicalEvent, ConclusionLevel, DetectionFinding
from platform_core.detection_engine import (
    ConditionEvaluator,
    DetectionEngine,
    DetectionRule,
    SafeRegexEvaluator,
    calculate_integrity_hash,
    get_detection_engine,
)
from platform_core.detection_correlation import DetectionCorrelationLayer


class DetectionEngineTests(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.engine = DetectionEngine(detections_dir=self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_safe_regex_evaluator(self):
        pattern = r"(?i)powershell(\.exe)?\s+.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{10,}"
        valid_payload = "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."
        self.assertTrue(SafeRegexEvaluator.search(pattern, valid_payload))
        self.assertFalse(SafeRegexEvaluator.search(pattern, "powershell.exe -File script.ps1"))

        # Input limits protection
        huge_payload = "A" * 10000 + " powershell.exe -enc ABCD12345678"
        # Since it is clamped to 4096 chars, trailing pattern beyond 4096 is not matched
        self.assertFalse(SafeRegexEvaluator.search(pattern, huge_payload))

    def test_condition_evaluator_operators(self):
        evt = CanonicalEvent(
            event_id="4625",
            username="admin",
            source_ip="192.168.1.100",
            message="An account failed to log on with SubStatus 0xc000006a",
            raw_fields={"SubStatus": "0xc000006a", "LogonType": 3}
        )

        # 1. eq
        self.assertTrue(ConditionEvaluator.evaluate_node(evt, {"field": "event_id", "operator": "eq", "value": "4625"}))
        self.assertFalse(ConditionEvaluator.evaluate_node(evt, {"field": "event_id", "operator": "eq", "value": "4624"}))

        # 2. dot notation in raw_fields
        self.assertTrue(ConditionEvaluator.evaluate_node(evt, {"field": "raw_fields.SubStatus", "operator": "eq", "value": "0xc000006a"}))
        self.assertTrue(ConditionEvaluator.evaluate_node(evt, {"field": "raw_fields.LogonType", "operator": "==", "value": 3}))

        # 3. in / not_in
        self.assertTrue(ConditionEvaluator.evaluate_node(evt, {"field": "event_id", "operator": "in", "value": ["4624", "4625"]}))
        self.assertFalse(ConditionEvaluator.evaluate_node(evt, {"field": "event_id", "operator": "not_in", "value": ["4624", "4625"]}))

        # 4. contains_ci
        self.assertTrue(ConditionEvaluator.evaluate_node(evt, {"field": "message", "operator": "contains_ci", "value": "ACCOUNT FAILED TO LOG ON"}))

        # 5. Compound Boolean (and, or, not)
        cond = {
            "and": [
                {"field": "event_id", "operator": "eq", "value": "4625"},
                {
                    "or": [
                        {"field": "raw_fields.SubStatus", "operator": "eq", "value": "0xc000006a"},
                        {"field": "raw_fields.SubStatus", "operator": "eq", "value": "0xc0000234"},
                    ]
                },
                {
                    "not": {"field": "username", "operator": "eq", "value": "guest"}
                }
            ]
        }
        self.assertTrue(ConditionEvaluator.evaluate_node(evt, cond))

    def test_lifecycle_and_evaluation_filtering(self):
        # Create 3 rules: production, testing, development
        rule_prod_data = {
            "id": "RULE-PROD-001",
            "name": "Production Rule",
            "lifecycle": "production",
            "enabled": True,
            "condition": {"field": "event_id", "operator": "eq", "value": "1102"}
        }
        rule_test_data = {
            "id": "RULE-TEST-001",
            "name": "Testing Rule",
            "lifecycle": "testing",
            "enabled": True,
            "condition": {"field": "event_id", "operator": "eq", "value": "1102"}
        }
        rule_dev_data = {
            "id": "RULE-DEV-001",
            "name": "Development Rule",
            "lifecycle": "development",
            "enabled": True,
            "condition": {"field": "event_id", "operator": "eq", "value": "1102"}
        }

        self.engine.create_or_update_rule(rule_prod_data)
        self.engine.create_or_update_rule(rule_test_data)
        self.engine.create_or_update_rule(rule_dev_data)

        evt = CanonicalEvent(event_id="1102", message="Audit log cleared")

        # Standard live evaluation must ONLY evaluate production rules
        findings = self.engine.evaluate_event(evt, run_testing_rules=False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detection_id, "RULE-PROD-001")

        # With run_testing_rules=True, production and testing both evaluate
        findings_test = self.engine.evaluate_event(evt, run_testing_rules=True)
        self.assertEqual(len(findings_test), 2)
        found_ids = {f.detection_id for f in findings_test}
        self.assertIn("RULE-PROD-001", found_ids)
        self.assertIn("RULE-TEST-001", found_ids)
        self.assertNotIn("RULE-DEV-001", found_ids)

    def test_soft_delete_and_version_history(self):
        rule_data = {
            "id": "RULE-DEL-001",
            "name": "Rule To Delete",
            "lifecycle": "production",
            "enabled": True,
            "condition": {"field": "event_id", "operator": "eq", "value": "9999"}
        }
        rule = self.engine.create_or_update_rule(rule_data, changed_by="admin", reason="Initial")
        file_path = rule.file_path

        self.assertIsNotNone(file_path)
        self.assertTrue(file_path.exists())

        # Perform soft delete
        deleted_rule = self.engine.soft_delete_rule("RULE-DEL-001", deleted_by="lead_analyst", reason="Outdated detection")

        # Verify rule is not in active list
        active_rules = self.engine.get_all_rules(include_deleted=False)
        self.assertEqual(len(active_rules), 0)

        # Verify rule is still present when include_deleted=True
        all_rules = self.engine.get_all_rules(include_deleted=True)
        self.assertEqual(len(all_rules), 1)
        self.assertTrue(deleted_rule.is_deleted)
        self.assertEqual(deleted_rule.lifecycle, "deprecated")
        self.assertFalse(deleted_rule.enabled)

        # Verify physical file STILL exists on disk!
        self.assertTrue(file_path.exists())

        # Verify version history has both creation and soft deletion entries
        history = deleted_rule.version_history
        self.assertGreaterEqual(len(history), 2)
        self.assertIn("Soft Deleted", history[0]["reason"])

    def test_positive_negative_test_samples_runner(self):
        rule_data = {
            "id": "RULE-TEST-RUNNER",
            "name": "Ransomware vssadmin check",
            "lifecycle": "production",
            "condition": {"field": "message", "operator": "contains_ci", "value": "vssadmin delete shadows"},
            "test_samples": {
                "positive": [
                    {"message": "cmd.exe /c vssadmin delete shadows /all /quiet", "source": "cmd"},
                    {"message": "VSSADMIN delete SHADOWS", "source": "powershell"}
                ],
                "negative": [
                    {"message": "vssadmin list shadows", "source": "cmd"},
                    {"message": "system backup started", "source": "backup"}
                ]
            }
        }
        self.engine.create_or_update_rule(rule_data)
        res = self.engine.run_rule_tests("RULE-TEST-RUNNER")

        self.assertTrue(res["success"])
        self.assertTrue(res["all_passed"])
        self.assertEqual(res["positive"]["passed"], 2)
        self.assertEqual(res["negative"]["passed"], 2)

    def test_export_and_import_package_with_integrity_hash(self):
        rule_data = {
            "id": "RULE-PKG-001",
            "name": "Exported Test Rule",
            "lifecycle": "production",
            "condition": {"field": "event_id", "operator": "eq", "value": "1234"}
        }
        self.engine.create_or_update_rule(rule_data)

        # Export package
        pkg = self.engine.export_rules_package()
        self.assertIn("manifest", pkg)
        self.assertIn("rules", pkg)
        self.assertEqual(pkg["manifest"]["total_rules"], 1)

        # Import into a new engine instance
        new_tmp = Path(tempfile.mkdtemp())
        try:
            new_engine = DetectionEngine(detections_dir=new_tmp)
            import_res = new_engine.import_rules_package(pkg, overwrite=True)
            self.assertTrue(import_res["success"])
            self.assertEqual(import_res["imported_count"], 1)

            # Test tampered rule rejection
            tampered_pkg = copy.deepcopy(pkg)
            tampered_pkg["rules"][0]["name"] = "Tampered Malicious Name"
            tamper_res = new_engine.import_rules_package(tampered_pkg, overwrite=True)
            self.assertFalse(tamper_res["success"])
            self.assertEqual(len(tamper_res["errors"]), 1)
            self.assertIn("Integrity check failed", tamper_res["errors"][0]["error"])
        finally:
            shutil.rmtree(new_tmp, ignore_errors=True)

    def test_all_standard_repository_rules(self):
        """Verify that all default rules in the repo load correctly and pass their regression tests."""
        repo_engine = get_detection_engine()
        repo_rules = repo_engine.get_all_rules(include_deleted=False)
        self.assertGreaterEqual(len(repo_rules), 10)

        for rule in repo_rules:
            test_res = repo_engine.run_rule_tests(rule.id)
            self.assertTrue(
                test_res["all_passed"],
                f"Rule {rule.id} failed its own regression test samples: {test_res}"
            )


class DetectionCorrelationTests(unittest.TestCase):

    def test_incident_policy_threshold(self):
        corr = DetectionCorrelationLayer(max_retention_seconds=300)

        class MockIncidentManager:
            def __init__(self):
                self.promoted = []

            def promote_detection_to_incident(self, **kwargs):
                self.promoted.append(kwargs)
                return kwargs

        mock_mgr = MockIncidentManager()

        rule_dict = {
            "id": "DET-WIN-002",
            "severity": "high",
            "confidence": 85,
            "incident_policy": {
                "auto_promote": True,
                "threshold": 3,
                "time_window_seconds": 60,
                "min_confidence": 80,
                "group_by": ["username", "src_ip"]
            }
        }

        finding = DetectionFinding(
            detection_id="DET-WIN-002",
            title_ar="محاولات دخول فاشلة",
            description_ar="فشل تسجيل الدخول",
            base_severity=75,
            confidence=85
        )

        evt = CanonicalEvent(event_id="4625", username="target_user", source_ip="192.168.1.50")

        # First match -> under threshold
        res1 = corr.process_detection(finding, evt, rule_dict, incident_mgr=mock_mgr)
        self.assertIsNone(res1)
        self.assertEqual(len(mock_mgr.promoted), 0)

        # Second match -> under threshold
        res2 = corr.process_detection(finding, evt, rule_dict, incident_mgr=mock_mgr)
        self.assertIsNone(res2)
        self.assertEqual(len(mock_mgr.promoted), 0)

        # Third match -> threshold (3) met! Triggers promotion to incident
        res3 = corr.process_detection(finding, evt, rule_dict, incident_mgr=mock_mgr)
        self.assertIsNotNone(res3)
        self.assertEqual(res3["type"], "policy_promotion")
        self.assertEqual(len(mock_mgr.promoted), 1)
        self.assertIn("target_user", str(mock_mgr.promoted[0]["raw_evidence"]))


if __name__ == "__main__":
    unittest.main()
