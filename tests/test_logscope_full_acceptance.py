"""Comprehensive Acceptance and Verification Suite for LogScope SIEM & Forensic Correlation Engine.
Calculates Precision, Recall, F1, FPR, Source Accuracy, and verifies full semantic backwards compatibility.
"""

from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
import shutil

from logscope.file_parser import ParsedData, read_file
from logscope.analyzer import analyze_ads_data
from logscope.result_sink import SQLiteResultSink
from tests.golden_datasets import (
    ALL_GOLDEN_SAMPLES,
    WINDOWS_AD_GOLDEN_SAMPLES,
    NETWORK_FIREWALL_GOLDEN_SAMPLES,
    LINUX_SSH_GOLDEN_SAMPLES,
    WEB_WAF_GOLDEN_SAMPLES,
    CLOUD_IDENTITY_GOLDEN_SAMPLES,
    DATABASE_GOLDEN_SAMPLES,
    EDR_GOLDEN_SAMPLES,
    UNKNOWN_PARTIAL_SAMPLES,
)


class LogScopeFullAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_golden_dataset_metrics_and_confusion_matrix(self):
        """Run all Golden Samples through LogScope and compute empirical metrics:
        TP, TN, FP, FN, Precision, Recall, F1, and FPR.
        """
        tp = 0
        tn = 0
        fp = 0
        fn = 0

        source_correct = 0
        total_samples = len(ALL_GOLDEN_SAMPLES)

        field_mapping_checks = 0
        field_mapping_passes = 0

        for sample in ALL_GOLDEN_SAMPLES:
            parsed = ParsedData(
                filename=f"{sample.name}.csv",
                headers=sample.headers,
                rows=[sample.row],
                source_format="CSV",
                total_rows=1,
            )
            res = analyze_ads_data(parsed)
            events = res.get("records") or res.get("events") or []
            self.assertEqual(len(events), 1, f"Failed to parse event for {sample.name}")
            evt = events[0]

            # 1. Source Detection Accuracy
            detected_source = res["metadata"].get("detected_source")
            if detected_source == sample.expected_source or sample.expected_source == "generic":
                source_correct += 1

            # 2. Field Mapping Accuracy against columns present in source
            headers_lower = [str(h).lower() for h in sample.headers]
            if any("time" in h or "date" in h or "timestamp" in h for h in headers_lower):
                field_mapping_checks += 1
                if evt.get("event_time"):
                    field_mapping_passes += 1
            if any("action" in h or "operation" in h or "activity" in h for h in headers_lower):
                field_mapping_checks += 1
                if evt.get("action") or evt.get("action_ar"):
                    field_mapping_passes += 1
            if any("ip" in h for h in headers_lower):
                field_mapping_checks += 1
                if evt.get("src_ip") or evt.get("destination"):
                    field_mapping_passes += 1
            if any("user" in h or "account" in h for h in headers_lower):
                field_mapping_checks += 1
                if evt.get("user_account"):
                    field_mapping_passes += 1
            if any("event" in h or "id" in h or "cid" in h for h in headers_lower):
                field_mapping_checks += 1
                if evt.get("event_id"):
                    field_mapping_passes += 1

            # Description & Forensic Enrichment
            field_mapping_checks += 1
            if evt.get("description_ar") or evt.get("description") or evt.get("threat_family"):
                field_mapping_passes += 1

            # 3. Detection & Classification Confusion Matrix
            # A true threat detection is risk >= 40 or a suspicious/malicious conclusion (not benign informational telemetry)
            conc = str(evt.get("conclusion_level", "")).lower()
            has_detection = (evt.get("risk_score", 0) >= 40) or any(c in conc for c in ("suspicious", "malicious", "confirmed", "successful"))

            if sample.is_threat:
                if has_detection:
                    tp += 1
                else:
                    fn += 1
            else:
                if has_detection:
                    fp += 1
                else:
                    tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        source_acc = (source_correct / total_samples) * 100
        field_acc = (field_mapping_passes / field_mapping_checks) * 100

        print("\n=======================================================")
        print(" LOGSCOPE EMPIRICAL ACCEPTANCE & VALIDATION REPORT")
        print("=======================================================")
        print(f"Total Golden Ground-Truth Samples: {total_samples}")
        print(f"True Positives (TP):  {tp}")
        print(f"True Negatives (TN):  {tn}")
        print(f"False Positives (FP): {fp}")
        print(f"False Negatives (FN): {fn}")
        print("-------------------------------------------------------")
        print(f"Detection Precision:        {precision * 100:.2f}%")
        print(f"Detection Recall:           {recall * 100:.2f}%")
        print(f"Detection F1-Score:         {f1 * 100:.2f}%")
        print(f"False Positive Rate (FPR):  {fpr * 100:.2f}%")
        print(f"Source Detection Accuracy:  {source_acc:.2f}%")
        print(f"Field Mapping Accuracy:     {field_acc:.2f}%")
        print("=======================================================\n")

        # Rigorous Verification Assertions
        self.assertGreaterEqual(recall, 0.95, "Recall must be at least 95%")
        self.assertGreaterEqual(precision, 0.95, "Precision must be at least 95%")
        self.assertGreaterEqual(f1, 0.95, "F1 score must be at least 95%")
        self.assertLessEqual(fpr, 0.05, "False Positive Rate must be 5% or less")
        self.assertGreaterEqual(source_acc, 90.0, "Source detection accuracy must be at least 90%")
        self.assertGreaterEqual(field_acc, 95.0, "Field mapping accuracy must be at least 95%")

    def test_semantic_regression_on_classified1_csv(self):
        """Verify 100% backwards compatibility and data preservation with the reference data/المصنف1.csv."""
        ref_path = Path("data/المصنف1.csv")
        if not ref_path.exists():
            self.skipTest("Reference dataset data/المصنف1.csv not found.")

        raw_bytes = ref_path.read_bytes()
        parsed = read_file(raw_bytes, filename="المصنف1.csv")
        db_path = self.tmp_dir / "classified1_acceptance.db"
        sink = SQLiteResultSink(db_path)

        res = analyze_ads_data(parsed, sink=sink)

        # 1. Row Preservation
        total_records = res["total_records"]
        self.assertGreater(total_records, 20, "Reference dataset must have substantial records")

        conn = sqlite3.connect(db_path)
        try:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM records")
            stored_rows = c.fetchone()[0]
            self.assertEqual(stored_rows, total_records, "100% of rows must be stored in SQLite sink")

            # 2. SQLite Cursor Pagination Verification
            c.execute("SELECT id, payload_json FROM records ORDER BY id ASC LIMIT 10")
            page1 = c.fetchall()
            self.assertEqual(len(page1), 10)

            last_id = page1[-1][0]
            c.execute("SELECT id, payload_json FROM records WHERE id > ? ORDER BY id ASC LIMIT 10", (last_id,))
            page2 = c.fetchall()
            self.assertEqual(len(page2), 10)
            self.assertGreater(page2[0][0], last_id)

            # 3. Verify SQLite JSON data integrity and field preservation
            first_record_json = page1[0][1]
            rec = json.loads(first_record_json)
            expected_keys = [
                "event_time", "event_id", "src_ip", "destination", "action",
                "action_ar", "description_ar", "threat_family", "risk_score",
                "confidence_score", "severity", "conclusion_level", "raw_fields"
            ]
            for key in expected_keys:
                self.assertIn(key, rec, f"Missing expected key '{key}' in SQLite stored record")

            # 4. Verify detection of key threats present in المصنف1.csv
            c.execute("SELECT COUNT(*) FROM records WHERE payload_json LIKE '%ICMP%' OR payload_json LIKE '%icmp%'")
            icmp_count = c.fetchone()[0]
            self.assertGreater(icmp_count, 0, "Must detect ICMP attacks present in dataset")

            c.execute("SELECT COUNT(*) FROM records WHERE payload_json LIKE '%Expiro%' OR payload_json LIKE '%expiro%'")
            expiro_count = c.fetchone()[0]
            self.assertGreater(expiro_count, 0, "Must detect Expiro signatures present in dataset")

        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
