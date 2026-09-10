from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[1]
WORKSPACE = PROJECT.parent
sys.path.insert(0, str(PROJECT))

from analyzer import analyze_workbook, apply_enrichment, classify_hash  # noqa: E402
from csv_parser import read_csv  # noqa: E402
from docx_report import build_report_docx  # noqa: E402
from enrichment import enrich_hashes  # noqa: E402
from report_builder import build_report_html  # noqa: E402
from server import _export_filename as threat_export_filename  # noqa: E402
from xlsx_parser import SheetData, read_xlsx  # noqa: E402
from xlsx_report import build_report_xlsx  # noqa: E402


class AnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = WORKSPACE / "data" / "threats.xlsx"
        source = cls.sample.read_bytes()
        cls.analysis = analyze_workbook(read_xlsx(source), source, cls.sample.name)

    def test_hash_classification(self):
        self.assertEqual(classify_hash("a" * 32), ("a" * 32, "MD5"))
        self.assertEqual(classify_hash("B" * 40), ("b" * 40, "SHA-1"))
        self.assertEqual(classify_hash("f" * 64), ("f" * 64, "SHA-256"))
        self.assertEqual(classify_hash("not-a-hash"), (None, None))

    def test_export_filename_contains_xdr_source_system(self):
        filename = threat_export_filename(
            {"metadata": {"source_system_label": "C-OUT"}}, "docx"
        )
        self.assertRegex(filename, r"^ThreatScope_C-OUT_XDR_Report_\d{8}_\d{6}\.docx$")

    def test_accepts_common_xdr_headers_and_hash_only_rows(self):
        sheets = [SheetData("XDR alerts", [
            ["Alert title", "Device Name", "SHA-256", "Incident State", "Detection Time", "Initiating Process", "File Path"],
            ["Suspicious executable", "HOST-01", "a" * 64, "Active", "2026-08-17 10:00", "cmd.exe", r"C:\\Temp\\run.exe"],
            [None, "HOST-02", "b" * 64, "New", "2026-08-17 10:05", None, r"C:\\Temp\\unknown.bin"],
        ])]
        analysis = analyze_workbook(sheets, b"alternate-xdr-export", "alternate.xlsx")
        self.assertEqual(analysis["summary"]["records"], 2)
        self.assertEqual(analysis["summary"]["unique_hashes"], 2)
        self.assertEqual(analysis["mapping"]["hash"], "SHA-256")
        self.assertEqual(analysis["mapping"]["threat_name"], "Alert title")
        self.assertEqual(analysis["records"][1]["threat_name"], r"C:\\Temp\\unknown.bin")

    def test_accepts_utf8_csv_with_detected_semicolon_delimiter(self):
        source = (
            "Alert title;Device Name;SHA-256;Incident State;Detection Time;File Path\r\n"
            f'"تنبيه، يحتوي فاصلة";HOST-CSV;{"a" * 64};Unresolved;2026-08-24 10:00;C:\\Temp\\sample.exe\r\n'
        ).encode("utf-8-sig")
        analysis = analyze_workbook(read_csv(source), source, "alerts.csv")
        self.assertEqual(analysis["summary"]["records"], 1)
        self.assertEqual(analysis["summary"]["unique_hashes"], 1)
        self.assertEqual(analysis["records"][0]["endpoint"], "HOST-CSV")
        self.assertEqual(analysis["records"][0]["threat_name"], "تنبيه، يحتوي فاصلة")
        self.assertEqual(analysis["metadata"]["sheet"], "CSV")

    def test_accepts_arabic_cp1256_csv(self):
        source = (
            "اسم التنبيه,اسم الجهاز,هاش,حالة الحادث\r\n"
            f"ملف مشبوه,جهاز-1,{('b' * 64)},غير محلول\r\n"
        ).encode("cp1256")
        analysis = analyze_workbook(read_csv(source), source, "arabic.csv")
        self.assertEqual(analysis["summary"]["records"], 1)
        self.assertEqual(analysis["records"][0]["endpoint"], "جهاز-1")
        self.assertEqual(analysis["records"][0]["hash_type"], "SHA-256")

    def test_sample_metrics(self):
        summary = self.analysis["summary"]
        self.assertEqual(summary["records"], 50)
        self.assertEqual(summary["unique_hashes"], 38)
        self.assertEqual(summary["duplicate_rows"], 4)
        self.assertEqual(summary["unresolved"], 40)
        self.assertEqual(summary["not_mitigated"], 50)
        self.assertEqual(summary["pending_actions"], 9)

    def test_sample_quality(self):
        self.assertIn("External Ticket Id", self.analysis["quality"]["blank_columns"])
        self.assertEqual(self.analysis["quality"]["invalid_hashes"], 0)
        self.assertEqual(self.analysis["timing"]["maximum_detection_to_report_seconds"], 300.0)

    def test_generated_report_is_readable_xlsx(self):
        from threatscope.result_sink import MemoryResultReader
        import tempfile, os
        reader = MemoryResultReader(self.analysis.get("records") or [])
        fd, path = tempfile.mkstemp(suffix=".xlsx")
        os.close(fd)
        build_report_xlsx(self.analysis, reader, path)
        with open(path, "rb") as f:
            report = f.read()
        os.remove(path)
        sheets = read_xlsx(report)
        self.assertEqual([sheet.name for sheet in sheets], ["الملخص", "النتائج", "استخبارات الهاش"])
        self.assertGreaterEqual(len(sheets[1].rows), 51)

    def test_external_malicious_verdict_sets_high_minimum(self):
        source = self.sample.read_bytes()
        analysis = analyze_workbook(read_xlsx(source), source, self.sample.name)
        target_hash = analysis["records"][0]["hash"]
        enrichment = {
            "status": "completed",
            "providers": {"virustotal": {"enabled": True, "queries": 1, "errors": 0}},
            "results": {target_hash: {"virustotal": {"verdict": "malicious", "source_status": "ok"}}},
        }
        apply_enrichment(analysis, enrichment)
        record = next(item for item in analysis["records"] if item["hash"] == target_hash)
        self.assertGreaterEqual(record["risk_score"], 70)
        self.assertIn(record["risk_level"], {"مرتفع", "حرج"})

    def test_formal_word_report_is_valid_docx(self):
        import io
        import zipfile
        from xml.etree import ElementTree as ET

        from threatscope.result_sink import MemoryResultReader
        import tempfile, os
        reader = MemoryResultReader(self.analysis.get("records") or [])
        fd, path = tempfile.mkstemp(suffix=".docx")
        os.close(fd)
        build_report_docx(self.analysis, reader, path)
        with open(path, "rb") as f:
            report = f.read()
        os.remove(path)
        with zipfile.ZipFile(io.BytesIO(report)) as archive:
            document = archive.read("word/document.xml")
            ET.fromstring(document)
            text = document.decode("utf-8")
            self.assertIn("الخلاصة التنفيذية", text)
            self.assertIn("سجل مؤشرات الاختراق", text)
            self.assertNotIn("حدود التحليل", text)
            self.assertNotIn("ThreatScope", text)
            self.assertNotIn("MVP", text)
            self.assertNotIn("تم إنشاؤه بواسطة", text)
            self.assertNotIn(self.analysis["metadata"]["filename"], text)
            self.assertNotIn(self.analysis["metadata"]["source_sha256"], text)
            self.assertIn('<w:bidi w:val="1"/>', text)
            self.assertIn("\u200f", text)
            self.assertIn('<w:bidi w:val="1"/><w:jc w:val="left"/>', text)
            self.assertEqual(text.count('<w:cantSplit/>'), text.count('<w:tblHeader/>'))

    def test_formal_word_report_supports_legacy_minimal_jobs(self):
        import io
        import zipfile
        from threatscope.result_sink import MemoryResultReader
        import tempfile
        import os
        legacy = {
            "metadata": {"source_system_label": "C-IN"},
            "summary": {"records": 1, "unique_hashes": 1, "critical": 0, "high": 1},
            "records": [{
                "hash": "a" * 64,
                "hash_type": "SHA-256",
                "threat_name": "Legacy alert",
                "endpoint": "HOST-01",
                "risk_score": 70,
                "risk_level": "مرتفع",
            }],
            "enrichment": {"status": "not_started", "results": {}},
        }
        reader = MemoryResultReader(legacy.get("records") or [])
        fd, path = tempfile.mkstemp(suffix=".docx")
        os.close(fd)
        build_report_docx(legacy, reader, path)
        with open(path, "rb") as f:
            report = f.read()
        os.remove(path)
        with zipfile.ZipFile(io.BytesIO(report)) as archive:
            self.assertIn("word/document.xml", archive.namelist())
        
        fd2, path2 = tempfile.mkstemp(suffix=".xlsx")
        os.close(fd2)
        build_report_xlsx(legacy, reader, path2)
        with open(path2, "rb") as f:
            workbook = f.read()
        os.remove(path2)
        with zipfile.ZipFile(io.BytesIO(workbook)) as archive:
            self.assertIn("xl/workbook.xml", archive.namelist())

    def test_word_report_hides_provider_refresh_failures_and_keeps_analyst_voice(self):
        import io
        import zipfile

        analysis = copy.deepcopy(self.analysis)
        target_hash = analysis["records"][0]["hash"]
        enrichment = {
            "status": "completed_partial", "refresh_failures": 1, "fallback": 1,
            "providers": {"virustotal": {"enabled": True, "queries": 1, "errors": 0}},
            "results": {target_hash: {"virustotal": {
                "verdict": "malicious", "source_status": "ok", "malicious": 10,
                "suspicious": 1, "cached": True, "stale": True, "fallback": True,
                "refresh_source_status": "quota_exceeded",
            }}},
        }
        apply_enrichment(analysis, enrichment)
        from threatscope.result_sink import MemoryResultReader
        import tempfile
        import os
        reader = MemoryResultReader(analysis.get("records") or [])
        fd, path = tempfile.mkstemp(suffix=".docx")
        os.close(fd)
        build_report_docx(analysis, reader, path)
        with open(path, "rb") as f:
            report = f.read()
        os.remove(path)
        with zipfile.ZipFile(io.BytesIO(report)) as archive:
            text = archive.read("word/document.xml").decode("utf-8")

        self.assertIn("الاستنتاج المهني", text)
        self.assertIn("سياق الحادث ونتائج التحقق", text)
        for forbidden in ("تعذر التحديث", "نتيجة محفوظة", "نفاد الحصة", "اكتمل التحقق جزئيًا"):
            self.assertNotIn(forbidden, text)

    def test_user_reports_hide_ingestion_metadata(self):
        html = build_report_html(self.analysis, "a" * 32)
        self.assertNotIn(self.analysis["metadata"]["filename"], html)
        self.assertNotIn(self.analysis["metadata"]["sheet"], html)
        self.assertNotIn(self.analysis["metadata"]["source_sha256"], html)
        self.assertNotIn("ThreatScope", html)
        self.assertNotIn("MVP", html)

        from threatscope.result_sink import MemoryResultReader
        import tempfile
        import os
        reader = MemoryResultReader(self.analysis.get("records") or [])
        fd, path = tempfile.mkstemp(suffix=".xlsx")
        os.close(fd)
        build_report_xlsx(self.analysis, reader, path)
        with open(path, "rb") as f:
            report = f.read()
        os.remove(path)
        summary_sheet = read_xlsx(report)[0]
        summary_text = " ".join(str(value) for row in summary_sheet.rows for value in row if value is not None)
        self.assertNotIn(self.analysis["metadata"]["filename"], summary_text)
        self.assertNotIn(self.analysis["metadata"]["sheet"], summary_text)
        self.assertNotIn(self.analysis["metadata"]["source_sha256"], summary_text)

    def test_hash_snapshot_cache_only_queries_new_hashes(self):
        first_hash = "a" * 64
        second_hash = "b" * 64
        calls = []

        def fake_lookup(file_hash, _key):
            calls.append(file_hash)
            return {"verdict": "clean_or_unknown", "source_status": "ok", "known": True}

        configuration = {
            "virustotal": {"enabled": True, "key": "test"},
            "malwarebazaar": {"enabled": False, "key": ""},
        }
        with tempfile.TemporaryDirectory() as directory, \
                patch("enrichment.provider_configuration", return_value=configuration), \
                patch("enrichment.lookup_virustotal", side_effect=fake_lookup):
            cache_path = Path(directory) / "cache.sqlite3"
            first = enrich_hashes([{"hash": first_hash, "type": "SHA-256"}], cache_path)
            second = enrich_hashes([
                {"hash": first_hash, "type": "SHA-256"},
                {"hash": second_hash, "type": "SHA-256"},
            ], cache_path)

        self.assertEqual(calls, [first_hash, second_hash])
        self.assertEqual(first["cached"], 0)
        self.assertEqual(second["cached"], 1)
        self.assertEqual(second["new"], 1)
        self.assertTrue(second["results"][first_hash]["virustotal"]["cached"])

    def test_transient_hash_result_is_retried_not_saved(self):
        file_hash = "c" * 64
        responses = [
            {"verdict": "unavailable", "source_status": "quota_exceeded"},
            {"verdict": "clean_or_unknown", "source_status": "ok", "known": True},
        ]
        configuration = {
            "virustotal": {"enabled": True, "key": "test"},
            "malwarebazaar": {"enabled": False, "key": ""},
        }
        with tempfile.TemporaryDirectory() as directory, \
                patch("enrichment.provider_configuration", return_value=configuration), \
                patch("enrichment.lookup_virustotal", side_effect=responses) as lookup:
            cache_path = Path(directory) / "cache.sqlite3"
            first = enrich_hashes([{"hash": file_hash, "type": "SHA-256"}], cache_path)
            second = enrich_hashes([{"hash": file_hash, "type": "SHA-256"}], cache_path)

        self.assertEqual(lookup.call_count, 2)
        self.assertEqual(first["cached"], 0)
        self.assertEqual(second["cached"], 0)
        self.assertEqual(second["results"][file_hash]["virustotal"]["source_status"], "ok")

    def test_virustotal_falls_back_to_second_key_after_quota(self):
        file_hash = "9" * 64
        used_keys = []

        def fake_lookup(_file_hash, key):
            used_keys.append(key)
            if key == "primary":
                return {"verdict": "unavailable", "source_status": "quota_exceeded"}
            return {"verdict": "malicious", "source_status": "ok", "malicious": 8}

        configuration = {
            "virustotal": {"enabled": True, "key": "primary", "keys": ["primary", "fallback"]},
            "malwarebazaar": {"enabled": False, "key": ""},
        }
        with tempfile.TemporaryDirectory() as directory, \
                patch("enrichment.provider_configuration", return_value=configuration), \
                patch("enrichment.lookup_virustotal", side_effect=fake_lookup):
            result = enrich_hashes(
                [{"hash": file_hash, "type": "SHA-256"}], Path(directory) / "cache.sqlite3"
            )

        self.assertEqual(used_keys, ["primary", "fallback"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["providers"]["virustotal"]["queries"], 2)
        self.assertEqual(result["results"][file_hash]["virustotal"]["verdict"], "malicious")

    def test_force_refresh_replaces_cached_hash_snapshot(self):
        file_hash = "d" * 64
        calls = []

        def fake_lookup(value, _key):
            calls.append(value)
            malicious = 0 if len(calls) == 1 else 7
            return {
                "verdict": "clean_or_unknown" if malicious == 0 else "malicious",
                "source_status": "ok", "known": True, "malicious": malicious,
            }

        configuration = {
            "virustotal": {"enabled": True, "key": "test"},
            "malwarebazaar": {"enabled": False, "key": ""},
        }
        with tempfile.TemporaryDirectory() as directory, \
                patch("enrichment.provider_configuration", return_value=configuration), \
                patch("enrichment.lookup_virustotal", side_effect=fake_lookup):
            cache_path = Path(directory) / "cache.sqlite3"
            enrich_hashes([{"hash": file_hash, "type": "SHA-256"}], cache_path)
            refreshed = enrich_hashes(
                [{"hash": file_hash, "type": "SHA-256"}], cache_path, force_refresh=True
            )
            reused = enrich_hashes([{"hash": file_hash, "type": "SHA-256"}], cache_path)

        self.assertEqual(calls, [file_hash, file_hash])
        self.assertEqual(refreshed["cached"], 0)
        self.assertFalse(refreshed["results"][file_hash]["virustotal"]["cached"])
        self.assertEqual(reused["results"][file_hash]["virustotal"]["malicious"], 7)

    def test_force_refresh_uses_stale_snapshot_when_provider_quota_fails(self):
        file_hash = "e" * 64
        responses = [
            {
                "verdict": "malicious", "source_status": "ok", "known": True,
                "malicious": 12, "suspicious": 1,
            },
            {"verdict": "unavailable", "source_status": "quota_exceeded"},
        ]
        configuration = {
            "virustotal": {"enabled": True, "key": "test"},
            "malwarebazaar": {"enabled": False, "key": ""},
        }
        with tempfile.TemporaryDirectory() as directory, \
                patch("enrichment.provider_configuration", return_value=configuration), \
                patch("enrichment.lookup_virustotal", side_effect=responses):
            cache_path = Path(directory) / "cache.sqlite3"
            enrich_hashes([{"hash": file_hash, "type": "SHA-256"}], cache_path)
            refreshed = enrich_hashes(
                [{"hash": file_hash, "type": "SHA-256"}], cache_path, force_refresh=True
            )

        result = refreshed["results"][file_hash]["virustotal"]
        self.assertEqual(refreshed["status"], "completed_partial")
        self.assertEqual(refreshed["refresh_failures"], 1)
        self.assertEqual(refreshed["fallback"], 1)
        self.assertEqual(refreshed["unavailable"], 0)
        self.assertEqual(result["verdict"], "malicious")
        self.assertEqual(result["malicious"], 12)
        self.assertTrue(result["cached"])
        self.assertTrue(result["stale"])
        self.assertTrue(result["fallback"])
        self.assertEqual(result["refresh_source_status"], "quota_exceeded")

    def test_reapplying_hash_enrichment_does_not_compound_risk(self):
        source = self.sample.read_bytes()
        analysis = analyze_workbook(read_xlsx(source), source, self.sample.name)
        target_hash = analysis["records"][0]["hash"]
        enrichment_result = {
            "status": "completed", "providers": {},
            "results": {target_hash: {"virustotal": {"verdict": "malicious", "source_status": "ok"}}},
        }
        apply_enrichment(analysis, enrichment_result)
        first_score = next(item for item in analysis["records"] if item["hash"] == target_hash)["risk_score"]
        apply_enrichment(analysis, enrichment_result)
        second_score = next(item for item in analysis["records"] if item["hash"] == target_hash)["risk_score"]
        self.assertEqual(first_score, second_score)


if __name__ == "__main__":
    unittest.main()
