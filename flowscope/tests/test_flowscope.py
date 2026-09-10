import io
import json
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import analyzer
import enrichment
import file_parser
import server
from docx_report import (
    _arabic_detail,
    _event_reputation_result,
    _ranked_events,
    _run,
    _source_reputation_details,
    build_report_docx,
)
from xlsx_report import build_report_xlsx


class FlowScopeTests(unittest.TestCase):
    def test_export_filename_contains_flow_source_system(self):
        filename = server._export_filename(
            {"metadata": {"source_system_label": "DCS"}}, ".xlsx"
        )
        self.assertRegex(filename, r"^FlowScope_DCS_Flow_Report_\d{8}_\d{6}\.xlsx$")

    def test_http_server_disallows_shared_port(self):
        self.assertFalse(server.ExclusiveThreadingHTTPServer.allow_reuse_address)

    def test_event_details_are_translated_to_arabic(self):
        translated = _arabic_detail("Transferred: 3.82 GiB, top peer transfer: 589.31 MiB.")
        self.assertEqual(
            translated,
            "بلغ إجمالي البيانات المنقولة 3.82 GiB، وكان أكبر حجم منقول إلى نظير واحد 589.31 MiB.",
        )
        self.assertNotIn("Transferred", translated)

    def test_ltr_measurements_and_timestamps_stay_in_one_run(self):
        measurement = _run("بلغ الحجم 3.28 GiB خلال الفحص")
        timestamp = _run("وقت الكشف 2026-08-21 23:31:18")
        owner = _run("الجهة المالكة: Public Telecommunication Corporation")

        self.assertIn('<w:t xml:space="preserve">3.28 GiB</w:t>', measurement)
        self.assertIn('<w:t xml:space="preserve">2026-08-21 23:31:18</w:t>', timestamp)
        self.assertIn('<w:t xml:space="preserve">Public Telecommunication Corporation</w:t>', owner)

    def test_events_are_ranked_by_risk_then_transferred_volume(self):
        records = [
            {"event_id": "small", "risk_score": 70, "attributes": "BytesIn=100"},
            {"event_id": "high-risk", "risk_score": 90, "attributes": "BytesIn=1"},
            {"event_id": "large", "risk_score": 70, "attributes": "BytesIn=900"},
        ]

        ranked = _ranked_events(records)

        self.assertEqual([record["event_id"] for record in ranked], ["high-risk", "large", "small"])

    def test_source_reputation_details_include_provider_findings(self):
        details = "".join(_source_reputation_details({
            "virustotal": {
                "source_status": "ok", "verdict": "suspicious",
                "malicious": 2, "suspicious": 1, "reputation": -2,
                "country": "YE", "as_owner": "Example Network",
            },
            "shodan": {"source_status": "provider_deferred", "verdict": "unavailable"},
        }))

        self.assertIn("نتيجة التحليل", details)
        self.assertIn("عدد المحركات المصنفة ضارة", details)
        self.assertIn("مؤجل بسبب حدود الخدمة", details)
        self.assertNotIn("VirusTotal", details)
        self.assertNotIn("Shodan", details)

    def test_private_event_source_uses_most_important_target_result(self):
        record = {
            "event_source": "192.168.1.20",
            "event_targets": ["8.8.8.8", "9.9.9.9"],
        }
        results = {
            "8.8.8.8": {"virustotal": {"verdict": "clean", "source_status": "ok"}},
            "9.9.9.9": {"virustotal": {"verdict": "suspicious", "source_status": "ok"}},
        }

        ip, providers, count = _event_reputation_result(record, results)

        self.assertEqual(ip, "9.9.9.9")
        self.assertEqual(count, 2)
        self.assertEqual(providers["virustotal"]["verdict"], "suspicious")

    def test_csv_bom_is_removed_and_progress_completes(self):
        source = (
            "Event ID;Event source;Type;Detail;Targets\n"
            "1;8.8.8.8;DOS;Transferred 2 GiB;1.1.1.1\n"
        ).encode("utf-8-sig")
        parsed = file_parser.read_file(source, "events.csv")
        progress = []
        result = analyzer.analyze_ads_data(parsed, progress_callback=lambda *values: progress.append(values))

        self.assertEqual(parsed.headers[0], "Event ID")
        self.assertEqual(result["metadata"]["filename"], "events.csv")
        self.assertEqual(result["records"][0]["risk_score"], 65)
        self.assertTrue(progress)

    def test_ads_protocols_are_extracted_from_attributes(self):
        source = (
            "Event ID;Event source;Type;Attributes\n"
            "1;192.168.1.10;ANOMALY;Protocols=[1, 6, 17, 249]\n"
        ).encode("utf-8")
        parsed = file_parser.read_file(source, "events.csv")
        result = analyzer.analyze_ads_data(parsed)

        self.assertEqual(result["records"][0]["protocol"], "ICMP، TCP، UDP، IP-249")

    def test_ip_classification_uses_real_ip_rules(self):
        self.assertTrue(enrichment.is_private_ip("192.168.1.1"))
        self.assertTrue(enrichment.is_private_ip("not-an-ip"))
        self.assertFalse(enrichment.is_private_ip("8.8.8.8"))
        self.assertFalse(enrichment.is_private_ip("172.200.1.1"))

    def test_background_analysis_persists_completed_state(self):
        source = b"src ip,dst ip,bytes,packets,dst port\n8.8.8.8,1.1.1.1,1200,3,443\n"
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            input_file = root / "input.bin"
            job_file = root / "analysis.json"
            input_file.write_bytes(source)
            server._write_json_atomic(job_file, {
                "metadata": {"job_id": "a" * 32}, "summary": {}, "records": [],
                "enrichment": {"status": "not_started"},
                "analysis": {"status": "queued", "progress": 5},
            })

            with patch.object(
                server.learning_engine, "annotate_analysis", side_effect=lambda app, job, data: data
            ), patch.object(server, "_schedule_model_analysis"):
                server.RequestHandler._run_analysis(None, "a" * 32, "flows.csv", input_file, job_file)
            result = json.loads(job_file.read_text(encoding="utf-8"))

        self.assertEqual(result["analysis"]["status"], "completed")
        self.assertEqual(result["analysis"]["progress"], 100)
        self.assertEqual(result["summary"]["records"], 1)
        self.assertFalse(input_file.exists())

    def test_reports_are_well_formed_ooxml(self):
        parsed = file_parser.read_file(
            b"src ip,dst ip,bytes,packets\n8.8.8.8,1.1.1.1,100,2\n", "flows.csv"
        )
        import flow_analyzer
        import tempfile
        import os
        from flowscope.result_sink import MemoryResultReader
        result = flow_analyzer.analyze_flow_data(parsed)
        result["analysis"] = {"status": "completed"}

        reader = MemoryResultReader(result.get("records") or [])
        fd, docx_path = tempfile.mkstemp(suffix=".docx")
        os.close(fd)
        build_report_docx(result, reader, docx_path)
        with open(docx_path, "rb") as f:
            docx = f.read()
        os.remove(docx_path)
        
        fd, xlsx_path = tempfile.mkstemp(suffix=".xlsx")
        os.close(fd)
        build_report_xlsx(result, reader, xlsx_path)
        with open(xlsx_path, "rb") as f:
            xlsx = f.read()
        os.remove(xlsx_path)

        for report in (docx, xlsx):
            with zipfile.ZipFile(io.BytesIO(report)) as archive:
                self.assertIsNone(archive.testzip())
                for name in archive.namelist():
                    if name.endswith(".xml"):
                        ET.fromstring(archive.read(name))

        with zipfile.ZipFile(io.BytesIO(docx)) as archive:
            document_text = archive.read("word/document.xml").decode("utf-8")
            self.assertIn("الملخص التنفيذي", document_text)
            self.assertIn("نتائج تحليل سمعة المصادر", document_text)
            self.assertNotIn("flows.csv", document_text)
            self.assertNotIn("اسم الملف", document_text)
            self.assertNotIn("استخبارات", document_text)
            self.assertIn("التوصيات", document_text)
            self.assertIn('<w:bidi w:val="1"/>', document_text)
            self.assertIn("\u200f", document_text)
            self.assertIn('<w:bidi w:val="1"/><w:jc w:val="left"/>', document_text)
            self.assertEqual(document_text.count('<w:cantSplit/>'), document_text.count('<w:tblHeader/>'))
            self.assertIn("word/header1.xml", archive.namelist())
            self.assertIn("word/footer1.xml", archive.namelist())

    def test_enrichment_is_parallel_and_stops_after_virustotal_quota(self):
        active = 0
        max_active = 0
        counter_lock = threading.Lock()

        def fake_shodan(ip, key):
            nonlocal active, max_active
            with counter_lock:
                active += 1
                max_active = max(max_active, active)
            import time
            time.sleep(0.02)
            with counter_lock:
                active -= 1
            return {"verdict": "normal", "source_status": "ok"}

        vt_calls = 0
        def fake_virustotal(ip, key):
            nonlocal vt_calls
            vt_calls += 1
            return {"verdict": "unavailable", "source_status": "quota_exceeded"}

        configuration = {
            "abuseipdb": {"enabled": False, "key": ""},
            "virustotal": {"enabled": True, "key": "key"},
            "shodan": {"enabled": True, "key": ""},
        }
        ips = {f"8.8.8.{index}" for index in range(1, 21)}
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory, \
             patch.object(enrichment, "provider_configuration", return_value=configuration), \
             patch.object(enrichment, "lookup_shodan", side_effect=fake_shodan), \
             patch.object(enrichment, "lookup_virustotal", side_effect=fake_virustotal):
            result = enrichment.enrich_ips(ips, Path(directory) / "cache.sqlite3")

        self.assertGreater(max_active, 1)
        self.assertEqual(vt_calls, 1)
        self.assertEqual(result["checked"], 20)
        self.assertEqual(result["status"], "completed")

    def test_virustotal_ip_lookup_rotates_to_fallback_key(self):
        used_keys = []

        def fake_virustotal(_ip, key):
            used_keys.append(key)
            if key == "primary":
                return {"verdict": "unavailable", "source_status": "quota_exceeded"}
            return {"verdict": "clean", "source_status": "ok"}

        configuration = {
            "abuseipdb": {"enabled": False, "key": ""},
            "virustotal": {"enabled": True, "key": "primary", "keys": ["primary", "fallback"]},
            "shodan": {"enabled": False, "key": ""},
        }
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory, \
             patch.object(enrichment, "provider_configuration", return_value=configuration), \
             patch.object(enrichment, "lookup_virustotal", side_effect=fake_virustotal):
            result = enrichment.enrich_ips({"8.8.8.8"}, Path(directory) / "cache.sqlite3")

        self.assertEqual(used_keys, ["primary", "fallback"])
        self.assertEqual(result["providers"]["virustotal"]["queries"], 2)
        self.assertEqual(result["results"]["8.8.8.8"]["virustotal"]["source_status"], "ok")

    def test_ip_snapshot_cache_only_queries_new_addresses(self):
        calls = []

        def fake_lookup(ip, key):
            calls.append(ip)
            return {"verdict": "normal", "source_status": "ok", "ports": []}

        configuration = {
            "abuseipdb": {"enabled": False, "key": ""},
            "virustotal": {"enabled": False, "key": ""},
            "shodan": {"enabled": True, "key": ""},
        }
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory, \
             patch.object(enrichment, "provider_configuration", return_value=configuration), \
             patch.object(enrichment, "lookup_shodan", side_effect=fake_lookup):
            cache_path = Path(directory) / "cache.sqlite3"
            first = enrichment.enrich_ips({"8.8.8.8"}, cache_path)
            second = enrichment.enrich_ips({"8.8.8.8", "9.9.9.9"}, cache_path)

        self.assertEqual(calls, ["8.8.8.8", "9.9.9.9"])
        self.assertEqual(first["cached"], 0)
        self.assertEqual(second["cached"], 1)
        self.assertEqual(second["new"], 1)
        self.assertEqual(second["providers"]["shodan"]["queries"], 1)
        self.assertTrue(second["results"]["8.8.8.8"]["shodan"]["cached"])

    def test_force_refresh_replaces_cached_ip_snapshot(self):
        calls = []

        def fake_lookup(ip, key):
            calls.append(ip)
            verdict = "normal" if len(calls) == 1 else "notable"
            return {"verdict": verdict, "source_status": "ok", "ports": []}

        configuration = {
            "abuseipdb": {"enabled": False, "key": ""},
            "virustotal": {"enabled": False, "key": ""},
            "shodan": {"enabled": True, "key": ""},
        }
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory, \
             patch.object(enrichment, "provider_configuration", return_value=configuration), \
             patch.object(enrichment, "lookup_shodan", side_effect=fake_lookup):
            cache_path = Path(directory) / "cache.sqlite3"
            enrichment.enrich_ips({"8.8.8.8"}, cache_path)
            refreshed = enrichment.enrich_ips({"8.8.8.8"}, cache_path, force_refresh=True)
            reused = enrichment.enrich_ips({"8.8.8.8"}, cache_path)

        self.assertEqual(calls, ["8.8.8.8", "8.8.8.8"])
        self.assertEqual(refreshed["cached"], 0)
        self.assertEqual(refreshed["new"], 1)
        self.assertFalse(refreshed["results"]["8.8.8.8"]["shodan"]["cached"])
        self.assertEqual(reused["results"]["8.8.8.8"]["shodan"]["verdict"], "notable")

    def test_valid_result_keeps_ip_cached_when_optional_source_fails(self):
        vt_calls = []
        shodan_calls = []

        def fake_vt(ip, key):
            vt_calls.append(ip)
            return {"verdict": "clean", "source_status": "ok"}

        def failing_shodan(ip, key):
            shodan_calls.append(ip)
            raise RuntimeError("temporary failure")

        configuration = {
            "abuseipdb": {"enabled": False, "key": ""},
            "virustotal": {"enabled": True, "key": "key"},
            "shodan": {"enabled": True, "key": ""},
        }
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory, \
             patch.object(enrichment, "provider_configuration", return_value=configuration), \
             patch.object(enrichment, "lookup_virustotal", side_effect=fake_vt), \
             patch.object(enrichment, "lookup_shodan", side_effect=failing_shodan):
            cache_path = Path(directory) / "cache.sqlite3"
            enrichment.enrich_ips({"8.8.8.8"}, cache_path)
            repeated = enrichment.enrich_ips({"8.8.8.8"}, cache_path)

        self.assertEqual(vt_calls, ["8.8.8.8"])
        self.assertEqual(shodan_calls, ["8.8.8.8"])
        self.assertEqual(repeated["cached"], 1)
        self.assertEqual(repeated["new"], 0)

    def test_ads_enrichment_collects_all_public_event_addresses(self):
        captured_ips = set()

        def fake_enrich(ips, cache_path, progress_callback=None, **kwargs):
            captured_ips.update(ips)
            return {
                "status": "completed", "checked": len(ips), "total": len(ips),
                "providers": {},
                "results": {ip: {"reason": "test"} for ip in ips},
            }

        data = {
            "metadata": {"data_type": "ads_events"},
            "summary": {"critical": 0, "high": 0},
            "records": [
                {"event_source": "8.8.8.8", "extracted_ips": ["8.8.8.8", "1.1.1.1"], "risk_score": 10},
                {"event_source": "9.9.9.9", "extracted_ips": ["9.9.9.9", "2.2.2.2"], "risk_score": 10},
                {"event_source": "192.168.1.20", "event_targets": ["3.3.3.3", "10.0.0.2"], "risk_score": 20},
            ],
            "enrichment": {"status": "running"},
            "analysis": {"status": "completed"},
        }

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory, \
             patch.object(enrichment, "enrich_ips", side_effect=fake_enrich), \
             patch.object(server, "_schedule_model_analysis"):
            job_file = Path(directory) / "analysis.json"
            server._write_json_atomic(job_file, data)
            server.RequestHandler._run_enrichment(None, "b" * 32, job_file)

        self.assertEqual(
            captured_ips,
            {"8.8.8.8", "1.1.1.1", "9.9.9.9", "2.2.2.2", "3.3.3.3"},
        )

    def test_interrupted_enrichment_becomes_retryable_after_restart(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            jobs_dir = Path(directory) / "jobs"
            job_file = jobs_dir / ("c" * 32) / "analysis.json"
            job_file.parent.mkdir(parents=True)
            server._write_json_atomic(job_file, {
                "analysis": {"status": "completed"},
                "enrichment": {"status": "running"},
            })
            with patch.object(server, "JOBS_DIR", jobs_dir):
                server._recover_interrupted_jobs()
            result = json.loads(job_file.read_text(encoding="utf-8"))

        self.assertEqual(result["enrichment"]["status"], "interrupted")

    def test_public_provider_configuration_never_exposes_keys(self):
        private = {
            "virustotal": {"enabled": True, "key": "secret-value"},
            "shodan": {"enabled": True, "key": ""},
        }
        with patch.object(enrichment, "provider_configuration", return_value=private):
            public = enrichment.public_provider_configuration()

        self.assertEqual(public["virustotal"], {"enabled": True})
        self.assertNotIn("secret-value", json.dumps(public))


if __name__ == "__main__":
    unittest.main()
