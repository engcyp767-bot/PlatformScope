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
import os
import result_sink
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


class LogScopeTests(unittest.TestCase):
    def test_export_filename_contains_log_source_system(self):
        filename = server._export_filename(
            {"metadata": {"source_system_label": "ManageEngine Log360"}}, ".xlsx"
        )
        self.assertRegex(filename, r"^LogScope_ManageEngine-Log360_Log_Report_\d{8}_\d{6}\.xlsx$")

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
            "extracted_ips": ["8.8.8.8", "9.9.9.9"],
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
            "Event ID,Source,Severity,Source IP,Message\n"
            "1102,Windows,Critical,8.8.8.8,Audit log cleared\n"
        ).encode("utf-8-sig")
        parsed = file_parser.read_file(source, "events.csv")
        progress = []
        result = analyzer.analyze_ads_data(parsed, progress_callback=lambda *values: progress.append(values))

        self.assertEqual(parsed.headers[0], "Event ID")
        self.assertEqual(result["metadata"]["filename"], "events.csv")
        self.assertEqual(result["records"][0]["risk_score"], 100)
        self.assertTrue(progress)

    def test_manageengine_aliases_are_normalized(self):
        source = (
            "Event Time,Event ID,Event Type Severity,Event Source,Computer Name,Username,Client IP,Message Description,Status\n"
            "2026-08-23 09:23:00,4625,High,Microsoft Windows security auditing.,DESKTOP-1,admin,192.168.1.50,An account failed to log on.,Failure\n"
        ).encode("utf-8")
        parsed = file_parser.read_file(source, "manageengine.csv")
        result = analyzer.analyze_ads_data(parsed)
        record = result["records"][0]

        self.assertEqual(record["event_id"], "4625")
        self.assertEqual(record["priority"], "High")
        self.assertEqual(record["device"], "DESKTOP-1")
        self.assertEqual(record["user_account"], "admin")
        self.assertEqual(record["src_ip"], "192.168.1.50")
        self.assertEqual(record["description"], "An account failed to log on.")
        self.assertIn("فاشلة", record["description_ar"])

    def test_manageengine_all_events_columns_include_device_and_display_name(self):
        source = (
            "Time,Device,DisplayName,Source,EventID,Severity\n"
            "8/31/2026 0:00,srv-dc1,Auditing Success,Microsoft-Windows-Security-Auditing,4624,Information\n"
        ).encode("utf-8")
        parsed = file_parser.read_file(source, "all_events.csv")
        result = analyzer.analyze_ads_data(parsed)
        record = result["records"][0]

        self.assertEqual(record["device"], "srv-dc1")
        self.assertEqual(record["description"], "Auditing Success")
        self.assertEqual(record["description_ar"], "تسجيل دخول ناجح")

    def test_manageengine_device_placeholder_becomes_event_description(self):
        source = (
            "Time,Device,Source,EventID,Severity\n"
            "8/31/2026 0:00,srv-dc1,Microsoft-Windows-Security-Auditing,4624,Information\n"
        ).encode("utf-8")
        parsed = file_parser.read_file(source, "events.csv")
        result = analyzer.analyze_ads_data(parsed)
        record = result["records"][0]

        self.assertEqual(record["device"], "srv-dc1")
        self.assertEqual(record["description"], "تسجيل دخول ناجح")

    def test_log360_csv_preamble_is_skipped_before_header_detection(self):
        source = (
            "ManageEngine Log360 Report\n"
            "Generated at 2026-08-31\n"
            "\n"
            "Time,Event ID,Severity,Source,Message\n"
            "8/31/2026 0:00,1102,High,Security,The audit log was cleared.\n"
        ).encode("utf-8")
        parsed = file_parser.read_file(source, "preamble.csv")
        result = analyzer.analyze_ads_data(parsed)

        self.assertEqual(result["records"][0]["event_id"], "1102")
        self.assertEqual(result["records"][0]["severity"], "حرج")

    def test_log360_report_families_accept_custom_columns_and_preserve_every_field(self):
        source = (
            "Compliance Control,Policy,Status,Device Name,Custom Tag\n"
            "PCI-DSS 10.2,Audit Policy,Compliant,srv-db1,Production\n"
        ).encode("utf-8")
        parsed = file_parser.read_file(source, "compliance.csv")
        result = analyzer.analyze_ads_data(parsed)

        self.assertEqual(result["metadata"]["report_family"], "compliance")
        self.assertEqual(result["records"][0]["raw_fields"]["Custom Tag"], "Production")

    def test_huawei_attack_export_fields_are_normalized_without_losing_context(self):
        source = (
            "Time,Source IP,Destination IP,Attack Name,Action\n"
            "8/31/2026 0:00,1.1.1.1,2.2.2.2,Port Scan,Block\n"
        ).encode("utf-8")
        parsed = file_parser.read_file(source, "huawei.csv")
        result = analyzer.analyze_ads_data(parsed)

        self.assertEqual(result["records"][0]["action"], "Block")
        self.assertIn("استكشاف المنافذ", result["records"][0]["description_ar"])

    def test_exported_xlsx_keeps_original_log360_columns_in_a_dedicated_sheet(self):
        source = (
            "Time,Device,Source IP,Custom Column\n"
            "8/31/2026 0:00,srv-1,10.0.0.1,Custom Value\n"
        ).encode("utf-8")
        parsed = file_parser.read_file(source, "export.csv")
        result = analyzer.analyze_ads_data(parsed)
        reader = result_sink.MemoryResultReader(result.get("records") or [])
        fd, xlsx_path = tempfile.mkstemp(suffix=".xlsx")
        os.close(fd)
        build_report_xlsx(result, reader, xlsx_path)
        with open(xlsx_path, "rb") as f:
            xlsx = f.read()
        os.remove(xlsx_path)

        with zipfile.ZipFile(io.BytesIO(xlsx)) as archive:
            sheet_names = archive.namelist()
            self.assertTrue(any("sheet" in name for name in sheet_names))

    def test_ip_classification_uses_real_ip_rules(self):
        self.assertTrue(enrichment.is_private_ip("192.168.1.1"))
        self.assertTrue(enrichment.is_private_ip("not-an-ip"))
        self.assertFalse(enrichment.is_private_ip("8.8.8.8"))
        self.assertFalse(enrichment.is_private_ip("172.200.1.1"))

    def test_background_analysis_persists_completed_state(self):
        source = b"Time,Event ID,Severity,Source IP\n8/31/2026,4625,High,8.8.8.8\n"
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
                server.RequestHandler._run_analysis(None, "a" * 32, "logs.csv", input_file, job_file)
            result = json.loads(job_file.read_text(encoding="utf-8"))

        self.assertEqual(result["analysis"]["status"], "completed")
        self.assertEqual(result["analysis"]["progress"], 100)
        self.assertEqual(result["summary"]["records"], 1)
        self.assertFalse(input_file.exists())

    def test_reports_are_well_formed_ooxml(self):
        source = b"Time,Event ID,Severity,Source IP\n8/31/2026,4625,High,8.8.8.8\n"
        parsed = file_parser.read_file(source, "logs.csv")
        result = analyzer.analyze_ads_data(parsed)
        result["analysis"] = {"status": "completed"}

        reader = result_sink.MemoryResultReader(result.get("records") or [])
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

    def test_utm_firewall_syslog_signatures_and_destinations_are_extracted(self):
        source = (
            'Time,Device,Source IP,Destination IP,Attack Name,Action,Application,Source Zone,Transmission Protocol,Message\n'
            '8/31/2026 0:00,10.47.15.5,10.221.118.180,82.114.163.31,Virus,Block,DNS,trust,UDP,"CID=0x814f041e;An intrusion was detected. (SyslogId=31037711, SrcIp=10.221.118.180, DstIp=82.114.163.31, SignName=""Virus Expiro : vjaxhpbji.biz"", SignId=3360575, Severity=high, Action=Block)"\n'
            '8/31/2026 0:00,10.47.15.5,10.222.208.129,193.118.39.35,Other,Alert,HTTP,trust,TCP,"CID=0x814f041e;An intrusion was detected. (SyslogId=30975646, SignName=""Spring Security Vulnerability"", SignId=720020, Reference=CVE-2022-22978, Severity=high, Action=Alert)"\n'
        ).encode("utf-8")
        result = analyzer.analyze_ads_data(file_parser.read_file(source, "utm.csv"))
        records = result["records"]
        
        self.assertEqual(len(records), 2)
        # First record
        self.assertEqual(records[0]["event_id"], "3360575")
        self.assertEqual(records[0]["src_ip"], "10.221.118.180")
        self.assertEqual(records[0]["destination"], "82.114.163.31")
        self.assertEqual(records[0]["device"], "10.47.15.5")
        self.assertEqual(records[0]["description"], "Virus Expiro : vjaxhpbji.biz")
        self.assertGreaterEqual(records[0]["risk_score"], 75)
        
        # Second record
        self.assertEqual(records[1]["event_id"], "720020")
        self.assertEqual(records[1]["src_ip"], "10.222.208.129")
        self.assertEqual(records[1]["destination"], "193.118.39.35")
        self.assertIn("CVE-2022-22978", records[1]["description"])
        self.assertGreaterEqual(records[1]["risk_score"], 85)
        
        # Protocols and Forensic Arabic Translations
        self.assertEqual(records[0]["protocol"], "UDP")
        self.assertIn("حظر", records[0]["action_ar"])
        self.assertIn("Expiro", records[0]["threat_family"])
        self.assertIn("فيروس Expiro", records[0]["description_ar"])

        self.assertEqual(records[1]["protocol"], "TCP")
        self.assertIn("تنبيه", records[1]["action_ar"])
        
        # Extracted public IPs for threat intelligence
        self.assertIn("82.114.163.31", result["all_extracted_ips"])
        self.assertIn("193.118.39.35", result["all_extracted_ips"])

    def test_protocol_ports_and_forensic_explanations(self):
        source = (
            'Time,Source IP,Source Port,Destination IP,Destination Port,Transmission Protocol,Attack Name,Action\n'
            '8/31/2026 0:00,10.221.118.180,49152,8.8.8.8,53,UDP,Virus Expiro : vjaxhpbji.biz,Block\n'
            '8/31/2026 0:01,185.80.143.117,54321,10.47.15.5,0,ICMP,Trace route attack,Discard\n'
            '8/31/2026 0:02,192.178.204.100,50000,10.225.138.198,80,TCP,ICMP unreachable attack,Discard\n'
            '8/31/2026 0:03,82.114.163.31,60000,10.48.11.76,443,TCP,Trojan Tiggre : cvgrf.biz,Block\n'
            '8/31/2026 0:04,10.221.123.106,9994,103.195.103.66,9993,UDP,Internal Network Penetration Tools - Zerotier Communication Traffic,Alert\n'
        ).encode("utf-8")
        result = analyzer.analyze_ads_data(file_parser.read_file(source, "forensic.csv"))
        records = result["records"]

        self.assertEqual(len(records), 5)
        
        # 1. Expiro with DNS port 53
        self.assertEqual(records[0]["protocol"], "UDP")
        self.assertEqual(records[0]["src_port"], "49152")
        self.assertEqual(records[0]["dst_port"], "53")
        self.assertEqual(records[0]["service_name"], "DNS")
        self.assertIn("فيروس Expiro", records[0]["description_ar"])
        self.assertIn("vjaxhpbji.biz", records[0]["description_ar"])
        self.assertIn("حظر", records[0]["action_ar"])

        # 2. Traceroute Reconnaissance
        self.assertEqual(records[1]["protocol"], "ICMP")
        self.assertEqual(records[1]["src_port"], "54321")
        self.assertIn("استطلاع وتتبع مسار الشبكة", records[1]["description_ar"])
        self.assertIn("إسقاط", records[1]["action_ar"])

        # 3. ICMP Unreachable
        self.assertIn("إغراق رسائل تحكم ICMP", records[2]["description_ar"])
        self.assertIn("إسقاط", records[2]["action_ar"])

        # 4. Tiggre Trojan with HTTPS port 443
        self.assertEqual(records[3]["protocol"], "TCP")
        self.assertEqual(records[3]["dst_port"], "443")
        self.assertEqual(records[3]["service_name"], "HTTPS")
        self.assertIn("تروجان Tiggre", records[3]["description_ar"])
        self.assertIn("cvgrf.biz", records[3]["description_ar"])
        self.assertIn("حظر", records[3]["action_ar"])

        # 5. Zerotier Penetration Tools with port 9993
        self.assertEqual(records[4]["protocol"], "UDP")
        self.assertEqual(records[4]["src_port"], "9994")
        self.assertEqual(records[4]["dst_port"], "9993")
        self.assertIn("Zerotier", records[4]["description_ar"])
        self.assertIn("أدوات اختراق", records[4]["description_ar"])
        self.assertIn("تنبيه", records[4]["action_ar"])
        self.assertIn("أدوات اختراق", records[4]["threat_family"])

    def test_utf16_encoded_csv_and_long_preamble_delimiter_detection(self):
        preamble = "\n".join([f"Log360 Meta Header Line {i}; Generated=True" for i in range(15)])
        csv_body = (
            f"{preamble}\n"
            "Time,Device,Source IP,Destination IP,Attack Name,Action,Transmission Protocol,Source Port,Destination Port\n"
            "2026-08-31 23:04:45,Huawei-USG6000,10.221.123.106,103.195.103.66,Internal Network Penetration Tools - Zerotier Communication Traffic,Alert,UDP,9994,9993\n"
        )
        source_utf16 = csv_body.encode("utf-16")
        parsed = file_parser.read_file(source_utf16, "Huawei_All_Attacks_2026-08-31_23_04_45.csv")
        result = analyzer.analyze_ads_data(parsed)
        records = result["records"]

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["event_time"], "2026-08-31 23:04:45")
        self.assertEqual(records[0]["device"], "Huawei-USG6000")
        self.assertEqual(records[0]["src_ip"], "10.221.123.106")
        self.assertEqual(records[0]["destination"], "103.195.103.66")
        self.assertEqual(records[0]["protocol"], "UDP")
        self.assertEqual(records[0]["src_port"], "9994")
        self.assertEqual(records[0]["dst_port"], "9993")
        self.assertIn("Zerotier", records[0]["description_ar"])

    def test_heuristic_extraction_when_standard_column_names_differ(self):
        source = (
            "Occur Date,Firewall Appliance,Initiator Host,Target Host,Threat Signature,Firewall Disposition,Transport,Client Pt,Server Pt\n"
            "2026-08-31 12:00:00,FW-CORE-01,192.168.10.50,8.8.8.8,Virus Expiro : evil.com,Drop,TCP,51234,443\n"
        ).encode("utf-8")
        parsed = file_parser.read_file(source, "custom_firewall.csv")
        result = analyzer.analyze_ads_data(parsed)
        records = result["records"]

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["event_time"], "2026-08-31 12:00:00")
        self.assertEqual(records[0]["device"], "FW-CORE-01")
        self.assertEqual(records[0]["src_ip"], "192.168.10.50")
        self.assertEqual(records[0]["destination"], "8.8.8.8")
        self.assertEqual(records[0]["protocol"], "TCP")
        self.assertEqual(records[0]["src_port"], "51234")
        self.assertEqual(records[0]["dst_port"], "443")
        self.assertIn("إسقاط", records[0]["action_ar"])
        self.assertIn("فيروس Expiro", records[0]["description_ar"])

    def test_comma_csv_with_semicolons_inside_message_is_not_hijacked(self):
        source = (
            "Time,Device,Source IP,Destination IP,Attack Name,Action,Application,Source Zone,Transmission Protocol,Message\n"
            "8/31/2026 0:00,10.47.15.5,10.221.118.180,114.114.114.114,Virus,Block,DNS,trust,UDP,\"CID=0x814f041e;An intrusion was detected. (SyslogId=31037711, VSys=\"\"public\"\", Policy=\"\"trust_untrust_VRF_Internet\"\", SrcIp=10.221.118.180, DstIp=114.114.114.114, SrcPort=0, DstPort=53)\"\n"
        ).encode("utf-8")
        parsed = file_parser.read_file(source, "test_semicolons.csv")
        result = analyzer.analyze_ads_data(parsed)
        records = result["records"]

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["event_time"], "8/31/2026 0:00")
        self.assertEqual(records[0]["device"], "10.47.15.5")
        self.assertEqual(records[0]["src_ip"], "10.221.118.180")
        self.assertEqual(records[0]["destination"], "114.114.114.114")
        self.assertEqual(records[0]["protocol"], "UDP")
        self.assertEqual(records[0]["dst_port"], "53")
        self.assertEqual(records[0]["action"], "Block")


if __name__ == "__main__":
    unittest.main()
