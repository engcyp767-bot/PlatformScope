"""Comprehensive test suite for Platform Logging & Observability Architecture."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from platform_core import audit_engine
from platform_core.logging import (
    PlatformLogger,
    PlatformLogStorage,
    clear_context,
    get_current_context,
    get_logger,
    get_metrics,
    get_platform_log_level,
    init_platform_logging,
    log_context,
    redact_data,
    redact_string,
    set_context,
    set_platform_log_level,
)
from platform_core.logging.formatter import StructuredLogFormatter
from platform_core.logging.handlers import AsyncLogHandler


class TestRedactionEngine(unittest.TestCase):
    """Test sensitive data redaction and masking engine."""

    def test_redact_sensitive_dictionary_keys(self):
        payload = {
            "username": "soc_admin",
            "password": "SuperSecretPassword123!",
            "api_key": "sk-1234567890abcdef1234567890abcdef",
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "nested": {
                "secret_key": "TOP_SECRET_VALUE",
                "normal_field": "visible_value",
            },
        }
        sanitized = redact_data(payload)
        self.assertEqual(sanitized["username"], "soc_admin")
        self.assertEqual(sanitized["password"], "[REDACTED]")
        self.assertEqual(sanitized["api_key"], "[REDACTED]")
        self.assertEqual(sanitized["access_token"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["secret_key"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["normal_field"], "visible_value")

    def test_redact_string_patterns(self):
        text = "Request with Bearer ya29.a0AfH6SM123456 and token secret_token_xyz"
        redacted = redact_string(text)
        self.assertNotIn("ya29.a0AfH6SM123456", redacted)
        self.assertIn("Bearer [REDACTED]", redacted)


class TestStructuredLogFormatter(unittest.TestCase):
    """Test schema compliance, parameterization and bilingual resolution."""

    def setUp(self):
        self.formatter = StructuredLogFormatter(redact=True)

    def test_schema_compliance_and_defaults(self):
        event = self.formatter.format_event(
            level="INFO",
            logger_name="platform.test",
            component="test_component",
            event_type="test.event",
            event_code="SYS_START",
            message="Server initialized",
            correlation_id="CORR-1234567890",
            request_id="REQ-0987654321",
        )
        self.assertEqual(event["level"], "INFO")
        self.assertEqual(event["logger"], "platform.test")
        self.assertEqual(event["component"], "test_component")
        self.assertEqual(event["event_code"], "SYS_START")
        self.assertEqual(event["correlation_id"], "CORR-1234567890")
        self.assertEqual(event["request_id"], "REQ-0987654321")
        self.assertTrue(len(event["message_ar"]) > 0)
        self.assertTrue(len(event["message_en"]) > 0)
        self.assertIn("timestamp", event)

    def test_redaction_in_formatter(self):
        event = self.formatter.format_event(
            level="WARNING",
            logger_name="platform.auth",
            component="auth",
            event_type="auth.event",
            technical_details={"password": "MySecretPassword!", "public_info": "127.0.0.1"},
        )
        self.assertEqual(event["technical_details"]["password"], "[REDACTED]")
        self.assertEqual(event["technical_details"]["public_info"], "127.0.0.1")

    def test_arabic_message_resolution(self):
        # 1. Test LOG_LEVEL_CHANGED
        ev1 = self.formatter.format_event(
            level="INFO",
            logger_name="platform.backend",
            component="backend",
            event_type="system.config",
            event_code="LOG_LEVEL_CHANGED",
            old_level="TRACE",
            new_level="INFO",
        )
        self.assertIn("تم تغيير مستوى تسجيل المنصة من TRACE إلى INFO", ev1["message_ar"])
        self.assertEqual(ev1["message"], ev1["message_ar"])
        self.assertIn("Platform log level changed from TRACE to INFO", ev1["message_en"])

        # 2. Test SYS_START
        ev2 = self.formatter.format_event(
            level="INFO",
            logger_name="platform.backend",
            component="backend",
            event_type="system.lifecycle",
            event_code="SYS_START",
            host="127.0.0.1",
            port=8000,
        )
        self.assertIn("بدء تشغيل خادم المنصة الموحد", ev2["message_ar"])

        # 3. Test English pattern auto-translation fallback
        ev3 = self.formatter.format_event(
            level="INFO",
            logger_name="platform.test",
            component="backend",
            event_type="general",
            event_code="GENERAL_EVENT",
            message="Platform log level changed from WARNING to INFO",
        )
        self.assertIn("تم تغيير مستوى تسجيل المنصة من WARNING", ev3["message_ar"])


class TestContextManagement(unittest.TestCase):
    """Test contextvars-based propagation and thread safety."""

    def setUp(self):
        clear_context()

    def tearDown(self):
        clear_context()

    def test_set_and_clear_context(self):
        set_context(
            request_id="REQ-TEST1",
            correlation_id="CORR-TEST1",
            job_id="job-123",
            user_id="analyst",
            component="backend",
        )
        ctx = get_current_context()
        self.assertEqual(ctx["request_id"], "REQ-TEST1")
        self.assertEqual(ctx["correlation_id"], "CORR-TEST1")
        self.assertEqual(ctx["job_id"], "job-123")
        self.assertEqual(ctx["user_id"], "analyst")
        self.assertEqual(ctx["component"], "backend")

        clear_context()
        self.assertEqual(get_current_context(), {})

    def test_context_manager_scope(self):
        self.assertEqual(get_current_context(), {})
        with log_context(correlation_id="CORR-SCOPED", request_id="REQ-SCOPED"):
            ctx = get_current_context()
            self.assertEqual(ctx["correlation_id"], "CORR-SCOPED")
            self.assertEqual(ctx["request_id"], "REQ-SCOPED")
        # Restored
        self.assertNotIn("correlation_id", get_current_context())


class TestPlatformLogStorage(unittest.TestCase):
    """Test SQLite-based platform log storage, indexing, and querying."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_logs.db"
        self.storage = PlatformLogStorage(db_path=self.db_path)

    def tearDown(self):
        self.storage.close()
        self.temp_dir.cleanup()

    def test_store_and_query_logs(self):
        event1 = {
            "timestamp": "2026-09-08T01:00:00.000000Z",
            "level": "INFO",
            "logger": "platform.backend",
            "component": "backend",
            "event_type": "request",
            "event_code": "REQ_RECEIVED",
            "message_ar": "تم استلام الطلب بنجاح",
            "message_en": "Request received successfully",
            "message": "Request received successfully",
            "correlation_id": "CORR-AAA111",
            "request_id": "REQ-111",
        }
        event2 = {
            "timestamp": "2026-09-08T01:00:01.000000Z",
            "level": "ERROR",
            "logger": "platform.flowscope",
            "component": "flowscope",
            "event_type": "error",
            "event_code": "JOB_FAILED",
            "message_ar": "فشل تحليل تدفق الشبكة",
            "message_en": "Network traffic analysis failed",
            "message": "Network traffic analysis failed",
            "correlation_id": "CORR-AAA111",
            "request_id": "REQ-222",
            "error_code": "ERR_PCAP_PARSE",
        }

        self.storage.store_event(event1)
        self.storage.store_event(event2)

        # Query all
        res = self.storage.query_logs()
        self.assertEqual(res["total"], 2)
        self.assertEqual(len(res["logs"]), 2)

        # Query by level
        res_err = self.storage.query_logs(level="ERROR")
        self.assertEqual(res_err["total"], 1)
        self.assertEqual(res_err["logs"][0]["level"], "ERROR")

        # Query by component
        res_comp = self.storage.query_logs(component="flowscope")
        self.assertEqual(res_comp["total"], 1)

        # Query KPIs
        kpis = self.storage.get_kpis()
        self.assertEqual(kpis["total_events"], 2)
        self.assertEqual(kpis["errors"], 1)
        self.assertEqual(kpis["info"], 1)

        # Correlation timeline
        timeline = self.storage.get_correlation_timeline("CORR-AAA111")
        self.assertEqual(len(timeline), 2)
        self.assertEqual(timeline[0]["event_code"], "REQ_RECEIVED")
        self.assertEqual(timeline[1]["event_code"], "JOB_FAILED")


class TestAsyncLogHandlerAndBackpressure(unittest.TestCase):
    """Test non-blocking log worker and backpressure dropping policy."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_handler.db"
        self.storage = PlatformLogStorage(db_path=self.db_path)
        self.handler = AsyncLogHandler(
            storage=self.storage,
            log_dir=Path(self.temp_dir.name) / "logs",
            queue_size=5,
        )

    def tearDown(self):
        self.handler.close(timeout=1.0)
        self.temp_dir.cleanup()


    def test_worker_processes_enqueued_events(self):
        event = {
            "timestamp": "2026-09-08T01:00:00Z",
            "level": "INFO",
            "logger": "platform.test",
            "component": "test",
            "event_type": "test",
            "event_code": "SYS_START",
            "message": "Async worker test",
        }
        self.handler.enqueue(event)
        self.handler.flush()
        time.sleep(0.15)
        res = self.storage.query_logs()
        self.assertEqual(res["total"], 1)

    def test_critical_never_dropped_under_backpressure(self):
        # Flood the queue with low-priority DEBUG items
        for i in range(10):
            self.handler.enqueue({
                "timestamp": "2026-09-08T01:00:00Z",
                "level": "DEBUG",
                "logger": "platform.test",
                "component": "test",
                "event_type": "test",
                "event_code": f"DEBUG_{i}",
                "message": f"Debug log {i}",
            })

        # CRITICAL event must NOT be dropped
        crit_event = {
            "timestamp": "2026-09-08T01:00:00Z",
            "level": "CRITICAL",
            "logger": "platform.security",
            "component": "security",
            "event_type": "alert",
            "event_code": "SECURITY_BREACH",
            "message": "Critical security incident occurred",
        }
        self.handler.enqueue(crit_event)
        time.sleep(0.5)

        res = self.storage.query_logs(level="CRITICAL")
        self.assertGreaterEqual(res["total"], 1)
        self.assertEqual(res["logs"][0]["event_code"], "SECURITY_BREACH")


class TestDynamicLogLevel(unittest.TestCase):
    """Test dynamic runtime filtering and level modifications."""

    def test_log_level_threshold(self):
        set_platform_log_level("WARNING")
        self.assertEqual(get_platform_log_level(), "WARNING")

        logger = get_logger("test_filter")
        self.assertFalse(logger.is_enabled_for("DEBUG"))
        self.assertFalse(logger.is_enabled_for("INFO"))
        self.assertTrue(logger.is_enabled_for("WARNING"))
        self.assertTrue(logger.is_enabled_for("ERROR"))
        self.assertTrue(logger.is_enabled_for("CRITICAL"))

        # Reset to INFO
        set_platform_log_level("INFO")
        self.assertTrue(logger.is_enabled_for("INFO"))
        self.assertFalse(logger.is_enabled_for("DEBUG"))


class TestAuditCryptographicHashChain(unittest.TestCase):
    """Test tamper-evident SHA-256 hash chaining for audit logs."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.audit_file = Path(self.temp_dir.name) / "audit_test.jsonl"
        self.patcher = patch.object(audit_engine, "AUDIT_DIR", Path(self.temp_dir.name))
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.temp_dir.cleanup()

    def test_audit_hash_chain_verification_and_tampering(self):
        # Record 3 events
        audit_engine.record_engine_event(
            application="platform",
            action="login",
            message="User login",
            category="authentication",
            details={"user": "analyst1"},
        )
        audit_engine.record_engine_event(
            application="threatscope",
            action="analysis",
            message="Threat analysis started",
            category="analysis",
            details={"user": "analyst1"},
        )
        audit_engine.record_engine_event(
            application="platform",
            action="export",
            message="Report exported",
            category="report",
            details={"user": "analyst1"},
        )

        audit_files = list(Path(self.temp_dir.name).glob("*.jsonl"))
        self.assertTrue(len(audit_files) > 0)
        target_file = audit_files[0]

        # Verify integrity of untampered file
        ok, msg = audit_engine.verify_audit_integrity(target_file)
        self.assertTrue(ok, f"Integrity verification failed: {msg}")

        # Tamper with the second line in the audit file
        lines = target_file.read_text(encoding="utf-8").splitlines()
        rec2 = json.loads(lines[1])
        rec2["user"] = "attacker_impersonator"
        lines[1] = json.dumps(rec2, ensure_ascii=False)
        target_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Re-verify -> MUST FAIL
        ok_tampered, msg_tampered = audit_engine.verify_audit_integrity(target_file)
        self.assertFalse(ok_tampered)
        self.assertIn("Tampered record", msg_tampered)


class TestPlatformHealthComponents(unittest.TestCase):
    """Test platform health inspection and 10 components status check."""

    def test_health_data_structure_and_components(self):
        import backend_server
        data = backend_server._get_platform_health_data()
        self.assertIn("status", data)
        self.assertIn("components", data)
        self.assertEqual(len(data["components"]), 10)

        component_ids = {c["id"] for c in data["components"]}
        expected_ids = {
            "backend",
            "gateway",
            "logs_db",
            "audit_chain",
            "threatscope",
            "flowscope",
            "logscope",
            "memory",
            "disk",
            "log_worker",
        }
        self.assertEqual(component_ids, expected_ids)

        for comp in data["components"]:
            self.assertIn(comp["status"], ("healthy", "degraded", "unhealthy"))
            self.assertTrue(len(comp["name_ar"]) > 0)
            self.assertTrue(len(comp["name_en"]) > 0)
            self.assertIsInstance(comp["details"], dict)


if __name__ == "__main__":
    unittest.main()

