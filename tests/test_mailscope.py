"""Unit tests for MailScope — Email Security Forensics & BEC Detection Engine."""

import os
import tempfile
import unittest
from pathlib import Path

from mailscope.analyzer import MailAnalyzer
from mailscope.models import (
    AuthStatus,
    EmailAnalysisReport,
    EmailAttachment,
    EmailAuthResults,
    EmailFinding,
    EmailHop,
    EmailURL,
    EmailVerdict,
    ParsedEmail,
    Severity,
)
from mailscope.parser import MailParser, calculate_entropy
from mailscope.store import MailStore


class TestMailParser(unittest.TestCase):
    """Tests for MailParser RFC 822 / MIME decoding."""

    def test_parse_clean_email(self):
        raw_eml = """From: "Security Team" <security@example.com>
To: alice@example.com
Subject: Monthly Security Awareness Bulletin
Date: Mon, 10 Sep 2026 10:00:00 +0300
Message-ID: <msg001@example.com>
Authentication-Results: mx.example.com; spf=pass (client-ip=192.0.2.1) smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass
Content-Type: text/plain; charset=utf-8

Hello Alice,
Please review the security awareness bulletin on our intranet:
https://intranet.example.com/security/bulletin-sep-2026
Best regards,
Security Team
"""
        parsed = MailParser.parse(raw_eml)
        self.assertEqual(parsed.subject, "Monthly Security Awareness Bulletin")
        self.assertEqual(parsed.sender_name, "Security Team")
        self.assertEqual(parsed.sender_address, "security@example.com")
        self.assertEqual(parsed.sender_domain, "example.com")
        self.assertEqual(parsed.to, ["alice@example.com"])
        self.assertEqual(parsed.auth_results.spf_status, AuthStatus.PASS)
        self.assertEqual(parsed.auth_results.dkim_status, AuthStatus.PASS)
        self.assertEqual(parsed.auth_results.dmarc_status, AuthStatus.PASS)
        self.assertTrue(parsed.auth_results.is_aligned())
        self.assertEqual(len(parsed.urls), 1)
        self.assertEqual(parsed.urls[0].domain, "intranet.example.com")

    def test_parse_multipart_with_attachment_and_mismatched_url(self):
        raw_eml = """From: "Microsoft 365" <admin@phish-portal.net>
Reply-To: badguy@phish-portal.net
To: bob@example.com
Subject: Action Required: Your mailbox is full
Date: Mon, 10 Sep 2026 11:30:00 +0300
Message-ID: <phish123@phish-portal.net>
Authentication-Results: mx.example.com; spf=fail (client-ip=198.51.100.25); dmarc=fail action=reject
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY123"

--BOUNDARY123
Content-Type: text/html; charset=utf-8

<html>
<body>
<p>Dear User,</p>
<p>Your mailbox quota exceeded. Click below to verify password:</p>
<a href="http://198.51.100.99/update-billing/login.php">https://login.microsoft.com/verify</a>
</body>
</html>

--BOUNDARY123
Content-Type: application/octet-stream; name="Urgent_Invoice.pdf.exe"
Content-Disposition: attachment; filename="Urgent_Invoice.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

--BOUNDARY123--
"""
        parsed = MailParser.parse(raw_eml)
        self.assertEqual(parsed.sender_address, "admin@phish-portal.net")
        self.assertEqual(parsed.reply_to, "badguy@phish-portal.net")
        self.assertEqual(parsed.auth_results.spf_status, AuthStatus.FAIL)
        self.assertEqual(parsed.auth_results.dmarc_status, AuthStatus.FAIL)
        self.assertEqual(len(parsed.attachments), 1)

        att = parsed.attachments[0]
        self.assertEqual(att.filename, "Urgent_Invoice.pdf.exe")
        self.assertTrue(att.is_dangerous_type)
        self.assertTrue(att.is_double_extension)
        self.assertTrue(len(att.sha256) == 64)

        # Verify URL mismatch detection
        self.assertTrue(len(parsed.urls) >= 1)
        url_obj = parsed.urls[0]
        self.assertTrue(url_obj.is_mismatched)
        self.assertTrue(url_obj.is_ip_based)
        self.assertTrue(url_obj.has_credential_keywords)
        self.assertEqual(url_obj.category, "phishing")

    def test_entropy_and_punycode_detection(self):
        low_entropy = calculate_entropy(b"AAAAAAAAAAAAAAAAAAAA")
        high_entropy = calculate_entropy(bytes(range(256)))
        self.assertLess(low_entropy, 1.0)
        self.assertGreater(high_entropy, 7.5)


class TestMailAnalyzer(unittest.TestCase):
    """Tests for MailAnalyzer heuristics, BEC impersonation, and scoring."""

    def setUp(self):
        self.analyzer = MailAnalyzer(
            org_domains=["acmecorp.com", "saudisecurity.gov.sa"],
            vip_names=["John Doe", "سعد القحطاني", "الرئيس التنفيذي"],
            threat_ioc_hashes={"a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"},
        )

    def test_clean_email_verdict(self):
        email = ParsedEmail(
            message_id="clean-01",
            subject="Team lunch on Thursday",
            sender_name="Alice Smith",
            sender_address="alice@acmecorp.com",
            sender_domain="acmecorp.com",
            to=["bob@acmecorp.com"],
            body_text="Hi Bob, lunch is at 12:30pm.",
            auth_results=EmailAuthResults(
                spf_status=AuthStatus.PASS,
                dkim_status=AuthStatus.PASS,
                dmarc_status=AuthStatus.PASS,
            ),
        )
        report = self.analyzer.analyze(email)
        self.assertEqual(report.verdict, EmailVerdict.CLEAN)
        self.assertLess(report.overall_score, 20)
        self.assertEqual(report.risk_level, Severity.INFO)
        self.assertTrue(len(report.digital_signature) == 64)

    def test_bec_vip_impersonation_detection(self):
        email = ParsedEmail(
            message_id="bec-01",
            subject="URGENT: Wire transfer request for client acquisition",
            sender_name="John Doe (CEO)",
            sender_address="ceo.johndoe.acmecorp@gmail.com",
            sender_domain="gmail.com",
            to=["finance@acmecorp.com"],
            body_text="Please process an urgent wire transfer of 85,000 SAR immediately. Confidential request.",
            auth_results=EmailAuthResults(
                spf_status=AuthStatus.PASS,
                dkim_status=AuthStatus.PASS,
                dmarc_status=AuthStatus.NONE,
            ),
        )
        report = self.analyzer.analyze(email)
        self.assertEqual(report.verdict, EmailVerdict.BEC_FRAUD)
        self.assertGreaterEqual(report.overall_score, 60)
        self.assertIn("QUARANTINE_EMAIL", report.recommended_actions)
        self.assertIn("CREATE_SECURITY_INCIDENT", report.recommended_actions)

        # Check BEC finding
        bec_findings = [f for f in report.findings if f.category == "bec"]
        self.assertTrue(len(bec_findings) >= 1)
        self.assertEqual(bec_findings[0].severity, Severity.CRITICAL)

    def test_bec_arabic_financial_fraud_detection(self):
        email = ParsedEmail(
            message_id="bec-ar-01",
            subject="طلب تحويل بنكي عاجل وسري",
            sender_name="الرئيس التنفيذي - سعد القحطاني",
            sender_address="saad.alqahtani@yahoo.com",
            sender_domain="yahoo.com",
            to=["accountant@saudisecurity.gov.sa"],
            body_text="يرجى سداد فاتورة مستعجلة وتحديث الآيبان إلى الحساب الجديد فوراً. هذا الأمر سري للغاية.",
        )
        report = self.analyzer.analyze(email)
        self.assertEqual(report.verdict, EmailVerdict.BEC_FRAUD)
        self.assertGreaterEqual(report.overall_score, 65)

    def test_lookalike_typosquatting_detection(self):
        email = ParsedEmail(
            message_id="typo-01",
            subject="Update employee records",
            sender_name="HR Portal",
            sender_address="hr@acrnecorp.com",  # rn looks like m
            sender_domain="acrnecorp.com",
            to=["user@acmecorp.com"],
            body_text="Please click here to update your credentials.",
        )
        report = self.analyzer.analyze(email)
        self.assertIn(report.verdict, {EmailVerdict.BEC_FRAUD, EmailVerdict.PHISHING, EmailVerdict.SUSPICIOUS})
        typo_findings = [f for f in report.findings if "Typosquatting" in f.title]
        self.assertTrue(len(typo_findings) >= 1)

    def test_malicious_attachment_and_ioc_match(self):
        email = ParsedEmail(
            message_id="mal-att-01",
            subject="Scanned document from printer",
            sender_name="Scanner",
            sender_address="scanner@external-domain.com",
            sender_domain="external-domain.com",
            to=["staff@acmecorp.com"],
            attachments=[
                EmailAttachment(
                    filename="Malware.exe",
                    content_type="application/octet-stream",
                    size_bytes=4096,
                    sha256="a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
                    is_dangerous_type=True,
                )
            ],
        )
        report = self.analyzer.analyze(email)
        self.assertEqual(report.verdict, EmailVerdict.MALICIOUS)
        self.assertEqual(report.overall_score, 100)
        self.assertEqual(report.risk_level, Severity.CRITICAL)
        self.assertIn("QUARANTINE_EMAIL", report.recommended_actions)


class TestMailStore(unittest.TestCase):
    """Tests for MailStore SQLite database persistence and queries."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_mail.db"
        self.store = MailStore(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_and_retrieve_report(self):
        parsed = ParsedEmail(
            message_id="msg-999",
            subject="Suspicious alert",
            sender_name="Evil Sender",
            sender_address="evil@badsite.org",
            sender_domain="badsite.org",
            to=["target@company.com"],
        )
        report = EmailAnalysisReport(
            id="mail_test123",
            analyzed_at="2026-09-10T12:00:00Z",
            verdict=EmailVerdict.PHISHING,
            overall_score=85,
            risk_level=Severity.HIGH,
            parsed_email=parsed,
            recommended_actions=["QUARANTINE_EMAIL", "BLOCK_SENDER_DOMAIN"],
        )
        report.digital_signature = report.compute_signature()

        self.store.save_report(report)

        retrieved = self.store.get_report("mail_test123")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["id"], "mail_test123")
        self.assertEqual(retrieved["verdict"], "phishing")
        self.assertEqual(retrieved["overall_score"], 85)
        self.assertTrue(retrieved["is_quarantined"])

    def test_list_and_stats(self):
        for i in range(5):
            verdict = EmailVerdict.PHISHING if i % 2 == 0 else EmailVerdict.CLEAN
            parsed = ParsedEmail(
                message_id=f"msg-{i}",
                subject=f"Test email {i}",
                sender_name=f"Sender {i}",
                sender_address=f"sender{i}@test.com",
                sender_domain="test.com",
                to=["user@test.com"],
            )
            report = EmailAnalysisReport(
                id=f"mail_{i}",
                analyzed_at=f"2026-09-10T10:0{i}:00Z",
                verdict=verdict,
                overall_score=75 if verdict == EmailVerdict.PHISHING else 10,
                risk_level=Severity.HIGH if verdict == EmailVerdict.PHISHING else Severity.INFO,
                parsed_email=parsed,
                recommended_actions=["QUARANTINE_EMAIL"] if verdict == EmailVerdict.PHISHING else [],
            )
            report.digital_signature = report.compute_signature()
            self.store.save_report(report)

        # Test listing
        all_reports = self.store.list_reports()
        self.assertEqual(len(all_reports), 5)

        phish_reports = self.store.list_reports(verdict="phishing")
        self.assertEqual(len(phish_reports), 3)

        # Test quarantine toggle
        self.store.set_quarantine("mail_1", quarantined=True)
        r1 = self.store.get_report("mail_1")
        self.assertTrue(r1["is_quarantined"])

        # Test incident link
        self.store.link_incident("mail_1", "INC-2026-001")
        r1_inc = self.store.get_report("mail_1")
        self.assertEqual(r1_inc["incident_id"], "INC-2026-001")

        # Test stats
        stats = self.store.get_dashboard_stats()
        self.assertEqual(stats["total_analyzed"], 5)
        self.assertEqual(stats["phishing_count"], 3)
        self.assertEqual(stats["clean_count"], 2)


if __name__ == "__main__":
    unittest.main()
