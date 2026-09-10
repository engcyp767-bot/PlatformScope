"""MailScope — Email Forensics, Threat Analyzer & BEC Detection Engine.

Performs deep multi-vector inspection on parsed emails:
1. SPF / DKIM / DMARC authentication verification and alignment.
2. Executive / VIP impersonation & Business Email Compromise (BEC) detection.
3. Lookalike & typosquatting domain detection.
4. Malicious URL analysis (homoglyphs, mismatches, credential harvesting keywords).
5. Dangerous attachment triage (macros, executables, double extensions, high entropy).
6. Urgent financial fraud language heuristics (English & Arabic).
7. Composite scoring, verdict synthesis, MITRE ATT&CK mapping, and automated playbooks.
"""

from __future__ import annotations

import difflib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from mailscope.models import (
    AuthStatus,
    EmailAnalysisReport,
    EmailAttachment,
    EmailAuthResults,
    EmailFinding,
    EmailURL,
    EmailVerdict,
    ParsedEmail,
    Severity,
)

# Common Freemail / Public Webmail domains
FREEMAIL_DOMAINS: Set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "icloud.com", "protonmail.com", "mail.com", "zoho.com", "aol.com",
    "yandex.ru", "gmx.com", "mail.ru", "tutanota.com",
}

# Standard VIP / Executive Roles to protect from impersonation
DEFAULT_VIP_ROLES: List[str] = [
    "ceo", "chief executive officer", "cfo", "chief financial officer",
    "coo", "cio", "ciso", "president", "managing director", "director",
    "payroll", "human resources", "hr department", "finance department",
    "it support", "security operations", "helpdesk",
    "الرئيس التنفيذي", "المدير المالي", "المدير العام", "إدارة الموارد البشرية",
    "قسم المالية", "الدعم الفني", "أمن المعلومات", "شؤون الموظفين",
]

# BEC Financial Urgent Keywords (English & Arabic)
BEC_FINANCIAL_KEYWORDS: List[Tuple[str, str, int]] = [
    # English
    ("wire transfer", "طلب تحويل بنكي", 25),
    ("urgent payment", "سداد دفعة مالية عاجلة", 25),
    ("invoice overdue", "فاتورة متأخرة السداد", 20),
    ("bank details changed", "تغيير بيانات الحساب البنكي", 30),
    ("updated banking information", "تحديث المعلومات البنكية", 30),
    ("swift transfer", "تحويل سويفت", 20),
    ("direct deposit change", "تعديل الإيداع المباشر", 25),
    ("purchase gift cards", "شراء بطاقات هدايا", 30),
    ("confidential request", "طلب سري للغاية", 15),
    ("immediate wire", "تحويل فوري مستعجل", 25),
    ("remittance advice", "إشعار سداد مالي", 15),
    ("new bank account", "حساب بنكي جديد للمدفوعات", 25),
    # Arabic
    ("تحويل بنكي عاجل", "Urgent wire transfer", 25),
    ("تعديل بيانات الحساب", "Bank account modification", 30),
    ("سداد فاتورة مستعجلة", "Urgent invoice payment", 20),
    ("بطاقات هدايا للموظفين", "Gift cards request", 30),
    ("سري للغاية ولا تخبر أحدا", "Strictly confidential request", 25),
    ("تحديث الآيبان", "IBAN update request", 30),
    ("إشعار دفع بنكي", "Bank payment notification", 15),
]


class MailAnalyzer:
    """Multi-vector security and forensics analyzer for parsed emails."""

    def __init__(
        self,
        org_domains: Optional[List[str]] = None,
        vip_names: Optional[List[str]] = None,
        threat_ioc_hashes: Optional[Set[str]] = None,
    ) -> None:
        """Initializes analyzer with optional organizational context."""
        self.org_domains = [d.lower().strip() for d in (org_domains or [])]
        self.vip_names = [n.lower().strip() for n in (vip_names or [])]
        self.threat_ioc_hashes = {h.lower().strip() for h in (threat_ioc_hashes or set())}

    def analyze(self, email: ParsedEmail) -> EmailAnalysisReport:
        """Executes full forensic analysis and generates structured report."""
        report_id = f"mail_{uuid.uuid4().hex[:12]}"
        analyzed_at = datetime.now(timezone.utc).isoformat()
        findings: List[EmailFinding] = []

        # 1. Authentication Inspection
        auth_score, auth_findings, auth_summary = self._inspect_authentication(email)
        findings.extend(auth_findings)

        # 2. Sender Spoofing & BEC Impersonation Inspection
        bec_score, bec_findings, bec_summary = self._inspect_bec_and_spoofing(email)
        findings.extend(bec_findings)

        # 3. URL & Phishing Inspection
        url_score, url_findings, url_summary = self._inspect_urls(email)
        findings.extend(url_findings)

        # 4. Attachment Security Triage
        att_score, att_findings, att_summary = self._inspect_attachments(email)
        findings.extend(att_findings)

        # 5. Content & Language Heuristics
        content_score, content_findings = self._inspect_content_heuristics(email)
        findings.extend(content_findings)

        # 6. Composite Score & Verdict Calculation
        # Max vector dominance model: High-severity specific attack vector sets baseline
        max_vector = max(bec_score, url_score, att_score, int(auth_score * 0.8), content_score)
        additive = (auth_score * 0.15 + bec_score * 0.2 + url_score * 0.2 + att_score * 0.2 + content_score * 0.15)
        overall_score = min(100, int(round(max(max_vector, additive))))

        # Determine Verdict
        verdict = self._determine_verdict(
            overall_score=overall_score,
            bec_score=bec_score,
            url_score=url_score,
            att_score=att_score,
            findings=findings,
        )

        # Determine Risk Level
        if overall_score >= 80 or verdict in {EmailVerdict.MALICIOUS, EmailVerdict.BEC_FRAUD}:
            risk_level = Severity.CRITICAL
        elif overall_score >= 60 or verdict == EmailVerdict.PHISHING:
            risk_level = Severity.HIGH
        elif overall_score >= 40 or verdict == EmailVerdict.SUSPICIOUS:
            risk_level = Severity.MEDIUM
        elif overall_score >= 20 or verdict == EmailVerdict.SPAM:
            risk_level = Severity.LOW
        else:
            risk_level = Severity.INFO

        # 7. Recommended Actions & Remediation Playbook
        recommended_actions, playbook = self._generate_playbook(verdict, findings, email)

        report = EmailAnalysisReport(
            id=report_id,
            analyzed_at=analyzed_at,
            verdict=verdict,
            overall_score=overall_score,
            risk_level=risk_level,
            parsed_email=email,
            findings=findings,
            auth_summary=auth_summary,
            url_summary=url_summary,
            attachment_summary=att_summary,
            bec_summary=bec_summary,
            recommended_actions=recommended_actions,
            remediation_playbook=playbook,
        )

        report.digital_signature = report.compute_signature()
        return report

    def _inspect_authentication(
        self, email: ParsedEmail
    ) -> Tuple[int, List[EmailFinding], Dict[str, Any]]:
        """Evaluates SPF, DKIM, and DMARC authentication and alignment."""
        findings: List[EmailFinding] = []
        auth = email.auth_results
        score = 0

        spf_failed = auth.spf_status in {AuthStatus.FAIL, AuthStatus.SOFTFAIL, AuthStatus.PERMERROR}
        dkim_failed = auth.dkim_status in {AuthStatus.FAIL, AuthStatus.PERMERROR}
        dmarc_failed = auth.dmarc_status == AuthStatus.FAIL

        # DMARC Failure
        if dmarc_failed:
            score += 40
            findings.append(EmailFinding(
                id=f"auth_{uuid.uuid4().hex[:6]}",
                category="auth",
                severity=Severity.HIGH,
                title="DMARC Policy Validation Failed",
                title_ar="فشل التحقق من سياسة DMARC للبريد الإلكتروني",
                description=f"DMARC validation failed for domain '{email.sender_domain}'. Policy action: {auth.dmarc_policy}.",
                description_ar=f"فشل التحقق من تطابق DMARC لنطاق المرسل '{email.sender_domain}'. إجراء السياسة: {auth.dmarc_policy}.",
                mitre_technique="T1566.002",
                evidence=f"DMARC status: {auth.dmarc_status.value}, policy: {auth.dmarc_policy}",
            ))

        # SPF Failure
        if spf_failed:
            score += 25
            findings.append(EmailFinding(
                id=f"auth_{uuid.uuid4().hex[:6]}",
                category="auth",
                severity=Severity.MEDIUM,
                title="SPF (Sender Policy Framework) Validation Failed",
                title_ar="فشل مطابقة إطار سياسة المرسل (SPF)",
                description=f"SPF record failed ({auth.spf_status.value}) for sending IP {auth.spf_ip or 'unknown'}.",
                description_ar=f"فشلت مصادقة سجل SPF ({auth.spf_status.value}) لعنوان IP المرسل {auth.spf_ip or 'غير معروف'}.",
                mitre_technique="T1566.002",
                evidence=f"SPF status: {auth.spf_status.value}, sender: {auth.spf_sender}",
            ))

        # DKIM Failure
        if dkim_failed:
            score += 25
            findings.append(EmailFinding(
                id=f"auth_{uuid.uuid4().hex[:6]}",
                category="auth",
                severity=Severity.MEDIUM,
                title="DKIM Cryptographic Signature Failed",
                title_ar="فشل التوقيع الرقمي المشفر (DKIM)",
                description=f"DKIM signature verification failed for domain '{auth.dkim_domain or email.sender_domain}'.",
                description_ar=f"فشل التحقق من صحة التوقيع الرقمي DKIM للنطاق '{auth.dkim_domain or email.sender_domain}'.",
                mitre_technique="T1566.002",
                evidence=f"DKIM status: {auth.dkim_status.value}, domain: {auth.dkim_domain}",
            ))

        # Sender Domain vs Reply-To mismatch
        if email.reply_to and "@" in email.reply_to:
            reply_domain = email.reply_to.split("@")[-1].lower()
            if email.sender_domain and reply_domain != email.sender_domain:
                score += 30
                findings.append(EmailFinding(
                    id=f"auth_{uuid.uuid4().hex[:6]}",
                    category="header",
                    severity=Severity.HIGH,
                    title="Mismatched Reply-To Address Detected",
                    title_ar="عدم تطابق عنوان الرد (Reply-To) مع نطاق المرسل",
                    description=f"Sender domain is '{email.sender_domain}' but replies are routed to '{reply_domain}'. Common in phishing.",
                    description_ar=f"نطاق المرسل هو '{email.sender_domain}' بينما توجّه الردود إلى '{reply_domain}'. مؤشر شائع في هجمات التصيد.",
                    mitre_technique="T1566.002",
                    evidence=f"From: {email.sender_address} | Reply-To: {email.reply_to}",
                ))

        summary = {
            "spf": auth.spf_status.value,
            "dkim": auth.dkim_status.value,
            "dmarc": auth.dmarc_status.value,
            "is_aligned": auth.is_aligned(),
            "sender_ip": auth.spf_ip,
        }

        return min(100, score), findings, summary

    def _inspect_bec_and_spoofing(
        self, email: ParsedEmail
    ) -> Tuple[int, List[EmailFinding], Dict[str, Any]]:
        """Detects Executive / VIP Display Name Spoofing & Lookalike Domains."""
        findings: List[EmailFinding] = []
        score = 0
        is_impersonation = False
        is_lookalike = False
        sender_name_lower = (email.sender_name or "").lower()
        sender_domain = email.sender_domain

        # 1. VIP / Executive Name Spoofing from Freemail or External domain
        matched_vip = None
        all_vips = set(DEFAULT_VIP_ROLES + self.vip_names)
        for vip in all_vips:
            if vip in sender_name_lower:
                matched_vip = vip
                break

        if matched_vip:
            is_freemail = sender_domain in FREEMAIL_DOMAINS
            is_external = self.org_domains and sender_domain not in self.org_domains

            if is_freemail or is_external:
                is_impersonation = True
                score += 65
                findings.append(EmailFinding(
                    id=f"bec_{uuid.uuid4().hex[:6]}",
                    category="bec",
                    severity=Severity.CRITICAL,
                    title=f"VIP / Executive Impersonation Detected ({matched_vip.title()})",
                    title_ar=f"انتحال هوية مسؤول تنفيذي / جهة حساسة ({matched_vip})",
                    description=f"Sender display name contains VIP identifier '{matched_vip}' but email was sent from external/freemail domain '{sender_domain}'.",
                    description_ar=f"يحتوي الاسم الظاهر للمرسل على صفة تنفيذية '{matched_vip}' لكن البريد صادر من مزود عام/خارجي '{sender_domain}'.",
                    mitre_technique="T1566.002",
                    evidence=f"Display Name: '{email.sender_name}' | Sender: {email.sender_address}",
                ))

        # 2. Lookalike / Typosquatting Domain Check
        if self.org_domains and sender_domain:
            for org_dom in self.org_domains:
                if sender_domain == org_dom:
                    continue
                # Calculate similarity ratio
                ratio = difflib.SequenceMatcher(None, sender_domain, org_dom).ratio()
                if 0.75 <= ratio < 1.0:
                    is_lookalike = True
                    score += 55
                    findings.append(EmailFinding(
                        id=f"bec_{uuid.uuid4().hex[:6]}",
                        category="bec",
                        severity=Severity.CRITICAL,
                        title=f"Lookalike / Typosquatting Domain Spoofing ({sender_domain})",
                        title_ar=f"نطاق مرسل مضلل ومطابق بصرياً للنطاق المؤسسي ({sender_domain})",
                        description=f"Sender domain '{sender_domain}' closely resembles legitimate corporate domain '{org_dom}' (similarity: {int(ratio*100)}%).",
                        description_ar=f"النطاق '{sender_domain}' يحاكي بشكل مضلل النطاق المؤسسي المعتمد '{org_dom}' (نسبة التطابق: {int(ratio*100)}%).",
                        mitre_technique="T1566.002",
                        evidence=f"Suspicious Domain: {sender_domain} | Target Domain: {org_dom}",
                    ))
                    break

        summary = {
            "is_vip_impersonation": is_impersonation,
            "is_lookalike_domain": is_lookalike,
            "matched_vip_role": matched_vip,
            "sender_domain": sender_domain,
            "is_freemail": sender_domain in FREEMAIL_DOMAINS,
        }

        return min(100, score), findings, summary

    def _inspect_urls(
        self, email: ParsedEmail
    ) -> Tuple[int, List[EmailFinding], Dict[str, Any]]:
        """Evaluates all extracted URLs for phishing, homoglyphs, and deception."""
        findings: List[EmailFinding] = []
        score = 0
        phishing_count = 0
        suspicious_count = 0

        for url_obj in email.urls:
            if url_obj.category == "phishing" or url_obj.reputation_score >= 50:
                phishing_count += 1
                score += url_obj.reputation_score
                findings.append(EmailFinding(
                    id=f"url_{uuid.uuid4().hex[:6]}",
                    category="phishing",
                    severity=Severity.HIGH if url_obj.reputation_score < 75 else Severity.CRITICAL,
                    title=f"Malicious / Phishing URL Detected ({url_obj.domain})",
                    title_ar=f"رابط تصيد احتيالي مشبوه ({url_obj.domain})",
                    description=f"Suspicious link detected in email body: {url_obj.url}. Flags: {', '.join(url_obj.threat_flags)}",
                    description_ar=f"تم اكتشاف رابط مشبوه في محتوى البريد: {url_obj.url}. المؤشرات: {', '.join(url_obj.threat_flags)}",
                    mitre_technique="T1566.002",
                    evidence=f"URL: {url_obj.url} | Flags: {', '.join(url_obj.threat_flags)}",
                ))
            elif url_obj.category == "suspicious":
                suspicious_count += 1
                score += 20

        summary = {
            "total_urls": len(email.urls),
            "phishing_urls": phishing_count,
            "suspicious_urls": suspicious_count,
            "clean_urls": len(email.urls) - phishing_count - suspicious_count,
        }

        return min(100, score), findings, summary

    def _inspect_attachments(
        self, email: ParsedEmail
    ) -> Tuple[int, List[EmailFinding], Dict[str, Any]]:
        """Triages email attachments for dangerous types, macros, and known IOCs."""
        findings: List[EmailFinding] = []
        score = 0
        dangerous_count = 0

        for att in email.attachments:
            # Check IOC hashes in ThreatScope
            if att.sha256.lower() in self.threat_ioc_hashes or att.md5.lower() in self.threat_ioc_hashes:
                score += 100
                dangerous_count += 1
                findings.append(EmailFinding(
                    id=f"att_{uuid.uuid4().hex[:6]}",
                    category="attachment",
                    severity=Severity.CRITICAL,
                    title=f"Known Malicious File Hash Match ({att.filename})",
                    title_ar=f"تطابق هاش المرفق مع قاعدة بيانات التهديدات المعروفة ({att.filename})",
                    description=f"Attachment SHA-256 hash '{att.sha256}' matched known malicious threat intelligence IOC database.",
                    description_ar=f"بصمة الهاش SHA-256 للمرفق '{att.sha256}' مطابقة لقاعدة مؤشرات الاختراق (IOC) المعروفة.",
                    mitre_technique="T1566.001",
                    evidence=f"Filename: {att.filename} | SHA256: {att.sha256}",
                ))
            elif att.is_dangerous_type:
                score += 70
                dangerous_count += 1
                findings.append(EmailFinding(
                    id=f"att_{uuid.uuid4().hex[:6]}",
                    category="attachment",
                    severity=Severity.HIGH,
                    title=f"Dangerous Executable / Script Attachment ({att.filename})",
                    title_ar=f"مرفق برمجي / تنفيذي عالي الخطورة ({att.filename})",
                    description=f"Attachment has dangerous executable or script format. Findings: {', '.join(att.findings)}",
                    description_ar=f"المرفق يحتوي على صيغة تنفيذية أو سكريبت خطير. الملاحظات: {', '.join(att.findings)}",
                    mitre_technique="T1566.001",
                    evidence=f"Filename: {att.filename} | Type: {att.content_type} | Entropy: {att.entropy}",
                ))
            elif att.has_macros:
                score += 45
                findings.append(EmailFinding(
                    id=f"att_{uuid.uuid4().hex[:6]}",
                    category="attachment",
                    severity=Severity.MEDIUM,
                    title=f"Macro-Enabled Office Document ({att.filename})",
                    title_ar=f"مستند أوفيس مزود بوحدات ماكرو برمجية ({att.filename})",
                    description="Office document contains macros which may execute malicious code upon opening.",
                    description_ar="يحتوي المستند على تعليمات برمجية (Macros) قد تنفذ برمجيات خبيثة فور الفتح.",
                    mitre_technique="T1566.001",
                    evidence=f"Filename: {att.filename} | Size: {att.size_bytes} bytes",
                ))

        summary = {
            "total_attachments": len(email.attachments),
            "dangerous_attachments": dangerous_count,
            "has_macros": any(a.has_macros for a in email.attachments),
        }

        return min(100, score), findings, summary

    def _inspect_content_heuristics(
        self, email: ParsedEmail
    ) -> Tuple[int, List[EmailFinding]]:
        """Analyzes subject and body text for urgent financial fraud / BEC language."""
        findings: List[EmailFinding] = []
        score = 0
        full_content = f"{email.subject} {email.body_text}".lower()

        matched_phrases: List[str] = []
        for phrase_en_ar, phrase_desc, pts in BEC_FINANCIAL_KEYWORDS:
            if phrase_en_ar.lower() in full_content:
                matched_phrases.append(phrase_en_ar)
                score += pts

        if matched_phrases:
            findings.append(EmailFinding(
                id=f"content_{uuid.uuid4().hex[:6]}",
                category="content",
                severity=Severity.MEDIUM if score < 40 else Severity.HIGH,
                title="Urgent Financial / BEC Language Heuristics Detected",
                title_ar="اكتشاف عبارات مالية مستعجلة تدل على احتيال تحويل الأموال (BEC)",
                description=f"Email content contains urgent financial fraud phrases: {', '.join(matched_phrases[:4])}.",
                description_ar=f"يتضمن محتوى البريد عبارات احتيال مالي واستعجال لتحويل أموال: {', '.join(matched_phrases[:4])}.",
                mitre_technique="T1566.002",
                evidence=f"Matched Phrases: {', '.join(matched_phrases)}",
            ))

        return min(100, score), findings

    def _determine_verdict(
        self,
        overall_score: int,
        bec_score: int,
        url_score: int,
        att_score: int,
        findings: List[EmailFinding],
    ) -> EmailVerdict:
        """Determines the primary classification verdict for the email."""
        if any(f.severity == Severity.CRITICAL for f in findings):
            if bec_score >= 50:
                return EmailVerdict.BEC_FRAUD
            if att_score >= 70:
                return EmailVerdict.MALICIOUS
            if url_score >= 50:
                return EmailVerdict.PHISHING

        if bec_score >= 50:
            return EmailVerdict.BEC_FRAUD
        if att_score >= 70:
            return EmailVerdict.MALICIOUS
        if url_score >= 40:
            return EmailVerdict.PHISHING
        if overall_score >= 50:
            return EmailVerdict.SUSPICIOUS
        if overall_score >= 25:
            return EmailVerdict.SPAM
        return EmailVerdict.CLEAN

    def _generate_playbook(
        self, verdict: EmailVerdict, findings: List[EmailFinding], email: ParsedEmail
    ) -> Tuple[List[str], List[Dict[str, Any]]]:
        """Generates actionable SOC remediation playbook based on verdict and findings."""
        actions: List[str] = []
        playbook: List[Dict[str, Any]] = []

        if verdict in {EmailVerdict.MALICIOUS, EmailVerdict.PHISHING, EmailVerdict.BEC_FRAUD}:
            actions.append("QUARANTINE_EMAIL")
            playbook.append({
                "step": 1,
                "action": "QUARANTINE_EMAIL",
                "title_ar": "حجز وعزل الرسالة فوراً من صندوق الوارد",
                "title_en": "Quarantine Email from User Mailbox",
                "status": "recommended",
                "automated": True,
            })

            if email.sender_domain and email.sender_domain not in FREEMAIL_DOMAINS:
                actions.append("BLOCK_SENDER_DOMAIN")
                playbook.append({
                    "step": 2,
                    "action": "BLOCK_SENDER_DOMAIN",
                    "title_ar": f"حظر النطاق المرسل بالكامل على بوابة البريد ({email.sender_domain})",
                    "title_en": f"Block Sender Domain at Email Gateway ({email.sender_domain})",
                    "status": "recommended",
                    "automated": False,
                })

            if verdict == EmailVerdict.MALICIOUS or any(f.category == "attachment" for f in findings):
                actions.append("ENDPOINT_ISOLATION_SCAN")
                playbook.append({
                    "step": 3,
                    "action": "ENDPOINT_ISOLATION_SCAN",
                    "title_ar": "فحص أجهزة المستلمين عبر EndpointScope للتأكد من عدم فتح المرفقات",
                    "title_en": "Initiate EndpointScope Host Inspection for Recipients",
                    "status": "recommended",
                    "automated": True,
                })

            actions.append("CREATE_SECURITY_INCIDENT")
            playbook.append({
                "step": 4,
                "action": "CREATE_SECURITY_INCIDENT",
                "title_ar": "تصعيد حادث أمني إلى IncidentManager للتحقيق الموسع",
                "title_en": "Escalate Security Incident to IncidentManager",
                "status": "recommended",
                "automated": True,
            })

        elif verdict == EmailVerdict.SUSPICIOUS:
            actions.append("FLAG_BANNER_WARNING")
            playbook.append({
                "step": 1,
                "action": "FLAG_BANNER_WARNING",
                "title_ar": "إضافة شريط تحذيري مشدد للمستخدم قبل التفاعل مع الرسالة",
                "title_en": "Inject Warning Banner in Email Message",
                "status": "recommended",
                "automated": True,
            })

        return actions, playbook
