"""Source & Format Detector: Discovers log vendor/product with verifiable evidence and confidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SourceDetectionResult:
    source_id: str
    source_label_ar: str
    confidence: int                                    # 0 to 100
    evidence: list[str] = field(default_factory=list)
    analysis_mode: str = "full"                        # "full" or "partial"


class SourceDetector:
    """Analyzes headers, field tokens, and sample message payloads to determine the log source."""

    def detect(self, headers: list[str], sample_rows: list[list[Any]]) -> SourceDetectionResult:
        normalised_headers = [re.sub(r"[\s_./\\:()\[\]-]+", " ", str(h).lower().strip()) for h in headers]
        headers_blob = " ".join(normalised_headers)
        
        sample_cells = []
        for r in sample_rows[:30]:
            for cell in r:
                s = str(cell or "").strip()
                if s:
                    sample_cells.append(s)
        data_blob = (headers_blob + " " + " ".join(sample_cells)).lower()
        messages_blob = data_blob

        # 1. Windows Security & Active Directory
        win_evidence = []
        if any(h in headers_blob for h in ("event id", "eventid", "event code", "task category", "logon type")):
            win_evidence.append("وجود أعمدة معرّف أحداث ويندوز أو نوع تسجيل الدخول (Event ID / Logon Type)")
        if any(h in headers_blob for h in ("samaccountname", "subject username", "target username", "userprincipalname", "account name", "workstation name", "target domain")):
            win_evidence.append("وجود أسماء حسابات وهويات Active Directory المعتمدة")
        if re.search(r"\b(4624|4625|4672|4688|4720|4728|4732|4740|4768|4769|4771|1102|104|7045)\b", data_blob):
            win_evidence.append("رصد معرّفات أحداث أمان ويندوز الشهيرة في البيانات (مثل 4625, 4624, 1102)")
        if "microsoft-windows-security-auditing" in data_blob or "an account was successfully logged on" in data_blob or "an account failed to log on" in data_blob:
            win_evidence.append("نصوص تدقيق أمان Windows Server الصريحة في نص الرسالة")

        if len(win_evidence) >= 2:
            conf = 95 if len(win_evidence) >= 3 else 88
            return SourceDetectionResult(
                source_id="windows_active_directory",
                source_label_ar="سجلات أمان ويندوز والدليل النشط (Windows Security / AD)",
                confidence=conf,
                evidence=win_evidence,
                analysis_mode="full",
            )

        # 2. UTM / Firewall (e.g., FortiGate, Huawei, Palo Alto, Cisco)
        fw_evidence = []
        if any(h in headers_blob for h in ("source zone", "destination zone", "srczone", "dstzone", "policy name")):
            fw_evidence.append("وجود حقول مناطق وسياسات جدران الحماية (Zones & Security Policies)")
        if any(h in headers_blob for h in ("attack name", "attack type", "signature name", "threat name", "transmission protocol")):
            fw_evidence.append("وجود حقول توقيعات الهجمات وتصنيفات التهديدات والبروتوكول الشبكي")
        if "cid=0x" in messages_blob or "syslogid=" in messages_blob or "vsys=" in messages_blob or "signname=" in messages_blob:
            fw_evidence.append("بصمات وسجلات أجهزة جدار الحماية (SyslogId, VSys, Policy, CID, SignName)")
        if any(f in messages_blob for f in ("type=traffic", "type=utm", "fortigate", "devid=fg")):
            fw_evidence.append("بصمة ترويسة سجلات FortiGate الرسمية")
        if any(p in messages_blob for p in ("pan-os", "threat,file", "threat,vulnerability")):
            fw_evidence.append("بصمة سجلات Palo Alto Networks (PAN-OS)")
        if any(h in headers_blob for h in ("destination port", "dst port", "dport")) and any(h in headers_blob for h in ("source ip", "src ip")):
            fw_evidence.append("حقول تدفق الشبكة وحزم البيانات (Source IP / Destination Port)")

        if len(fw_evidence) >= 1:
            conf = 96 if len(fw_evidence) >= 2 else 85
            label = "سجلات جدار الحماية وشبكات الأمان (Firewall / UTM / IDS)"
            if any("fortigate" in e.lower() for e in fw_evidence):
                label = "سجلات جدار حماية فورتينت (FortiGate UTM)"
            return SourceDetectionResult(
                source_id="firewall_utm",
                source_label_ar=label,
                confidence=conf,
                evidence=fw_evidence,
                analysis_mode="full",
            )

        # 3. Linux / Unix Syslog (SSH, Sudo, Auth)
        linux_evidence = []
        if any(h in headers_blob for h in ("facility", "ident", "syslog tag", "process name", "daemon")):
            linux_evidence.append("وجود حقول مخصصة لخوادم Linux Syslog")
        if any(k in messages_blob for k in ("sshd[", "sudo:", "pam_unix", "failed password for", "invalid user", "accepted publickey")):
            linux_evidence.append("بصمات تسجيل دخول خوادم Linux عبر SSH وأوامر Sudo و PAM")

        if linux_evidence:
            conf = 92 if len(linux_evidence) >= 2 else 78
            return SourceDetectionResult(
                source_id="linux_syslog",
                source_label_ar="سجلات نظام وخوادم لينكس (Linux / Unix Syslog)",
                confidence=conf,
                evidence=linux_evidence,
                analysis_mode="full",
            )

        # 4. Web Servers & WAF (Nginx, Apache, ModSecurity, Cloudflare)
        web_evidence = []
        if any(h in headers_blob for h in ("cs uri stem", "cs method", "sc status", "http method", "request url", "uri path")):
            web_evidence.append("وجود حقول W3C وسجلات خوادم الويب (URI Stem, HTTP Method, Status)")
        if any(k in messages_blob for k in ("get /", "post /", "http/1.1", "http/2.0", "user-agent:", "mod_security")):
            web_evidence.append("بصمات طلبات HTTP وتطبيقات الويب وجدران التطبيقات WAF")

        if web_evidence:
            conf = 90 if len(web_evidence) >= 2 else 80
            return SourceDetectionResult(
                source_id="web_waf",
                source_label_ar="سجلات خوادم وتطبيقات الويب (Web Server / WAF)",
                confidence=conf,
                evidence=web_evidence,
                analysis_mode="full",
            )

        # 5. Cloud & Microsoft 365 / Entra ID
        cloud_evidence = []
        if any(h in headers_blob for h in ("workload", "operation", "userid", "clientipaddress", "useragent")):
            cloud_evidence.append("وجود حقول تدقيق Microsoft 365 Unified Audit Log")
        if any(k in messages_blob for k in ("userloggedin", "mailitemaccessed", "mailboxforwarding", "password spray", "impossible travel")):
            cloud_evidence.append("بصمات أنشطة الهوية السحابية والبريد المشبوهة")

        if cloud_evidence:
            conf = 90 if len(cloud_evidence) >= 2 else 75
            return SourceDetectionResult(
                source_id="cloud_identity",
                source_label_ar="سجلات السحابة والهوية المدارة (M365 / Azure Entra ID)",
                confidence=conf,
                evidence=cloud_evidence,
                analysis_mode="full",
            )

        # 6. Database Auditing (MSSQL, Oracle, MySQL, Postgres)
        db_evidence = []
        if any(h in headers_blob for h in ("database name", "query text", "sql statement", "db user", "schema")):
            db_evidence.append("وجود أعمدة قواعد البيانات وجمل الاستعلام (Database & SQL Query)")
        if any(k in messages_blob for k in ("error: 18456", "ora-01017", "select * from", "drop table", "truncate table")):
            db_evidence.append("بصمات أخطاء مصادقة أو استعلامات قواعد البيانات")

        if db_evidence:
            conf = 88 if len(db_evidence) >= 2 else 72
            return SourceDetectionResult(
                source_id="database_audit",
                source_label_ar="سجلات تدقيق قواعد البيانات (Database Audit)",
                confidence=conf,
                evidence=db_evidence,
                analysis_mode="full",
            )

        # 7. Fallback / Unknown with Partial Analysis
        partial_evidence = []
        if any(h in headers_blob for h in ("ip", "time", "date", "source", "message", "status", "action")):
            partial_evidence.append("تم استخراج حقول عامة تدعم التحليل الأمني الجزئي (IP / Time / Action)")
            conf = 55
            mode = "partial"
        else:
            partial_evidence.append("سجلات نصية عامة غير محددة المصدر - تطبيق القواعد العامة")
            conf = 35
            mode = "partial"

        return SourceDetectionResult(
            source_id="unknown_generic",
            source_label_ar="مصدر سجلات عام / غير محدد مسبقاً (Generic / Custom Log)",
            confidence=conf,
            evidence=partial_evidence,
            analysis_mode=mode,
        )
