"""Web Applications and WAF OWASP Domain Detector."""

from __future__ import annotations

import re
from logscope.canonical import CanonicalEvent, DetectionFinding, ConclusionLevel
from logscope.detectors import BaseDetector


class WebDetector(BaseDetector):
    """Detects OWASP Top 10 web attacks (SQLi, XSS, Path Traversal, Web Shells, Log4Shell, SSRF)."""
    detector_name = "web_waf"

    def analyze_event(self, event: CanonicalEvent) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        raw = event.message
        raw_lower = (raw + " " + " ".join(str(v) for v in event.raw_fields.values())).lower()

        # 1. Log4Shell / JNDI Exploit
        if "jndi:ldap" in raw_lower or "jndi:rmi" in raw_lower or "jndi:dns" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-WEB-LOG4J-001",
                title_ar="محاولة استغلال ثغرة Log4Shell عبر حقن بروتوكول JNDI (Log4Shell Remote Code Execution)",
                description_ar="رصد محاولة استغلال ثغرة CVE-2021-44228 عبر إرسال سلاسل ${jndi:ldap...} لتنفيذ كود برمجي خبيث عن بعد.",
                base_severity=95,
                confidence=98,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="ثغرات وتطبيقات خبيثة (Exploit / Vulnerability)",
                mitre_tactics=["Execution", "Initial Access"],
                mitre_techniques=["T1190 - Exploit Public-Facing Application"],
                evidence=["رصد استدعاء ${jndi:...} في نص الطلب أو الترويسة"],
            ))

        # 2. SQL Injection (SQLi)
        elif any(w in raw_lower for w in ("union select", "information_schema", "' or '1'='1", "or 1=1", "waitfor delay", "benchmark(", "sql injection", "sqli")):
            findings.append(DetectionFinding(
                detection_id="DET-WEB-SQLI-001",
                title_ar="محاولة حقن قواعد البيانات (SQL Injection Attack)",
                description_ar="رصد مدخلات خبيثة تحتوي على كلمات مفتاحية لجمل SQL تهدف لتجاوز المصادقة أو استخراج بيانات حساسة.",
                base_severity=85,
                confidence=92,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="حقن قواعد البيانات (SQL Injection)",
                mitre_tactics=["Initial Access", "الوصول الأولي"],
                mitre_techniques=["T1190 - Exploit Public-Facing Application"],
                evidence=["تطابق أنماط SQL Injection في نص الطلب"],
            ))

        # 3. Cross-Site Scripting (XSS)
        elif any(w in raw_lower for w in ("<script", "javascript:", "onerror=", "onload=", "document.cookie", "xss attack")):
            findings.append(DetectionFinding(
                detection_id="DET-WEB-XSS-001",
                title_ar="محاولة حقن نصوص برمجية في المتصفح (Cross-Site Scripting - XSS)",
                description_ar="رصد محاولة تضمين وسوم برمجية خبيثة عبر المتصفح لسرقة ملفات تعريف الارتباط أو انتحال الجلسة.",
                base_severity=75,
                confidence=90,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="حقن نصوص المتصفح (XSS)",
                mitre_tactics=["Initial Access", "الوصول الأولي"],
                mitre_techniques=["T1189 - Drive-by Compromise"],
                evidence=["رصد وسوم HTML أو سكريبتات في معلمات الرابط"],
            ))

        # 4. Path Traversal / Arbitrary File Read
        elif any(w in raw_lower for w in ("../..", "..\\..", "/etc/passwd", "win.ini", "boot.ini", "path traversal")):
            findings.append(DetectionFinding(
                detection_id="DET-WEB-TRAVERSAL-001",
                title_ar="محاولة تتبع المسارات وقراءة ملفات النظام (Path Traversal / Local File Inclusion)",
                description_ar="رصد محاولة استخدام محارف الرجوع للخلف لتجاوز مسار خادم الويب والوصول لملفات النظام الحساسة.",
                base_severity=80,
                confidence=90,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="تجاوز المسار والوصول للملفات (Path Traversal)",
                mitre_tactics=["Initial Access", "الوصول الأولي"],
                mitre_techniques=["T1083 - File and Directory Discovery"],
                evidence=["رصد سلاسل ../ أو مسارات ملفات النظام الحساسة"],
            ))

        # 5. Web Shell Upload & Interaction
        elif any(w in raw_lower for w in ("c99.php", "r57.php", "b374k", "eval(base64_decode", "eval(gzinflate", "webshell", "cmd.jsp", "shell.aspx")):
            findings.append(DetectionFinding(
                detection_id="DET-WEB-SHELL-001",
                title_ar="رصد أدوات إدارة خبيثة وصفحات ويب شل (Web Shell Activity)",
                description_ar="رصد استدعاءات أو محاولات رفع صفحات ويب شل تمنح المهاجم قدرة التحكم عن بعد بالخادم.",
                base_severity=95,
                confidence=95,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="أدوات تحكم خبيثة (Web Shell / Backdoor)",
                mitre_tactics=["Persistence", "Execution"],
                mitre_techniques=["T1505.003 - Web Shell"],
                evidence=["رصد أسماء أو بصمات Web Shell شهيرة"],
            ))

        # 6. Server-Side Request Forgery (SSRF)
        elif "169.254.169.254" in raw_lower or "metadata.google.internal" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-WEB-SSRF-001",
                title_ar="محاولة استغلال تزوير الطلبات من جانب الخادم (Server-Side Request Forgery - SSRF)",
                description_ar="محاولة توجيه خادم الويب للاتصال بخدمة بيانات التعريف السحابية (Cloud Metadata API) لسرقة مفاتيح الحساب.",
                base_severity=90,
                confidence=92,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="تزوير طلبات الخادم (SSRF)",
                mitre_tactics=["Credential Access", "Initial Access"],
                mitre_techniques=["T1078.004 - Cloud Accounts"],
                evidence=["استهداف IP بيانات التعريف السحابية 169.254.169.254"],
            ))

        return findings
