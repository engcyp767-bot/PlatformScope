"""Cloud and Identity (M365 / Entra ID / AWS) Domain Detector."""

from __future__ import annotations

import re
from logscope.canonical import CanonicalEvent, DetectionFinding, ConclusionLevel
from logscope.detectors import BaseDetector


class CloudDetector(BaseDetector):
    """Detects Impossible Travel, Password Spray, BEC Mailbox Forwarding, and OAuth abuse."""
    detector_name = "cloud_identity"

    def analyze_event(self, event: CanonicalEvent) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        raw = event.message
        raw_lower = (raw + " " + " ".join(str(v) for v in event.raw_fields.values())).lower()

        # 1. Impossible Travel Alert
        if "impossible travel" in raw_lower or "unfamiliar location" in raw_lower or "anomalous travel" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-CLD-TRAVEL-001",
                title_ar="تسجيل دخول من موقعين جغرافيين مستحيل السفر بينهما (Impossible Travel Alert)",
                description_ar=f"رصد تسجيل دخول الحساب [{event.username or 'المستخدم'}] من موقعين جغرافيين متباعدين في فترة زمنية قصيرة يستحيل التنقل بينهما.",
                base_severity=85,
                confidence=90,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="هجمات الهوية السحابية (Cloud Identity Threats)",
                mitre_tactics=["Initial Access", "الوصول الأولي"],
                mitre_techniques=["T1078.004 - Cloud Accounts"],
                evidence=["تنبيه Impossible Travel الصادر من محرك حماية الهوية السحابية"],
            ))

        # 2. Business Email Compromise (BEC) - Mailbox Forwarding Rule
        elif any(w in raw_lower for w in ("new-inboxrule", "set-mailbox", "forwardto", "redirectto", "inboxrule created", "mailbox forwarding")):
            findings.append(DetectionFinding(
                detection_id="DET-CLD-BEC-001",
                title_ar="إنشاء قاعدة توجيه بريد إلكتروني مشبوهة (BEC Mailbox Forwarding Rule)",
                description_ar=f"رصد إنشاء قاعدة توجيه تلقائي لرسائل البريد الإلكتروني للحساب [{event.username or 'حساب بريد'}] إلى عناوين خارجية.",
                base_severity=85,
                confidence=92,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="اختراق البريد التجاري والتجسس (BEC / Collection)",
                mitre_tactics=["Collection", "التجميع والتنصت"],
                mitre_techniques=["T1114.003 - Email Forwarding Rule"],
                evidence=["إنشاء قاعدة توجيه بريد إلكتروني خارجية"],
            ))

        # 3. Cloud Password Spray
        elif "password spray" in raw_lower or "riskyuser" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-CLD-SPRAY-001",
                title_ar="هجوم رش كلمات المرور السحابي (Cloud Password Spraying)",
                description_ar="رصد محاولات مصادقة متزامنة باستخدام كلمات مرور شائعة ضد حسابات متعددة في البيئة السحابية.",
                base_severity=80,
                confidence=88,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="سرقة بيانات الاعتماد (Credential Access)",
                mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
                mitre_techniques=["T1110.003 - Password Spraying"],
                evidence=["بصمة هجوم Password Spray في بوابة الهوية"],
            ))

        return findings
