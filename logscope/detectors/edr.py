"""EDR and Malware Families Domain Detector."""

from __future__ import annotations

import re
from logscope.canonical import CanonicalEvent, DetectionFinding, ConclusionLevel
from logscope.detectors import BaseDetector


class EDRDetector(BaseDetector):
    """Detects malware families, coin miners, credential dumpers, and ransomware activity."""
    detector_name = "edr_security"

    def analyze_event(self, event: CanonicalEvent) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        raw = event.message
        raw_lower = (raw + " " + " ".join(str(v) for v in event.raw_fields.values())).lower()

        # 1. Expiro Malware Family
        if "expiro" in raw_lower:
            domain_m = re.search(r"expiro\s*:\s*([a-zA-Z0-9.\-_]+)", raw, re.IGNORECASE)
            domain = domain_m.group(1).strip() if domain_m else ""
            desc = "برمجية خبيثة متقدمة تدمج بين إصابة الملفات التنفيذية وسرقة بيانات الاعتماد والشهادات الرقمية للتطبيقات"
            if domain:
                desc += f"، مع رصد محاولة اتصال بنطاق القيادة والسيطرة الخبيث: {domain}"

            findings.append(DetectionFinding(
                detection_id="DET-EDR-EXPIRO-001",
                title_ar="برمجية Expiro الخبيثة (Virus Expiro Infection)",
                description_ar=desc,
                base_severity=90,
                confidence=95,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="برمجيات خبيثة وفيروسات (Malware / Expiro)",
                mitre_tactics=["Execution", "Command and Control"],
                mitre_techniques=["T1204 - User Execution", "T1071.004 - DNS"],
                evidence=["تطابق توقيع برمجية Expiro في سجل الفحص"],
            ))

        # 2. Tiggre Trojan Family
        elif "tiggre" in raw_lower:
            domain_m = re.search(r"tiggre\s*:\s*([a-zA-Z0-9.\-_]+)", raw, re.IGNORECASE)
            domain = domain_m.group(1).strip() if domain_m else ""
            desc = "حصان طروادة خبيث (Trojan Tiggre) يستخدم لتثبيت برمجيات التعدين المخفية وسرقة كلمات المرور المحفوظة"
            if domain:
                desc += f"، مع محاولة الاتصال بعنوان خبيث: {domain}"

            findings.append(DetectionFinding(
                detection_id="DET-EDR-TIGGRE-001",
                title_ar="حصان طروادة تيجري (Trojan Tiggre)",
                description_ar=desc,
                base_severity=85,
                confidence=95,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="أحصنة طروادة (Trojans / Tiggre)",
                mitre_tactics=["Execution", "Command and Control"],
                mitre_techniques=["T1059 - Command and Scripting Interpreter"],
                evidence=["تطابق توقيع Trojan Tiggre في الفحص"],
            ))

        # 3. Cryptocurrency CoinMiners
        elif any(w in raw_lower for w in ("coinminer", "cryptominer", "xmrig", "monero miner", "stratum+tcp")):
            domain_m = re.search(r"coinminer\s*:\s*([a-zA-Z0-9.\-_]+)", raw, re.IGNORECASE)
            domain = domain_m.group(1).strip() if domain_m else ""
            desc = "برمجية تعدين عملات رقمية غير مصرح بها (Cryptocurrency CoinMiner) تستهلك موارد المعالجة"
            if domain:
                desc += f" وترتبط بحوض التعدين الخبيث: {domain}"

            findings.append(DetectionFinding(
                detection_id="DET-EDR-MINER-001",
                title_ar="برمجية تعدين العملات الرقمية غير المصرح بها (CoinMiner Trojan)",
                description_ar=desc,
                base_severity=75,
                confidence=92,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="برمجيات التعدين الخبيثة (Cryptojacking)",
                mitre_tactics=["Impact", "التأثير والتخريب"],
                mitre_techniques=["T1496 - Resource Hijacking"],
                evidence=["رصد برمجيات تعدين العملات الرقمية المشبوهة"],
            ))

        # 4. Cryptocurrency Platforms (e.g., Binance Domain)
        elif "binance" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-EDR-CRYPTO-001",
                title_ar="تداول عملات مشفرة أو نشاط مالي محظور في بيئة العمل (Cryptocurrency Exchange Access)",
                description_ar="رصد اتصال شبكي بمنصة تداول العملات الرقمية Binance بما يخالف سياسات الاستخدام المقبول ويشير لنشاط مشبوه.",
                base_severity=45,
                confidence=85,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="مخالفة سياسات الاستخدام (Policy Violation / Crypto)",
                mitre_tactics=["Impact", "التأثير والتخريب"],
                mitre_techniques=["T1496 - Resource Hijacking"],
                evidence=["رصد استعلام لنطاق منصة Binance"],
            ))

        return findings
