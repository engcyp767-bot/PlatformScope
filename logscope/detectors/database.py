"""Database Security and Audit Domain Detector."""

from __future__ import annotations

import re
from logscope.canonical import CanonicalEvent, DetectionFinding, ConclusionLevel
from logscope.detectors import BaseDetector


class DatabaseDetector(BaseDetector):
    """Detects database authentication failures, privilege abuse, and destructive DDL statements."""
    detector_name = "database_audit"

    def analyze_event(self, event: CanonicalEvent) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        raw = event.message
        raw_lower = (raw + " " + " ".join(str(v) for v in event.raw_fields.values())).lower()

        # 1. MSSQL / Oracle Failed Logins (e.g. Error 18456)
        if "error: 18456" in raw_lower or "ora-01017" in raw_lower or "login failed for user" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-DB-AUTH-001",
                title_ar="فشل مصادقة قاعدة البيانات (Database Login Failed)",
                description_ar=f"فشلت محاولة تسجيل الدخول إلى خادم قواعد البيانات للحساب [{event.username or 'مستخدم قاعدة البيانات'}].",
                base_severity=50,
                confidence=90,
                conclusion_level=ConclusionLevel.OBSERVED,
                threat_family="مصادقة قواعد البيانات (Database Authentication)",
                mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
                mitre_techniques=["T1110 - Brute Force"],
                evidence=["رسالة خطأ مصادقة خادم قواعد البيانات"],
            ))

        # 2. Destructive DDL Queries (DROP TABLE, TRUNCATE)
        elif any(w in raw_lower for w in ("drop table", "truncate table", "drop database")):
            findings.append(DetectionFinding(
                detection_id="DET-DB-DDL-001",
                title_ar="أمر تخريبي أو حذف جداول بقاعدة البيانات (Destructive DDL Statement)",
                description_ar=f"رصد استعلام لتدمير أو حذف جداول كاملة (DROP/TRUNCATE) بواسطة الحساب [{event.username or 'مستخدم'}].",
                base_severity=85,
                confidence=95,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="تخريب وفقدان البيانات (Impact / Data Destruction)",
                mitre_tactics=["Impact", "التأثير والتخريب"],
                mitre_techniques=["T1485 - Data Destruction"],
                evidence=["رصد أمر DROP أو TRUNCATE في نص الاستعلام"],
            ))

        # 3. Database Privilege Escalation (sysadmin role)
        elif any(w in raw_lower for w in ("sp_addsrvrolemember", "grant sysadmin", "grant dba")):
            findings.append(DetectionFinding(
                detection_id="DET-DB-PRIV-001",
                title_ar="منح صلاحيات مدير النظام بقاعدة البيانات (Database Privilege Escalation)",
                description_ar=f"تم منح صلاحيات مسؤول قاعدة البيانات (sysadmin / DBA) للحساب [{event.username or 'مستخدم'}].",
                base_severity=80,
                confidence=92,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="تصعيد الصلاحيات (Privilege Escalation)",
                mitre_tactics=["Privilege Escalation", "تصعيد الصلاحيات"],
                mitre_techniques=["T1078.002 - Domain Accounts"],
                evidence=["تنفيذ أمر ترقية الصلاحيات الإدارية في قاعدة البيانات"],
            ))

        return findings
