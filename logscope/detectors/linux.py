"""Linux / Unix Auth and Syslog Domain Detector."""

from __future__ import annotations

import re
from logscope.canonical import CanonicalEvent, DetectionFinding, ConclusionLevel
from logscope.detectors import BaseDetector


class LinuxDetector(BaseDetector):
    """Detects SSH brute force, sudo violations, user enumeration, and cron persistence on Linux."""
    detector_name = "linux_syslog"

    def analyze_event(self, event: CanonicalEvent) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        msg = event.message
        msg_lower = msg.lower()
        raw_lower = (msg_lower + " " + " ".join(str(v) for v in event.raw_fields.values())).lower()

        # 1. SSH Failed Password / Invalid User
        if "failed password for" in raw_lower:
            user_m = re.search(r"failed password for (?:invalid user )?([^\s]+)", raw_lower)
            target_user = user_m.group(1) if user_m else event.username
            is_invalid = "invalid user" in raw_lower

            det_id = "DET-LNX-AUTH-002" if is_invalid else "DET-LNX-AUTH-001"
            title = "استطلاع مستخدمين غير موجودين عبر SSH (User Enumeration)" if is_invalid else "فشل مصادقة كلمة مرور SSH (SSH Failed Password)"
            desc = f"فشل مصادقة SSH للحساب [{target_user or 'غير محدد'}]"
            if is_invalid:
                desc += " - الحساب غير مسجل في خادم لينكس (محاولة استطلاع)."

            findings.append(DetectionFinding(
                detection_id=det_id,
                title_ar=title,
                description_ar=desc,
                base_severity=55 if is_invalid else 45,
                confidence=90,
                conclusion_level=ConclusionLevel.SUSPICIOUS if is_invalid else ConclusionLevel.OBSERVED,
                threat_family="مصادقة خوادم لينكس (Linux Credential Access)",
                mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
                mitre_techniques=["T1110.001 - Password Guessing"],
                evidence=[f"Message: {msg[:120]}"],
            ))

        # 2. Sudo Security Violations
        elif "not in sudoers" in raw_lower or "sudo: 3 incorrect password attempts" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-LNX-SUDO-001",
                title_ar="محاولة غير مصرح بها لاستخدام أمر Sudo (Sudo Authorization Failure)",
                description_ar=f"قام الحساب [{event.username or 'مستخدم'}] بمحاولة تنفيذ أوامر بصلاحية الجذر (root) دون إدراجه في ملف sudoers.",
                base_severity=75,
                confidence=92,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="تصعيد الصلاحيات (Privilege Escalation)",
                mitre_tactics=["Privilege Escalation", "تصعيد الصلاحيات"],
                mitre_techniques=["T1548.003 - Sudo and Sudo Caching"],
                evidence=[f"Message: {msg[:120]}"],
            ))

        # 3. Successful SSH Authentication (Benign or Takeover target)
        elif "accepted password for" in raw_lower or "accepted publickey for" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-LNX-LOGON-001",
                title_ar="تسجيل دخول SSH ناجح (Successful SSH Logon)",
                description_ar=f"تم تسجيل الدخول بنجاح عبر بروتوكول SSH للحساب [{event.username or 'مستخدم'}].",
                base_severity=20,
                confidence=95,
                conclusion_level=ConclusionLevel.OBSERVED,
                threat_family="وصول أولي وحسابات صالحة (Valid Accounts)",
                mitre_tactics=["Initial Access", "الوصول الأولي"],
                mitre_techniques=["T1078 - Valid Accounts"],
                evidence=[f"Message: {msg[:120]}"],
            ))

        return findings
