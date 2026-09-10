"""Windows Security and Active Directory Domain Detector."""

from __future__ import annotations

import re
from logscope.canonical import CanonicalEvent, DetectionFinding, ConclusionLevel
from logscope.detectors import BaseDetector

SUBSTATUS_EXPLANATIONS = {
    "0xc000006a": ("كلمة مرور خاطئة (Bad Password)", "DET-WIN-AUTH-001"),
    "0xc0000064": ("اسم المستخدم غير موجود (User Does Not Exist)", "DET-WIN-AUTH-002"),
    "0xc0000234": ("الحساب مغلق بسبب تجاوز محاولات الدخول (Account Locked Out)", "DET-WIN-AUTH-003"),
    "0xc0000072": ("الحساب معطل (Account Disabled)", "DET-WIN-AUTH-004"),
    "0xc000006f": ("محاولة الدخول خارج أوقات العمل المحددة (Logon Hours Restriction)", "DET-WIN-AUTH-005"),
    "0xc0000193": ("صلاحية الحساب منتهية (Account Expired)", "DET-WIN-AUTH-006"),
}

LOGON_TYPES = {
    "2": "تسجيل دخول تفاعلي مباشر عبر لوحة المفاتيح (Interactive)",
    "3": "تسجيل دخول شبكي لمشاركة الملفات أو الطابعات (Network - SMB/RPC)",
    "4": "تشغيل مهمة مجدولة مجدولة مسبقاً (Batch Job)",
    "5": "بدء تشغيل خدمة من خدمات النظام (Service Start)",
    "7": "إلغاء قفل الشاشة (Screen Unlock)",
    "8": "تسجيل دخول شبكي مع إرسال كلمة المرور بنص واضح (NetworkCleartext - IIS/Basic)",
    "9": "استخدام هوية بديلة مختلفة عن الجلسة الحالية (NewCredentials - RunAs/PTH)",
    "10": "تسجيل دخول عبر سطح المكتب البعيد (RemoteDesktop / RDP)",
    "11": "تسجيل دخول باستخدام بيانات اعتماد مخزنة محلياً (CachedInteractive)",
}


class WindowsDetector(BaseDetector):
    """Detects security anomalies, privilege abuse, and credential threats in Windows/AD environments."""
    detector_name = "windows_active_directory"

    def analyze_event(self, event: CanonicalEvent) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        eid = str(event.event_id or "").strip()
        raw = str(event.message or "")
        raw_lower = (raw + " " + " ".join(str(v) for v in event.raw_fields.values())).lower()

        # 1. Audit Log Cleared (Event 1102 / 104)
        if eid in {"1102", "104"} or "the audit log was cleared" in raw_lower or "the event log was cleared" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-WIN-EVASION-001",
                title_ar="مسح وتفريغ سجل التدقيق الأمني (Audit Log Cleared)",
                description_ar="قام مستخدم بحذف وتفريغ سجلات التدقيق الأمني بشكل متعمد لإخفاء الأثر الرقمي للأعمال المنفذة.",
                base_severity=95,
                confidence=95,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="إخفاء الأثر والدفاع (Defense Evasion)",
                mitre_tactics=["Defense Evasion", "إخفاء الأثر والتمويه"],
                mitre_techniques=["T1070.001 - Clear Windows Event Logs"],
                evidence=[f"Event ID: {eid}", "رصد استدعاء صريح لمسح وتفريغ سجل الأحداث الأمني"],
                contributing_factors=["حذف السجلات إجراء نادر وشديد الحساسية يرتبط بنهاية عمليات الاختراق"],
            ))

        # 2. Failed Logon (Event 4625)
        elif eid == "4625" or "an account failed to log on" in raw_lower:
            substatus = (event.raw_fields.get("SubStatus") or event.raw_fields.get("sub_status") or "").lower()
            if not substatus:
                m = re.search(r"\b(0xc0000[0-9a-f]{3})\b", raw_lower)
                if m:
                    substatus = m.group(1)

            reason_desc, det_id = SUBSTATUS_EXPLANATIONS.get(substatus, ("فشل التحقق من بيانات الاعتماد", "DET-WIN-AUTH-GENERIC"))
            logon_type_code = str(event.raw_fields.get("LogonType") or event.raw_fields.get("logon_type") or "").strip()
            logon_type_desc = LOGON_TYPES.get(logon_type_code, "")

            desc = f"فشل تسجيل الدخول لحساب [{event.username or 'مستخدم'}] - السبب: {reason_desc}."
            if logon_type_desc:
                desc += f" النمط: {logon_type_desc}."

            findings.append(DetectionFinding(
                detection_id=det_id,
                title_ar="فشل تسجيل الدخول (Failed Logon)",
                description_ar=desc,
                base_severity=55 if substatus == "0xc0000234" else 40,
                confidence=85,
                conclusion_level=ConclusionLevel.SUSPICIOUS if substatus in {"0xc0000234", "0xc0000064"} else ConclusionLevel.OBSERVED,
                threat_family="وصول أولي ومصادقة (Initial Access / Credential Access)",
                mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
                mitre_techniques=["T1110 - Brute Force"],
                evidence=[f"Event ID: 4625", f"SubStatus: {substatus or 'N/A'}", f"User: {event.username}"],
            ))

        # 3. Successful Logon (Event 4624)
        elif eid == "4624" or "an account was successfully logged on" in raw_lower:
            logon_type_code = str(event.raw_fields.get("LogonType") or event.raw_fields.get("logon_type") or "").strip()
            logon_type_desc = LOGON_TYPES.get(logon_type_code, "تسجيل دخول قياسي")

            # High-risk logon types
            sev = 20
            conc = ConclusionLevel.OBSERVED
            tactics = ["Initial Access"]
            techniques = ["T1078 - Valid Accounts"]
            factors = []

            if logon_type_code == "10":
                sev = 35
                factors.append("جلسة سطح مكتب بعيد (RDP) واردة إلى النظام")
            elif logon_type_code == "9":
                sev = 50
                conc = ConclusionLevel.SUSPICIOUS
                factors.append("استخدام بيانات اعتماد جديدة في مسار تشغيل منفصل (NewCredentials/PTH)")
            elif logon_type_code == "8":
                sev = 45
                conc = ConclusionLevel.SUSPICIOUS
                factors.append("مصادقة ببيانات اعتماد غير مشفرة عبر الشبكة (Cleartext)")

            findings.append(DetectionFinding(
                detection_id="DET-WIN-LOGON-001",
                title_ar="تسجيل دخول ناجح (Successful Logon)",
                description_ar=f"تم توثيق دخول الحساب [{event.username or 'غير محدد'}] بنجاح. النمط: {logon_type_desc}.",
                base_severity=sev,
                confidence=90,
                conclusion_level=conc,
                threat_family="وصول أولي وحسابات صالحة (Valid Accounts)",
                mitre_tactics=tactics,
                mitre_techniques=techniques,
                evidence=[f"Event ID: 4624", f"LogonType: {logon_type_code}", f"User: {event.username}"],
                contributing_factors=factors,
            ))

        # 4. Special Privileges Assigned (Event 4672)
        elif eid == "4672" or "special privileges assigned to new logon" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-WIN-PRIV-001",
                title_ar="منح امتيازات خاصة وصلاحيات سيادية (Special Privileges Assigned)",
                description_ar=f"تم منح صلاحيات إدارية عليا (مثل SeDebugPrivilege أو مسؤولي النطاق) لجلسة الحساب [{event.username or 'حساب مسؤول'}].",
                base_severity=55,
                confidence=90,
                conclusion_level=ConclusionLevel.OBSERVED,
                threat_family="تصعيد الصلاحيات (Privilege Escalation)",
                mitre_tactics=["Privilege Escalation", "تصعيد الصلاحيات"],
                mitre_techniques=["T1078.002 - Domain Accounts"],
                evidence=["Event ID: 4672", f"User: {event.username}"],
            ))

        # 5. Process Creation (Event 4688) & Command Line Analysis
        elif eid == "4688" or "a new process has been created" in raw_lower or "process name" in raw_lower:
            cmd = (event.raw_fields.get("CommandLine") or event.raw_fields.get("ProcessCommandLine") or raw).lower()

            # Ransomware Volume Shadow Copy Invalidation
            if any(w in cmd for w in ("vssadmin", "delete shadows", "shadowcopy delete", "wbadmin delete catalog")):
                findings.append(DetectionFinding(
                    detection_id="DET-WIN-RANSOM-001",
                    title_ar="حذف النسخ الاحتياطية للنظام (Inhibit System Recovery)",
                    description_ar="محاولة خبيثة لحذف النسخ الاحتياطية للظل (Volume Shadow Copies) لتعطيل استعادة النظام قبيل التشفير.",
                    base_severity=95,
                    confidence=95,
                    conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                    threat_family="برمجيات الفدية والتعطيل (Ransomware / Impact)",
                    mitre_tactics=["Impact", "التأثير والتخريب"],
                    mitre_techniques=["T1490 - Inhibit System Recovery"],
                    evidence=["أمر حذف النسخ الاحتياطية vssadmin delete shadows", f"Command: {cmd[:150]}"],
                ))

            # Suspicious Encoded PowerShell
            elif any(w in cmd for w in ("-encodedcommand", "-enc ", "downloadstring", "invoke-expression", "iex(", "bypass -nop")):
                findings.append(DetectionFinding(
                    detection_id="DET-WIN-EXEC-001",
                    title_ar="تنفيذ أوامر باورشيل مشفرة ومشبوهة (Encoded PowerShell Execution)",
                    description_ar="رصد تشغيل PowerShell باستخدام تشفير Base64 أو تنزيل مباشر من الإنترنت مع تخطي سياسات التنفيذ.",
                    base_severity=82,
                    confidence=85,
                    conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                    threat_family="تنفيذ الأوامر (Execution)",
                    mitre_tactics=["Execution", "تنفيذ الأوامر"],
                    mitre_techniques=["T1059.001 - PowerShell"],
                    evidence=["معاملات تشفير وتخطي الصلاحيات في سطر أوامر PowerShell", f"Command: {cmd[:150]}"],
                ))

            # LSASS Dump / Credential Harvesting
            elif any(w in cmd for w in ("mimikatz", "sekurlsa", "lsass.exe", "procdump", "comsvcs.dll")):
                findings.append(DetectionFinding(
                    detection_id="DET-WIN-CRED-001",
                    title_ar="محاولة استخراج وتفريغ كلمات المرور من الذاكرة (LSASS Memory Dump)",
                    description_ar="رصد أدوات أو مسارات استخراج تجزئات كلمات المرور من ذاكرة عملية خادم الأمان المحلي (LSASS).",
                    base_severity=95,
                    confidence=92,
                    conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                    threat_family="سرقة بيانات الاعتماد (Credential Access)",
                    mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
                    mitre_techniques=["T1003.001 - OS Credential Dumping: LSASS Memory"],
                    evidence=["استهداف ذاكرة عملية LSASS لاستخراج أسرار النظام", f"Command: {cmd[:150]}"],
                ))

        # 6. Service Installation (Event 7045 / 4697)
        elif eid in {"7045", "4697"} or "a service was installed in the system" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-WIN-PERSIST-001",
                title_ar="تثبيت خدمة نظام جديدة (New Service Installed)",
                description_ar=f"تم تثبيت خدمة جديدة في النظام [{event.service_name or 'خدمة غير محددة'}] مما قد يستخدم لتثبيت التواجد الدائم.",
                base_severity=65,
                confidence=80,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="التواجد الدائم (Persistence)",
                mitre_tactics=["Persistence", "التواجد الدائم والمستمر"],
                mitre_techniques=["T1543.003 - Windows Service"],
                evidence=[f"Event ID: {eid}", f"Service: {event.service_name or 'N/A'}"],
            ))

        # 7. Privileged Group Membership Change (Event 4728 / 4732 / 4756)
        elif eid in {"4728", "4732", "4756"} or "a member was added to a security-enabled" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-WIN-ACCT-002",
                title_ar="إضافة مستخدم إلى مجموعة حساسة أو إدارية (Privileged Group Modification)",
                description_ar=f"تمت إضافة حساب مستخدم إلى إحدى مجموعات الأمان الإدارية الحساسة (Domain Admins / Administrators).",
                base_severity=80,
                confidence=90,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="تصعيد الصلاحيات (Privilege Escalation)",
                mitre_tactics=["Privilege Escalation", "تصعيد الصلاحيات"],
                mitre_techniques=["T1098 - Account Manipulation"],
                evidence=[f"Event ID: {eid}", f"User: {event.username}"],
            ))

        # 8. User Account Locked Out (Event 4740)
        elif eid == "4740" or "a user account was locked out" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-WIN-ACCT-003",
                title_ar="إغلاق حساب المستخدم بسبب تكرار الفشل (User Account Locked Out)",
                description_ar=f"تم قفل حساب المستخدم [{event.username or 'المستخدم'}] تلقائياً في الدليل النشط إثر تجاوز الحد المسموح به من محاولات الدخول الخاطئة.",
                base_severity=60,
                confidence=95,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="وصول أولي وتخمين (Credential Access)",
                mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
                mitre_techniques=["T1110 - Brute Force"],
                evidence=[f"Event ID: 4740", f"User: {event.username}"],
            ))

        return findings
