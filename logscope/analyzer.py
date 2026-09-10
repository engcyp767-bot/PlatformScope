"""SIEM and Log Events Analyzer and Risk Scoring Engine."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

RISK_THRESHOLDS = (40, 70, 85)

WINDOWS_EVENT_DESCRIPTIONS_AR = {
    # System Lifecycle & Anti-Forensics
    "104": "تم مسح سجل أحداث النظام (System Log Cleared)",
    "1102": "تم مسح وتفريغ سجل التدقيق الأمني لمنع التحقيق الجنائي (Audit Log Cleared)",
    "6": "برنامج تشغيل تصفية أنظمة الملفات (Filter Manager)",
    "1074": "إيقاف تشغيل أو إعادة تشغيل النظام بواسطة مستخدم أو تطبيق",
    "4608": "بدء تشغيل نظام التشغيل Windows واستدعاء حزم الأمان",
    "4609": "إيقاف تشغيل نظام التشغيل Windows",
    "4616": "تم تعديل توقيت وساعة النظام (System Time Changed)",
    
    # Logon, Authentication & Sessions
    "4624": "تسجيل دخول ناجح إلى النظام أو الحساب",
    "4625": "محاولة تسجيل دخول فاشلة إلى الحساب",
    "4634": "انتهاء جلسة تسجيل دخول مستخدم (Logoff)",
    "4647": "تسجيل خروج صريح بدأه المستخدم",
    "4648": "تسجيل دخول باستخدام بيانات اعتماد صريحة محددة (Runas / Explicit Credentials)",
    "4672": "منح امتيازات إدارية خاصة لجلسة تسجيل الدخول (Administrator Privileges)",
    "4778": "إعادة الاتصال بجلسة سطح مكتب RDP نشطة",
    "4779": "فصل الاتصال بجلسة سطح مكتب RDP",
    
    # Process Creation & Persistence
    "4688": "إنشاء وبدء تشغيل عملية تنفيذية جديدة (New Process Created)",
    "4689": "إنهاء وخروج عملية تنفيذية من النظام",
    "4697": "تثبيت خدمة نظام جديدة في الخلفية (New Service Installed - Persistence)",
    "7045": "تثبيت خدمة جديدة عبر Service Control Manager (Persistence)",
    "4698": "إنشاء مهمة مجدولة جديدة في النظام (Scheduled Task Created)",
    "4699": "حذف مهمة مجدولة من النظام",
    "4700": "تمكين مهمة مجدولة في النظام",
    "4702": "تحديث أو تعديل مهمة مجدولة في النظام",
    
    # User Account Lifecycle
    "4720": "إنشاء حساب مستخدم جديد على النظام أو النطاق",
    "4722": "تمكين وتفعيل حساب مستخدم",
    "4723": "محاولة تغيير كلمة المرور بواسطة المستخدم نفسه",
    "4724": "محاولة إعادة تعيين كلمة مرور الحساب بواسطة مسؤول النظام",
    "4725": "تعطيل حساب مستخدم (User Account Disabled)",
    "4726": "حذف حساب مستخدم نهائياً من النظام أو النطاق",
    "4738": "تعديل خصائص حساب مستخدم (User Account Modified)",
    "4740": "قفل حساب مستخدم تلقائياً بسبب تكرار المحاولات الفاشلة (Account Locked Out)",
    "4767": "إلغاء قفل حساب مستخدم بواسطة مسؤول النظام",
    "4781": "تغيير وتعديل اسم حساب مستخدم",
    
    # Security Groups & Privilege Escalation
    "4728": "إضافة عضو إلى مجموعة أمان عامة حساسة (Security Group Member Added)",
    "4729": "إزالة عضو من مجموعة أمان عامة",
    "4732": "إضافة عضو إلى مجموعة المدراء والمشرفين المحلية (Administrators Group)",
    "4733": "إزالة عضو من مجموعة أمان محلية",
    "4756": "إضافة عضو إلى مجموعة أمان عالمية للمؤسسة (Enterprise Admins)",
    "4757": "إزالة عضو من مجموعة أمان عالمية",
    
    # Kerberos & NTLM Authentication
    "4768": "طلب تذكرة مصادقة Kerberos TGT (AS-REQ)",
    "4769": "طلب تذكرة خدمة Kerberos TGS (TGS-REQ - فحص Kerberoasting)",
    "4771": "فشل المصادقة المسبقة لـ Kerberos (Pre-Authentication Failed)",
    "4776": "التحقق من بيانات اعتماد حساب عبر بروتوكول NTLM",
    "4777": "فشل التحقق من بيانات الاعتماد عبر بروتوكول NTLM",
    
    # File, Share & Object Access
    "4656": "طلب مقبض كائن وصول في النظام (ملف أو مجلد)",
    "4657": "تعديل في سجل النظام المحمي (Registry Value Modified)",
    "4663": "محاولة وصول لكائن في النظام (ملف أو مجلد أو مفتاح سجل)",
    "4670": "تغيير وتعديل أذونات كائن أو ملف (Permissions Changed)",
    "5140": "تم الوصول إلى كائن مشاركة شبكية (Network Share Access)",
    "5145": "فحص أذونات الوصول إلى مشاركة شبكية حساسة (C$, ADMIN$, IPC$)",
    
    # Policy & Firewall
    "4719": "تغيير وتعديل في سياسة تدقيق النظام الأمني (Audit Policy Changed)",
    "4946": "إضافة قاعدة جديدة إلى جدار حماية Windows Firewall",
    "4947": "تعديل قاعدة في جدار حماية Windows Firewall",
    "4948": "حذف قاعدة من جدار حماية Windows Firewall",
    "4950": "تغيير إعداد عام في جدار حماية Windows Firewall",
    "5156": "سمح جدار حماية Windows باتصال شبكي",
    "5157": "حظر جدار حماية Windows اتصالاً شبكياً غير مصرح به",
    
    # AppLocker, PowerShell & System Audits
    "4103": "تنفيذ وتشغيل وحدة PowerShell برمجية (Module Logging)",
    "4104": "تسجيل نص برمجي PowerShell Script Block (تحليل أوامر مشبوهة)",
    "8003": "حظر تشغيل برنامج أو أداة غير موثقة بواسطة AppLocker",
    "8004": "تدقيق تشغيل برنامج تنفيذي بواسطة AppLocker",
    "5632": "طلب مصادقة شبكة لاسلكية 802.1X",
    "6013": "تسجيل مدة تشغيل واستقرار النظام (System Uptime)",
    "1000": "تعطل مفاجئ في تطبيق تنفيذي (Application Error / Crash)",
    "1001": "تقرير أخطاء Windows Error Reporting",
}

WINDOWS_LOGON_TYPES_AR = {
    "0": "بدء تشغيل النظام (System)",
    "2": "تسجيل دخول تفاعلي مباشر من الشاشة (Interactive/Console)",
    "3": "تسجيل دخول عبر الشبكة ومشاركة الملفات (Network/SMB)",
    "4": "مهمة دفعية مجدولة (Batch/Scheduled Task)",
    "5": "بدء خدمة نظام خلفية (Windows Service)",
    "7": "إلغاء قفل محطة العمل (Unlock)",
    "8": "تسجيل دخول بنص صريح عبر الشبكة (Network Cleartext)",
    "9": "استخدام بيانات اعتماد جديدة مختلفة (New Credentials/Runas)",
    "10": "اتصال سطح مكتب بعيد (Remote Desktop / RDP)",
    "11": "تسجيل دخول ببيانات اعتماد مخزنة مؤقتاً (Cached Credentials)",
    "12": "جلسة وصول عن بُعد مخصصة (Cached Remote)",
    "13": "إلغاء قفل الشاشة عن بُعد (Cached Unlock)",
}

WINDOWS_LOGON_SUBSTATUS_AR = {
    "0xc000006a": "كلمة المرور غير صحيحة (Bad Password)",
    "0xc0000064": "اسم المستخدم غير موجود في النطاق (User does not exist - استطلاع حسابات)",
    "0xc000006d": "بيانات الاعتماد غير صالحة عموماً (Bad Username or Password)",
    "0xc000006e": "قيود على حساب المستخدم تمنع تسجيل الدخول",
    "0xc000006f": "محاولة تسجيل دخول خارج ساعات العمل المسموح بها (Outside logon hours)",
    "0xc0000070": "محاولة تسجيل دخول من محطة عمل غير مصرح بها (Workstation restriction)",
    "0xc0000071": "كلمة المرور منتهية الصلاحية (Password Expired)",
    "0xc0000072": "الحساب معطل حالياً بواسطة مسؤول النظام (Account Disabled)",
    "0xc0000193": "الحساب منتهي الصلاحية بالكامل (Account Expired)",
    "0xc0000224": "يجب تغيير كلمة المرور عند تسجيل الدخول القادم",
    "0xc0000234": "الحساب مقفل مؤقتاً لتجاوز محاولات الدخول الخاطئة (Account Locked Out)",
    "0xc0000371": "تعذر الاتصال بوحدة تحكم النطاق Domain Controller",
    "0x18": "فشل المصادقة المسبقة لـ Kerberos: كلمة مرور خاطئة (Bad Password / Kerberoasting)",
    "0x17": "فشل المصادقة المسبقة لـ Kerberos: كلمة المرور منتهية الصلاحية",
    "0x6": "اسم المستخدم غير معروف لمركز توزيع مفاتيح Kerberos (KDC)",
    "0xc": "فارق التوقيت كبير بين محطة العمل ووحدة تحكم النطاق KDC (Clock Skew)",
}

MITRE_TACTICS_AR = {
    "initial_access": "الوصول الأولي (Initial Access)",
    "execution": "تنفيذ الأوامر (Execution)",
    "persistence": "ترسيخ التواجد (Persistence)",
    "privilege_escalation": "تصعيد الصلاحيات (Privilege Escalation)",
    "defense_evasion": "تجاوز وسائل الدفاع (Defense Evasion)",
    "credential_access": "سرقة بيانات الاعتماد (Credential Access)",
    "discovery": "الاستكشاف واستطلاع الشبكة (Discovery)",
    "lateral_movement": "التحرك الجانبي (Lateral Movement)",
    "collection": "جمع البيانات الحساسة (Collection)",
    "c2": "الاتصال بمركز القيادة والتحكم (C2)",
    "exfiltration": "تسريب واستخراج البيانات (Exfiltration)",
    "impact": "تخريب وتعطيل العمليات (Impact)",
}

try:
    from .file_parser import ParsedData
except ImportError:
    from file_parser import ParsedData

# Standardise column names for ManageEngine Log360, EventLog Analyzer, Firewalls, Web, and Syslog
FIELD_ALIASES = {
    "event_time": {
        "event time", "time", "date", "timestamp", "وقت الحدث", "generation time",
        "start time", "log time", "last message time", "alert time", "incident time",
        "created time", "receive time", "recv time", "generated time", "occur time",
        "date time", "datetime", "logged time", "event date", "timecreated", "time_created",
        "time created", "logon time", "logon_time", "logontime", "created_at", "timestamp_utc",
        "eventtimestamp", "event_timestamp", "date_time", "event_date_time", "system_time",
        "collection_time", "generated_time", "recv_time", "تاريخ الحدث", "وقت التسجيل",
    },
    "event_id": {
        "event id", "id", "معرّف الحدث", "eventid", "windows event id", "alert id",
        "incident id", "rule id", "record id", "signature id", "signid", "sign id",
        "syslogid", "syslog id", "threat id", "cve", "reference", "event number", "event num",
        "event code", "eventcode", "action_id", "msg_id", "reason_code", "status_code",
        "error code", "win_event_id", "win_eid", "event_identifier", "substatus", "sub_status",
        "statuscode", "error_code", "رمز الحدث", "رقم الحدث",
    },
    "priority": {
        "event type severity", "severity", "priority", "level", "الخطورة", "type",
        "risk", "risk level", "alert severity", "syslog severity", "threat level",
        "criticality", "importance", "severity_label", "threat_severity", "alert_level",
        "درجة الخطورة", "مستوى التنبيه",
    },
    "event_source": {
        "event source", "source", "مصدر الحدث", "log source", "application", "service",
        "facility", "vendor", "product", "profile", "policy name", "source zone",
        "rule name", "security zone", "source_name", "sourcename", "provider_name",
        "provider", "channel", "facility_name", "log_name", "logname", "component",
        "مقدم الخدمة", "القناة",
    },
    "device": {
        "device", "device name", "computer", "computer name", "host name", "hostname",
        "الجهاز", "server", "workstation", "asset", "resource", "device ip", "dev name",
        "dev ip", "firewall", "sensor", "node", "appliance", "machinename", "machine name",
        "devicename", "computername", "endpoint", "agent_id", "host_name", "machine_name",
        "computer_name", "اسم الجهاز", "الخادم", "المحطة",
    },
    "user_account": {
        "user", "user account", "account", "username", "user name", "المستخدم",
        "target user name", "subject user name", "actor", "owner", "initiated by",
        "src user", "dst user", "source user", "destination user", "operator", "login name",
        "userprincipalname", "targetusername", "subjectusername", "account_name",
        "samaccountname", "userid", "user_id", "caller", "email",
        "session_server_principal_name", "target_user", "subject_user", "user_name",
        "identity", "account_id", "اسم الحساب", "اسم المستخدم",
    },
    "src_ip": {
        "source host ip", "source ip", "src ip", "host", "client ip", "عنوان المصدر",
        "source network address", "ip address", "remote ip", "origin ip", "source address",
        "src addr", "srcip", "source", "src", "client address", "source host", "initiator ip",
        "clientip", "c-ip", "client_ip", "remote_addr", "remote_ip", "caller_ip",
        "source_ip", "src_host", "src_address", "client_address", "cip", "srcip_address",
        "اي بي المصدر", "عنوان العميل",
    },
    "description": {
        "message description", "message", "description", "details", "الوصف", "event message",
        "displayname", "display name", "event name", "alert name", "incident name", "rule name",
        "signature name", "attack name", "threat name", "reason", "event description",
        "log text", "raw log", "msg", "log_message", "statement", "command", "query", "url",
        "uri", "cs-uri-stem", "request_url", "threat_name", "event_summary", "payload",
        "cmdline", "commandline", "process_command_line", "نص الرسالة", "تفاصيل الحدث", "الأمر البرمجي",
    },
    "status": {
        "status", "state", "result", "outcome", "compliance status", "device status",
        "response status", "disposition", "verdict", "حالة الحدث", "النتيجة",
    },
    "action": {
        "action", "operation", "activity", "command", "event action", "audit action",
        "policy action", "response", "mitigation", "firewall action", "disposition",
        "action_taken", "firewall_action", "outcome", "decision", "event_result",
        "resolution", "الإجراء المتخذ", "الإجراء",
    },
    "category": {
        "category", "event category", "report category", "log type", "subtype", "control",
        "policy", "threat type", "attack name", "attack type", "classification", "threat category",
        "event_type", "eventtype", "threat_type", "log_type", "event_class", "alert_type",
        "mitre_technique", "threat_category", "subtype", "نوع الحدث", "تصنيف التهديد",
    },
    "destination": {
        "destination", "destination ip", "dst ip", "target", "target host", "target resource",
        "object name", "file name", "target ip", "destination address", "dst addr", "dstip",
        "dest ip", "dest address", "server ip", "destination host", "recipient ip",
        "dstip", "s-ip", "server_ip", "dst_host", "dest_host", "target_ip", "destination_ip",
        "target_host", "sip", "dest_ip", "target_resource", "object_name", "file_name",
        "destination_address", "اي بي الوجهة", "الهدف",
    },
    "protocol": {
        "protocol", "proto", "transmission protocol", "ip protocol", "البروتوكول",
        "trans proto", "ip_proto", "trans protocol", "network protocol", "transport protocol",
        "app protocol", "trans_protocol", "protocol_name", "transport",
    },
    "src_port": {
        "source port", "src port", "sport", "منفذ المصدر", "client port", "source_port",
        "src_port", "srcport", "sourceport", "c-port", "client_port", "src_p", "sport_num",
        "source_port_number", "منفذ العميل",
    },
    "dst_port": {
        "destination port", "dst port", "dport", "منفذ الوجهة", "server port", "target port",
        "destination_port", "dst_port", "dstport", "destport", "dest port", "s-port",
        "server_port", "dst_p", "target_port", "dport_num", "dest_port_number", "منفذ الخادم",
    },
    "count": {
        "count", "event count", "total count", "events", "total", "occurrences",
        "عدد الأحداث", "total packets", "packet count", "repeat count", "hit count", "التكرار",
    },
}

PROTOCOL_NAMES = {
    "1": "ICMP", "2": "IGMP", "6": "TCP", "17": "UDP", "41": "IPv6",
    "47": "GRE", "50": "ESP", "51": "AH", "58": "ICMPv6", "89": "OSPF",
    "132": "SCTP",
}

PORT_SERVICES = {
    "20": "FTP-Data", "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP",
    "53": "DNS", "67": "DHCP", "68": "DHCP", "69": "TFTP", "80": "HTTP",
    "88": "Kerberos", "110": "POP3", "123": "NTP", "135": "RPC", "137": "NetBIOS",
    "138": "NetBIOS", "139": "NetBIOS", "143": "IMAP", "161": "SNMP", "162": "SNMP-Trap",
    "389": "LDAP", "443": "HTTPS", "445": "SMB", "465": "SMTPS", "514": "Syslog",
    "587": "SMTP-Sub", "636": "LDAPS", "993": "IMAPS", "995": "POP3S", "1433": "MSSQL",
    "1521": "Oracle", "3306": "MySQL", "3389": "RDP", "5432": "PostgreSQL",
    "5900": "VNC", "8080": "HTTP-Proxy", "8443": "HTTPS-Alt", "8888": "HTTP-Alt",
}

ARABIC_ACTIONS = {
    "block": "حظر",
    "blocked": "تم الحظر",
    "discard": "إسقاط",
    "discarded": "تم الإسقاط",
    "drop": "إسقاط",
    "dropped": "تم الإسقاط",
    "deny": "رفض",
    "denied": "تم الرفض",
    "reject": "رفض",
    "rejected": "تم الرفض",
    "allow": "سماح",
    "allowed": "تم السماح",
    "permit": "تصريح",
    "permitted": "تم التصريح",
    "pass": "تمرير",
    "passed": "تم التمرير",
    "alert": "تنبيه",
    "alerted": "تم التنبيه",
    "log": "تسجيل",
    "logged": "تم التسجيل",
    "quarantine": "عزل",
    "quarantined": "تم العزل",
    "clean": "تنظيف",
    "cleaned": "تم التنظيف",
    "remediated": "تمت المعالجة",
    "failed": "فشل الإجراء",
    "success": "نجاح",
    "successful": "ناجح",
    "failure": "فشل",
}

def _protocol_label(value: str) -> str:
    if not value:
        return ""
    val_clean = str(value).strip().upper()
    tokens = [token.strip() for token in re.split(r"[,;/\s]+", str(value or "")) if token.strip()]
    if not tokens:
        return ""
    return "، ".join(PROTOCOL_NAMES.get(token, PROTOCOL_NAMES.get(token.lower(), f"IP-{token}" if token.isdigit() else token.upper())) for token in tokens)

def _port_service_label(port: str) -> str:
    clean_port = str(port or "").strip()
    return PORT_SERVICES.get(clean_port, "")

SECURITY_PHRASE_TRANSLATIONS = [
    ("internal network penetration tools", "أدوات اختراق واختبار اختراق الشبكة الداخلية"),
    ("zerotier communication traffic", "حركة مرور اتصالات نفق Zerotier P2P المشفر"),
    ("penetration tools", "أدوات اختراق وتجاوز الأنظمة"),
    ("communication traffic", "حركة اتصالات وتبادل بيانات"),
    ("internal network", "الشبكة الداخلية"),
    ("an intrusion was detected", "تم رصد محاولة تسلل واختراق أمني"),
    ("the audit log was cleared", "تم مسح وتفريغ سجل التدقيق الأمني"),
    ("audit log cleared", "تم تفريغ سجل التدقيق الأمني"),
    ("an account failed to log on", "محاولة تسجيل دخول فاشلة إلى الحساب"),
    ("an account was successfully logged on", "تسجيل دخول ناجح إلى الحساب"),
    ("a user account was created", "إنشاء حساب مستخدم جديد"),
    ("a user account was deleted", "حذف حساب مستخدم"),
    ("a user account was disabled", "تعطيل حساب مستخدم"),
    ("a user account was locked out", "قفل حساب مستخدم لتكرار المحاولات"),
    ("special privileges assigned to new logon", "تعيين امتيازات وصلاحيات خاصة لجلسة الدخول"),
    ("a new service was installed in the system", "تثبيت خدمة جديدة في النظام"),
    ("a service was installed in the system", "تثبيت خدمة في النظام"),
    ("a new process has been created", "إنشاء وبدء عملية تنفيذية جديدة"),
    ("suspicious activity", "نشاط وسلوك أمني مشبوه"),
    ("network scan", "مسح واستكشاف الشبكة"),
    ("privilege escalation", "محاولة رفع الصلاحيات غير المصرح بها"),
    ("data exfiltration", "محاولة تسريب بيانات حساسة"),
    ("access denied", "تم رفض وحظر الوصول"),
    ("unauthorized access", "محاولة وصول غير مصرح بها"),
    ("policy violation", "انتهاك للسياسات الأمنية"),
    ("malicious connection", "محاولة اتصال بجهة خبيثة"),
    ("c2 traffic", "حركة مرور اتصالات مركز القيادة والتحكم C2"),
    ("impossible travel", "تسجيل دخول مستحيل جغرافياً"),
    ("password spray", "هجوم رش وتجربة كلمات المرور"),
    ("credential dumping", "محاولة سرقة واستخراج بيانات الاعتماد"),
    ("mailbox forwarding rule", "إنشاء قاعدة إعادة توجيه للبريد الإلكتروني"),
    ("shadow copy deletion", "حذف النسخ الاحتياطية لتعطيل الاستعادة"),
    ("process injection", "حقن تعليمات برمجية داخل عملية تنفيذية"),
    ("kerberoasting", "استخراج تذاكر خدمة Kerberos للتخمين بدون اتصال"),
    ("pre-authentication failed", "فشل المصادقة المسبقة لـ Kerberos"),
    ("account locked out", "تم قفل حساب المستخدم"),
    ("member added to security group", "إضافة عضو إلى مجموعة أمان حساسة"),
    ("file integrity violation", "انتهاك لسلامة وتكامل الملفات"),
    ("remote code execution", "تنفيذ تعليمات برمجية عن بُعد"),
    ("command injection", "حقن أوامر نظام التشغيل"),
    ("directory traversal", "تجاوز المسار وقراءة ملفات النظام"),
    ("local file inclusion", "تضمين ملفات محلية حساسة"),
    ("cross-site scripting", "برمجة نصية عابرة للمواقع XSS"),
    ("sql injection", "حقن استعلامات قواعد البيانات"),
    ("brute force attack", "هجوم تخمين كلمات المرور المتكرر"),
    ("port scan detected", "رصد مسح واستكشاف للمنافذ"),
    ("syn flood", "فيضان حزم التزامن SYN Flood"),
    ("udp flood", "فيضان حزم UDP Flood"),
    ("dns tunneling", "نفق بروتوكول DNS لنقل البيانات الخبيثة"),
    ("unauthorized command execution", "تنفيذ أمر برمجي غير مصرح به"),
    ("login failed for user", "فشل تسجيل الدخول للمستخدم في قاعدة البيانات"),
]

def _translate_phrase_to_ar(text: str) -> str:
    result = text
    lower_text = text.lower()
    for eng, ar in SECURITY_PHRASE_TRANSLATIONS:
        if eng in lower_text:
            pattern = re.compile(re.escape(eng), re.IGNORECASE)
            result = pattern.sub(ar, result)
    return result

def _forensic_threat_explanation(desc: str, eid: str = "", action: str = "", raw_fields: dict[str, str] | None = None) -> tuple[str, str, str]:
    """Provide structured Arabic forensic description, action badge, and threat family with MITRE mapping."""
    raw = str(desc or "").strip()
    raw_lower = raw.lower()
    fields = raw_fields or {}

    act_raw = str(action or "").strip().lower()
    act_ar = ARABIC_ACTIONS.get(act_raw, action.upper() if action else "")
    if act_ar and action:
        act_display = f"{act_ar} ({action.upper()})"
    elif action:
        act_display = action.upper()
    else:
        act_display = ""

    # Extract sub_status if present
    substatus = (
        fields.get("Sub Status")
        or fields.get("SubStatus")
        or fields.get("Failure Reason")
        or fields.get("Status Code")
        or ""
    ).strip().lower()
    if not substatus:
        sub_match = re.search(r"\b(0x[c0-9a-f]{8}|0x18|0x17|0x6|0xc)\b", raw, re.IGNORECASE)
        if sub_match:
            substatus = sub_match.group(1).lower()

    # Extract logon_type if present
    logon_type = (
        fields.get("Logon Type")
        or fields.get("LogonType")
        or fields.get("Logon_Type")
        or ""
    ).strip()
    if not logon_type:
        lt_match = re.search(r"\b(?:logon\s*type|type)[:\s=]+(\d+)\b", raw, re.IGNORECASE)
        if lt_match:
            logon_type = lt_match.group(1)

    # 1. Malware Families & Known Botnets
    if "expiro" in raw_lower:
        domain_match = re.search(r"expiro\s*:\s*([a-zA-Z0-9.\-_]+)", raw, re.IGNORECASE)
        domain = domain_match.group(1).strip() if domain_match else ""
        desc_ar = f"فيروس Expiro - محاولة اتصال بنطاق تحكم C2 خبيث: {domain}" if domain else "فيروس Expiro - برمجية خبيثة تصيب ملفات النظام وتسرق بيانات الاعتماد"
        return desc_ar, act_display, "فيروس Expiro (Expiro Virus)"

    if "tiggre" in raw_lower:
        domain_match = re.search(r"tiggre\s*:\s*([a-zA-Z0-9.\-_]+)", raw, re.IGNORECASE)
        domain = domain_match.group(1).strip() if domain_match else ""
        desc_ar = f"تروجان Tiggre - محاولة اتصال بملف/نطاق خبيث لتعدين العملات أو التنزيل: {domain}" if domain else "تروجان Tiggre - حصان طروادة خبيث"
        return desc_ar, act_display, "تروجان Tiggre (Tiggre Trojan)"

    if any(k in raw_lower for k in ("coinminer", "cryptominer", "monero", "crypto mining")):
        return "تروجان تعدين العملات المشفرة واستهلاك موارد الأجهزة (CoinMiner Trojan)", act_display, "تأثير: تعدين عملات (CoinMiner)"

    if "ransomware" in raw_lower:
        return "نشاط برمجيات الفدية الخبيثة ومحاولة تشفير الملفات وتعطيل النظام (Ransomware Activity)", act_display, "تأثير: برمجية فدية (Ransomware)"

    if any(k in raw_lower for k in ("vssadmin", "shadowcopy", "shadowstorage")):
        return "محاولة حذف النسخ الاحتياطية لتعطيل استعادة النظام تمهيداً للتشفير (Inhibit System Recovery)", act_display, "تأثير: حذف النسخ الاحتياطية (Inhibit Recovery)"

    if any(k in raw_lower for k in ("mimikatz", "sekurlsa", "lsass", "procdump", "comsvcs")):
        return "محاولة استخراج وقراءة كلمات المرور ومفاتيح التشفير من ذاكرة النظام LSASS (Credential Dumping)", act_display, "سرقة اعتمادات: قراءة ذاكرة LSASS"

    # 2. Windows Active Directory & Security Events
    if eid == "4625" or "failed to log on" in raw_lower or "failed logon" in raw_lower:
        reason_text = WINDOWS_LOGON_SUBSTATUS_AR.get(substatus, "")
        lt_text = WINDOWS_LOGON_TYPES_AR.get(str(logon_type), "")
        parts = ["محاولة تسجيل دخول فاشلة إلى الحساب"]
        if reason_text:
            parts.append(f"السبب: {reason_text}")
        if lt_text:
            parts.append(f"عبر {lt_text}")
        desc_ar = " — ".join(parts)
        return desc_ar, act_display, "وصول أولي: محاولة دخول فاشلة (Failed Logon)"

    if eid == "4624" or "successfully logged on" in raw_lower or "successful logon" in raw_lower:
        lt_text = WINDOWS_LOGON_TYPES_AR.get(str(logon_type), "")
        if str(logon_type) == "10":
            desc_ar = "تسجيل دخول ناجح عبر اتصال سطح مكتب بعيد (RDP Interactive Session)"
            return desc_ar, act_display, "وصول أولي: اتصال سطح مكتب RDP"
        if str(logon_type) == "3":
            desc_ar = "تسجيل دخول ناجح عبر مشاركة الملفات والشبكة (Network SMB Session)"
            return desc_ar, act_display, "وصول أولي: دخول شبكي SMB"
        desc_ar = f"تسجيل دخول ناجح إلى النظام ({lt_text})" if lt_text else "تسجيل دخول ناجح إلى النظام والحساب"
        return desc_ar, act_display, "وصول أولي: تسجيل دخول (Logon Success)"

    if eid in {"1102", "104"} or "audit log was cleared" in raw_lower or "the audit log was cleared" in raw_lower or "audit log cleared" in raw_lower:
        return "مسح وتفريغ سجل التدقيق الأمني لمنع التحقيق الجنائي وتتبع المهاجمين (Audit Log Cleared)", act_display, "تجاوز الدفاعات: مسح سجلات التدقيق (Anti-Forensics)"

    if eid == "4672" or "special privileges assigned" in raw_lower:
        return "منح امتيازات إدارية خاصة لجلسة تسجيل الدخول (Administrator Privileges Assigned)", act_display, "تصعيد صلاحيات: امتيازات مسؤول (Admin Privileges)"

    if eid in {"4728", "4732", "4756"} or ("member was added" in raw_lower and "group" in raw_lower):
        group_name = WINDOWS_EVENT_DESCRIPTIONS_AR.get(eid, "مجموعة أمان حساسة")
        return f"إضافة عضو إلى {group_name} (تصعيد امتيازات إدارية عالي الخطورة)", act_display, "تصعيد صلاحيات: إضافة لمجموعة إدارية (Privilege Escalation)"

    if eid == "4720" or "user account was created" in raw_lower:
        return "إنشاء حساب مستخدم جديد على النظام أو النطاق (New User Created)", act_display, "ترسيخ التواجد: إنشاء حساب (Account Creation)"

    if eid == "4740" or "user account was locked out" in raw_lower or "locked out" in raw_lower:
        return "قفل حساب المستخدم تلقائياً بسبب تكرار محاولات تسجيل الدخول الخاطئة (Account Lockout)", act_display, "استكشاف: قفل حساب مستخدم (Account Lockout)"

    if eid in {"4697", "7045"} or "service was installed" in raw_lower:
        return "تثبيت خدمة جديدة في نظام التشغيل لتثبيت التواجد الخبيث (New Service Installed)", act_display, "ترسيخ التواجد: تثبيت خدمة (Persistence)"

    if eid in {"4698", "4702"} or "scheduled task" in raw_lower:
        return "إنشاء أو تعديل مهمة مجدولة في النظام للتشغيل التلقائي (Scheduled Task Persistence)", act_display, "ترسيخ التواجد: مهمة مجدولة (Scheduled Task)"

    if eid in {"4768", "4769", "4771"} or "kerberos" in raw_lower:
        if eid == "4771" or substatus in {"0x18", "0x17", "0x6"}:
            reason_text = WINDOWS_LOGON_SUBSTATUS_AR.get(substatus, "فشل المصادقة المسبقة")
            return f"فشل مصادقة Kerberos المسبقة ({reason_text}) - احتمال هجوم كيربيروس أو تخمين", act_display, "سرقة اعتمادات: كيربيروس (Kerberos Attack)"
        if eid == "4769":
            return "طلب تذكرة خدمة Kerberos TGS (فحص رصد هجمات Kerberoasting لاستخراج كلمات المرور)", act_display, "سرقة اعتمادات: كيربيروس (Kerberoasting)"
        return "طلب تذكرة مصادقة Kerberos TGT (AS-REQ)", act_display, "مصادقة: كيربيروس (Kerberos Auth)"

    if eid in {"5140", "5145"} or "network share" in raw_lower:
        return "الوصول إلى مشاركة ملفات شبكية أو فحص مشاركات إدارية حساسة (C$, ADMIN$, IPC$)", act_display, "تحرك جانبي: مشاركة ملفات (Lateral Movement)"

    # 3. PowerShell & Suspicious Script Execution
    if "-enc" in raw_lower or "encodedcommand" in raw_lower:
        return "تشغيل أوامر PowerShell مشفرة بالقاعدة 64 لإخفاء النشاط البرمجي الخبيث (Encoded PowerShell Execution)", act_display, "تنفيذ: باور شيل مشفر (Encoded PowerShell)"

    if any(k in raw_lower for k in ("downloadstring", "invoke-expression", "webclient")) or "iex " in raw_lower:
        return "تحميل وتشغيل نصوص برمجية خبيثة مباشرة في الذاكرة دون حفظ على القرص (Fileless Download & Execute)", act_display, "تنفيذ: تحميل في الذاكرة (Fileless Execution)"

    if "certutil" in raw_lower or "bitsadmin" in raw_lower:
        return "استخدام أدوات النظام المعتمدة لتنزيل ملفات مشبوهة من الإنترنت (LOLBins Ingress Tool)", act_display, "تجاوز دفاعات: تنزيل بأدوات موثوقة (LOLBins)"

    if any(k in raw_lower for k in ("whoami /priv", "nltest", "net user /domain")):
        return "تنفيذ أوامر استطلاع واستكشاف صلاحيات وحسابات النطاق (Reconnaissance Commands)", act_display, "استكشاف: استطلاع الصلاحيات والنطاق (Discovery)"

    # 4. Linux & Unix Syslog Auditing
    if "failed password for" in raw_lower:
        u_match = re.search(r"failed password for (?:invalid user\s+)?(\S+)", raw, re.IGNORECASE)
        target_u = u_match.group(1) if u_match else "المستخدم"
        return f"محاولة فاشلة لتسجيل الدخول إلى خادم Linux عبر SSH للحساب [{target_u}] بكلمة مرور غير صحيحة", act_display, "وصول أولي: تخمين دخول SSH (SSH Failed Login)"

    if "invalid user" in raw_lower:
        u_match = re.search(r"invalid user\s+(\S+)", raw, re.IGNORECASE)
        target_u = u_match.group(1) if u_match else "مجهول"
        return f"محاولة تخمين دخول SSH لاسم مستخدم غير موجود على خادم Linux [{target_u}] (استطلاع حسابات)", act_display, "استكشاف: استطلاع حسابات SSH (SSH Enumeration)"

    if "accepted publickey" in raw_lower or "accepted password" in raw_lower:
        u_match = re.search(r"accepted (?:publickey|password) for (\S+)", raw, re.IGNORECASE)
        target_u = u_match.group(1) if u_match else "المستخدم"
        return f"تسجيل دخول ناجح إلى خادم Linux عبر بروتوكول SSH للحساب [{target_u}]", act_display, "وصول أولي: دخول SSH ناجح (SSH Login Success)"

    if "sudo:" in raw_lower and "authentication failure" in raw_lower:
        return "فشل مصادقة كلمة المرور أثناء محاولة استخدام صلاحيات المسؤول sudo على نظام Linux", act_display, "تصعيد صلاحيات: فشل مصادقة sudo (Sudo Failure)"

    if "sudo:" in raw_lower and "not in sudoers" in raw_lower:
        return "محاولة استخدام صلاحيات المسؤول sudo من مستخدم غير مصرح له في النظام (انتهاك صلاحيات)", act_display, "تصعيد صلاحيات: انتهاك صلاحيات sudo (Sudo Violation)"

    if "crontab" in raw_lower and any(k in raw_lower for k in ("replace", "edit", "install")):
        return "تعديل مهام الجدولة Cron على نظام Linux لتثبيت التواجد الخبيث (Crontab Persistence)", act_display, "ترسيخ التواجد: جدولة Cron (Linux Persistence)"

    # 5. Web Applications & OWASP Top 10
    if any(k in raw_lower for k in ("union select", "information_schema", "sqli", "sql injection")) or "' or 1=1" in raw_lower or "sleep(" in raw_lower:
        return "هجوم حقن قواعد البيانات SQL Injection لمحاولة استخراج البيانات أو تجاوز المصادقة", act_display, "استغلال ثغرة: حقن SQL (SQL Injection)"

    if "<script" in raw_lower or "javascript:" in raw_lower or "onerror=" in raw_lower or "xss" in raw_lower:
        return "هجوم البرمجة النصية عبر المواقع Cross-Site Scripting (XSS) لاستهداف متصفحات المستخدمين", act_display, "استغلال ثغرة: برمجة نصية XSS (Cross-Site Scripting)"

    if "../" in raw_lower or "/etc/passwd" in raw_lower or "win.ini" in raw_lower or "path traversal" in raw_lower:
        return "محاولة تجاوز المسار وقراءة ملفات النظام الحساسة (Path Traversal / Local File Inclusion)", act_display, "استكشاف: تجاوز المسار (Directory Traversal)"

    if any(k in raw_lower for k in ("webshell", "rce", "remote code execution", "passthru(", "cmd.exe", "/bin/sh")):
        return "محاولة استدعاء WebShell أو تنفيذ أوامر برمجية عن بُعد على الخادم (RCE Attack)", act_display, "تنفيذ: ويب شل وأوامر خادم (WebShell/RCE)"

    if "${jndi:" in raw_lower or "log4j" in raw_lower:
        return "محاولة استغلال ثغرة Log4Shell (CVE-2021-44228) للتحكم في الخادم عن بُعد", act_display, "استغلال ثغرة: ثغرة Log4Shell (CVE-2021-44228)"

    if "169.254.169.254" in raw_lower or "metadata.google.internal" in raw_lower or "ssrf" in raw_lower:
        return "محاولة استغلال ثغرات طلبات الخادم المزورة SSRF للوصول إلى بيانات تعريف السحابة الحساسة", act_display, "استغلال ثغرة: استدعاء سحابي مزور (SSRF)"

    if any(k in raw_lower for k in ("/wp-admin", "/.env", "/.git", "/phpmyadmin", "/eval-stdin")):
        return "مسح واستكشاف ملفات الإعدادات والبيئات ولوحات التحكم المكشوفة للويب (Web Reconnaissance)", act_display, "استكشاف: مسح لوحات التحكم والبيئات (Web Scan)"

    # 6. Cloud & Microsoft 365 / Identity
    if "impossible travel" in raw_lower:
        return "تسجيل دخول مستحيل جغرافياً لحساب السحابة خلال فترة زمنية متقاربة (Impossible Travel Alert)", act_display, "وصول أولي: دخول مستحيل جغرافياً (Impossible Travel)"

    if "password spray" in raw_lower:
        return "هجوم رش وتجربة كلمات مرور شائعة على عدة حسابات في السحابة (Password Spray Attack)", act_display, "سرقة اعتمادات: رش كلمات المرور (Password Spray)"

    if "mailbox forwarding" in raw_lower or "forwarding rule" in raw_lower:
        return "إنشاء قاعدة إعادة توجيه بريد إلكتروني خبيثة لسرقة المراسلات والتحويلات المالية (BEC Attack)", act_display, "تسريب بيانات: توجيه بريد إلكتروني (BEC Forwarding)"

    if "oauth consent" in raw_lower or "risky application" in raw_lower:
        return "منح تطبيق سحابي صلاحيات غير مقيدة للوصول إلى البريد والملفات (Suspicious OAuth Grant)", act_display, "ترسيخ التواجد: تطبيق سحابي مشبوه (Malicious OAuth)"

    # 7. Database Auditing
    if "login failed for user" in raw_lower or "18456" in raw_lower or "ora-01017" in raw_lower:
        return "فشل تسجيل الدخول لخادم قواعد البيانات بسبب خطأ في بيانات الاعتماد (Database Login Failure)", act_display, "وصول أولي: فشل دخول قاعدة البيانات (DB Login Failed)"

    if any(k in raw_lower for k in ("drop table", "drop database", "truncate table")):
        return "تنفيذ أمر حذف جدول أو قاعدة بيانات كاملة (تدمير بيانات حساس في خادم البيانات)", act_display, "تخريب: حذف جداول قواعد البيانات (Drop Table / Impact)"

    if "sp_addsrvrolemember" in raw_lower or "grant all" in raw_lower:
        return "منح صلاحيات إدارية كاملة (sysadmin) لمستخدم في قاعدة البيانات (DB Privilege Escalation)", act_display, "تصعيد صلاحيات: صلاحيات قاعدة بيانات (DB Privilege Escalation)"

    # 8. Network Firewalls & Perimeter Controls
    if "zerotier" in raw_lower:
        return "أدوات اختراق وتجاوز الشبكة الداخلية - رصد اتصالات نفق Zerotier P2P المشفر (Zerotier Penetration)", act_display, "أدوات اختراق (Penetration Tools)"

    if "penetration" in raw_lower:
        return "أدوات اختراق واختبار اختراق الشبكة الداخلية والأنظمة (Internal Penetration Tools)", act_display, "أدوات اختراق (Penetration Tools)"

    if any(k in raw_lower for k in ("tunneling", "shadowsocks", "proxy bypass", "wireguard", "openvpn")):
        return "استخدام أنفاق واتصالات مشفرة لتجاوز جدار الحماية (Tunneling / Proxy Bypass)", act_display, "تجاوز دفاعات: أنفاق وبروكسي (Tunnel/Proxy)"

    if "dns tunnel" in raw_lower or "dga domain" in raw_lower:
        return "استخدام أنفاق DNS أو نطاقات مولدة خوارزمياً للاتصال بمراكز القيادة C2 (DNS Tunneling)", act_display, "قيادة وتحكم: أنفاق DNS خبيثة (DNS Tunneling)"

    if "tor exit" in raw_lower or "vpn exit" in raw_lower:
        return "حركة مرور متصلة بعقد شبكة Tor أو خوادم VPN لتجاوز سياسات الحماية الجغرافية", act_display, "تجاوز دفاعات: حركة شبكة تور وبروكسي (Tor/VPN Traffic)"

    if "trace route" in raw_lower or "traceroute" in raw_lower:
        return "هجوم استطلاع وتتبع مسار الشبكة وتحديد الأجهزة الوسيطة (Traceroute Reconnaissance)", act_display, "استكشاف: استطلاع الشبكة (Reconnaissance)"

    if "icmp unreachable" in raw_lower:
        return "هجوم استغلال وإغراق رسائل تحكم ICMP (Unreachable Flood Attack)", act_display, "تأثير: هجوم ICMP (ICMP Flood)"

    if "icmp flood" in raw_lower or "ping flood" in raw_lower:
        return "هجوم إغراق رسائل تحكم ICMP/Ping Flood للتعطيل", act_display, "تأثير: هجوم ICMP (ICMP Flood)"

    if "brute force" in raw_lower or "dictionary attack" in raw_lower:
        return "هجوم تخمين كلمات المرور ومحاولات دخول متكررة (Brute Force Attack)", act_display, "سرقة اعتمادات: تخمين دخول (Brute Force)"

    if any(k in raw_lower for k in ("port scan", "portscan", "network scan", "host sweep")):
        return "مسح واستكشاف المنافذ والخدمات المفتوحة في الشبكة (Port Scan Reconnaissance)", act_display, "استكشاف: مسح المنافذ (Port Scan)"

    if any(k in raw_lower for k in ("ip spoof", "spoofing", "arp spoof")):
        return "هجوم انتحال وتزييف عناوين الشبكة لتجاوز قواعد الحماية (IP Spoofing Attack)", act_display, "تجاوز دفاعات: انتحال العناوين (IP Spoof)"

    if any(k in raw_lower for k in ("syn flood", "udp flood", "tcp flood", "ddos", "denial of service")):
        return "هجوم حجب الخدمة وإغراق تدفقات الشبكة (DoS / DDoS Flood Attack)", act_display, "تأثير: حجب خدمة (DoS/DDoS)"

    if "cve-" in raw_lower or "vulnerability" in raw_lower:
        ref_match = re.search(r"(CVE-\d{4}-\d+)", raw, re.IGNORECASE)
        cve_text = f" ({ref_match.group(1).upper()})" if ref_match else ""
        return f"محاولة استغلال ثغرة أمنية في التطبيقات والأنظمة{cve_text}", act_display, "استغلال ثغرة (CVE Exploit)"

    if "worm" in raw_lower:
        return "دودة حاسوبية خبيثة سريعة الانتشار عبر الشبكة (Network Worm)", act_display, "برمجية خبيثة: دودة (Worm)"

    if any(k in raw_lower for k in ("spyware", "keylogger", "stealer", "infostealer")):
        return "برمجية تجسس وسرقة بيانات اعتماد وكلمات مرور (Information Stealer)", act_display, "سرقة اعتمادات: برمجية تجسس (Spyware)"

    if "botnet" in raw_lower or "c2 traffic" in raw_lower:
        return "نشاط اتصال بمركز قيادة وتحكم خبيث أو شبكة روبوتات (Botnet / C2 Traffic)", act_display, "قيادة وتحكم: شبكة بوتنت (Botnet/C2)"

    if "virus" in raw_lower:
        return f"نشاط برمجية فيروسية خبيثة رصدها الجدار الناري: {raw}", act_display, "برمجية خبيثة: فيروس (Virus)"

    if "trojan" in raw_lower or "backdoor" in raw_lower:
        return f"حصان طروادة أو باب خلفي خبيث رصده الجدار الناري: {raw}", act_display, "برمجية خبيثة: حصان طروادة (Trojan)"

    if "icmp" in raw_lower:
        return f"نشاط بروتوكول التحكم في الشبكة (ICMP): {raw}", act_display, "نشاط شبكي: ICMP"

    # 9. Windows Event ID Lookup
    if eid and eid in WINDOWS_EVENT_DESCRIPTIONS_AR:
        return WINDOWS_EVENT_DESCRIPTIONS_AR[eid], act_display, "حدث ويندوز (Windows Event)"

    # 10. Automatic phrase translation fallback
    translated = _translate_phrase_to_ar(raw)
    if translated != raw:
        return translated, act_display, "حدث أمني (Security Event)"

    return raw, act_display, "حدث أمني (Security Event)"

@dataclass
class NormalizedEvent:
    event_time: str = ""
    event_id: str = ""
    priority: str = "Info"
    event_source: str = ""
    device: str = ""
    user_account: str = ""
    src_ip: str = ""
    description: str = ""
    status: str = ""
    action: str = ""
    category: str = ""
    destination: str = ""
    protocol: str = ""
    src_port: str = ""
    dst_port: str = ""
    service_name: str = ""
    description_ar: str = ""
    action_ar: str = ""
    threat_family: str = ""
    report_family: str = "events"
    record_count: int = 1
    raw_fields: dict[str, str] = field(default_factory=dict)
    
    # Analysis outputs
    risk_score: int = 0
    confidence_score: int = 50
    severity: str = "Info"
    conclusion_level: str = "observed"
    incident_id: str | None = None
    detection_ids: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)
    extracted_ips: set[str] = field(default_factory=set)

    @property
    def source_ip(self) -> str:
        return self.src_ip

    @source_ip.setter
    def source_ip(self, val: str) -> None:
        self.src_ip = str(val or "")

    @property
    def destination_ip(self) -> str:
        return self.destination

    @destination_ip.setter
    def destination_ip(self, val: str) -> None:
        self.destination = str(val or "")

    @property
    def username(self) -> str:
        return self.user_account

    @username.setter
    def username(self, val: str) -> None:
        self.user_account = str(val or "")

    @property
    def message(self) -> str:
        return self.description

    @message.setter
    def message(self, val: str) -> None:
        self.description = str(val or "")

    @property
    def action_disposition(self):
        try:
            from .canonical import ActionDisposition
        except ImportError:
            from canonical import ActionDisposition
        return ActionDisposition.from_string(self.action)


def _normalise_header(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", text)
    text = text.lower()
    text = re.sub(r"[\s_./\\:()\[\]-]+", " ", text)
    return " ".join(text.split())


def _find_column(headers: list[str], aliases: set[str], priority_aliases: list[str] | None = None) -> int | None:
    normalised_headers = [_normalise_header(header) for header in headers]
    if priority_aliases:
        for pref in priority_aliases:
            pref_clean = _normalise_header(pref)
            if pref_clean in normalised_headers:
                return normalised_headers.index(pref_clean)

    normalised_aliases = {_normalise_header(alias) for alias in aliases}
    for index, clean_header in enumerate(normalised_headers):
        if clean_header in normalised_aliases:
            return index
    return None


def _report_family(headers: list[str], mapping: dict[str, int]) -> str:
    joined = " ".join(_normalise_header(header) for header in headers)
    if any(word in joined for word in ("compliance", "compliant", "control", "policy", "امتثال")):
        return "compliance"
    if "start time" in joined and any(word in joined for word in ("end time", "duration", "session")):
        return "sessions"
    if any(word in joined for word in ("incident", "alert", "correlation rule")):
        return "alerts"
    if "device" in mapping and "event_id" not in mapping and any(word in joined for word in ("status", "last message", "device type")):
        return "devices"
    if any(word in joined for word in ("file integrity", "file name", "folder", "object name")):
        return "file_audit"
    if any(word in joined for word in ("firewall", "source port", "destination port", "protocol", "attack name")):
        return "network"
    return "events" if ("event_id" in mapping or "description" in mapping) else "custom"


def _positive_int(value: str) -> int:
    match = re.search(r"\d[\d,]*", str(value or ""))
    if not match:
        return 1
    try:
        return max(int(match.group(0).replace(",", "")), 1)
    except ValueError:
        return 1


def _generic_description(raw_fields: dict[str, str], preferred: str = "") -> str:
    if preferred.strip():
        return preferred.strip()
    parts = [f"{name}: {value}" for name, value in raw_fields.items() if value][:8]
    return " | ".join(parts) or "سجل أمني صادر من النظام"


def _is_ip(value: str) -> bool:
    val = str(value or "").strip().split("%", 1)[0]
    if not val or len(val) > 45 or ("." not in val and ":" not in val):
        return False
    if val.count(".") != 3 and ":" not in val:
        return False
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        pass
    if ":" in val and "." in val:  # e.g. 192.168.1.1:8080
        part = val.split(":", 1)[0]
        if part.count(".") == 3:
            try:
                ipaddress.ip_address(part)
                return True
            except ValueError:
                pass
    return False


_IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')


def _extract_ips(text: str) -> list[str]:
    """Extract valid IPv4 and IPv6 addresses from a given text block with high performance."""
    if not text or ("." not in text and ":" not in text):
        return []
    candidates = _IPV4_RE.findall(text)
    valid_ips: list[str] = []
    for c in candidates:
        if _is_ip(c) and c not in valid_ips:
            valid_ips.append(c)
    if ":" in text:
        for token in text.split():
            candidate = token.strip(" ,;|()[]{}<>\"'").rsplit("=", 1)[-1]
            if ":" in candidate and "." not in candidate:
                if _is_ip(candidate) and candidate not in valid_ips:
                    valid_ips.append(candidate)
    return valid_ips


_SYSLOG_KV_RE = re.compile(r'([a-zA-Z0-9_\-]+)=(?:\"([^\"]*)\"|\'([^\']*)\'|([^\s,;()]+))')


def _parse_syslog_key_values(text: str) -> dict[str, str]:
    """Extract key-value parameters from Syslog / CEF / UTM message strings."""
    if not text or "=" not in text:
        return {}
    attrs: dict[str, str] = {}
    for m in _SYSLOG_KV_RE.finditer(text):
        k = m.group(1).strip()
        v = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
        if k and v is not None:
            attrs[k] = v.strip()
    return attrs


def _is_placeholder_user(val: str) -> bool:
    """Identify whether a user field is merely a generic system placeholder."""
    v = str(val or "").strip().lower()
    return v in {"", "-", "unknown", "n/a", "na", "none", "null", "undefined", "anonymous logon", "--"}


def _parse_stream_ips(raw_text: str) -> tuple[str, str, list[str], str, str]:
    """Parse complex source text containing IP mappings (e.g., '185.1.48.74:80->185.80.143.117:53; ...')."""
    if "->" not in raw_text:
        return "", "", [], "", ""
    all_ips: list[str] = []
    primary_src = ""
    primary_dst = ""
    src_port = ""
    dst_port = ""
    pairs = raw_text.split(";")
    for pair in pairs:
        pair = pair.strip()
        if "->" in pair:
            parts = pair.split("->", 1)
            s_raw = parts[0].strip()
            d_raw = parts[1].replace(", begin", "").strip()
            
            s_ip = s_raw.split(":")[0].strip()
            if ":" in s_raw and not _is_ip(s_raw): # e.g. 1.2.3.4:53
                cand_port = s_raw.split(":", 1)[1].strip()
                if cand_port.isdigit():
                    src_port = cand_port

            d_ip = d_raw.split(":")[0].strip()
            if ":" in d_raw and not _is_ip(d_raw):
                cand_port = d_raw.split(":", 1)[1].strip()
                if cand_port.isdigit():
                    dst_port = cand_port

            if _is_ip(s_ip):
                if not primary_src:
                    primary_src = s_ip
                if s_ip not in all_ips:
                    all_ips.append(s_ip)
            if _is_ip(d_ip):
                if not primary_dst:
                    primary_dst = d_ip
                if d_ip not in all_ips:
                    all_ips.append(d_ip)
    return primary_src, primary_dst, all_ips, src_port, dst_port


def _meaningful_description(event_id: str, description: str, device: str, event_source: str) -> str:
    """Replace exporter placeholders with a useful Windows event or threat description."""
    raw = description.strip()
    if raw and raw not in {device.strip(), event_source.strip()} and not _is_ip(raw):
        return raw
    event_id = event_id.strip()
    if event_id in WINDOWS_EVENT_DESCRIPTIONS_AR:
        return WINDOWS_EVENT_DESCRIPTIONS_AR[event_id]
    if event_id:
        return f"حدث أمني مسجل برقم المعرف {event_id}"
    return raw or "حدث أمني صادر من النظام"


def normalize_events(data: ParsedData, progress_callback=None) -> list[NormalizedEvent]:
    """Convert raw tabular data into standardized objects with deep forensic extraction."""
    headers = data.headers
    mapping: dict[str, int] = {}
    
    desc_priority = ["message", "description", "details", "event message", "event description", "msg", "log message", "الوصف", "نص الرسالة", "تفاصيل الحدث"]
    act_priority = ["action", "action taken", "operation", "activity", "command", "firewall action", "disposition", "الإجراء"]

    for field_name, aliases in FIELD_ALIASES.items():
        priority = desc_priority if field_name == "description" else (act_priority if field_name == "action" else None)
        index = _find_column(headers, aliases, priority)
        if index is not None:
            mapping[field_name] = index

    family = _report_family(headers, mapping)
    if not headers or not any(str(header).strip() for header in headers):
        raise ValueError("الملف لا يحتوي على رؤوس أعمدة قابلة للتحليل.")

    norm_header_map = {header: _normalise_header(header) for header in headers}

    fallback_eid_col = None
    fallback_priority_col = None
    fallback_device_col = None
    fallback_source_col = None
    fallback_user_col = None
    fallback_src_col = None
    fallback_dst_col = None
    fallback_action_col = None

    for idx, header in enumerate(headers):
        k_norm = norm_header_map.get(header, "")
        if fallback_eid_col is None and any(w in k_norm for w in ("signature id", "signid", "sign id", "event id", "eventid", "rule id", "threat id")):
            fallback_eid_col = idx
        if fallback_priority_col is None and any(w in k_norm for w in ("severity", "priority", "level", "risk")):
            fallback_priority_col = idx
        if fallback_device_col is None and any(w in k_norm for w in ("device", "host", "computer", "firewall", "server", "sensor", "asset")):
            fallback_device_col = idx
        if fallback_source_col is None and any(w in k_norm for w in ("source zone", "profile", "application", "vendor", "log source")):
            fallback_source_col = idx
        if fallback_user_col is None and any(w in k_norm for w in ("user", "account", "login", "actor", "operator", "username")):
            fallback_user_col = idx
        if fallback_src_col is None and any(w in k_norm for w in ("src", "source", "client", "origin", "remote")):
            fallback_src_col = idx
        if fallback_dst_col is None and any(w in k_norm for w in ("dst", "dest", "target", "server", "destination")):
            fallback_dst_col = idx
        if fallback_action_col is None and any(w in k_norm for w in ("action", "disposition", "verdict", "response", "policy action")):
            fallback_action_col = idx

    total_rows = getattr(data, "total_rows", 0) or (len(data.rows) if hasattr(data.rows, "__len__") else 0)
    for row_index, row in enumerate(data.rows, 1):
        if not any(row):  # Skip entirely empty rows
            continue
            
        def get_val(key: str) -> str:
            if key in mapping and mapping[key] < len(row):
                val = row[mapping[key]]
                return str(val).strip() if val is not None else ""
            return ""

        raw_fields = {
            (str(header).strip() or f"Column {index + 1}"): str(row[index]).strip()
            for index, header in enumerate(headers)
            if index < len(row) and row[index] is not None and str(row[index]).strip()
        }

        # Inspect Message / Details for Syslog / CEF key-value pairs
        msg_val = get_val("description")
        if not msg_val:
            for msg_k in ("Message", "message", "Event Message", "Description", "details", "الوصف"):
                if msg_k in raw_fields and raw_fields[msg_k]:
                    msg_val = raw_fields[msg_k]
                    break
        
        syslog_attrs = _parse_syslog_key_values(msg_val)

        # 1. Event ID / Signature ID
        eid = get_val("event_id")
        if not eid or eid in ("-", "none", "NA", "N/A"):
            eid = syslog_attrs.get("SignId") or syslog_attrs.get("SyslogId") or syslog_attrs.get("EventNum") or ""
        if (not eid or eid in ("-", "none", "NA", "N/A")) and fallback_eid_col is not None and fallback_eid_col < len(row):
            candidate = str(row[fallback_eid_col]).strip()
            if candidate not in ("-", "none", "NA", "N/A"):
                eid = candidate

        # 2. Priority / Severity
        priority = get_val("priority") or syslog_attrs.get("Severity") or ""
        if not priority and fallback_priority_col is not None and fallback_priority_col < len(row):
            priority = str(row[fallback_priority_col]).strip()
        priority = priority or "Info"

        # 3. Event Source & Device
        device = get_val("device")
        if (not device or device in ("-", "none", "NA", "N/A")) and fallback_device_col is not None and fallback_device_col < len(row):
            candidate = str(row[fallback_device_col]).strip()
            if candidate not in ("-", "none", "NA", "N/A"):
                device = candidate

        event_source = get_val("event_source") or syslog_attrs.get("Profile") or syslog_attrs.get("Application") or ""
        if not event_source and fallback_source_col is not None and fallback_source_col < len(row):
            event_source = str(row[fallback_source_col]).strip()

        # 4. User Account
        raw_user = get_val("user_account") or syslog_attrs.get("User") or ""
        if (not raw_user or _is_placeholder_user(raw_user)) and fallback_user_col is not None and fallback_user_col < len(row):
            raw_user = str(row[fallback_user_col]).strip()
        user_account = "" if _is_placeholder_user(raw_user) else raw_user

        # 5. Source IP, Destination IP, and Stream IP extraction
        src_raw = get_val("src_ip") or syslog_attrs.get("SrcIp") or ""
        dst_raw = get_val("destination") or syslog_attrs.get("DstIp") or ""
        
        stream_src, stream_dst, stream_ips, stream_sport, stream_dport = _parse_stream_ips(src_raw)
        if stream_src:
            src_ip = stream_src
            dst_ip = dst_raw if (dst_raw and dst_raw != "-" and _is_ip(dst_raw)) else stream_dst
        else:
            src_ip = src_raw if (src_raw and src_raw != "-") else (syslog_attrs.get("SrcIp") or "")
            dst_ip = dst_raw if (dst_raw and dst_raw != "-") else (syslog_attrs.get("DstIp") or "")

        # Fallback IP extraction across raw_fields
        if (not src_ip or src_ip == "-") and fallback_src_col is not None and fallback_src_col < len(row):
            cand = str(row[fallback_src_col]).strip()
            if _is_ip(cand):
                src_ip = cand
        if (not dst_ip or dst_ip == "-") and fallback_dst_col is not None and fallback_dst_col < len(row):
            cand = str(row[fallback_dst_col]).strip()
            if _is_ip(cand):
                dst_ip = cand

        # 6. Action & Category
        action = get_val("action") or syslog_attrs.get("Action") or ""
        if (not action or action == "-") and fallback_action_col is not None and fallback_action_col < len(row):
            action = str(row[fallback_action_col]).strip()
        if not action:
            for v in raw_fields.values():
                v_lower = v.strip().lower()
                if v_lower in ("block", "blocked", "discard", "drop", "alert", "allow", "permit", "deny", "reject", "pass"):
                    action = v
                    break

        category = get_val("category") or syslog_attrs.get("Category") or raw_fields.get("Attack Name") or ""
        if not category:
            for k, v in raw_fields.items():
                k_norm = _normalise_header(k)
                if any(w in k_norm for w in ("attack", "category", "classification", "type", "threat")):
                    category = v
                    break

        # 7. Protocol, Ports and Service Extraction
        proto_raw = (
            get_val("protocol")
            or syslog_attrs.get("Proto")
            or syslog_attrs.get("Protocol")
            or syslog_attrs.get("trans_proto")
            or raw_fields.get("Transmission Protocol")
            or raw_fields.get("Protocol")
            or ""
        )
        if not proto_raw and "Protocols=" in msg_val:
            match_proto = re.search(r"\bProtocols?\s*=\s*\[([^\]]+)\]", msg_val, re.IGNORECASE)
            if match_proto:
                proto_raw = match_proto.group(1)
        if not proto_raw:
            for k, v in raw_fields.items():
                k_norm = _normalise_header(k)
                if any(w in k_norm for w in ("proto", "transport", "network proto", "app proto")):
                    proto_raw = v
                    break
        if not proto_raw:
            for v in raw_fields.values():
                v_clean = v.strip().upper()
                if v_clean in ("UDP", "TCP", "ICMP", "GRE", "ESP", "OSPF", "IPV6"):
                    proto_raw = v_clean
                    break
        protocol = _protocol_label(proto_raw) or proto_raw

        src_port = (
            get_val("src_port")
            or syslog_attrs.get("SrcPort")
            or syslog_attrs.get("SPort")
            or syslog_attrs.get("sport")
            or stream_sport
            or raw_fields.get("Source Port")
            or ""
        )
        dst_port = (
            get_val("dst_port")
            or syslog_attrs.get("DstPort")
            or syslog_attrs.get("DPort")
            or syslog_attrs.get("dport")
            or stream_dport
            or raw_fields.get("Destination Port")
            or ""
        )
        if not dst_port and "Ports=" in msg_val:
            match_ports = re.search(r"\bPorts?\s*=\s*\[([^\]]+)\]", msg_val, re.IGNORECASE)
            if match_ports:
                port_list = [p.strip() for p in match_ports.group(1).split(",") if p.strip()]
                if port_list:
                    dst_port = port_list[0]
        if not src_port or src_port == "-":
            for k, v in raw_fields.items():
                k_norm = _normalise_header(k)
                if any(w in k_norm for w in ("sport", "source port", "src port", "client port", "client pt", "src pt", "source pt", "s port", "s pt")) and v.isdigit():
                    src_port = v
                    break
        if not dst_port or dst_port == "-":
            for k, v in raw_fields.items():
                k_norm = _normalise_header(k)
                if any(w in k_norm for w in ("dport", "dest port", "dst port", "target port", "server port", "destination port", "server pt", "dst pt", "target pt", "d port", "d pt")) and v.isdigit():
                    dst_port = v
                    break
        
        service_name = _port_service_label(dst_port) or _port_service_label(src_port)

        # 8. Event Time Extraction with Fallbacks
        event_time = get_val("event_time")
        if not event_time or event_time == "-":
            for k, v in raw_fields.items():
                k_norm = _normalise_header(k)
                if any(w in k_norm for w in ("time", "date", "timestamp", "start", "created", "recv", "occur", "log time")) and v not in ("-", "none"):
                    event_time = v
                    break
        if not event_time or event_time == "-":
            for v in raw_fields.values():
                if re.search(r"\b\d{1,4}[-/]\d{1,2}[-/]\d{1,4}\b|\b\d{1,2}:\d{1,2}(?::\d{1,2})?\b", v):
                    event_time = v
                    break

        # 9. Forensic Description & Threat Signature Formatting
        sign_name = syslog_attrs.get("SignName") or ""
        attack_type = syslog_attrs.get("AttackType") or ""
        attack_col = raw_fields.get("Attack Name") or raw_fields.get("Signature Name") or raw_fields.get("Threat Name") or ""
        ref_cve = syslog_attrs.get("Reference") or ""
        total_packets = syslog_attrs.get("total packets") or ""
        
        if sign_name:
            desc = sign_name
            if ref_cve and ref_cve not in {"NA", "N/A", "-"}:
                desc += f" (مرجع: {ref_cve})"
        elif attack_type:
            desc = f"هجوم {attack_type}"
            if total_packets:
                try:
                    desc += f" ({int(total_packets):,} حزمة)"
                except ValueError:
                    desc += f" ({total_packets} حزمة)"
        elif msg_val and msg_val not in ("-", "none", "NA", "N/A", "حدث أمني صادر من النظام"):
            desc = msg_val
        elif get_val("description") and get_val("description") not in ("-", "none", "NA", "N/A", "حدث أمني صادر من النظام"):
            desc = get_val("description")
        elif attack_col and attack_col not in {"-", "none", "NA", "N/A"}:
            desc = attack_col
        else:
            desc = ""

        if not desc:
            for k, v in raw_fields.items():
                k_norm = _normalise_header(k)
                if any(w in k_norm for w in ("attack", "signature", "threat", "message", "description", "event name", "alert name", "activity", "details")) and v not in ("-", "none", "NA", "N/A", "حدث أمني صادر من النظام"):
                    desc = v
                    break

        preferred_desc = _meaningful_description(eid, desc, device, event_source)
        final_desc = _generic_description(raw_fields, preferred_desc)

        # 10. Structured Forensic Arabic translation
        desc_ar, act_ar, threat_family = _forensic_threat_explanation(
            preferred_desc or final_desc or desc, eid, action, raw_fields
        )

        evt = NormalizedEvent(
            event_time=event_time,
            event_id=eid,
            priority=priority,
            event_source=event_source,
            device=device,
            user_account=user_account,
            src_ip=src_ip,
            description=final_desc,
            status=get_val("status"),
            action=action,
            category=category,
            destination=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            service_name=service_name,
            description_ar=desc_ar,
            action_ar=act_ar,
            threat_family=threat_family,
            report_family=family,
            record_count=_positive_int(get_val("count")),
            raw_fields=raw_fields,
        )
        
        # Build extracted IPs
        if evt.src_ip and _is_ip(evt.src_ip):
            evt.extracted_ips.add(evt.src_ip)
        if evt.destination and _is_ip(evt.destination):
            evt.extracted_ips.add(evt.destination)
        if evt.device and _is_ip(evt.device):
            evt.extracted_ips.add(evt.device)
        for ip in stream_ips:
            evt.extracted_ips.add(ip)
        
        # Parse all remaining IPs from raw fields and message for enrichment
        if msg_val and ("." in msg_val or ":" in msg_val):
            for ip in _extract_ips(msg_val):
                evt.extracted_ips.add(ip)
        for value in raw_fields.values():
            if ("." in value or ":" in value) and len(value) < 200:
                for ip in _extract_ips(value):
                    evt.extracted_ips.add(ip)

        yield evt

        if progress_callback and (row_index == total_rows or row_index % 100 == 0):
            progress_callback(row_index, total_rows)


def score_event_risk(event: NormalizedEvent) -> int:
    """Calculate the base risk of a log event based on Event IDs, Attack Signatures, and Forensics."""
    score = 0
    eid = str(event.event_id).strip()
    desc_lower = f"{event.description} {event.description_ar}".lower()

    # High-Risk Windows & Directory Event IDs
    if eid in {"1102", "104"}:  # The audit log was cleared (Anti-forensics)
        score = max(score, 90)
    elif eid in {"4728", "4732", "4756"}:  # User added to privileged group
        score = max(score, 75)
    elif eid == "4625":  # Failed Logon
        if any(code in desc_lower for code in ("0xc0000064", "user does not exist", "اسم المستخدم غير موجود")):
            score = max(score, 65)  # Username enumeration
        elif any(code in desc_lower for code in ("0xc0000234", "locked out", "مقفل")):
            score = max(score, 70)  # Account locked out
        else:
            score = max(score, 45)
    elif eid == "4740":  # Account locked out
        score = max(score, 65)
    elif eid in {"4697", "7045", "4698", "4702"}:  # New service / Scheduled task (Persistence)
        score = max(score, 60)
    elif eid in {"4769", "4771"}:  # Kerberos pre-auth failure / TGS request
        score = max(score, 60)
    elif eid == "4720":  # User account created
        score = max(score, 40)
    elif eid == "4672":  # Special privileges assigned to new logon
        score = max(score, 30)
    elif eid == "4624":  # Successful Logon
        if "type 10" in desc_lower or "remote desktop" in desc_lower:
            score = max(score, 25)
        else:
            score = max(score, 5)
    elif eid:
        score += 10  # Generic Event ID matched

    # Threat Signatures & Critical Forensic Patterns via classified threat_family
    tf = event.threat_family
    if any(w in tf for w in ("فدية", "Ransomware", "Inhibit Recovery", "ذاكرة LSASS")):
        score = max(score, 95)
    elif any(w in tf for w in ("WebShell", "RCE", "Log4Shell", "ثغرة Log4Shell")):
        score = max(score, 90)
    elif "حقن SQL" in tf:
        score = max(score, 85)
    elif any(w in tf for w in ("Expiro", "Tiggre", "فيروس", "حصان طروادة", "Worm", "دودة")):
        score = max(score, 80)
    elif any(w in tf for w in ("CoinMiner", "تعدين")):
        score = max(score, 80)
    elif any(w in tf for w in ("C2", "بوتنت", "Botnet", "DNS Tunnel")):
        score = max(score, 85)
    elif any(w in tf for w in ("مستحيل جغرافياً", "رش كلمات", "BEC Forwarding", "OAuth")):
        score = max(score, 85)
    elif any(w in tf for w in ("XSS", "برمجة نصية", "مسار", "Directory Traversal")):
        score = max(score, 75)
    elif any(w in tf for w in ("ثغرة", "CVE Exploit")):
        score = max(score, 80)
    elif any(w in tf for w in ("قواعد البيانات", "Drop Table")):
        score = max(score, 80)
    elif any(w in tf for w in ("تخمين", "Brute Force", "SSH Failed")):
        score = max(score, 65)
    elif any(w in tf for w in ("مسح المنافذ", "Port Scan")):
        score = max(score, 60)
    elif any(w in tf for w in ("حجب خدمة", "DoS", "DDoS", "Flood", "ICMP Flood")):
        score = max(score, 75)
    elif any(w in tf for w in ("انتحال", "IP Spoof")):
        score = max(score, 70)
    elif "استطلاع" in tf or "Reconnaissance" in tf:
        score = max(score, 55)
    else:
        # Fallback to description check only if threat_family is unclassified
        desc_sample = (event.description or "").lower()
        if any(w in desc_sample for w in ("ransomware", "فدية")):
            score = max(score, 95)
        elif any(w in desc_sample for w in ("mimikatz", "lsass")):
            score = max(score, 95)
        elif any(w in desc_sample for w in ("webshell", "rce", "log4j")):
            score = max(score, 90)
        elif any(w in desc_sample for w in ("sql injection", "sqli")):
            score = max(score, 85)
        elif any(w in desc_sample for w in ("virus", "trojan", "malware")):
            score = max(score, 80)
        elif any(w in desc_sample for w in ("cve-", "vulnerability")):
            score = max(score, 80)
        elif any(w in desc_sample for w in ("brute force", "brute-force")):
            score = max(score, 65)
        elif any(w in desc_sample for w in ("port scan", "portscan")):
            score = max(score, 60)
        elif any(w in desc_sample for w in ("flood", "ddos")):
            score = max(score, 75)

    # Priority weighting
    p = str(event.priority).upper()
    if p in {"CRITICAL", "FATAL"}:
        score = max(score + 20, 85)
    elif p in {"HIGH", "ERROR"}:
        score = max(score + 15, 70)
    elif p in {"WARNING", "WARN", "MEDIUM"}:
        score = max(score + 5, 40)

    # Disposition / Action Impact
    act = (event.action or "").strip().lower()
    if act in {"allow", "allowed", "permit", "permitted", "pass", "passed"} and score >= 60:
        score = min(score + 15, 100)
    elif act in {"alert", "alerted"} and score >= 50:
        score = min(score + 10, 100)
    elif act in {"block", "blocked", "drop", "dropped", "deny", "denied", "quarantine", "quarantined"} and score > 40:
        score = max(score - 10, 35)

    return min(max(score, 0), 100)


def calculate_risk(events: Iterable[NormalizedEvent], total_events: int = 0, progress_callback=None, correlation_engine=None) -> Iterable[NormalizedEvent]:
    """Score the risk of each event, evaluate decoupled confidence, and identify temporal attack chains."""
    try:
        from .correlation import CorrelationEngine
        from .risk_engine import RiskEngine
        from .detectors import DetectorRegistry
        from .detectors.windows import WindowsDetector
        from .detectors.linux import LinuxDetector
        from .detectors.network import NetworkDetector
        from .detectors.web import WebDetector
        from .detectors.cloud import CloudDetector
        from .detectors.database import DatabaseDetector
        from .detectors.edr import EDRDetector
    except ImportError:
        from correlation import CorrelationEngine
        from risk_engine import RiskEngine
        from detectors import DetectorRegistry
        from detectors.windows import WindowsDetector
        from detectors.linux import LinuxDetector
        from detectors.network import NetworkDetector
        from detectors.web import WebDetector
        from detectors.cloud import CloudDetector
        from detectors.database import DatabaseDetector
        from detectors.edr import EDRDetector

    detectors = DetectorRegistry()
    detectors.register(WindowsDetector())
    detectors.register(LinuxDetector())
    detectors.register(NetworkDetector())
    detectors.register(WebDetector())
    detectors.register(CloudDetector())
    detectors.register(DatabaseDetector())
    detectors.register(EDRDetector())

    try:
        from platform_core.detection_engine import DeclarativeRulesDetector, get_detection_engine
        from platform_core.detection_correlation import get_detection_correlation_layer
        declarative_engine = get_detection_engine()
        declarative_corr = get_detection_correlation_layer()
        detectors.register(DeclarativeRulesDetector(declarative_engine))
    except Exception:
        declarative_engine = None
        declarative_corr = None

    try:
        from platform_core.threat_intel import ThreatIntelDetector
        detectors.register(ThreatIntelDetector())
    except Exception:
        pass

    corr = correlation_engine if correlation_engine is not None else CorrelationEngine()
    risk_eng = RiskEngine()

    for event_index, evt in enumerate(events, 1):
        findings = detectors.run_all(evt)
        if findings:
            evt.findings.extend(findings)
            for f in findings:
                if f.detection_id not in evt.detection_ids:
                    evt.detection_ids.append(f.detection_id)
                for t in f.mitre_tactics:
                    if t not in evt.mitre_tactics:
                        evt.mitre_tactics.append(t)
                for te in f.mitre_techniques:
                    if te not in evt.mitre_techniques:
                        evt.mitre_techniques.append(te)
                if f.threat_family and not evt.threat_family:
                    evt.threat_family = f.threat_family
                if f.title_ar and not evt.description_ar:
                    evt.description_ar = f.title_ar

                if declarative_engine and declarative_corr:
                    rule = declarative_engine.get_rule(f.detection_id)
                    if rule:
                        try:
                            declarative_corr.process_detection(f, evt, rule.to_dict())
                        except Exception:
                            pass

        corr.process_event(evt)
        # Ensure base risk is computed if not already evaluated
        if not evt.risk_score:
            evt.risk_score = score_event_risk(evt)
        risk_eng.evaluate(evt)

        yield evt

        if progress_callback and (event_index == total_events or event_index % 100 == 0 or total_events == 0):
            progress_callback(event_index, total_events)


def analyze_ads_data(data: ParsedData, sink=None, progress_callback=None) -> dict[str, Any]:
    """Perform a complete analysis on SIEM Log events."""
    try:
        from .source_detector import SourceDetector
    except ImportError:
        from source_detector import SourceDetector

    total_rows = getattr(data, "total_rows", 0) or (len(data.rows) if hasattr(data.rows, "__len__") else 0)

    # 1. Source Detection with Audit Evidence
    sample_rows = []
    iterator = iter(data.rows)
    for _ in range(25):
        try:
            sample_rows.append(next(iterator))
        except StopIteration:
            break

    source_detector = SourceDetector()
    source_res = source_detector.detect(data.headers, sample_rows)

    def reassembled_rows():
        for r in sample_rows:
            yield r
        for r in iterator:
            yield r

    data.rows = reassembled_rows()

    def report_range(start: int, end: int, stage: str):
        def report(processed: int, total: int) -> None:
            effective_total = total if total > 0 else total_rows
            if effective_total > 0:
                ratio = min(max(processed / effective_total, 0.0), 1.0)
                prog = start + round((end - start) * ratio)
            else:
                prog = start
            if progress_callback:
                progress_callback(prog, stage, processed, effective_total)
        return report

    try:
        from .correlation import CorrelationEngine
    except ImportError:
        from correlation import CorrelationEngine

    corr = CorrelationEngine()
    events = normalize_events(data, None)
    scored_events = calculate_risk(events, total_rows, report_range(20, 95, "تحليل السجلات وترابط الأحداث وكشف التهديدات"), correlation_engine=corr)
    
    # Generate statistics & forensic aggregations
    unique_ips = set()
    unique_accounts = set()
    unique_devices = set()
    event_ids_dist: dict[str, int] = {}
    critical = 0
    high = 0
    report_family = source_res.source_id or "custom"
    first_event = True
    record_count = 0
    test_records = []
    seen_incidents: set[str] = set()

    total_findings_count = 0
    total_detections_count = 0
    total_confidence_sum = 0
    detections_summary: dict[str, dict] = {}
    patterns_summary: dict[str, dict] = {}
    mitre_matrix: dict[str, dict] = {}
    entities_users: dict[str, dict] = {}
    entities_ips: dict[str, dict] = {}
    entities_devices: dict[str, dict] = {}

    for e in scored_events:
        if first_event:
            if not e.report_family or e.report_family == "events":
                e.report_family = report_family
            first_event = False
            
        record_count += 1
        conf_val = getattr(e, "confidence_score", 50)
        total_confidence_sum += conf_val

        if e.src_ip:
            unique_ips.add(e.src_ip)
        for ip in e.extracted_ips:
            unique_ips.add(ip)
        
        if e.user_account:
            unique_accounts.add(e.user_account)
        if e.device:
            unique_devices.add(e.device)
            
        eid_key = e.event_id or "UNKNOWN"
        event_ids_dist[eid_key] = event_ids_dist.get(eid_key, 0) + 1
        
        if e.severity == "حرج":
            critical += 1
        elif e.severity == "مرتفع":
            high += 1

        if getattr(e, "incident_id", None):
            seen_incidents.add(e.incident_id)

        # Forensic findings & detections
        f_list = getattr(e, "findings", []) or []
        if f_list:
            total_findings_count += len(f_list)
        d_ids = getattr(e, "detection_ids", []) or []
        if d_ids:
            total_detections_count += len(d_ids)
            for det_id in d_ids:
                if det_id not in detections_summary:
                    detections_summary[det_id] = {
                        "detection_id": det_id,
                        "title_ar": e.description_ar or det_id,
                        "severity": e.severity,
                        "count": 0,
                        "threat_family": e.threat_family or "تهديد أمني",
                        "mitre_tactics": list(e.mitre_tactics or []),
                        "mitre_techniques": list(e.mitre_techniques or []),
                    }
                detections_summary[det_id]["count"] += 1

        # Patterns
        tf = e.threat_family or "أحداث مراقبة"
        if tf not in patterns_summary:
            patterns_summary[tf] = {
                "pattern_name": tf,
                "events_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "severity": e.severity,
            }
        patterns_summary[tf]["events_count"] += 1
        if e.severity == "حرج":
            patterns_summary[tf]["critical_count"] += 1
        elif e.severity == "مرتفع":
            patterns_summary[tf]["high_count"] += 1

        # MITRE matrix
        for t in (e.mitre_techniques or []):
            if t not in mitre_matrix:
                tactic = (e.mitre_tactics[0] if e.mitre_tactics else "General")
                mitre_matrix[t] = {
                    "technique": t,
                    "tactic": tactic,
                    "count": 0,
                    "threat_family": tf,
                }
            mitre_matrix[t]["count"] += 1

        # Entity tracking
        if e.user_account and e.user_account not in {"-", "unknown", "N/A"}:
            u = e.user_account
            if u not in entities_users:
                entities_users[u] = {
                    "username": u,
                    "count": 0,
                    "critical": 0,
                    "high": 0,
                    "last_seen": e.event_time,
                }
            entities_users[u]["count"] += 1
            if e.severity == "حرج":
                entities_users[u]["critical"] += 1
            elif e.severity == "مرتفع":
                entities_users[u]["high"] += 1

        if e.src_ip and e.src_ip not in {"-", "unknown"}:
            ip = e.src_ip
            if ip not in entities_ips:
                entities_ips[ip] = {
                    "ip": ip,
                    "count": 0,
                    "critical": 0,
                    "high": 0,
                    "destinations": set(),
                    "ports": set(),
                }
            entities_ips[ip]["count"] += 1
            if e.severity == "حرج":
                entities_ips[ip]["critical"] += 1
            elif e.severity == "مرتفع":
                entities_ips[ip]["high"] += 1
            if e.destination and e.destination != "-":
                entities_ips[ip]["destinations"].add(e.destination)
            if e.dst_port:
                entities_ips[ip]["ports"].add(str(e.dst_port))

        if e.device and e.device not in {"-", "unknown"}:
            dev = e.device
            if dev not in entities_devices:
                entities_devices[dev] = {
                    "device": dev,
                    "count": 0,
                }
            entities_devices[dev]["count"] += 1
            
        record_dict = {
            "event_time": e.event_time,
            "event_id": e.event_id,
            "priority": e.priority,
            "event_source": e.event_source or source_res.source_label_ar,
            "device": e.device,
            "user_account": e.user_account,
            "src_ip": e.src_ip,
            "description": e.description,
            "status": e.status,
            "action": e.action,
            "category": e.category,
            "destination": e.destination,
            "protocol": e.protocol,
            "src_port": e.src_port,
            "dst_port": e.dst_port,
            "service_name": e.service_name,
            "description_ar": e.description_ar,
            "action_ar": e.action_ar,
            "threat_family": e.threat_family,
            "report_family": e.report_family,
            "record_count": e.record_count,
            "raw_fields": e.raw_fields,
            "risk_score": e.risk_score,
            "base_risk_score": e.risk_score,
            "confidence_score": conf_val,
            "severity": e.severity,
            "conclusion_level": str(getattr(e, "conclusion_level", "observed")),
            "incident_id": getattr(e, "incident_id", None),
            "detection_ids": getattr(e, "detection_ids", []),
            "mitre_tactics": getattr(e, "mitre_tactics", []),
            "mitre_techniques": getattr(e, "mitre_techniques", []),
            "extracted_ips": list(e.extracted_ips),
            "risk_explanation": e.risk_explanation.to_dict() if getattr(e, "risk_explanation", None) and hasattr(e.risk_explanation, "to_dict") else None,
        }
        
        if sink:
            sink.add(record_dict)
        else:
            test_records.append(record_dict)

    if sink:
        sink.finalize()
    if progress_callback:
        progress_callback(100, "اكتمل التحليل", record_count, record_count)

    incidents = [inc.to_dict() for inc in corr.get_all_incidents()]

    serialized_ips = []
    for item in sorted(entities_ips.values(), key=lambda x: x["count"], reverse=True)[:50]:
        serialized_ips.append({
            "ip": item["ip"],
            "count": item["count"],
            "critical": item["critical"],
            "high": item["high"],
            "destinations": list(item["destinations"])[:10],
            "ports": list(item["ports"])[:10],
        })

    return {
        "metadata": {
            "filename": data.filename,
            "data_type": "siem_logs",
            "row_count": record_count,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "report_family": report_family,
            "detected_source": source_res.source_id,
            "detected_source_label": source_res.source_label_ar,
            "source_confidence": source_res.confidence,
            "source_evidence": source_res.evidence,
            "analysis_mode": source_res.analysis_mode,
            "source_headers": [str(header) for header in data.headers],
            "recognized_fields": sorted(mapping for mapping in FIELD_ALIASES if _find_column(data.headers, FIELD_ALIASES[mapping]) is not None),
        },
        "summary": {
            "records": record_count,
            "unique_ips": len(unique_ips),
            "unique_accounts": len(unique_accounts),
            "unique_devices": len(unique_devices),
            "critical": critical,
            "high": high,
            "incidents_count": len(incidents),
            "detections_count": total_detections_count,
            "threat_findings_count": total_findings_count,
            "avg_confidence": round(total_confidence_sum / max(record_count, 1)),
        },
        "total_records": record_count,
        "unique_ips_count": len(unique_ips),
        "unique_accounts_count": len(unique_accounts),
        "unique_devices_count": len(unique_devices),
        "event_ids_distribution": event_ids_dist,
        "incidents": incidents,
        "detections_summary": list(detections_summary.values()),
        "patterns_summary": list(patterns_summary.values()),
        "mitre_matrix": list(mitre_matrix.values()),
        "entities_summary": {
            "top_users": sorted(entities_users.values(), key=lambda x: x["count"], reverse=True)[:50],
            "top_ips": serialized_ips,
            "top_devices": sorted(entities_devices.values(), key=lambda x: x["count"], reverse=True)[:50],
        },
        "records": test_records if not sink else [],
        "events": test_records if not sink else [],
        "all_extracted_ips": list(unique_ips)
    }
