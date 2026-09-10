"""Forensic Knowledge Base: High-value security event explanations, MITRE ATT&CK taxonomy, and SOC guidance in Arabic."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ForensicKnowledgeItem:
    """A rich knowledge base entry for a high-value forensic event or threat pattern."""
    event_id: str
    name_ar: str
    description_ar: str
    category_ar: str
    why_it_matters: str
    investigation_guidance: str
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    base_severity: int = 50


# High-value Forensic Event Catalog
FORENSIC_KB_CATALOG: dict[str, ForensicKnowledgeItem] = {
    # 1. Windows Authentication & Logons
    "4624": ForensicKnowledgeItem(
        event_id="4624",
        name_ar="تسجيل دخول ناجح إلى النظام",
        description_ar="تم توثيق دخول حساب مستخدم أو نظام إلى محطة العمل أو الخادم بنجاح.",
        category_ar="المصادقة وتسجيل الدخول (Authentication)",
        why_it_matters="يحدد وقت بدء نشاط المستخدم ونمط تسجيل الدخول (محلي، شبكي، RDP) ويفيد في كشف الحسابات المسروقة.",
        investigation_guidance="تحقق من حقل LogonType ومصدر الاتصال (Source IP) ووقت الدخول مقارنة بأوقات العمل الرسمية.",
        mitre_tactics=["Initial Access", "الوصول الأولي"],
        mitre_techniques=["T1078 - Valid Accounts"],
        base_severity=20,
    ),
    "4625": ForensicKnowledgeItem(
        event_id="4625",
        name_ar="فشل تسجيل الدخول",
        description_ar="فشلت محاولة تسجيل الدخول بسبب بيانات اعتماد غير صالحة أو قيود في الحساب.",
        category_ar="المصادقة وتسجيل الدخول (Authentication)",
        why_it_matters="المؤشر الأبرز لهجمات تخمين كلمات المرور (Brute-force) وهجمات رش كلمات المرور (Password Spraying).",
        investigation_guidance="حلل كود SubStatus لمعرفة سبب الفشل، وراقب تكرار الحدث من نفس العنوان IP أو ضد عدة مستخدمين.",
        mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
        mitre_techniques=["T1110 - Brute Force"],
        base_severity=45,
    ),
    "4648": ForensicKnowledgeItem(
        event_id="4648",
        name_ar="محاولة تسجيل الدخول باستخدام بيانات اعتماد صريحة",
        description_ar="قام تطبيق أو عملية بطلب تسجيل دخول باستخدام اسم مستخدم وكلمة مرور محددة (مثل أمر runas).",
        category_ar="المصادقة وتسجيل الدخول (Authentication)",
        why_it_matters="قد يشير إلى محاولة المهاجم استخدام بيانات اعتماد تم الاستيلاء عليها للتحرك الجانبي داخل الشبكة.",
        investigation_guidance="افحص اسم البرنامج المستدعي (Process Name) واسم الحساب المستهدف.",
        mitre_tactics=["Lateral Movement", "التحرك الجانبي"],
        mitre_techniques=["T1078 - Valid Accounts"],
        base_severity=50,
    ),
    "4672": ForensicKnowledgeItem(
        event_id="4672",
        name_ar="منح صلاحيات سيادية خاصة للمستخدم الجديد",
        description_ar="تم منح جلسة المستخدم صلاحيات إدارية عليا (مثل SeDebugPrivilege أو صلاحيات مسؤولي النطاق).",
        category_ar="إدارة الصلاحيات (Privilege Management)",
        why_it_matters="يؤكد بدء جلسة ذات صلاحيات عالية، ومراقبتها حيوية لمنع إساءة استخدام الصلاحيات الإدارية.",
        investigation_guidance="تأكد من أن الحساب مخصص لمسؤول معتمد ومصرح له بالعمل في هذا التوقيت.",
        mitre_tactics=["Privilege Escalation", "تصعيد الصلاحيات"],
        mitre_techniques=["T1078.002 - Domain Accounts"],
        base_severity=55,
    ),

    # 2. Defense Evasion & System Integrity
    "1102": ForensicKnowledgeItem(
        event_id="1102",
        name_ar="مسح وتفريغ سجل التدقيق الأمني",
        description_ar="قام أحد المستخدمين بحذف كافة أحداث سجل الأمان الأمني في خادم ويندوز.",
        category_ar="إخفاء الأثر والتمويه (Defense Evasion)",
        why_it_matters="سلوك شديد الخطورة يعتمده المهاجمون في المرحلة الأخيرة من الهجوم لمسح الأدلة الجنائية.",
        investigation_guidance="حدد فوراً الحساب المنفذ (Subject User) وعنوان المحطة وافحص السجلات السابقة لواقعة المسح.",
        mitre_tactics=["Defense Evasion", "إخفاء الأثر والتمويه"],
        mitre_techniques=["T1070.001 - Clear Windows Event Logs"],
        base_severity=95,
    ),
    "104": ForensicKnowledgeItem(
        event_id="104",
        name_ar="مسح سجل أحداث النظام",
        description_ar="تم تفريغ وحذف سجل أحداث النظام (System Log) في ويندوز.",
        category_ar="إخفاء الأثر والتمويه (Defense Evasion)",
        why_it_matters="محاولة إخفاء تثبيت الخدمات الخبيثة أو تعديل تعريفات النظام.",
        investigation_guidance="افحص التوقيت والحساب المسؤول عن الحذف وافحص العمليات المشغلة حينها.",
        mitre_tactics=["Defense Evasion", "إخفاء الأثر والتمويه"],
        mitre_techniques=["T1070.001 - Clear Windows Event Logs"],
        base_severity=90,
    ),

    # 3. Execution & Persistence
    "4688": ForensicKnowledgeItem(
        event_id="4688",
        name_ar="إنشاء عملية جديدة في النظام",
        description_ar="تم تشغيل برنامج أو ملف تنفيذي جديد كعملية فرعية أو رئيسية.",
        category_ar="تنفيذ الأوامر (Execution)",
        why_it_matters="الأساس في كشف هجمات تشغيل الأوامر الخبيثة وأسطر PowerShell وCMD والمحملات الجنائية.",
        investigation_guidance="دقق في حقل CommandLine والعملية الأب (ParentProcessName) ومسار الملف المنفذ.",
        mitre_tactics=["Execution", "تنفيذ الأوامر"],
        mitre_techniques=["T1059 - Command and Scripting Interpreter"],
        base_severity=50,
    ),
    "7045": ForensicKnowledgeItem(
        event_id="7045",
        name_ar="تثبيت خدمة نظام جديدة",
        description_ar="تمت إضافة وتثبيت خدمة جديدة في نظام تشغيل ويندوز.",
        category_ar="التواجد الدائم (Persistence)",
        why_it_matters="تكتيك رئيسي لتثبيت التواجد المستمر (Persistence) والتحرك الجانبي (مثل أدوات PsExec).",
        investigation_guidance="افحص مسار الملف التنفيذي للخدمة (ImagePath) واسم الخدمة والحساب المولد لها.",
        mitre_tactics=["Persistence", "التواجد الدائم والمستمر"],
        mitre_techniques=["T1543.003 - Windows Service"],
        base_severity=70,
    ),

    # 4. Active Directory Account Management
    "4720": ForensicKnowledgeItem(
        event_id="4720",
        name_ar="إنشاء حساب مستخدم جديد",
        description_ar="تم إنشاء حساب مستخدم جديد في الدليل النشط أو محطة العمل المحلية.",
        category_ar="إدارة الحسابات (Account Management)",
        why_it_matters="قد يمثل حساباً خلفياً (Backdoor Account) ينشئه المهاجم للحفاظ على إمكانية الوصول.",
        investigation_guidance="تحقق من طلب التغيير الإداري المعتمد ومنشئ الحساب والصلاحيات الممنوحة له.",
        mitre_tactics=["Persistence", "التواجد الدائم والمستمر"],
        mitre_techniques=["T1136.001 - Local Account", "T1136.002 - Domain Account"],
        base_severity=60,
    ),
    "4728": ForensicKnowledgeItem(
        event_id="4728",
        name_ar="إضافة مستخدم إلى مجموعة أمان عامة",
        description_ar="تمت إضافة حساب إلى مجموعة أمان حساسة في الدليل النشط.",
        category_ar="تصعيد الصلاحيات (Privilege Escalation)",
        why_it_matters="يستخدم لترقية مستخدم عادي ليصبح عضواً في Domain Admins أو Enterprise Admins.",
        investigation_guidance="تأكد من اسم المجموعة المستهدفة واسم العضو المضاف والحساب المنفذ للإضافة.",
        mitre_tactics=["Privilege Escalation", "تصعيد الصلاحيات"],
        mitre_techniques=["T1098 - Account Manipulation"],
        base_severity=75,
    ),
    "4740": ForensicKnowledgeItem(
        event_id="4740",
        name_ar="إغلاق حساب المستخدم لتكرار محاولات الدخول الفاشلة",
        description_ar="تم قفل حساب المستخدم إثر تجاوز عتبة محاولات المصادقة غير الصحيحة.",
        category_ar="التحكم في الوصول (Access Control)",
        why_it_matters="دليل قوي على استهداف الحساب بمحاولات تخمين مكثفة أو هجوم حجب خدمة على الهوية.",
        investigation_guidance="افحص اسم المحطة التي أرسلت المحاولات وتوقيتات الفشل المرتبطة بـ 4625.",
        mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
        mitre_techniques=["T1110 - Brute Force"],
        base_severity=65,
    ),

    # 5. Kerberos Attacks
    "4768": ForensicKnowledgeItem(
        event_id="4768",
        name_ar="طلب تذكرة Kerberos TGT",
        description_ar="تم إصدار تذكرة منح التذاكر (TGT) بواسطة مركز توزيع المفاتيح KDC.",
        category_ar="مصادقة كيربيروس (Kerberos Authentication)",
        why_it_matters="أولى خطوات مصادقة المستخدم في نطاق ويندوز وتفيد في تتبع مصدر الدخول.",
        investigation_guidance="راقب طلبات TGT ذات التشفير الضعيف (RC4) أو الواردة من خارج النطاق.",
        mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
        mitre_techniques=["T1558 - Steal or Forge Kerberos Tickets"],
        base_severity=30,
    ),
    "4769": ForensicKnowledgeItem(
        event_id="4769",
        name_ar="طلب تذكرة خدمة Kerberos Service Ticket",
        description_ar="طلب مستخدم تذكرة للوصول إلى خدمة معينة (SPN) في النطاق.",
        category_ar="مصادقة كيربيروس (Kerberos Authentication)",
        why_it_matters="المؤشر الرئيسي لهجمات Kerberoasting لاستخراج تجزئات كلمات مرور حسابات الخدمات.",
        investigation_guidance="تحقق من استخدام تشفير 0x17 (RC4-HMAC) وطلبات الخدمة المتعددة في وقت قصير.",
        mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
        mitre_techniques=["T1558.003 - Kerberoasting"],
        base_severity=70,
    ),
    "4771": ForensicKnowledgeItem(
        event_id="4771",
        name_ar="فشل المصادقة المسبقة لكيربيروس",
        description_ar="فشل المستخدم في تقديم مفتاح المصادقة المسبقة الصحيح إلى خادم KDC.",
        category_ar="مصادقة كيربيروس (Kerberos Authentication)",
        why_it_matters="مؤشر على هجمات AS-REP Roasting أو تجربة كلمات مرور خاطئة في النطاق.",
        investigation_guidance="افحص كود الخطأ (0x18 تعني كلمة مرور غير صحيحة) وعنوان IP المصدري.",
        mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
        mitre_techniques=["T1558.004 - AS-REP Roasting"],
        base_severity=55,
    ),

    # 6. PowerShell ScriptBlock Logging
    "4104": ForensicKnowledgeItem(
        event_id="4104",
        name_ar="تنفيذ كتلة برمجية عبر باورشيل (ScriptBlock Logging)",
        description_ar="قام محرك باورشيل بتسجيل النص البرمجي الكامل للكتلة المنفذة.",
        category_ar="تنفيذ الأوامر والبرمجة (Execution)",
        why_it_matters="أقوى سجل جنائي لكشف هجمات البرمجيات الخبيثة وتنزيل المحملات والملفات في الذاكرة.",
        investigation_guidance="ابحث في نص الكتلة البرمجية عن دوال التحميل المباشر وتشفير Base64.",
        mitre_tactics=["Execution", "تنفيذ الأوامر"],
        mitre_techniques=["T1059.001 - PowerShell"],
        base_severity=60,
    ),
}


class ForensicKnowledgeBase:
    """Provides querying and enrichment for high-value forensic items."""

    def __init__(self):
        self._catalog = FORENSIC_KB_CATALOG

    def get_by_event_id(self, event_id: str) -> ForensicKnowledgeItem | None:
        clean_id = str(event_id or "").strip()
        return self._catalog.get(clean_id)

    def count(self) -> int:
        return len(self._catalog)
