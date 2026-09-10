"""Centralized permissions registry and catalog for the platform."""

from __future__ import annotations

import threading
from typing import Dict, List, Optional, Tuple

# Base feature permission definitions (Feature -> list of (code, label, action))
_CORE_PERMISSION_GROUPS: Dict[str, List[Tuple[str, str, str]]] = {
    "عام والبوابة": [
        ("portal.access", "الدخول إلى البوابة", "access"),
        ("history.view", "عرض سجل العمليات التاريخية", "view"),
    ],
    "سجلات المنصة والتدقيق": [
        ("platform_logs.view_own", "عرض سجلات المنصة الخاصة بنشاط المستخدم", "view_own"),
        ("platform_logs.view_shared", "عرض سجلات المنصة المشتركة مع المستخدم", "view_shared"),
        ("platform_logs.view_all", "عرض كافة سجلات المنصة والتدقيق للجميع", "view_all"),
        ("platform_logs.export", "تصدير سجلات المنصة والتدقيق", "export"),
    ],
    "إدارة المستخدمين والأدوار": [
        ("users.view", "عرض قائمة وتفاصيل المستخدمين", "view"),
        ("users.create", "إنشاء مستخدم جديد", "create"),
        ("users.update", "تعديل بيانات المستخدم وحالته", "update"),
        ("users.delete", "حذف المستخدمين", "delete"),
        ("users.manage_permissions", "إدارة وتعديل صلاحيات المستخدمين الخاصة", "manage"),
        ("users.manage", "الإدارة الشاملة للمستخدمين (توافق عكسي)", "manage"),
        ("roles.view", "عرض الأدوار ومصفوفة الصلاحيات", "view"),
        ("roles.manage", "إنشاء وتعديل وحذف واستنساخ الأدوار", "manage"),
        ("groups.view", "عرض مجموعات العمل والأعضاء", "view"),
        ("groups.manage", "إدارة وإنشاء وتعديل مجموعات العمل والأعضاء", "manage"),
        ("sharing.view", "عرض سجل الموارد المشتركة", "view"),
        ("sharing.manage", "مشاركة الموارد وإلغاء المشاركات", "manage"),
    ],
    "الحوادث الأمنية": [
        ("incidents.view", "عرض الحوادث وتفاصيلها ومؤشراتها", "view"),
        ("incidents.create", "إنشاء حوادث أمنية جديدة", "create"),
        ("incidents.update", "تحديث حالة الحادث والأولوية والتعيين", "update"),
        ("incidents.manage", "إدارة الحادث وإضافة الأدلة والملاحظات والترقية", "manage"),
        ("incidents.export", "تصدير ملفات التحقيق الجنائي الرقمي والتحقق من سلامتها", "export"),
        ("incidents.delete", "حذف الحوادث الأمنية", "delete"),
        ("copilot.query", "استخدام المساعد الأمني الذكي للتحقيق وتوليد التوصيات", "query"),
    ],
    "الأصول الأمنية": [
        ("assets.view", "عرض واستعراض سجل الأصول الأمنية ومقاييس الخطورة", "view"),
        ("assets.manage", "إضافة وتعديل وحذف واستيراد وتصدير الأصول", "manage"),
        ("assets.isolate", "تنفيذ واعتماد خطط العزل والاحتواء الأمني للأصول", "isolate"),
    ],
    "قواعد الكشف والأنماط": [
        ("detections.view", "عرض قواعد الكشف وتفاصيلها ومقاييس الأداء", "view"),
        ("detections.manage", "إنشاء وتعديل وتفعيل القواعد واختبارها واستيرادها وتصديرها", "manage"),
        ("sigma.view", "عرض قواعد Sigma وقوالب الكشف", "view"),
        ("sigma.manage", "تحويل واستيراد وتحديث وتفعيل قواعد Sigma", "manage"),
    ],
    "استخبارات التهديدات والترابط": [
        ("intel.view", "عرض قاعدة مؤشرات التهديد (IOCs) وتفاصيلها", "view"),
        ("intel.manage", "إضافة وتعديل وحذف واستيراد وتصدير مؤشرات التهديد", "manage"),
        ("correlation.view", "عرض شبكة الرسم البياني الأمني وسلاسل الهجوم والتنقل الأفقي", "view"),
        ("correlation.manage", "إجراء التحليل المتقدم للترابط وترقية الأنماط إلى حوادث", "manage"),
    ],
    "FlowScope": [
        ("flowscope.view", "عرض FlowScope ونتائجه", "view"),
        ("flowscope.analyze", "رفع ملفات التدفق وبدء التحليل", "analyze"),
        ("flowscope.enrich", "فحص مصادر السمعة وتحديث نتائج IP", "enrich"),
        ("flowscope.export", "معاينة تقارير التدفق وتصديرها (Word/Excel)", "export"),
        ("flowscope.feedback", "إضافة وتحديث تقييم المحلل للتدفقات", "feedback"),
        ("flowscope.delete", "حذف مهام تحليل التدفق", "delete"),
    ],
    "ThreatScope": [
        ("threatscope.view", "عرض ThreatScope ونتائجه", "view"),
        ("threatscope.analyze", "رفع ملفات البصمات وبدء التحليل", "analyze"),
        ("threatscope.enrich", "فحص مصادر السمعة وتحديث نتائج الهاش", "enrich"),
        ("threatscope.export", "معاينة تقارير التهديدات وتصديرها (Word/Excel)", "export"),
        ("threatscope.feedback", "إضافة وتحديث تقييم المحلل للبصمات", "feedback"),
        ("threatscope.delete", "حذف مهام تحليل التهديدات", "delete"),
    ],
    "LogScope": [
        ("logscope.view", "عرض LogScope وسجل الأحداث والكشوفات", "view"),
        ("logscope.analyze", "رفع ملفات السجلات وبدء التحليل الجنائي", "analyze"),
        ("logscope.enrich", "فحص وإثراء كيانات السجلات", "enrich"),
        ("logscope.export", "معاينة تقارير السجلات وتصديرها (Word/Excel)", "export"),
        ("logscope.feedback", "إضافة وتحديث تقييم المحلل للسجلات", "feedback"),
        ("logscope.delete", "حذف مهام تحليل السجلات", "delete"),
    ],
    "النظام والبنية التحتية": [
        ("system.status", "عرض حالة النظام وصحة الخدمات ومكونات التشغيل", "status"),
        ("database.status", "عرض حالة محركات قواعد البيانات والتخزين", "status"),
        ("enterprise.view", "عرض حالة العناقيد والمستأجرين وطوابير المهام", "view"),
        ("enterprise.manage", "إدارة المستأجرين والحصص وسياسات الأرشفة المؤسسية", "manage"),
    ],
}

_DYNAMIC_REGISTRY: Dict[str, Tuple[str, str, str]] = {}
_REGISTRY_LOCK = threading.RLock()


def register_permission(code: str, label: str, group: str = "مخصص", action: str = "manage") -> None:
    """Dynamically register a new permission into the central catalog."""
    with _REGISTRY_LOCK:
        code_str = str(code).strip()
        if not code_str:
            raise ValueError("Permission code cannot be empty.")
        _DYNAMIC_REGISTRY[code_str] = (label.strip(), group.strip(), action.strip())


def get_all_permissions() -> List[str]:
    """Return all valid permission codes across core and dynamic registries."""
    with _REGISTRY_LOCK:
        core_codes = [code for entries in _CORE_PERMISSION_GROUPS.values() for code, _, _ in entries]
        dynamic_codes = list(_DYNAMIC_REGISTRY.keys())
        # Preserve order while removing duplicates
        seen = set()
        out = []
        for code in core_codes + dynamic_codes:
            if code not in seen:
                seen.add(code)
                out.append(code)
        return out


def is_valid_permission(code: str) -> bool:
    """Check whether a permission code is valid in the platform."""
    return code in set(get_all_permissions())


def get_permission_catalog() -> Dict[str, List[Dict[str, str]]]:
    """Return formatted groups catalog for UI and API consumption."""
    with _REGISTRY_LOCK:
        result: Dict[str, List[Dict[str, str]]] = {}
        for group_name, entries in _CORE_PERMISSION_GROUPS.items():
            result[group_name] = [
                {"code": code, "label": label, "action": action}
                for code, label, action in entries
            ]
        # Append dynamic groups
        for code, (label, group_name, action) in _DYNAMIC_REGISTRY.items():
            if group_name not in result:
                result[group_name] = []
            if not any(item["code"] == code for item in result[group_name]):
                result[group_name].append({"code": code, "label": label, "action": action})
        return result

