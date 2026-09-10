"""Built-in roles and custom role models and operations."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from .permissions import get_all_permissions
from .scopes import DataScope

_NOW = lambda: datetime.now(timezone.utc).isoformat()

# Definition of Built-in Roles
BUILTIN_ROLES: Dict[str, Dict[str, Any]] = {
    "viewer": {
        "id": "viewer",
        "name": "viewer",
        "label_ar": "مشاهد (Viewer)",
        "description": "صلاحيات استعراض وقراءة النتائج والحوادث والأصول دون تعديل أو رفع أو حذف.",
        "default_scope": DataScope.OWN_SHARED.value,
        "is_builtin": True,
        "permissions": [
            "portal.access",
            "history.view",
            "platform_logs.view_own",
            "incidents.view",
            "detections.view",
            "sigma.view",
            "intel.view",
            "assets.view",
            "correlation.view",
            "flowscope.view",
            "flowscope.export",
            "threatscope.view",
            "threatscope.export",
            "logscope.view",
            "logscope.export",
        ],
    },
    "analyst": {
        "id": "analyst",
        "name": "analyst",
        "label_ar": "محلل (Analyst)",
        "description": "رفع ملفات التحليل، تشغيل الإثراء الجنائي، تسجيل الملاحظات، إنشاء الحوادث، واستعلام المساعد الذكي.",
        "default_scope": DataScope.OWN_SHARED.value,
        "is_builtin": True,
        "permissions": [
            "portal.access",
            "history.view",
            "platform_logs.view_own",
            "platform_logs.view_shared",
            "incidents.view",
            "incidents.create",
            "copilot.query",
            "detections.view",
            "sigma.view",
            "intel.view",
            "assets.view",
            "correlation.view",
            "flowscope.view",
            "flowscope.analyze",
            "flowscope.enrich",
            "flowscope.export",
            "flowscope.feedback",
            "threatscope.view",
            "threatscope.analyze",
            "threatscope.enrich",
            "threatscope.export",
            "threatscope.feedback",
            "logscope.view",
            "logscope.analyze",
            "logscope.enrich",
            "logscope.export",
            "logscope.feedback",
        ],
    },
    "security_analyst": {
        "id": "security_analyst",
        "name": "security_analyst",
        "label_ar": "محلل أمني (Security Analyst)",
        "description": "إدارة دورة حياة الحوادث الأمنية، الترابط المتقدم، تصدير ملفات التحقيق الجنائي الرقمي، وإدارة مؤشرات التهديد.",
        "default_scope": DataScope.GROUP.value,
        "is_builtin": True,
        "permissions": [
            "portal.access",
            "history.view",
            "platform_logs.view_own",
            "platform_logs.view_shared",
            "incidents.view",
            "incidents.create",
            "incidents.update",
            "incidents.manage",
            "incidents.export",
            "copilot.query",
            "detections.view",
            "detections.manage",
            "sigma.view",
            "sigma.manage",
            "intel.view",
            "intel.manage",
            "assets.view",
            "correlation.view",
            "correlation.manage",
            "flowscope.view",
            "flowscope.analyze",
            "flowscope.enrich",
            "flowscope.export",
            "flowscope.feedback",
            "threatscope.view",
            "threatscope.analyze",
            "threatscope.enrich",
            "threatscope.export",
            "threatscope.feedback",
            "logscope.view",
            "logscope.analyze",
            "logscope.enrich",
            "logscope.export",
            "logscope.feedback",
        ],
    },
    "operator": {
        "id": "operator",
        "name": "operator",
        "label_ar": "مشغل المنصة (Operator)",
        "description": "مراقبة صحة المنصة، حالة قواعد البيانات، فحص كافة سجلات التشغيل، وإدارة المهام التنفيذية.",
        "default_scope": DataScope.GROUP.value,
        "is_builtin": True,
        "permissions": [
            "portal.access",
            "history.view",
            "platform_logs.view_own",
            "platform_logs.view_shared",
            "platform_logs.view_all",
            "platform_logs.export",
            "system.status",
            "database.status",
            "incidents.view",
            "detections.view",
            "intel.view",
            "assets.view",
            "flowscope.view",
            "threatscope.view",
            "logscope.view",
        ],
    },
    "supervisor": {
        "id": "supervisor",
        "name": "supervisor",
        "label_ar": "مشرف أمني (Supervisor)",
        "description": "صلاحيات إشرافية شاملة لحذف الحوادث، اعتماد عزل الأصول، إدارة المشاركات، والاطلاع على المجموعات.",
        "default_scope": DataScope.DEPARTMENT.value,
        "is_builtin": True,
        "permissions": [
            "portal.access",
            "history.view",
            "platform_logs.view_own",
            "platform_logs.view_shared",
            "platform_logs.view_all",
            "platform_logs.export",
            "system.status",
            "database.status",
            "incidents.view",
            "incidents.create",
            "incidents.update",
            "incidents.manage",
            "incidents.export",
            "incidents.delete",
            "copilot.query",
            "assets.view",
            "assets.manage",
            "assets.isolate",
            "detections.view",
            "detections.manage",
            "sigma.view",
            "sigma.manage",
            "intel.view",
            "intel.manage",
            "correlation.view",
            "correlation.manage",
            "sharing.view",
            "sharing.manage",
            "groups.view",
            "flowscope.view",
            "flowscope.analyze",
            "flowscope.enrich",
            "flowscope.export",
            "flowscope.feedback",
            "flowscope.delete",
            "threatscope.view",
            "threatscope.analyze",
            "threatscope.enrich",
            "threatscope.export",
            "threatscope.feedback",
            "threatscope.delete",
            "logscope.view",
            "logscope.analyze",
            "logscope.enrich",
            "logscope.export",
            "logscope.feedback",
            "logscope.delete",
        ],
    },
    "administrator": {
        "id": "administrator",
        "name": "administrator",
        "label_ar": "مدير النظام (Administrator)",
        "description": "صلاحيات سيادية كاملة لإدارة المستخدمين، الأدوار، المجموعات، السياسات، وكافة محركات المنصة.",
        "default_scope": DataScope.ALL.value,
        "is_builtin": True,
        "permissions": [],  # Will be dynamically populated with all permissions
    },
}

# Populate administrator permissions with all available permissions
BUILTIN_ROLES["administrator"]["permissions"] = get_all_permissions()


def get_builtin_roles() -> Dict[str, Dict[str, Any]]:
    """Return copies of built-in roles with current permissions catalog."""
    roles = {}
    all_perms = get_all_permissions()
    for role_id, data in BUILTIN_ROLES.items():
        copy = dict(data)
        if role_id == "administrator":
            copy["permissions"] = list(all_perms)
        roles[role_id] = copy
    return roles


def is_builtin_role(role_id: str) -> bool:
    return str(role_id).lower() in BUILTIN_ROLES


def validate_role_permissions(permissions: List[str]) -> List[str]:
    valid_set = set(get_all_permissions())
    return [p for p in permissions if p in valid_set]

