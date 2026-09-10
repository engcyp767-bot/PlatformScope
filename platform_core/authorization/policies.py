"""Central Policy Engine implementing Deny by Default RBAC + ABAC evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from .scopes import DataScope, scope_allows_resource
from .sharing import is_shared_with


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    code: str  # 'allowed', 'unauthenticated', 'account_disabled', 'permission_denied', 'scope_violation'

    def raise_if_denied(self) -> None:
        if not self.allowed:
            from .access_control import AuthorizationError
            raise AuthorizationError(self.reason, code=self.code)


def evaluate_policy(
    context: Any,
    action: str,
    resource_type: Optional[str] = None,
    resource_data: Optional[Dict[str, Any]] = None,
    required_share_permission: str = "view",
) -> PolicyDecision:
    """Evaluate access for an action against a resource using Deny by Default."""
    # 1. Authentication check
    if not context or not getattr(context, "is_authenticated", False):
        return PolicyDecision(
            allowed=False,
            reason="المصادقة مطلوبة للوصول إلى هذا المورد أو تنفيذ هذا الإجراء.",
            code="unauthenticated",
        )

    # 2. Account active check
    if not getattr(context, "is_active", True):
        return PolicyDecision(
            allowed=False,
            reason="تم تعطيل حساب المستخدم. يرجى مراجعة مسؤول المنصة.",
            code="account_disabled",
        )

    # 3. Server-side Permission Check
    effective_permissions: Set[str] = getattr(context, "effective_permissions", set())
    if action not in effective_permissions and "all" not in effective_permissions:
        return PolicyDecision(
            allowed=False,
            reason=f"ليست لديك الصلاحية المطلوبة ({action}) لتنفيذ هذا الإجراء.",
            code="permission_denied",
        )

    # 4. Data Scope & Resource Sharing Check (if resource is provided)
    if resource_data is not None and resource_type is not None:
        user_scope = getattr(context, "data_scope", DataScope.OWN_SHARED.value)

        # Full visibility bypass for ALL scope
        if user_scope == DataScope.ALL.value:
            return PolicyDecision(allowed=True, reason="مصرح له بنطاق شامل لكافة البيانات.", code="allowed")

        user_id = getattr(context, "user_id", "")
        username = getattr(context, "username", "")
        groups = getattr(context, "groups", [])
        department = getattr(context, "department", None)

        res_id = str(resource_data.get("id") or resource_data.get("job_id") or "")
        res_owner = resource_data.get("owner_id")
        res_creator = resource_data.get("created_by") or resource_data.get("author")
        res_assignee = resource_data.get("assigned_to")
        res_group = resource_data.get("group_id")
        res_dept = resource_data.get("department")

        # Check resource sharing
        shared = False
        if res_id:
            shared = is_shared_with(
                resource_type=resource_type,
                resource_id=res_id,
                user_id=user_id,
                group_ids=groups,
                required_permission=required_share_permission,
            )

        allowed_by_scope = scope_allows_resource(
            user_scope=user_scope,
            user_id=user_id,
            username=username,
            user_groups=groups,
            user_department=department,
            resource_owner_id=res_owner,
            resource_creator=res_creator,
            resource_assignee=res_assignee,
            resource_group_id=res_group,
            resource_department=res_dept,
            is_shared_with_user=shared,
        )

        if not allowed_by_scope:
            return PolicyDecision(
                allowed=False,
                reason="المورد خارج نطاق البيانات المسموح لك بالاطلاع عليه أو تعديله.",
                code="scope_violation",
            )

    return PolicyDecision(
        allowed=True,
        reason="مصرح له بالوصول.",
        code="allowed",
    )

