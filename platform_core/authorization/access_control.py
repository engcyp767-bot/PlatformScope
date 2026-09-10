"""High-level Access Control facade, SecurityContext resolution, and enforcement."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from .permissions import get_all_permissions, is_valid_permission
from .policies import PolicyDecision, evaluate_policy
from .roles import get_builtin_roles
from .scopes import DataScope, SCOPE_HIERARCHY, normalize_scope
from .sharing import get_user_shares
from .storage import (
    get_group_by_id,
    get_role_by_id,
    get_user_group_ids,
    get_user_profile,
    init_authorization_db,
)


class AuthorizationError(PermissionError):
    """Raised when server-side access is denied by policy."""
    def __init__(self, message: str = "تم رفض الوصول.", code: str = "permission_denied"):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SecurityContext:
    user_id: str
    username: str
    display_name: str
    is_authenticated: bool
    is_active: bool
    role_id: str
    role_name: str
    role_label_ar: str
    data_scope: str
    department: str
    groups: List[str]
    custom_permissions: List[str]
    effective_permissions: Set[str] = field(default_factory=set)
    simulated_by: Optional[str] = None

    def has_permission(self, permission: str) -> bool:
        return permission in self.effective_permissions or "all" in self.effective_permissions

    def enforce(
        self,
        action: str,
        resource_type: Optional[str] = None,
        resource_data: Optional[Dict[str, Any]] = None,
        required_share_permission: str = "view",
    ) -> PolicyDecision:
        decision = evaluate_policy(
            self,
            action=action,
            resource_type=resource_type,
            resource_data=resource_data,
            required_share_permission=required_share_permission,
        )
        decision.raise_if_denied()
        return decision


_ANONYMOUS_CONTEXT = SecurityContext(
    user_id="",
    username="anonymous",
    display_name="غير مسجل",
    is_authenticated=False,
    is_active=False,
    role_id="none",
    role_name="none",
    role_label_ar="غير مسجل",
    data_scope=DataScope.OWN.value,
    department="",
    groups=[],
    custom_permissions=[],
    effective_permissions=set(),
)


def get_anonymous_context() -> SecurityContext:
    return _ANONYMOUS_CONTEXT


def build_security_context(user_dict: Optional[Dict[str, Any]], simulated_by: Optional[str] = None) -> SecurityContext:
    """Build a complete SecurityContext by resolving primary role, groups, and custom permissions."""
    if not user_dict or not user_dict.get("id"):
        return get_anonymous_context()

    init_authorization_db()
    user_id = str(user_dict["id"])
    username = str(user_dict["username"])
    display_name = str(user_dict.get("display_name") or username)
    is_active = bool(user_dict.get("active", True))

    # Check if this user had legacy 'users.manage' or is admin
    raw_user_perms = user_dict.get("permissions") or []
    has_legacy_admin = "users.manage" in raw_user_perms

    # Load stored profile
    profile = get_user_profile(user_id, is_admin=has_legacy_admin)
    role_id = profile["role_id"]
    assigned_scope = normalize_scope(profile["data_scope"])
    department = profile["department"]
    custom_permissions = profile.get("custom_permissions", [])

    # Load Role definition
    role = get_role_by_id(role_id)
    if not role:
        role = get_role_by_id("administrator" if has_legacy_admin else "analyst") or {}

    role_permissions = set(role.get("permissions", []))
    role_name = role.get("name", role_id)
    role_label = role.get("label_ar", role_id)

    # Load User Groups & Group Roles
    group_ids = get_user_group_ids(user_id)
    group_permissions: Set[str] = set()
    broadest_group_scope_level = 0
    broadest_group_scope = assigned_scope

    for gid in group_ids:
        grp = get_group_by_id(gid)
        if grp:
            for g_role_id in grp.get("roles", []):
                g_role = get_role_by_id(g_role_id)
                if g_role:
                    group_permissions.update(g_role.get("permissions", []))
            grp_scope = grp.get("default_scope")
            if grp_scope:
                lvl = SCOPE_HIERARCHY.get(grp_scope, 0)
                if lvl > broadest_group_scope_level:
                    broadest_group_scope_level = lvl
                    broadest_group_scope = grp_scope

    # If user has legacy explicit permissions, include them safely
    legacy_set = set(raw_user_perms)

    # Combine all permissions
    effective = set(role_permissions) | group_permissions | set(custom_permissions) | legacy_set

    # Administrators always have ALL permissions and ALL scope
    if role_id == "administrator" or "users.manage" in effective:
        effective.update(get_all_permissions())
        effective_scope = DataScope.ALL.value
    else:
        # Determine effective scope: max between assigned scope and group scope
        user_lvl = SCOPE_HIERARCHY.get(assigned_scope, 1)
        effective_scope = assigned_scope if user_lvl >= broadest_group_scope_level else broadest_group_scope

    return SecurityContext(
        user_id=user_id,
        username=username,
        display_name=display_name,
        is_authenticated=True,
        is_active=is_active,
        role_id=role_id,
        role_name=role_name,
        role_label_ar=role_label,
        data_scope=effective_scope,
        department=department,
        groups=group_ids,
        custom_permissions=custom_permissions,
        effective_permissions=effective,
        simulated_by=simulated_by,
    )


def get_security_context_from_headers(headers: Any) -> SecurityContext:
    """Extract identity from request headers and build the resolved SecurityContext."""
    from platform_core import security_auth
    identity = security_auth.request_identity(headers)
    return build_security_context(identity)


def filter_dataset(
    context: SecurityContext,
    items: List[Dict[str, Any]],
    resource_type: str,
    get_meta_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Filter a list of resource dictionaries using the user's SecurityContext and Deny by Default rules."""
    if context.data_scope == DataScope.ALL.value:
        return items

    filtered = []
    for item in items:
        meta = get_meta_fn(item) if get_meta_fn else item
        decision = evaluate_policy(context, action=f"{resource_type}.view", resource_type=resource_type, resource_data=meta)
        if decision.allowed:
            filtered.append(item)
    return filtered


def get_my_access_profile(context: SecurityContext) -> Dict[str, Any]:
    """Assemble the data profile for the 'صلاحياتي' (My Access Profile) screen."""
    if not context.is_authenticated:
        return {"authenticated": False}

    shared_resources = get_user_shares(context.user_id, context.groups)
    groups_detail = [get_group_by_id(gid) for gid in context.groups if get_group_by_id(gid)]

    return {
        "authenticated": True,
        "user_id": context.user_id,
        "username": context.username,
        "display_name": context.display_name,
        "role": {
            "id": context.role_id,
            "name": context.role_name,
            "label_ar": context.role_label_ar,
        },
        "data_scope": context.data_scope,
        "department": context.department,
        "groups": groups_detail,
        "custom_permissions": context.custom_permissions,
        "effective_permissions": sorted(list(context.effective_permissions)),
        "shared_resources_count": len(shared_resources),
        "shared_resources": shared_resources[:50],
        "simulated_by": context.simulated_by,
    }


def simulate_user_access(admin_context: SecurityContext, target_user_id: str) -> Dict[str, Any]:
    """Allow an administrator with 'users.manage' to simulate and view another user's effective access."""
    admin_context.enforce("users.manage")

    from platform_core import security_auth
    config = security_auth.load_config()
    target_user = None
    for u in config.get("users", []):
        if str(u.get("id")) == str(target_user_id) or str(u.get("username")).casefold() == str(target_user_id).casefold():
            target_user = security_auth._public_user(u)
            break

    if not target_user:
        raise LookupError("المستخدم المطلوب لمحاكاة صلاحياته غير موجود.")

    simulated_ctx = build_security_context(target_user, simulated_by=admin_context.username)
    return get_my_access_profile(simulated_ctx)

