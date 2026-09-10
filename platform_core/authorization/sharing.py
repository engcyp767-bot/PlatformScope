"""Resource sharing management and validation layer."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from .storage import (
    share_resource as _storage_share,
    revoke_resource_share as _storage_revoke,
    get_shares_for_resource as _storage_get_shares,
    get_resources_shared_with_user as _storage_get_user_shares,
    check_resource_shared as _storage_check_shared,
)

VALID_RESOURCE_TYPES = {
    "logs",
    "incidents",
    "assets",
    "reports",
    "investigations",
    "cases",
    "dashboards",
    "detection_rules",
    "sigma_rules",
}

VALID_SHARE_PERMISSIONS = {"view", "comment", "edit", "export"}


def share(
    resource_type: str,
    resource_id: str,
    shared_by: str,
    grantee_type: str,
    grantee_id: str,
    permissions: Optional[List[str]] = None,
    expires_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Share a platform resource with a target user or workgroup."""
    res_type = str(resource_type).strip().lower()
    res_id = str(resource_id).strip()
    g_type = str(grantee_type).strip().lower()
    g_id = str(grantee_id).strip()

    if res_type not in VALID_RESOURCE_TYPES:
        raise ValueError(f"نوع المورد '{res_type}' غير مدعوم للمشاركة.")
    if g_type not in ("user", "group"):
        raise ValueError("نوع الجهة المشتركة يجب أن يكون 'user' أو 'group'.")
    if not res_id or not g_id:
        raise ValueError("معرف المورد ومعرف الجهة المشتركة مطلوبان.")

    clean_perms = [p for p in (permissions or ["view"]) if p in VALID_SHARE_PERMISSIONS]
    if not clean_perms:
        clean_perms = ["view"]

    return _storage_share(
        resource_type=res_type,
        resource_id=res_id,
        shared_by=shared_by,
        grantee_type=g_type,
        grantee_id=g_id,
        permissions=clean_perms,
        expires_at=expires_at,
    )


def revoke(share_id: str) -> None:
    """Revoke a previously granted resource share."""
    _storage_revoke(share_id)


def get_shares(resource_type: str, resource_id: str) -> List[Dict[str, Any]]:
    """Retrieve all active shares for a given resource."""
    return _storage_get_shares(str(resource_type).strip().lower(), str(resource_id).strip())


def get_user_shares(user_id: str, group_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Retrieve all resources shared directly with a user or through their groups."""
    return _storage_get_user_shares(user_id, group_ids)


def is_shared_with(
    resource_type: str,
    resource_id: str,
    user_id: str,
    group_ids: Optional[List[str]] = None,
    required_permission: str = "view",
) -> bool:
    """Check whether a user has access to a resource via sharing."""
    return _storage_check_shared(
        resource_type=str(resource_type).strip().lower(),
        resource_id=str(resource_id).strip(),
        user_id=user_id,
        group_ids=group_ids,
        required_permission=required_permission,
    )

