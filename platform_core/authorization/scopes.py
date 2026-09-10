"""Data Scopes definition and scope boundary evaluation."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set


class DataScope(str, Enum):
    OWN = "own"
    OWN_SHARED = "own_shared"
    GROUP = "group"
    DEPARTMENT = "department"
    ORGANIZATION = "organization"
    ALL = "all"


SCOPE_LABELS = {
    DataScope.OWN.value: "خاص بي فقط (Own Only)",
    DataScope.OWN_SHARED.value: "الخاص بي والمشترك معي (Own + Shared)",
    DataScope.GROUP.value: "مجموعة العمل (Group)",
    DataScope.DEPARTMENT.value: "القسم التابع له (Department)",
    DataScope.ORGANIZATION.value: "كامل المؤسسة (Organization)",
    DataScope.ALL.value: "شامل لكافة البيانات (All)",
}

SCOPE_HIERARCHY = {
    DataScope.OWN.value: 1,
    DataScope.OWN_SHARED.value: 2,
    DataScope.GROUP.value: 3,
    DataScope.DEPARTMENT.value: 4,
    DataScope.ORGANIZATION.value: 5,
    DataScope.ALL.value: 6,
}


def is_valid_scope(value: str | None) -> bool:
    if not value:
        return False
    return str(value).lower() in {s.value for s in DataScope}


def normalize_scope(value: str | None, default: str = DataScope.OWN_SHARED.value) -> str:
    if not value:
        return default
    val_str = str(value).strip().lower()
    return val_str if is_valid_scope(val_str) else default


def get_available_scopes() -> List[Dict[str, str]]:
    """Return all available data scopes with Arabic/English labels."""
    return [
        {"scope": s.value, "label": SCOPE_LABELS[s.value], "level": SCOPE_HIERARCHY[s.value]}
        for s in DataScope
    ]


def scope_allows_resource(
    user_scope: str,
    user_id: str,
    username: str = "",
    user_groups: Optional[List[str] | Set[str]] = None,
    user_department: Optional[str] = None,
    resource_owner_id: str | None = None,
    resource_creator: str | None = None,
    resource_assignee: str | None = None,
    resource_group_id: str | None = None,
    resource_department: str | None = None,
    is_shared_with_user: bool = False,
) -> bool:
    """Evaluate whether a resource matches the user's data scope boundaries."""
    scope = normalize_scope(user_scope)

    # 1. 'ALL' scope grants visibility across all records
    if scope == DataScope.ALL.value:
        return True

    # Check direct ownership / authorship / assignment
    is_owner = False
    if resource_owner_id and str(resource_owner_id) == str(user_id):
        is_owner = True
    elif resource_creator and str(resource_creator).casefold() == str(username).casefold():
        is_owner = True
    elif resource_assignee and str(resource_assignee).casefold() == str(username).casefold():
        is_owner = True

    if is_owner:
        return True

    # 2. 'OWN' only allows records directly owned by or assigned to the user
    if scope == DataScope.OWN.value:
        return False

    # 3. 'OWN_SHARED' permits owned records plus explicitly shared items
    if is_shared_with_user:
        return True

    if scope == DataScope.OWN_SHARED.value:
        return False

    # 4. 'GROUP' permits records belonging to the user's workgroups
    user_groups_set = set(user_groups or [])
    if resource_group_id and str(resource_group_id) in user_groups_set:
        return True

    if scope == DataScope.GROUP.value:
        return False

    # 5. 'DEPARTMENT' permits records belonging to the same department
    if (
        user_department
        and resource_department
        and str(user_department).casefold() == str(resource_department).casefold()
    ):
        return True

    if scope == DataScope.DEPARTMENT.value:
        return False

    # 6. 'ORGANIZATION'
    if scope == DataScope.ORGANIZATION.value:
        return True

    return False
