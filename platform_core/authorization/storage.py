"""SQLite storage engine and in-memory cache for authorization, roles, groups, and shares."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .roles import BUILTIN_ROLES, get_builtin_roles, is_builtin_role, validate_role_permissions
from .scopes import DataScope, normalize_scope

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = ROOT_DIR / "storage"
DB_PATH = STORAGE_DIR / "authorization.sqlite3"

_LOCK = threading.RLock()
_PROFILE_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_VERSION = 0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def db_session():
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_authorization_db() -> None:
    """Initialize database tables and seed default workgroups."""
    with _LOCK, db_session() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS custom_roles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            label_ar TEXT NOT NULL,
            description TEXT,
            default_scope TEXT DEFAULT 'own_shared',
            permissions TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS groups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            label_ar TEXT NOT NULL,
            description TEXT,
            roles TEXT NOT NULL DEFAULT '[]',
            default_scope TEXT DEFAULT 'group',
            department TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS group_members (
            group_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            added_at TEXT NOT NULL,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id TEXT PRIMARY KEY,
            role_id TEXT NOT NULL DEFAULT 'analyst',
            data_scope TEXT DEFAULT 'own_shared',
            department TEXT,
            custom_permissions TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS resource_shares (
            id TEXT PRIMARY KEY,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            shared_by TEXT NOT NULL,
            grantee_type TEXT NOT NULL,
            grantee_id TEXT NOT NULL,
            permissions TEXT NOT NULL DEFAULT '["view"]',
            expires_at TEXT,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_shares_resource ON resource_shares(resource_type, resource_id);
        CREATE INDEX IF NOT EXISTS idx_shares_grantee ON resource_shares(grantee_type, grantee_id);
        CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);
        """)

        # Pre-seed standard enterprise workgroups if none exist
        cursor = conn.execute("SELECT COUNT(*) as count FROM groups")
        if cursor.fetchone()["count"] == 0:
            now = _now()
            default_groups = [
                ("soc_team", "soc_team", "فريق مركز العمليات (SOC Team)", "الفريق الأمني المباشر المسؤول عن مراقبة الحوادث والتحقيق الجنائي الرقمي", '["security_analyst"]', "group", "الأمن السيبراني"),
                ("security_team", "security_team", "فريق أمن المعلومات (Security Team)", "فريق التحليل الأمني وإدارة المخاطر والامتثال", '["analyst"]', "department", "الأمن السيبراني"),
                ("it_team", "it_team", "فريق تقنية المعلومات والشبكات (IT Team)", "فريق تشغيل وإدارة البنية التحتية والأنظمة والخوادم", '["operator"]', "group", "تقنية المعلومات"),
                ("management", "management", "الإدارة والقيادة التنفيذية (Management)", "إدارة المنصة والقيادة التنفيذية للاطلاع الشامل والتقارير", '["supervisor"]', "organization", "الإدارة العليا"),
            ]
            conn.executemany("""
            INSERT INTO groups (id, name, label_ar, description, roles, default_scope, department, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [(g[0], g[1], g[2], g[3], g[4], g[5], g[6], now, now) for g in default_groups])


def invalidate_cache() -> None:
    global _CACHE_VERSION
    with _LOCK:
        _PROFILE_CACHE.clear()
        _CACHE_VERSION += 1


# ----------------------------------------------------------------------
# Roles Store
# ----------------------------------------------------------------------

def get_role_by_id(role_id: str) -> Optional[Dict[str, Any]]:
    role_id_clean = str(role_id).strip().lower()
    # Check built-in roles first
    builtin = get_builtin_roles()
    if role_id_clean in builtin:
        return builtin[role_id_clean]

    init_authorization_db()
    with _LOCK, db_session() as conn:
        row = conn.execute("SELECT * FROM custom_roles WHERE id = ?", (role_id,)).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "name": row["name"],
            "label_ar": row["label_ar"],
            "description": row["description"] or "",
            "default_scope": row["default_scope"] or DataScope.OWN_SHARED.value,
            "permissions": json.loads(row["permissions"] or "[]"),
            "is_builtin": False,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }


def list_all_roles() -> List[Dict[str, Any]]:
    """Return all roles (built-in followed by custom roles)."""
    roles: List[Dict[str, Any]] = list(get_builtin_roles().values())
    init_authorization_db()
    with _LOCK, db_session() as conn:
        for row in conn.execute("SELECT * FROM custom_roles ORDER BY created_at ASC"):
            roles.append({
                "id": row["id"],
                "name": row["name"],
                "label_ar": row["label_ar"],
                "description": row["description"] or "",
                "default_scope": row["default_scope"] or DataScope.OWN_SHARED.value,
                "permissions": json.loads(row["permissions"] or "[]"),
                "is_builtin": False,
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            })
    return roles


def create_custom_role(
    name: str,
    label_ar: str,
    description: str = "",
    permissions: Optional[List[str]] = None,
    default_scope: str = DataScope.OWN_SHARED.value,
) -> Dict[str, Any]:
    name_clean = str(name).strip().lower().replace(" ", "_")
    if not name_clean:
        raise ValueError("اسم الدور مطلوب.")
    if is_builtin_role(name_clean):
        raise ValueError("لا يمكن استخدام اسم مطابق لأحد الأدوار القياسية.")

    init_authorization_db()
    role_id = f"custom_{uuid.uuid4().hex[:8]}"
    now = _now()
    validated_perms = validate_role_permissions(permissions or [])
    norm_scope = normalize_scope(default_scope)

    with _LOCK, db_session() as conn:
        existing = conn.execute("SELECT id FROM custom_roles WHERE name = ?", (name_clean,)).fetchone()
        if existing:
            raise ValueError(f"الدور '{name_clean}' موجود بالفعل.")

        conn.execute("""
        INSERT INTO custom_roles (id, name, label_ar, description, default_scope, permissions, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (role_id, name_clean, label_ar.strip(), description.strip(), norm_scope, json.dumps(validated_perms), now, now))

    invalidate_cache()
    return get_role_by_id(role_id)  # type: ignore


def update_custom_role(
    role_id: str,
    label_ar: Optional[str] = None,
    description: Optional[str] = None,
    permissions: Optional[List[str]] = None,
    default_scope: Optional[str] = None,
) -> Dict[str, Any]:
    if is_builtin_role(role_id):
        raise ValueError("لا يمكن تعديل الأدوار القياسية المدمجة.")

    init_authorization_db()
    with _LOCK, db_session() as conn:
        row = conn.execute("SELECT * FROM custom_roles WHERE id = ?", (role_id,)).fetchone()
        if not row:
            raise LookupError("الدور غير موجود.")

        updates = []
        params = []
        if label_ar is not None:
            updates.append("label_ar = ?")
            params.append(label_ar.strip())
        if description is not None:
            updates.append("description = ?")
            params.append(description.strip())
        if permissions is not None:
            updates.append("permissions = ?")
            params.append(json.dumps(validate_role_permissions(permissions)))
        if default_scope is not None:
            updates.append("default_scope = ?")
            params.append(normalize_scope(default_scope))

        if updates:
            updates.append("updated_at = ?")
            params.append(_now())
            params.append(role_id)
            conn.execute(f"UPDATE custom_roles SET {', '.join(updates)} WHERE id = ?", params)

    invalidate_cache()
    return get_role_by_id(role_id)  # type: ignore


def delete_custom_role(role_id: str) -> None:
    if is_builtin_role(role_id):
        raise ValueError("لا يمكن حذف الأدوار القياسية المدمجة.")

    init_authorization_db()
    with _LOCK, db_session() as conn:
        # Check if any user profile is using this role
        in_use = conn.execute("SELECT COUNT(*) as count FROM user_profiles WHERE role_id = ?", (role_id,)).fetchone()
        if in_use and in_use["count"] > 0:
            raise ValueError(f"لا يمكن حذف الدور لأنه مرتبط بـ {in_use['count']} مستخدم. قم بتغيير دور المستخدمين أولاً.")

        conn.execute("DELETE FROM custom_roles WHERE id = ?", (role_id,))

    invalidate_cache()


def clone_role(source_role_id: str, new_name: str, new_label_ar: str, description: str = "") -> Dict[str, Any]:
    source = get_role_by_id(source_role_id)
    if not source:
        raise LookupError(f"الدور المصدر '{source_role_id}' غير موجود.")

    return create_custom_role(
        name=new_name,
        label_ar=new_label_ar,
        description=description or f"نسخة مستنسخة من دور {source.get('label_ar', source_role_id)}",
        permissions=list(source.get("permissions", [])),
        default_scope=source.get("default_scope", DataScope.OWN_SHARED.value),
    )


# ----------------------------------------------------------------------
# Groups Store
# ----------------------------------------------------------------------

def list_all_groups() -> List[Dict[str, Any]]:
    init_authorization_db()
    with _LOCK, db_session() as conn:
        groups = []
        for row in conn.execute("SELECT * FROM groups ORDER BY created_at ASC"):
            gid = row["id"]
            members = [r["user_id"] for r in conn.execute("SELECT user_id FROM group_members WHERE group_id = ?", (gid,))]
            groups.append({
                "id": row["id"],
                "name": row["name"],
                "label_ar": row["label_ar"],
                "description": row["description"] or "",
                "roles": json.loads(row["roles"] or "[]"),
                "default_scope": row["default_scope"] or DataScope.GROUP.value,
                "department": row["department"] or "",
                "members": members,
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            })
        return groups


def get_group_by_id(group_id: str) -> Optional[Dict[str, Any]]:
    init_authorization_db()
    with _LOCK, db_session() as conn:
        row = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
        if not row:
            return None
        members = [r["user_id"] for r in conn.execute("SELECT user_id FROM group_members WHERE group_id = ?", (group_id,))]
        return {
            "id": row["id"],
            "name": row["name"],
            "label_ar": row["label_ar"],
            "description": row["description"] or "",
            "roles": json.loads(row["roles"] or "[]"),
            "default_scope": row["default_scope"] or DataScope.GROUP.value,
            "department": row["department"] or "",
            "members": members,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }


def create_group(
    name: str,
    label_ar: str,
    description: str = "",
    roles: Optional[List[str]] = None,
    default_scope: str = DataScope.GROUP.value,
    department: str = "",
    members: Optional[List[str]] = None,
) -> Dict[str, Any]:
    name_clean = str(name).strip().lower().replace(" ", "_")
    if not name_clean:
        raise ValueError("اسم المجموعة مطلوب.")

    init_authorization_db()
    gid = f"grp_{uuid.uuid4().hex[:8]}"
    now = _now()
    roles_list = roles or []

    with _LOCK, db_session() as conn:
        existing = conn.execute("SELECT id FROM groups WHERE name = ?", (name_clean,)).fetchone()
        if existing:
            raise ValueError(f"المجموعة '{name_clean}' موجودة بالفعل.")

        conn.execute("""
        INSERT INTO groups (id, name, label_ar, description, roles, default_scope, department, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (gid, name_clean, label_ar.strip(), description.strip(), json.dumps(roles_list), normalize_scope(default_scope, DataScope.GROUP.value), department.strip(), now, now))

        if members:
            for uid in set(members):
                conn.execute("INSERT OR IGNORE INTO group_members (group_id, user_id, added_at) VALUES (?, ?, ?)", (gid, uid, now))

    invalidate_cache()
    return get_group_by_id(gid)  # type: ignore


def update_group(
    group_id: str,
    label_ar: Optional[str] = None,
    description: Optional[str] = None,
    roles: Optional[List[str]] = None,
    default_scope: Optional[str] = None,
    department: Optional[str] = None,
    members: Optional[List[str]] = None,
) -> Dict[str, Any]:
    init_authorization_db()
    with _LOCK, db_session() as conn:
        row = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
        if not row:
            raise LookupError("المجموعة غير موجودة.")

        updates = []
        params = []
        if label_ar is not None:
            updates.append("label_ar = ?")
            params.append(label_ar.strip())
        if description is not None:
            updates.append("description = ?")
            params.append(description.strip())
        if roles is not None:
            updates.append("roles = ?")
            params.append(json.dumps(roles))
        if default_scope is not None:
            updates.append("default_scope = ?")
            params.append(normalize_scope(default_scope, DataScope.GROUP.value))
        if department is not None:
            updates.append("department = ?")
            params.append(department.strip())

        if updates:
            updates.append("updated_at = ?")
            params.append(_now())
            params.append(group_id)
            conn.execute(f"UPDATE groups SET {', '.join(updates)} WHERE id = ?", params)

        if members is not None:
            conn.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
            now = _now()
            for uid in set(members):
                conn.execute("INSERT INTO group_members (group_id, user_id, added_at) VALUES (?, ?, ?)", (group_id, uid, now))

    invalidate_cache()
    return get_group_by_id(group_id)  # type: ignore


def delete_group(group_id: str) -> None:
    init_authorization_db()
    with _LOCK, db_session() as conn:
        conn.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
        conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))

    invalidate_cache()


def get_user_group_ids(user_id: str) -> List[str]:
    init_authorization_db()
    with _LOCK, db_session() as conn:
        rows = conn.execute("SELECT group_id FROM group_members WHERE user_id = ?", (user_id,)).fetchall()
        return [r["group_id"] for r in rows]


# ----------------------------------------------------------------------
# User Profile Store (Role, Scope, Department, Custom Permissions)
# ----------------------------------------------------------------------

def get_user_profile(user_id: str, is_admin: bool = False) -> Dict[str, Any]:
    init_authorization_db()
    with _LOCK, db_session() as conn:
        row = conn.execute("SELECT * FROM user_profiles WHERE user_id = ?", (user_id,)).fetchone()
        if not row:
            # Fallback default profile
            role_id = "administrator" if is_admin else "analyst"
            scope = DataScope.ALL.value if is_admin else DataScope.OWN_SHARED.value
            return {
                "user_id": user_id,
                "role_id": role_id,
                "data_scope": scope,
                "department": "مركز العمليات الأمنية" if not is_admin else "الإدارة",
                "custom_permissions": [],
            }
        return {
            "user_id": row["user_id"],
            "role_id": row["role_id"],
            "data_scope": row["data_scope"],
            "department": row["department"] or "",
            "custom_permissions": json.loads(row["custom_permissions"] or "[]"),
        }


def save_user_profile(
    user_id: str,
    role_id: Optional[str] = None,
    data_scope: Optional[str] = None,
    department: Optional[str] = None,
    custom_permissions: Optional[List[str]] = None,
    group_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    init_authorization_db()
    now = _now()
    with _LOCK, db_session() as conn:
        existing = conn.execute("SELECT * FROM user_profiles WHERE user_id = ?", (user_id,)).fetchone()
        cur_role = existing["role_id"] if existing else "analyst"
        cur_scope = existing["data_scope"] if existing else DataScope.OWN_SHARED.value
        cur_dept = existing["department"] if existing else ""
        cur_custom = json.loads(existing["custom_permissions"]) if existing else []

        new_role = role_id if role_id is not None else cur_role
        new_scope = normalize_scope(data_scope if data_scope is not None else cur_scope)
        new_dept = department.strip() if department is not None else cur_dept
        new_custom = validate_role_permissions(custom_permissions) if custom_permissions is not None else cur_custom

        if existing:
            conn.execute("""
            UPDATE user_profiles
            SET role_id = ?, data_scope = ?, department = ?, custom_permissions = ?, updated_at = ?
            WHERE user_id = ?
            """, (new_role, new_scope, new_dept, json.dumps(new_custom), now, user_id))
        else:
            conn.execute("""
            INSERT INTO user_profiles (user_id, role_id, data_scope, department, custom_permissions, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, new_role, new_scope, new_dept, json.dumps(new_custom), now, now))

        # Update groups membership if provided
        if group_ids is not None:
            conn.execute("DELETE FROM group_members WHERE user_id = ?", (user_id,))
            for gid in set(group_ids):
                conn.execute("INSERT OR IGNORE INTO group_members (group_id, user_id, added_at) VALUES (?, ?, ?)", (gid, user_id, now))

    invalidate_cache()
    return get_user_profile(user_id)


# ----------------------------------------------------------------------
# Resource Sharing Store
# ----------------------------------------------------------------------

def share_resource(
    resource_type: str,
    resource_id: str,
    shared_by: str,
    grantee_type: str,
    grantee_id: str,
    permissions: Optional[List[str]] = None,
    expires_at: Optional[str] = None,
) -> Dict[str, Any]:
    init_authorization_db()
    share_id = f"shr_{uuid.uuid4().hex[:8]}"
    now = _now()
    perms = permissions or ["view"]

    with _LOCK, db_session() as conn:
        # Check if already shared with this grantee
        existing = conn.execute("""
        SELECT id FROM resource_shares
        WHERE resource_type = ? AND resource_id = ? AND grantee_type = ? AND grantee_id = ?
        """, (resource_type, resource_id, grantee_type, grantee_id)).fetchone()

        if existing:
            conn.execute("""
            UPDATE resource_shares
            SET permissions = ?, expires_at = ?
            WHERE id = ?
            """, (json.dumps(perms), expires_at, existing["id"]))
            share_id = existing["id"]
        else:
            conn.execute("""
            INSERT INTO resource_shares (id, resource_type, resource_id, shared_by, grantee_type, grantee_id, permissions, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (share_id, resource_type, resource_id, shared_by, grantee_type, grantee_id, json.dumps(perms), expires_at, now))

    invalidate_cache()
    return {
        "id": share_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "shared_by": shared_by,
        "grantee_type": grantee_type,
        "grantee_id": grantee_id,
        "permissions": perms,
        "expires_at": expires_at,
        "created_at": now,
    }


def revoke_resource_share(share_id: str) -> None:
    init_authorization_db()
    with _LOCK, db_session() as conn:
        conn.execute("DELETE FROM resource_shares WHERE id = ?", (share_id,))
    invalidate_cache()


def _is_expired(expires_at: Optional[str]) -> bool:
    if not expires_at:
        return False
    try:
        dt = datetime.fromisoformat(expires_at)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > dt
    except Exception:
        return False


def get_shares_for_resource(resource_type: str, resource_id: str) -> List[Dict[str, Any]]:
    init_authorization_db()
    with _LOCK, db_session() as conn:
        rows = conn.execute("""
        SELECT * FROM resource_shares
        WHERE resource_type = ? AND resource_id = ?
        ORDER BY created_at DESC
        """, (resource_type, resource_id)).fetchall()
        shares = []
        for r in rows:
            if _is_expired(r["expires_at"]):
                continue
            shares.append({
                "id": r["id"],
                "resource_type": r["resource_type"],
                "resource_id": r["resource_id"],
                "shared_by": r["shared_by"],
                "grantee_type": r["grantee_type"],
                "grantee_id": r["grantee_id"],
                "permissions": json.loads(r["permissions"] or "[]"),
                "expires_at": r["expires_at"],
                "created_at": r["created_at"],
            })
        return shares


def get_resources_shared_with_user(user_id: str, group_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    init_authorization_db()
    gids = group_ids or get_user_group_ids(user_id)
    with _LOCK, db_session() as conn:
        placeholders = ",".join("?" for _ in gids) if gids else "''"
        query = f"""
        SELECT * FROM resource_shares
        WHERE (grantee_type = 'user' AND grantee_id = ?)
           OR (grantee_type = 'group' AND grantee_id IN ({placeholders}))
        ORDER BY created_at DESC
        """
        params = [user_id] + list(gids)
        rows = conn.execute(query, params).fetchall()
        shares = []
        for r in rows:
            if _is_expired(r["expires_at"]):
                continue
            shares.append({
                "id": r["id"],
                "resource_type": r["resource_type"],
                "resource_id": r["resource_id"],
                "shared_by": r["shared_by"],
                "grantee_type": r["grantee_type"],
                "grantee_id": r["grantee_id"],
                "permissions": json.loads(r["permissions"] or "[]"),
                "expires_at": r["expires_at"],
                "created_at": r["created_at"],
            })
        return shares


def check_resource_shared(
    resource_type: str,
    resource_id: str,
    user_id: str,
    group_ids: Optional[List[str]] = None,
    required_permission: str = "view",
) -> bool:
    shares = get_resources_shared_with_user(user_id, group_ids)
    for s in shares:
        if s["resource_type"] == resource_type and s["resource_id"] == resource_id:
            perms = s.get("permissions", [])
            if required_permission in perms or "all" in perms or "manage" in perms:
                return True
    return False

