"""Multi-user authentication and permission management for the platform."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTH_FILE = ROOT / "storage" / "security_auth.json"
COOKIE_NAME = "security_session"
SESSION_SECONDS = max(900, int(os.environ.get("SECURITY_SESSION_HOURS", "12")) * 3600)
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "Admin@123"

PERMISSION_GROUPS = {
    "عام": (("portal.access", "الدخول إلى البوابة"), ("history.view", "عرض سجل العمليات")),
    "FlowScope": (
        ("flowscope.view", "عرض FlowScope ونتائجه"), ("flowscope.analyze", "رفع الملفات وبدء التحليل"),
        ("flowscope.enrich", "فحص المصادر وتحديث النتائج"), ("flowscope.export", "معاينة التقارير وتصديرها"),
        ("flowscope.feedback", "إضافة تقييم المحلل"), ("flowscope.delete", "حذف مهام التحليل"),
    ),
    "ThreatScope": (
        ("threatscope.view", "عرض ThreatScope ونتائجه"), ("threatscope.analyze", "رفع الملفات وبدء التحليل"),
        ("threatscope.enrich", "فحص المصادر وتحديث النتائج"), ("threatscope.export", "معاينة التقارير وتصديرها"),
        ("threatscope.feedback", "إضافة تقييم المحلل"), ("threatscope.delete", "حذف مهام التحليل"),
    ),
    "LogScope": (
        ("logscope.view", "عرض LogScope ونتائجه"), ("logscope.analyze", "رفع الملفات وبدء التحليل"),
        ("logscope.enrich", "فحص المصادر وتحديث النتائج"), ("logscope.export", "معاينة التقارير وتصديرها"),
        ("logscope.feedback", "إضافة تقييم المحلل"), ("logscope.delete", "حذف مهام التحليل"),
    ),
    "الحوادث": (
        ("incidents.view", "عرض الحوادث وتفاصيلها"),
        ("incidents.manage", "تحديث حالة الحادث وتعيين المحلل وإضافة الأدلة والملاحظات"),
        ("incidents.export", "تصدير ملفات التحقيق الجنائي الرقمي والتحقق من سلامتها"),
        ("copilot.query", "استخدام المساعد الأمني الذكي للتحقيق الجنائي وتوليد التوصيات"),
    ),
    "قواعد الكشف": (
        ("detections.view", "عرض قواعد الكشف وتفاصيلها ومقاييس الأداء"),
        ("detections.manage", "إنشاء وتعديل وتفعيل القواعد واختبارها واستيرادها وتصديرها"),
    ),
    "استخبارات التهديدات": (
        ("intel.view", "عرض قاعدة مؤشرات التهديد (IOCs) وتفاصيلها"),
        ("intel.manage", "إضافة وتعديل وحذف واستيراد وتصدير مؤشرات التهديد"),
    ),
    "الأصول الأمنية": (
        ("assets.view", "عرض واستعراض سجل الأصول الأمنية ومقاييس الخطورة"),
        ("assets.manage", "إضافة وتعديل وحذف واستيراد وتصدير الأصول"),
        ("assets.isolate", "تنفيذ واعتماد خطط العزل الأمني للأصول"),
    ),
    "الترابط الجنائي": (
        ("correlation.view", "عرض شبكة الرسم البياني الأمني وسلاسل الهجوم والتنقل الأفقي"),
        ("correlation.manage", "إجراء التحليل المتقدم للترابط وترقية الأنماط إلى حوادث"),
    ),
    "الإدارة": (
        ("users.manage", "إدارة المستخدمين والصلاحيات"),
        ("system.status", "عرض حالة النموذج والخدمات"),
        ("database.status", "عرض حالة محركات قواعد البيانات والتخزين"),
        ("enterprise.view", "عرض حالة العناقيد والمستأجرين وطوابير المهام"),
        ("enterprise.manage", "إدارة المستأجرين والحصص وسياسات الأرشفة المؤسسية"),
    ),
}
ALL_PERMISSIONS = tuple(code for items in PERMISSION_GROUPS.values() for code, _ in items)
PRESETS = {
    "administrator": list(ALL_PERMISSIONS),
    "analyst": [code for code in ALL_PERMISSIONS if code != "users.manage"],
    "viewer": [
        "portal.access", "history.view", "incidents.view", "detections.view", "intel.view", "assets.view", "correlation.view",
        "flowscope.view", "flowscope.export", "threatscope.view", "threatscope.export", "logscope.view", "logscope.export"
    ],
}
_CONFIG_LOCK = threading.RLock()
_CONFIG: dict | None = None
_CONFIG_MTIME_NS = 0


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _password_hash(password: str, salt: bytes) -> str:
    return _b64encode(hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000))


def _new_password_fields(password: str) -> dict:
    if len(password) < 8:
        raise ValueError("يجب ألا تقل كلمة المرور عن 8 أحرف.")
    salt = secrets.token_bytes(24)
    return {"password_salt": _b64encode(salt), "password_hash": _password_hash(password, salt)}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_username(value: str) -> str:
    username = str(value or "").strip()
    if not re.fullmatch(r"[^\s/\\:]{3,64}", username):
        raise ValueError("اسم المستخدم يجب أن يكون بين 3 و64 حرفاً ومن دون مسافات.")
    return username


def _validate_display_name(value: str) -> str:
    name = str(value or "").strip()
    if not 1 <= len(name) <= 80:
        raise ValueError("الاسم الظاهر مطلوب وبحد أقصى 80 حرفاً.")
    return name


def _normalize_permissions(values) -> list[str]:
    requested = {str(value) for value in (values or [])}
    return [code for code in ALL_PERMISSIONS if code in requested]


def _new_user(username: str, password: str, display_name: str, permissions) -> dict:
    user = {
        "id": secrets.token_hex(8), "username": _validate_username(username),
        "display_name": _validate_display_name(display_name or username), "active": True,
        "permissions": _normalize_permissions(permissions), "session_version": 1,
        "created_at": _now(), "updated_at": _now(),
    }
    user.update(_new_password_fields(password))
    return user


def _new_config() -> dict:
    username = os.environ.get("SECURITY_USERNAME", DEFAULT_USERNAME).strip() or DEFAULT_USERNAME
    password = os.environ.get("SECURITY_PASSWORD", DEFAULT_PASSWORD)
    return {"version": 2, "session_secret": _b64encode(secrets.token_bytes(48)), "users": [_new_user(username, password, "مدير المنصة", ALL_PERMISSIONS)]}


def _migrate(data: dict) -> tuple[dict, bool]:
    dirty = False
    if int(data.get("version") or 1) < 2 or not isinstance(data.get("users"), list):
        required = {"username", "password_salt", "password_hash", "session_secret"}
        if not required.issubset(data):
            raise RuntimeError(f"Invalid authentication configuration: {AUTH_FILE}")
        return {
            "version": 2, "session_secret": data["session_secret"],
            "users": [{"id": secrets.token_hex(8), "username": str(data["username"]), "display_name": "مدير المنصة",
                       "password_salt": data["password_salt"], "password_hash": data["password_hash"], "active": True,
                       "permissions": list(ALL_PERMISSIONS), "session_version": 1, "created_at": _now(), "updated_at": _now()}],
        }, True

    for user in data.get("users", []):
        perms = set(user.get("permissions") or [])
        if "users.manage" in perms:
            missing = set(ALL_PERMISSIONS) - perms
            if missing:
                user["permissions"] = [code for code in ALL_PERMISSIONS if code in perms or code in missing]
                dirty = True
    return data, dirty


def _write_config(config: dict) -> None:
    global _CONFIG, _CONFIG_MTIME_NS
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = AUTH_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, AUTH_FILE)
    _CONFIG = config
    _CONFIG_MTIME_NS = AUTH_FILE.stat().st_mtime_ns


def load_config() -> dict:
    global _CONFIG, _CONFIG_MTIME_NS
    try:
        current_mtime = AUTH_FILE.stat().st_mtime_ns
    except FileNotFoundError:
        current_mtime = 0
    if _CONFIG is not None and current_mtime == _CONFIG_MTIME_NS:
        return _CONFIG
    with _CONFIG_LOCK:
        AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        except FileNotFoundError:
            candidate = _new_config()
            try:
                with AUTH_FILE.open("x", encoding="utf-8") as handle:
                    json.dump(candidate, handle, ensure_ascii=False, indent=2)
            except FileExistsError:
                pass
            data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
        data, changed = _migrate(data)
        if changed:
            _write_config(data)
        if not data.get("users") or not data.get("session_secret"):
            raise RuntimeError(f"Invalid authentication configuration: {AUTH_FILE}")
        _CONFIG = data
        _CONFIG_MTIME_NS = AUTH_FILE.stat().st_mtime_ns
        return data


def _find_user(config: dict, *, username: str | None = None, user_id: str | None = None) -> dict | None:
    for user in config.get("users", []):
        if user_id is not None and hmac.compare_digest(str(user.get("id")), str(user_id)):
            return user
        if username is not None and str(user.get("username", "")).casefold() == str(username).casefold():
            return user
    return None


def _public_user(user: dict) -> dict:
    base = {key: value for key, value in {
        "id": str(user["id"]), "username": str(user["username"]), "display_name": str(user.get("display_name") or user["username"]),
        "active": bool(user.get("active", True)), "permissions": _normalize_permissions(user.get("permissions")),
        "created_at": user.get("created_at"), "updated_at": user.get("updated_at"),
    }.items()}
    try:
        from platform_core.authorization import get_user_profile, get_user_group_ids, get_role_by_id
        profile = get_user_profile(base["id"], is_admin="users.manage" in base["permissions"])
        base["role_id"] = profile["role_id"]
        role_obj = get_role_by_id(profile["role_id"])
        base["role"] = role_obj or {"id": profile["role_id"], "name": profile["role_id"], "label_ar": profile["role_id"]}
        base["data_scope"] = profile["data_scope"]
        base["department"] = profile["department"]
        base["custom_permissions"] = profile.get("custom_permissions", [])
        base["groups"] = get_user_group_ids(base["id"])
    except Exception:
        pass
    return base


def authenticate(username: str, password: str) -> dict | None:
    user = _find_user(load_config(), username=username)
    if not user or not user.get("active", True):
        return None
    try:
        actual = _password_hash(str(password), _b64decode(str(user["password_salt"])))
    except (KeyError, ValueError, TypeError):
        return None
    return _public_user(user) if hmac.compare_digest(actual, str(user.get("password_hash") or "")) else None


def verify_credentials(username: str, password: str) -> bool:
    return authenticate(username, password) is not None


def create_session(username: str) -> str:
    user = _find_user(load_config(), username=username)
    if not user or not user.get("active", True):
        raise ValueError("User is unavailable")
    now = int(time.time())
    payload = _b64encode(json.dumps({"id": user["id"], "v": int(user.get("session_version") or 1), "iat": now,
                                     "exp": now + SESSION_SECONDS, "n": secrets.token_urlsafe(12)}, separators=(",", ":")).encode("utf-8"))
    secret = _b64decode(str(load_config()["session_secret"]))
    signature = _b64encode(hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def session_identity(token: str | None) -> dict | None:
    if not token or "." not in token:
        return None
    try:
        payload, signature = token.split(".", 1)
        config = load_config()
        secret = _b64decode(str(config["session_secret"]))
        expected = _b64encode(hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        data = json.loads(_b64decode(payload))
        if int(data.get("exp") or 0) < int(time.time()):
            return None
        user = _find_user(config, user_id=str(data.get("id") or ""))
        if not user or not user.get("active", True) or int(data.get("v") or 0) != int(user.get("session_version") or 1):
            return None
        return _public_user(user)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def verify_session(token: str | None) -> str | None:
    identity = session_identity(token)
    return identity["username"] if identity else None


def request_identity(headers) -> dict | None:
    cookie = SimpleCookie()
    try:
        cookie.load(headers.get("Cookie", ""))
    except Exception:
        return None
    morsel = cookie.get(COOKIE_NAME)
    return session_identity(morsel.value if morsel else None)


def request_user(headers) -> str | None:
    identity = request_identity(headers)
    return identity["username"] if identity else None


def has_permission(identity: dict | None, permission: str) -> bool:
    if not identity:
        return False
    user_perms = identity.get("permissions", [])
    if permission in user_perms or "users.manage" in user_perms:
        return True
    try:
        from platform_core.authorization import build_security_context
        ctx = build_security_context(identity)
        return ctx.has_permission(permission)
    except Exception:
        return False


def permission_catalog() -> dict:
    try:
        from platform_core.authorization import (
            get_permission_catalog,
            list_all_roles,
            list_all_groups,
            get_available_scopes,
        )
        cat = get_permission_catalog()
        groups_list = [{"name": group_name, "permissions": entries} for group_name, entries in cat.items()]
        return {
            "groups": groups_list,
            "presets": PRESETS,
            "roles": list_all_roles(),
            "workgroups": list_all_groups(),
            "scopes": get_available_scopes(),
        }
    except Exception:
        return {"groups": [{"name": group, "permissions": [{"code": code, "label": label} for code, label in entries]}
                           for group, entries in PERMISSION_GROUPS.items()], "presets": PRESETS}


def list_users() -> list[dict]:
    return [_public_user(user) for user in load_config()["users"]]


def create_user(
    username: str,
    password: str,
    display_name: str,
    permissions,
    active: bool = True,
    role_id: str | None = None,
    data_scope: str | None = None,
    department: str | None = None,
    custom_permissions: list[str] | None = None,
    group_ids: list[str] | None = None,
) -> dict:
    global _CONFIG
    with _CONFIG_LOCK:
        config = load_config()
        if _find_user(config, username=username):
            raise ValueError("اسم المستخدم مستخدم بالفعل.")
        user = _new_user(username, password, display_name, permissions)
        user["active"] = bool(active)
        config["users"].append(user)
        _write_config(config)
        _CONFIG = config

        # Persist authorization profile
        try:
            from platform_core.authorization import save_user_profile
            eff_role = role_id or ("administrator" if "users.manage" in (user.get("permissions") or []) else "analyst")
            save_user_profile(
                user["id"],
                role_id=eff_role,
                data_scope=data_scope,
                department=department,
                custom_permissions=custom_permissions,
                group_ids=group_ids,
            )
        except Exception:
            pass

        return _public_user(user)


def _active_admin_count(config: dict, excluding: str | None = None) -> int:
    return sum(1 for user in config["users"] if user.get("id") != excluding and user.get("active", True) and "users.manage" in user.get("permissions", []))


def update_user(
    user_id: str,
    *,
    username=None,
    display_name=None,
    password=None,
    permissions=None,
    active=None,
    role_id=None,
    data_scope=None,
    department=None,
    custom_permissions=None,
    group_ids=None,
) -> dict:
    global _CONFIG
    with _CONFIG_LOCK:
        config = load_config()
        user = _find_user(config, user_id=user_id)
        if not user:
            raise LookupError("المستخدم غير موجود.")
        new_username = _validate_username(username if username is not None else user["username"])
        duplicate = _find_user(config, username=new_username)
        if duplicate and duplicate["id"] != user_id:
            raise ValueError("اسم المستخدم مستخدم بالفعل.")
        new_permissions = _normalize_permissions(permissions if permissions is not None else user.get("permissions"))
        new_active = bool(active) if active is not None else bool(user.get("active", True))
        was_admin = bool(user.get("active", True) and "users.manage" in user.get("permissions", []))
        remains_admin = bool(new_active and "users.manage" in new_permissions)
        if was_admin and not remains_admin and _active_admin_count(config, excluding=user_id) == 0:
            raise ValueError("لا يمكن تعطيل أو إزالة صلاحية آخر مدير للمنصة.")
        changed_identity = new_username != user["username"] or bool(password)
        user.update({"username": new_username, "display_name": _validate_display_name(display_name if display_name is not None else user.get("display_name")),
                     "permissions": new_permissions, "active": new_active, "updated_at": _now()})
        if password:
            user.update(_new_password_fields(str(password)))
        if changed_identity or not new_active:
            user["session_version"] = int(user.get("session_version") or 1) + 1
        _write_config(config)
        _CONFIG = config

        # Update authorization profile
        try:
            from platform_core.authorization import save_user_profile
            save_user_profile(
                user_id,
                role_id=role_id,
                data_scope=data_scope,
                department=department,
                custom_permissions=custom_permissions,
                group_ids=group_ids,
            )
        except Exception:
            pass

        return _public_user(user)


def delete_user(user_id: str) -> None:
    global _CONFIG
    with _CONFIG_LOCK:
        config = load_config()
        user = _find_user(config, user_id=user_id)
        if not user:
            raise LookupError("المستخدم غير موجود.")
        if user.get("active", True) and "users.manage" in user.get("permissions", []) and _active_admin_count(config, excluding=user_id) == 0:
            raise ValueError("لا يمكن حذف آخر مدير للمنصة.")
        config["users"] = [item for item in config["users"] if item.get("id") != user_id]
        _write_config(config)
        _CONFIG = config


def update_own_account(username: str, current_password: str, new_username: str, new_password: str | None, display_name: str) -> dict:
    identity = authenticate(username, current_password)
    if not identity:
        raise PermissionError("كلمة المرور الحالية غير صحيحة.")
    return update_user(identity["id"], username=new_username, display_name=display_name, password=new_password or None)


def session_cookie(token: str) -> str:
    return f"{COOKIE_NAME}={token}; Path=/; Max-Age={SESSION_SECONDS}; HttpOnly; SameSite=Strict"


def expired_cookie() -> str:
    return f"{COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"


def change_password(username: str, password: str) -> None:
    user = _find_user(load_config(), username=username)
    if not user:
        raise LookupError("User not found")
    update_user(user["id"], password=password)


if __name__ == "__main__":
    import getpass
    selected_user = input("Existing username: ").strip() or DEFAULT_USERNAME
    selected_password = getpass.getpass("New password (8+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if selected_password != confirmation:
        raise SystemExit("Passwords do not match")
    change_password(selected_user, selected_password)
    print("Credentials updated. Existing sessions for this user are now invalid.")
