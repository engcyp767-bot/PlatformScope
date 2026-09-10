"""Persistent runtime configuration for the unified security platform."""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
_STORAGE_ENV = os.environ.get("PLATFORM_STORAGE_DIR") or os.environ.get("PLATFORM_SCOPE_DATA_DIR")
if _STORAGE_ENV:
    STORAGE_DIR = Path(_STORAGE_ENV).resolve()
elif (ROOT / "storage").exists() or not os.name == "nt":
    STORAGE_DIR = ROOT / "storage"
elif os.environ.get("ProgramData") and (str(ROOT).lower().startswith(r"c:\program files") or (Path(os.environ["ProgramData"]) / "PlatformScope").exists()):
    STORAGE_DIR = Path(os.environ["ProgramData"]) / "PlatformScope"
else:
    STORAGE_DIR = ROOT / "storage"

CONFIG_FILE = STORAGE_DIR / "platform_config.json"
_LOCK = threading.RLock()
MASK = "••••••••••••"

DEFAULTS: dict[str, Any] = {
    "version": 1,
    "general": {
        "language": "ar", "timezone": "Asia/Riyadh", "default_app": "dashboard",
        "items_per_page": 25, "show_welcome": True, "show_system_status": True,
    },
    "appearance": {
        "theme": "dark", "primary_color": "#6366f1", "accent_color": "#ff4d8d",
        "compact_mode": False, "animations": True,
        "platform_title": "بوابة التحليل الأمني", "platform_subtitle": "مركز التحليل والاستجابة الموحد",
    },
    "ollama": {
        "enabled": True, "url": "http://127.0.0.1:11434", "preferred_model": "gemma4:31b",
        "fallback_model": "gpt-oss:20b", "timeout_seconds": 240, "max_records": 30,
    },
    "providers": {
        "virustotal": {"enabled": True, "api_keys": []},
        "abuseipdb": {"enabled": False, "api_key": ""},
        "malwarebazaar": {"enabled": False, "api_key": ""},
        "shodan": {"enabled": True},
    },
    "analysis": {
        "flow_workers": 8, "flow_max_external_ips": 0, "log_max_external_ips": 0,
        "flow_cache_ttl_days": 0, "threat_cache_ttl_days": 0, "log_cache_ttl_days": 0,
        "auto_enrich": False, "model_analysis_enabled": True, "learning_enabled": True,
        "critical_threshold": 85, "high_threshold": 70, "medium_threshold": 40,
    },
    "uploads": {
        "flowscope_max_mb": 50, "threatscope_max_mb": 20, "logscope_max_mb": 100,
        "xlsx_max_files": 2000, "xlsx_max_uncompressed_mb": 150,
        "xlsx_max_compression_ratio": 200,
    },
    "reports": {
        "organization_name": "", "classification": "للاستخدام الداخلي",
        "analyst_title": "محلل الأمن السيبراني", "top_findings": 15,
        "recommendations": 8, "include_ai_analysis": True,
        "include_source_results": True, "preview_engine": "auto",
    },
    "storage": {
        "job_retention_days": 0, "audit_retention_days": 0,
        "preview_retention_hours": 0, "history_page_size": 50,
    },
    "logging": {
        "enabled": True, "level": "info", "include_details": True,
        "max_detail_length": 500,
        "enabled": True, "level": "INFO", "structured": True,
        "async": True, "queue_size": 10000,
        "include_details": True, "max_detail_length": 500,
        "redaction": {"enabled": True},
        "rotation": {
            "max_size_mb": 100, "retention_days": 30, "max_files": 10, "compression": True,
        },
    },
    "security": {
        "session_hours": 12, "login_max_attempts": 5,
        "login_window_minutes": 5, "secure_cookie": False,
    },
    "features": {
        "flowscope_enabled": True, "threatscope_enabled": True, "logscope_enabled": True,
        "report_preview": True, "excel_export": True,
        "force_refresh": True, "analyst_feedback": True,
    },
    "source_systems": {
        "flowscope": [
            {"id": "flow_1", "label": "C-IN", "description": "تدفقات الدخول المركزية"},
            {"id": "flow_2", "label": "DCS", "description": "مركز البيانات والخدمات"},
            {"id": "flow_3", "label": "C-OUT", "description": "تدفقات الخروج والإنترنت"},
        ],
        "threatscope": [
            {"id": "xdr_1", "label": "C-IN", "description": "تنبيهات بيئة العمل المركزية"},
            {"id": "xdr_2", "label": "DCS", "description": "خوادم مركز البيانات"},
            {"id": "xdr_3", "label": "C-OUT", "description": "الأجهزة الطرفية والخارجية"},
        ],
        "logscope": [
            {"id": "manageengine", "label": "ManageEngine Log360", "description": "سجلات الحماية و SIEM"},
            {"id": "splunk", "label": "Splunk Enterprise", "description": "مركز السجلات المؤسسي"},
            {"id": "syslog", "label": "Raw Syslog", "description": "مستقبل السجلات العام"},
        ],
    },
    "network": {
        "frontend_port": 3000, "gateway_port": 8081, "analysis_port": 8082,
        "bind_address": "0.0.0.0", "trusted_origins": [], "proxy_timeout_seconds": 300,
    },
    "time": {
        "source": "host",
        "manual_time": "",
        "ntp_server": "pool.ntp.org",
        "ntp_port": 123,
        "ntp_sync_interval_seconds": 3600,
        "auto_sync": True,
    },
    "external_apis": [],
    "ai_providers": [],
    "governance": {
        "audit_retention_days": 90,
        "job_retention_days": 30,
        "max_workers": 4,
        "session_timeout_minutes": 60,
        "auto_vacuum_enabled": True,
        "backup_retention_copies": 7,
    },
}

CONFIG_HISTORY_DB = ROOT / "storage" / "config_history.db"


def _get_history_db() -> sqlite3.Connection:
    CONFIG_HISTORY_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(CONFIG_HISTORY_DB), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS config_revisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version INTEGER NOT NULL,
            actor TEXT NOT NULL DEFAULT 'admin',
            timestamp TEXT NOT NULL,
            summary TEXT NOT NULL DEFAULT '',
            config_json TEXT NOT NULL
        );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cfg_ver ON config_revisions(version DESC);")
    conn.commit()
    return conn


def record_revision(version: int, actor: str, summary: str, config: dict[str, Any]) -> None:
    try:
        conn = _get_history_db()
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn.execute(
            "INSERT INTO config_revisions (version, actor, timestamp, summary, config_json) VALUES (?, ?, ?, ?, ?);",
            (version, actor, now_iso, summary, json.dumps(config, ensure_ascii=False)),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_config_history(limit: int = 50) -> list[dict[str, Any]]:
    try:
        conn = _get_history_db()
        cursor = conn.execute(
            "SELECT id, version, actor, timestamp, summary FROM config_revisions ORDER BY id DESC LIMIT ?;",
            (limit,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [
            {
                "id": r["id"],
                "version": r["version"],
                "actor": r["actor"],
                "timestamp": r["timestamp"],
                "summary": r["summary"],
            }
            for r in rows
        ]
    except Exception:
        return []


def rollback_config(revision_id: int | None = None, version: int | None = None, actor: str = "admin") -> dict[str, Any]:
    conn = _get_history_db()
    row = None
    if revision_id is not None:
        cursor = conn.execute("SELECT config_json, version FROM config_revisions WHERE id = ?;", (revision_id,))
        row = cursor.fetchone()
    elif version is not None:
        cursor = conn.execute("SELECT config_json, version FROM config_revisions WHERE version = ? ORDER BY id DESC LIMIT 1;", (version,))
        row = cursor.fetchone()
    conn.close()

    if not row:
        raise ValueError("نسخة الإعدادات المستهدفة غير موجودة في سجل التغييرات.")

    target_cfg = json.loads(row["config_json"])
    target_ver = row["version"]
    res = save(target_cfg, actor=actor, summary=f"استرجاع آلي إلى الإصدار {target_ver}")
    return res


def _merge(base: dict, overlay: dict) -> dict:
    output = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(output.get(key), dict):
            output[key] = _merge(output[key], value)
        else:
            output[key] = copy.deepcopy(value)
    return output


def load() -> dict[str, Any]:
    with _LOCK:
        try:
            stored = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            return _merge(DEFAULTS, stored if isinstance(stored, dict) else {})
        except (OSError, json.JSONDecodeError):
            initial = copy.deepcopy(DEFAULTS)
            values = [os.environ.get("VIRUSTOTAL_API_KEY", ""), os.environ.get("VIRUSTOTAL_FALLBACK_API_KEY", ""), os.environ.get("VIRUSTOTAL_API_KEYS", "")]
            keys: list[str] = []
            for value in values:
                for key in re.split(r"[,;\s]+", value):
                    if key and key not in keys:
                        keys.append(key)
            initial["providers"]["virustotal"].update(enabled=bool(keys), api_keys=keys)
            for provider, variable in (("abuseipdb", "ABUSEIPDB_API_KEY"), ("malwarebazaar", "MALWAREBAZAAR_AUTH_KEY")):
                secret = os.environ.get(variable, "")
                initial["providers"][provider].update(enabled=bool(secret), api_key=secret)
            initial["ollama"].update({
                "enabled": os.environ.get("OLLAMA_ENABLED", "auto").lower() not in {"0", "false", "off", "disabled"},
                "url": os.environ.get("OLLAMA_URL", initial["ollama"]["url"]),
                "preferred_model": os.environ.get("OLLAMA_MODEL", initial["ollama"]["preferred_model"]),
                "fallback_model": os.environ.get("OLLAMA_FALLBACK_MODEL", initial["ollama"]["fallback_model"]),
            })
            return initial


def _valid_url(value: Any, field: str) -> str:
    url = str(value or "").strip().rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"عنوان {field} غير صالح؛ استخدم HTTP أو HTTPS من دون بيانات دخول داخل الرابط.")
    return url


def _validate_color(value: Any, fallback: str) -> str:
    text = str(value or fallback).strip()
    return text if re.fullmatch(r"#[0-9a-fA-F]{6}", text) else fallback


def _preserve_secret(new: Any, old: Any) -> Any:
    if new in {None, "", MASK}:
        return old
    return new


def _bounded_int(value: Any, fallback: int, minimum: int, maximum: int) -> int:
    try:
        return min(maximum, max(minimum, int(value)))
    except (TypeError, ValueError):
        return fallback


def _clean_source_systems(value: Any, application: str) -> list[dict[str, str]]:
    prefix = "flow" if application == "flowscope" else "xdr" if application == "threatscope" else "log"
    defaults = DEFAULTS["source_systems"][application]
    if not isinstance(value, list):
        return copy.deepcopy(defaults)
    output: list[dict[str, str]] = []
    for index, item in enumerate(value[:12], 1):
        if not isinstance(item, dict):
            continue
        identifier = re.sub(r"[^a-zA-Z0-9_-]", "", str(item.get("id") or f"{prefix}_{index}"))[:40]
        label = str(item.get("label") or "").strip()[:40]
        if identifier and label:
            output.append({"id": identifier, "label": label, "description": str(item.get("description") or "").strip()[:120]})
    return output or copy.deepcopy(defaults)


def save(payload: dict[str, Any], actor: str = "admin", summary: str = "تحديث الإعدادات") -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("صيغة الإعدادات غير صالحة.")
    previous = load()
    merged = _merge(previous, payload)
    general = merged["general"]
    general["language"] = str(general.get("language")) if general.get("language") in {"ar", "en"} else "ar"
    general["timezone"] = str(general.get("timezone") or "Asia/Riyadh")[:80]
    general["default_app"] = str(general.get("default_app")) if general.get("default_app") in {"dashboard", "flowscope", "threatscope", "logscope"} else "dashboard"
    general["items_per_page"] = _bounded_int(general.get("items_per_page"), 25, 10, 200)
    general["show_welcome"] = bool(general.get("show_welcome", True))
    general["show_system_status"] = bool(general.get("show_system_status", True))
    appearance = merged["appearance"]
    appearance["theme"] = str(appearance.get("theme")) if appearance.get("theme") in {"dark", "light", "midnight", "graphite", "navy"} else "dark"
    appearance["primary_color"] = _validate_color(appearance.get("primary_color"), "#00f0ff")
    appearance["accent_color"] = _validate_color(appearance.get("accent_color"), "#f43f5e")
    appearance["platform_title"] = str(appearance.get("platform_title") or DEFAULTS["appearance"]["platform_title"])[:80]
    appearance["platform_subtitle"] = str(appearance.get("platform_subtitle") or DEFAULTS["appearance"]["platform_subtitle"])[:140]

    ollama = merged["ollama"]
    ollama["url"] = _valid_url(ollama.get("url"), "Ollama")
    ollama["preferred_model"] = str(ollama.get("preferred_model") or "").strip()[:120]
    ollama["fallback_model"] = str(ollama.get("fallback_model") or "").strip()[:120]
    ollama["timeout_seconds"] = min(600, max(10, int(ollama.get("timeout_seconds") or 240)))
    ollama["max_records"] = min(60, max(5, int(ollama.get("max_records") or 30)))

    providers = merged["providers"]
    old_providers = previous["providers"]
    for name in ("abuseipdb", "malwarebazaar"):
        providers[name]["api_key"] = _preserve_secret(providers[name].get("api_key"), old_providers[name].get("api_key", ""))
    keys = providers["virustotal"].get("api_keys")
    if not isinstance(keys, list) or not [item for item in keys if item and item != MASK]:
        providers["virustotal"]["api_keys"] = old_providers["virustotal"].get("api_keys", [])
    else:
        providers["virustotal"]["api_keys"] = list(dict.fromkeys(str(item).strip() for item in keys if str(item).strip() and item != MASK))[:10]

    analysis = merged["analysis"]
    analysis["flow_workers"] = _bounded_int(analysis.get("flow_workers"), 8, 1, 32)
    analysis["flow_max_external_ips"] = _bounded_int(analysis.get("flow_max_external_ips"), 0, 0, 100_000)
    analysis["log_max_external_ips"] = _bounded_int(analysis.get("log_max_external_ips"), 0, 0, 100_000)
    analysis["flow_cache_ttl_days"] = _bounded_int(analysis.get("flow_cache_ttl_days"), 0, 0, 3650)
    analysis["threat_cache_ttl_days"] = _bounded_int(analysis.get("threat_cache_ttl_days"), 0, 0, 3650)
    analysis["log_cache_ttl_days"] = _bounded_int(analysis.get("log_cache_ttl_days"), 0, 0, 3650)
    analysis["auto_enrich"] = bool(analysis.get("auto_enrich", False))
    analysis["model_analysis_enabled"] = bool(analysis.get("model_analysis_enabled", True))
    analysis["learning_enabled"] = bool(analysis.get("learning_enabled", True))
    medium = _bounded_int(analysis.get("medium_threshold"), 40, 1, 98)
    high = _bounded_int(analysis.get("high_threshold"), 70, medium + 1, 99)
    critical = _bounded_int(analysis.get("critical_threshold"), 85, high + 1, 100)
    analysis.update(medium_threshold=medium, high_threshold=high, critical_threshold=critical)

    uploads = merged["uploads"]
    uploads["flowscope_max_mb"] = _bounded_int(uploads.get("flowscope_max_mb"), 50, 1, 4096)
    uploads["threatscope_max_mb"] = _bounded_int(uploads.get("threatscope_max_mb"), 20, 1, 4096)
    uploads["logscope_max_mb"] = _bounded_int(uploads.get("logscope_max_mb"), 100, 1, 4096)
    uploads["xlsx_max_files"] = _bounded_int(uploads.get("xlsx_max_files"), 2000, 20, 50_000)
    uploads["xlsx_max_uncompressed_mb"] = _bounded_int(uploads.get("xlsx_max_uncompressed_mb"), 150, 10, 8192)
    uploads["xlsx_max_compression_ratio"] = _bounded_int(uploads.get("xlsx_max_compression_ratio"), 200, 10, 2000)

    reports = merged["reports"]
    reports["organization_name"] = str(reports.get("organization_name") or "").strip()[:120]
    reports["classification"] = str(reports.get("classification") or "للاستخدام الداخلي").strip()[:80]
    reports["analyst_title"] = str(reports.get("analyst_title") or "محلل الأمن السيبراني").strip()[:80]
    reports["top_findings"] = _bounded_int(reports.get("top_findings"), 15, 3, 100)
    reports["recommendations"] = _bounded_int(reports.get("recommendations"), 8, 1, 30)
    reports["include_ai_analysis"] = bool(reports.get("include_ai_analysis", True))
    reports["include_source_results"] = bool(reports.get("include_source_results", True))
    reports["preview_engine"] = str(reports.get("preview_engine")) if reports.get("preview_engine") in {"auto", "word", "libreoffice"} else "auto"

    storage = merged["storage"]
    storage["job_retention_days"] = _bounded_int(storage.get("job_retention_days"), 0, 0, 3650)
    storage["audit_retention_days"] = _bounded_int(storage.get("audit_retention_days"), 0, 0, 3650)
    storage["preview_retention_hours"] = _bounded_int(storage.get("preview_retention_hours"), 0, 0, 8760)
    storage["history_page_size"] = _bounded_int(storage.get("history_page_size"), 50, 10, 500)

    logging = merged["logging"]
    logging["enabled"] = bool(logging.get("enabled", True))
    logging["level"] = str(logging.get("level")) if logging.get("level") in {"debug", "info", "warning", "error"} else "info"
    logging["include_details"] = bool(logging.get("include_details", True))
    logging["max_detail_length"] = _bounded_int(logging.get("max_detail_length"), 500, 100, 5000)

    security = merged["security"]
    security["session_hours"] = _bounded_int(security.get("session_hours"), 12, 1, 168)
    security["login_max_attempts"] = _bounded_int(security.get("login_max_attempts"), 5, 2, 30)
    security["login_window_minutes"] = _bounded_int(security.get("login_window_minutes"), 5, 1, 120)
    security["secure_cookie"] = bool(security.get("secure_cookie", False))

    features = merged["features"]
    for key in DEFAULTS["features"]:
        features[key] = bool(features.get(key, DEFAULTS["features"][key]))

    sources = merged["source_systems"]
    sources["flowscope"] = _clean_source_systems(sources.get("flowscope"), "flowscope")
    sources["threatscope"] = _clean_source_systems(sources.get("threatscope"), "threatscope")
    sources["logscope"] = _clean_source_systems(sources.get("logscope"), "logscope")

    network = merged["network"]
    network["frontend_port"] = _bounded_int(network.get("frontend_port"), 3000, 1, 65535)
    network["gateway_port"] = _bounded_int(network.get("gateway_port"), 8081, 1, 65535)
    network["analysis_port"] = _bounded_int(network.get("analysis_port"), 8082, 1, 65535)
    if len({network["frontend_port"], network["gateway_port"], network["analysis_port"]}) != 3:
        raise ValueError("يجب أن يكون لكل خدمة منفذ مختلف.")
    network["bind_address"] = str(network.get("bind_address") or "0.0.0.0").strip()[:80]
    network["proxy_timeout_seconds"] = _bounded_int(network.get("proxy_timeout_seconds"), 300, 10, 1800)
    origins = network.get("trusted_origins") if isinstance(network.get("trusted_origins"), list) else []
    network["trusted_origins"] = [_valid_url(item, "الأصل الموثوق") for item in origins[:20] if str(item).strip()]

    custom = []
    for item in merged.get("external_apis", [])[:20]:
        if not isinstance(item, dict):
            continue
        old = next((entry for entry in previous.get("external_apis", []) if entry.get("id") == item.get("id")), {})
        custom.append({
            "id": re.sub(r"[^a-zA-Z0-9_-]", "", str(item.get("id") or ""))[:40] or os.urandom(5).hex(),
            "name": str(item.get("name") or "API خارجي")[:80],
            "enabled": bool(item.get("enabled", True)),
            "scope": str(item.get("scope")) if item.get("scope") in {"flowscope", "threatscope", "logscope", "both", "all"} else "both",
            "base_url": _valid_url(item.get("base_url"), "API الخارجي"),
            "health_path": str(item.get("health_path") or "")[:200],
            "lookup_path": str(item.get("lookup_path") or "/lookup/{indicator}")[:300],
            "verdict_path": str(item.get("verdict_path") or "verdict")[:120],
            "malicious_values": str(item.get("malicious_values") or "malicious,suspicious,high")[:200],
            "auth_header": str(item.get("auth_header") or "Authorization")[:80],
            "api_key": _preserve_secret(item.get("api_key"), old.get("api_key", "")),
            "timeout_seconds": min(120, max(2, int(item.get("timeout_seconds") or 15))),
        })
    merged["external_apis"] = custom

    ai_providers = []
    for item in merged.get("ai_providers", [])[:10]:
        if not isinstance(item, dict):
            continue
        old = next((entry for entry in previous.get("ai_providers", []) if entry.get("id") == item.get("id")), {})
        ai_providers.append({
            "id": re.sub(r"[^a-zA-Z0-9_-]", "", str(item.get("id") or ""))[:40] or os.urandom(5).hex(),
            "name": str(item.get("name") or "مزود AI")[:80],
            "enabled": bool(item.get("enabled", True)),
            "base_url": _valid_url(item.get("base_url"), "مزود AI"),
            "chat_path": str(item.get("chat_path") or "/v1/chat/completions")[:240],
            "models_path": str(item.get("models_path") or "/v1/models")[:240],
            "model": str(item.get("model") or "").strip()[:120],
            "auth_header": str(item.get("auth_header") or "Authorization")[:80],
            "auth_prefix": str(item.get("auth_prefix") if item.get("auth_prefix") is not None else "Bearer ")[:30],
            "api_key": _preserve_secret(item.get("api_key"), old.get("api_key", "")),
            "timeout_seconds": min(600, max(10, int(item.get("timeout_seconds") or 180))),
            "priority": min(100, max(1, int(item.get("priority") or 10))),
        })
    merged["ai_providers"] = sorted(ai_providers, key=lambda entry: entry["priority"])

    time_cfg = merged.get("time") or {}
    source = str(time_cfg.get("source") or "host").strip().lower()
    if source not in {"host", "manual", "ntp"}:
        source = "host"
    time_cfg["source"] = source
    time_cfg["manual_time"] = str(time_cfg.get("manual_time") or "").strip()[:60]
    time_cfg["ntp_server"] = str(time_cfg.get("ntp_server") or "pool.ntp.org").strip()[:180] or "pool.ntp.org"
    time_cfg["ntp_port"] = _bounded_int(time_cfg.get("ntp_port"), 123, 1, 65535)
    time_cfg["ntp_sync_interval_seconds"] = _bounded_int(time_cfg.get("ntp_sync_interval_seconds"), 3600, 60, 604800)
    time_cfg["auto_sync"] = bool(time_cfg.get("auto_sync", True))
    merged["time"] = time_cfg
    governance = merged.get("governance") or {}
    governance["audit_retention_days"] = _bounded_int(governance.get("audit_retention_days"), 90, 1, 3650)
    governance["job_retention_days"] = _bounded_int(governance.get("job_retention_days"), 30, 1, 3650)
    governance["max_workers"] = _bounded_int(governance.get("max_workers"), 4, 1, 64)
    governance["session_timeout_minutes"] = _bounded_int(governance.get("session_timeout_minutes"), 60, 5, 1440)
    governance["auto_vacuum_enabled"] = bool(governance.get("auto_vacuum_enabled", True))
    governance["backup_retention_copies"] = _bounded_int(governance.get("backup_retention_copies"), 7, 1, 100)
    merged["governance"] = governance

    merged["version"] = int(previous.get("version", 1)) + 1

    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = CONFIG_FILE.with_suffix(".tmp")
    with _LOCK:
        temporary.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(CONFIG_FILE)
    apply_runtime(merged)
    record_revision(merged["version"], actor, summary, merged)
    return public_config(merged, include_admin=True)


def apply_runtime(config: dict[str, Any] | None = None) -> None:
    config = config or load()
    providers, analysis, ollama = config["providers"], config["analysis"], config["ollama"]
    vt_keys = providers["virustotal"].get("api_keys", []) if providers["virustotal"].get("enabled") else []
    os.environ["VIRUSTOTAL_API_KEYS"] = ",".join(vt_keys)
    os.environ["VIRUSTOTAL_API_KEY"] = vt_keys[0] if vt_keys else ""
    os.environ["VIRUSTOTAL_FALLBACK_API_KEY"] = vt_keys[1] if len(vt_keys) > 1 else ""
    os.environ["ABUSEIPDB_API_KEY"] = providers["abuseipdb"].get("api_key", "") if providers["abuseipdb"].get("enabled") else ""
    os.environ["MALWAREBAZAAR_AUTH_KEY"] = providers["malwarebazaar"].get("api_key", "") if providers["malwarebazaar"].get("enabled") else ""
    os.environ["FLOWSCOPE_ENRICH_WORKERS"] = str(analysis["flow_workers"])
    os.environ["WORD_PREVIEW_ENGINE"] = str(config["reports"]["preview_engine"])
    try:
        from . import audit_engine, ollama_advisor
        ollama_advisor.OLLAMA_URL = ollama["url"].rstrip("/")
        ollama_advisor.PREFERRED_MODEL = ollama["preferred_model"]
        ollama_advisor.FALLBACK_MODEL = ollama["fallback_model"]
        ollama_advisor.ENABLED = bool(ollama["enabled"])
        ollama_advisor.TIMEOUT_SECONDS = ollama["timeout_seconds"]
        ollama_advisor.MAX_RECORDS = ollama["max_records"]
        ollama_advisor._STATUS_CACHE.update({"checked": 0.0, "models": [], "error": None})
        import flowscope.enrichment as flow_enrichment
        import flowscope.file_parser as flow_file_parser
        import flowscope.analyzer as flow_analyzer
        import threatscope.enrichment as threat_enrichment
        import threatscope.analyzer as threat_analyzer
        import logscope.enrichment as log_enrichment
        import logscope.file_parser as log_file_parser
        import logscope.analyzer as log_analyzer
        import flowscope.server as flow_server
        import threatscope.server as threat_server
        import logscope.server as log_server
        flow_enrichment.CACHE_TTL_SECONDS = analysis["flow_cache_ttl_days"] * 86400
        threat_enrichment.CACHE_TTL_SECONDS = analysis["threat_cache_ttl_days"] * 86400
        log_enrichment.CACHE_TTL_SECONDS = analysis["log_cache_ttl_days"] * 86400
        flow_server.MAX_ENRICH_IPS = analysis["flow_max_external_ips"]
        log_server.MAX_ENRICH_IPS = analysis["log_max_external_ips"]
        uploads = config["uploads"]
        flow_server.MAX_UPLOAD_SIZE = uploads["flowscope_max_mb"] * 1024 * 1024
        threat_server.MAX_UPLOAD = uploads["threatscope_max_mb"] * 1024 * 1024
        log_server.MAX_UPLOAD_SIZE = uploads["logscope_max_mb"] * 1024 * 1024
        flow_file_parser.MAX_CSV_SIZE = flow_server.MAX_UPLOAD_SIZE
        flow_file_parser.MAX_XLSX_FILES = uploads["xlsx_max_files"]
        flow_file_parser.MAX_UNCOMPRESSED_BYTES = uploads["xlsx_max_uncompressed_mb"] * 1024 * 1024
        flow_file_parser.MAX_COMPRESSION_RATIO = uploads["xlsx_max_compression_ratio"]
        log_file_parser.MAX_CSV_SIZE = log_server.MAX_UPLOAD_SIZE
        log_file_parser.MAX_XLSX_FILES = uploads["xlsx_max_files"]
        log_file_parser.MAX_UNCOMPRESSED_BYTES = uploads["xlsx_max_uncompressed_mb"] * 1024 * 1024
        log_file_parser.MAX_COMPRESSION_RATIO = uploads["xlsx_max_compression_ratio"]
        flow_server.SOURCE_SYSTEMS = {item["id"]: item["label"] for item in config["source_systems"]["flowscope"]}
        threat_server.SOURCE_SYSTEMS = {item["id"]: item["label"] for item in config["source_systems"]["threatscope"]}
        log_server.SOURCE_SYSTEMS = {item["id"]: item["label"] for item in config["source_systems"]["logscope"]}
        flow_server.MODEL_ANALYSIS_ENABLED = bool(analysis["model_analysis_enabled"])
        threat_server.MODEL_ANALYSIS_ENABLED = bool(analysis["model_analysis_enabled"])
        log_server.MODEL_ANALYSIS_ENABLED = bool(analysis["model_analysis_enabled"])
        flow_server.AUTO_ENRICH = bool(analysis["auto_enrich"])
        threat_server.AUTO_ENRICH = bool(analysis["auto_enrich"])
        log_server.AUTO_ENRICH = bool(analysis["auto_enrich"])
        flow_server.LEARNING_ENABLED = bool(analysis["learning_enabled"])
        threat_server.LEARNING_ENABLED = bool(analysis["learning_enabled"])
        log_server.LEARNING_ENABLED = bool(analysis["learning_enabled"])
        flow_analyzer.RISK_THRESHOLDS = (analysis["medium_threshold"], analysis["high_threshold"], analysis["critical_threshold"])
        threat_analyzer.RISK_THRESHOLDS = (analysis["medium_threshold"], analysis["high_threshold"], analysis["critical_threshold"])
        log_analyzer.RISK_THRESHOLDS = (analysis["medium_threshold"], analysis["high_threshold"], analysis["critical_threshold"])
        audit_engine.configure(**config["logging"])
    except ImportError:
        pass
    try:
        from . import time_service
        time_service.get_time_service().apply_config(config.get("time", {}))
    except Exception:
        pass


def public_config(config: dict[str, Any] | None = None, *, include_admin: bool = False) -> dict[str, Any]:
    data = copy.deepcopy(config or load())
    if not include_admin:
        return {
            "version": data["version"], "appearance": data["appearance"],
            "general": data["general"], "features": data["features"],
            "source_systems": data["source_systems"],
            "uploads": {
                "flowscope_max_mb": data["uploads"]["flowscope_max_mb"],
                "threatscope_max_mb": data["uploads"]["threatscope_max_mb"],
                "logscope_max_mb": data["uploads"]["logscope_max_mb"],
            },
        }
    providers = data["providers"]
    providers["virustotal"]["configured_keys"] = len(providers["virustotal"].get("api_keys", []))
    providers["virustotal"]["api_keys"] = [MASK] * providers["virustotal"]["configured_keys"]
    for name in ("abuseipdb", "malwarebazaar"):
        providers[name]["configured"] = bool(providers[name].get("api_key"))
        providers[name]["api_key"] = MASK if providers[name]["configured"] else ""
    for item in data.get("external_apis", []):
        item["configured"] = bool(item.get("api_key"))
        item["api_key"] = MASK if item["configured"] else ""
    for item in data.get("ai_providers", []):
        item["configured"] = bool(item.get("api_key"))
        item["api_key"] = MASK if item["configured"] else ""
    return data


def apply_retention(config: dict[str, Any] | None = None) -> dict[str, int]:
    """Apply opt-in retention only inside validated platform storage roots."""
    settings = (config or load())["storage"]
    now = time.time()
    removed = {"jobs": 0, "audit_files": 0, "preview_directories": 0}
    job_days = int(settings.get("job_retention_days") or 0)
    if job_days > 0:
        cutoff = now - job_days * 86400
        for application in ("flowscope", "threatscope", "logscope"):
            root = (ROOT / application / "storage" / "jobs").resolve()
            if not root.is_dir():
                continue
            for target in root.iterdir():
                resolved = target.resolve()
                if resolved.parent != root or not target.is_dir() or not re.fullmatch(r"[0-9a-f]{32}", target.name):
                    continue
                marker = target / "analysis.json"
                if marker.is_file() and marker.stat().st_mtime < cutoff:
                    shutil.rmtree(target)
                    removed["jobs"] += 1
    audit_days = int(settings.get("audit_retention_days") or 0)
    audit_root = (ROOT / "storage" / "audit").resolve()
    if audit_days > 0 and audit_root.is_dir():
        cutoff = now - audit_days * 86400
        for target in audit_root.iterdir():
            if target.resolve().parent == audit_root and target.is_file() and target.suffix == ".jsonl" and target.stat().st_mtime < cutoff:
                target.unlink()
                removed["audit_files"] += 1
    preview_hours = int(settings.get("preview_retention_hours") or 0)
    preview_root = (ROOT / "tmp" / "report-previews").resolve()
    if preview_hours > 0 and preview_root.is_dir():
        cutoff = now - preview_hours * 3600
        for application in ("flowscope", "threatscope", "logscope"):
            app_root = (preview_root / application).resolve()
            if not app_root.is_dir() or app_root.parent != preview_root:
                continue
            for target in app_root.iterdir():
                if target.resolve().parent == app_root and target.is_dir() and re.fullmatch(r"[0-9a-f]{32}", target.name) and target.stat().st_mtime < cutoff:
                    shutil.rmtree(target)
                    removed["preview_directories"] += 1
    return removed


def test_connection(payload: dict[str, Any]) -> dict[str, Any]:
    kind = str(payload.get("kind") or "")
    config = load()
    if kind == "ollama":
        url = _valid_url(payload.get("url") or config["ollama"]["url"], "Ollama")
        request = urllib.request.Request(f"{url}/api/tags", headers={"Accept": "application/json"})
    elif kind == "external":
        item = payload.get("provider") or {}
        url = _valid_url(item.get("base_url"), "API الخارجي") + str(item.get("health_path") or "")
        headers = {"Accept": "application/json"}
        key = item.get("api_key")
        if key == MASK:
            stored = next((entry for entry in config.get("external_apis", []) if entry.get("id") == item.get("id")), {})
            key = stored.get("api_key")
        if key:
            headers[str(item.get("auth_header") or "Authorization")] = str(key)
        request = urllib.request.Request(url, headers=headers)
    elif kind == "ai":
        item = payload.get("provider") or {}
        url = _valid_url(item.get("base_url"), "مزود AI") + str(item.get("models_path") or "/v1/models")
        headers = {"Accept": "application/json"}
        key = str(item.get("api_key") or "")
        if key == MASK:
            stored = next((entry for entry in config.get("ai_providers", []) if entry.get("id") == item.get("id")), {})
            key = str(stored.get("api_key") or "")
        if key:
            headers[str(item.get("auth_header") or "Authorization")] = str(item.get("auth_prefix") if item.get("auth_prefix") is not None else "Bearer ") + key
        request = urllib.request.Request(url, headers=headers)
    elif kind == "ntp":
        from . import time_service
        server = str(payload.get("ntp_server") or payload.get("server") or config.get("time", {}).get("ntp_server") or "pool.ntp.org").strip()
        port = int(payload.get("ntp_port") or payload.get("port") or config.get("time", {}).get("ntp_port") or 123)
        res = time_service.query_ntp_server(server=server, port=port, timeout=4.0)
        if res.get("success"):
            return {
                "ok": True,
                "status": 200,
                "message": f"تم الاتصال بخادم NTP ({server}) بنجاح.",
                "sample": f"Stratum: {res.get('stratum')}, Delay: {res.get('delay_ms')}ms, Offset: {res.get('offset'):+.4f}s, Time: {res.get('server_time_iso')}",
            }
        else:
            return {
                "ok": False,
                "status": None,
                "message": str(res.get("error") or "فشل الاتصال بخادم NTP"),
            }
    else:
        raise ValueError("نوع اختبار الاتصال غير مدعوم.")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            sample = response.read(512).decode("utf-8", errors="replace")
            return {"ok": True, "status": response.status, "message": "تم الاتصال بنجاح.", "sample": sample[:300]}
    except Exception as exc:
        return {"ok": False, "status": None, "message": str(exc)[:300]}


def storage_stats() -> dict[str, Any]:
    """Calculate real disk and storage statistics across platform roots."""
    apps = ("flowscope", "threatscope", "logscope")
    jobs_info: dict[str, Any] = {}
    total_jobs_bytes = 0
    total_jobs_count = 0

    for app in apps:
        app_jobs_dir = (ROOT / app / "storage" / "jobs").resolve()
        count = 0
        size_bytes = 0
        if app_jobs_dir.is_dir():
            try:
                for entry in app_jobs_dir.iterdir():
                    if entry.is_dir() and re.fullmatch(r"[0-9a-f]{32}", entry.name):
                        count += 1
                        for root, _, files in os.walk(entry):
                            for f in files:
                                try:
                                    size_bytes += os.path.getsize(os.path.join(root, f))
                                except OSError:
                                    pass
            except OSError:
                pass
        jobs_info[app] = {"count": count, "bytes": size_bytes}
        total_jobs_bytes += size_bytes
        total_jobs_count += count

    audit_dir = (ROOT / "storage" / "audit").resolve()
    audit_count = 0
    audit_bytes = 0
    if audit_dir.is_dir():
        try:
            for entry in audit_dir.iterdir():
                if entry.is_file() and entry.suffix == ".jsonl":
                    audit_count += 1
                    try:
                        audit_bytes += entry.stat().st_size
                    except OSError:
                        pass
        except OSError:
            pass

    preview_dir = (ROOT / "tmp" / "report-previews").resolve()
    preview_count = 0
    preview_bytes = 0
    if preview_dir.is_dir():
        try:
            for root, _, files in os.walk(preview_dir):
                for f in files:
                    preview_count += 1
                    try:
                        preview_bytes += os.path.getsize(os.path.join(root, f))
                    except OSError:
                        pass
        except OSError:
            pass

    storage_dir = (ROOT / "storage").resolve()
    try:
        disk_total, disk_used, disk_free = shutil.disk_usage(storage_dir if storage_dir.is_dir() else ROOT)
    except OSError:
        disk_total, disk_used, disk_free = 0, 0, 0

    return {
        "disk": {
            "total_bytes": disk_total,
            "used_bytes": disk_used,
            "free_bytes": disk_free,
            "used_percent": round((disk_used / disk_total) * 100, 1) if disk_total > 0 else 0,
        },
        "jobs": {
            "total_count": total_jobs_count,
            "total_bytes": total_jobs_bytes,
            "flowscope": jobs_info.get("flowscope", {"count": 0, "bytes": 0}),
            "threatscope": jobs_info.get("threatscope", {"count": 0, "bytes": 0}),
            "logscope": jobs_info.get("logscope", {"count": 0, "bytes": 0}),
        },
        "audit": {
            "file_count": audit_count,
            "bytes": audit_bytes,
        },
        "previews": {
            "file_count": preview_count,
            "bytes": preview_bytes,
        },
    }
