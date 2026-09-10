"""Unified API server for FlowScope and ThreatScope."""

from __future__ import annotations

import json
import os
import re
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flowscope import server as flow_server
from platform_core.history import operation_history
from threatscope import server as threat_server
from logscope import server as log_server
from platform_core import (
    learning_engine, ollama_advisor, security_auth, platform_config, audit_engine,
    incident_manager, detection_engine, detection_correlation, sigma_engine, threat_intel,
    asset_manager, graph_correlation, case_export, ai_copilot, database, enterprise,
    time_service, authorization, notification_engine, backup_manager, search_engine, investigation_manager,
)
from platform_core.licensing import LicenseManager
from platform_core.api.router import get_api_router
from platform_core.api.v1.routes import register_v1_routes
from platform_core.feature_gate import get_feature_gate
from endpointscope.collector import get_endpoint_collector
from endpointscope.monitor import get_endpoint_monitor
from platform_core.logging import (
    get_logger,
    init_platform_logging,
    get_log_storage,
    get_metrics,
    set_platform_log_level,
    get_platform_log_level,
    get_log_handler,
    set_context,
    clear_context,
    get_current_context,
)

# Initialize official v1 API routes
v1_api_router = register_v1_routes()



def _get_process_memory() -> int:
    """Safely obtain current process working set memory in bytes."""
    try:
        import ctypes
        from ctypes import wintypes

        class PMC(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("pfc", wintypes.DWORD),
                ("pwss", ctypes.c_size_t),
                ("wss", ctypes.c_size_t),
                ("qpppu", ctypes.c_size_t),
                ("qppu", ctypes.c_size_t),
                ("qpnp", ctypes.c_size_t),
                ("qnp", ctypes.c_size_t),
                ("pfu", ctypes.c_size_t),
                ("ppfu", ctypes.c_size_t),
            ]

        c = PMC()
        c.cb = ctypes.sizeof(PMC)
        fn = ctypes.windll.psapi.GetProcessMemoryInfo
        fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
        fn.restype = wintypes.BOOL
        if fn(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(c), c.cb):
            return int(c.wss)
    except Exception:
        pass
    return 0


def _get_platform_health_data() -> dict:
    t0 = time.monotonic()
    components = []

    # 1. Backend Server
    mem_bytes = _get_process_memory()
    mem_mb = mem_bytes / (1024 * 1024) if mem_bytes else 0.0
    components.append({
        "id": "backend",
        "name_ar": "خادم بايثون الموحد",
        "name_en": "Unified Backend Server",
        "status": "healthy",
        "latency_ms": round((time.monotonic() - t0) * 1000, 2),
        "details": {
            "host": HOST,
            "port": PORT,
            "threads": threading.active_count(),
            "working_set_mb": round(mem_mb, 2),
        },
        "last_checked": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })

    # 2. Gateway Proxy
    components.append({
        "id": "gateway",
        "name_ar": "بوابة واجهة برمجة التطبيقات (Gateway)",
        "name_en": "API Gateway",
        "status": "healthy",
        "latency_ms": 0.5,
        "details": {"port": 3000, "engine_proxy": f"http://{HOST}:{PORT}"},
        "last_checked": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })

    # 3. SQLite Platform Logs DB
    logs_db_t0 = time.monotonic()
    logs_db_status = "healthy"
    records_count = 0
    db_size_mb = 0.0
    try:
        storage = get_log_storage()
        kpis = storage.get_kpis()
        records_count = kpis.get("total_events", 0)
        db_path = storage.db_path
        if db_path.exists():
            db_size_mb = round(db_path.stat().st_size / (1024 * 1024), 2)
    except Exception:
        logs_db_status = "unhealthy"
    components.append({
        "id": "logs_db",
        "name_ar": "قاعدة بيانات سجلات المنصة (SQLite)",
        "name_en": "Platform Logs SQLite Database",
        "status": logs_db_status,
        "latency_ms": round((time.monotonic() - logs_db_t0) * 1000, 2),
        "details": {"records": records_count, "size_mb": db_size_mb, "wal_mode": True},
        "last_checked": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })

    # 4. Cryptographic Audit Hash Chain
    audit_t0 = time.monotonic()
    audit_ok, audit_msg = audit_engine.verify_audit_integrity()
    audit_status = "healthy" if audit_ok else "degraded"
    components.append({
        "id": "audit_chain",
        "name_ar": "سلسلة تجزئة سجلات التدقيق التشفيرية",
        "name_en": "Cryptographic Audit Hash Chain",
        "status": audit_status,
        "latency_ms": round((time.monotonic() - audit_t0) * 1000, 2),
        "details": {"verified": audit_ok, "summary": audit_msg},
        "last_checked": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })

    # 5. ThreatScope Engine
    ts_status = "healthy" if threat_server.JOBS.exists() else "degraded"
    components.append({
        "id": "threatscope",
        "name_ar": "محرك تحليل التهديدات (ThreatScope)",
        "name_en": "ThreatScope Analysis Engine",
        "status": ts_status,
        "latency_ms": 0.1,
        "details": {"jobs_dir": str(threat_server.JOBS.name), "ready": True},
        "last_checked": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })

    # 6. FlowScope Engine
    fs_status = "healthy" if flow_server.JOBS_DIR.exists() else "degraded"
    components.append({
        "id": "flowscope",
        "name_ar": "محرك تحليل تدفق الشبكة (FlowScope)",
        "name_en": "FlowScope Traffic Analyzer",
        "status": fs_status,
        "latency_ms": 0.1,
        "details": {"jobs_dir": str(flow_server.JOBS_DIR.name), "ready": True},
        "last_checked": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })

    # 7. LogScope Engine
    ls_status = "healthy" if log_server.JOBS_DIR.exists() else "degraded"
    components.append({
        "id": "logscope",
        "name_ar": "محرك تحليل السجلات الأمنية (LogScope)",
        "name_en": "LogScope Security Log Engine",
        "status": ls_status,
        "latency_ms": 0.1,
        "details": {"jobs_dir": str(log_server.JOBS_DIR.name), "ready": True},
        "last_checked": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })

    # 8. System & Process Memory
    mem_status = "healthy"
    if mem_mb > 1024:
        mem_status = "degraded"
    components.append({
        "id": "memory",
        "name_ar": "ذاكرة النظام والعمليات",
        "name_en": "System & Process Memory",
        "status": mem_status,
        "latency_ms": 0.1,
        "details": {"working_set_mb": round(mem_mb, 2)},
        "last_checked": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })

    # 9. Disk Storage Capacity
    disk_status = "healthy"
    free_gb = 0.0
    total_gb = 0.0
    try:
        import shutil
        usage = shutil.disk_usage(os.path.dirname(__file__) or ".")
        free_gb = usage.free / (1024 ** 3)
        total_gb = usage.total / (1024 ** 3)
        if free_gb < 1.0:
            disk_status = "unhealthy"
        elif free_gb < 5.0:
            disk_status = "degraded"
    except Exception:
        pass
    components.append({
        "id": "disk",
        "name_ar": "مساحة التخزين والقرص",
        "name_en": "Disk Storage Capacity",
        "status": disk_status,
        "latency_ms": 0.2,
        "details": {"free_gb": round(free_gb, 2), "total_gb": round(total_gb, 2)},
        "last_checked": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })

    # 10. Async Log Processing Worker
    handler = get_log_handler()
    worker_alive = handler.is_alive()
    metrics = get_metrics().snapshot()
    dropped = metrics.get("dropped_total", 0)
    q_depth = metrics.get("queue_depth", 0)
    worker_status = "healthy"
    if not worker_alive:
        worker_status = "unhealthy"
    elif dropped > 0 or q_depth > 5000:
        worker_status = "degraded"
    components.append({
        "id": "log_worker",
        "name_ar": "خيط معالجة السجلات غير المتزامن",
        "name_en": "Async Log Processing Worker",
        "status": worker_status,
        "latency_ms": 0.1,
        "details": {
            "is_alive": worker_alive,
            "queue_depth": q_depth,
            "logs_written": metrics.get("written_total", 0),
            "logs_dropped": dropped,
        },
        "last_checked": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })

    overall = "healthy"
    if any(c["status"] == "unhealthy" for c in components):
        overall = "unhealthy"
    elif any(c["status"] == "degraded" for c in components):
        overall = "degraded"

    sys_metrics = enterprise.ClusterHealthManager.get_system_metrics()
    enterprise.ClusterHealthManager.record_sample({
        "timestamp": sys_metrics["timestamp"],
        "cpu_percent": sys_metrics["cpu_percent"],
        "ram_percent": sys_metrics["ram_percent"],
        "disk_percent": sys_metrics["disk_percent"],
        "latency_ms": round((time.monotonic() - t0) * 1000, 2),
        "status": overall,
    })

    return {
        "status": overall,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "system_metrics": sys_metrics,
        "components": components,
    }



HOST = os.environ.get("ANALYSIS_ENGINE_HOST", "127.0.0.1")
PORT = int(os.environ.get("ANALYSIS_ENGINE_PORT", "8082"))
ALLOWED_ORIGINS = {
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    *(origin.strip() for origin in os.environ.get("SECURITY_ALLOWED_ORIGINS", "").split(",") if origin.strip()),
}
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_LOGIN_LOCK = threading.Lock()
_LOGIN_WINDOW_SECONDS = 300
_LOGIN_MAX_ATTEMPTS = 5


class ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class UnifiedAPIHandler(threat_server.Handler):
    """Route both applications through one API origin and namespace."""

    server_version = "SecurityBackend/2.0"
    _run_analysis = flow_server.RequestHandler._run_analysis
    _run_enrichment = flow_server.RequestHandler._run_enrichment

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        req_id = self.headers.get("X-Request-ID") or f"REQ-{uuid.uuid4().hex[:10].upper()}"
        corr_id = self.headers.get("X-Correlation-ID") or f"CORR-{uuid.uuid4().hex[:10].upper()}"
        job_id = self.headers.get("X-Job-ID") or ""
        client_ip = self.client_address[0] if self.client_address else ""
        set_context(
            request_id=req_id,
            correlation_id=corr_id,
            job_id=job_id,
            client_ip=client_ip,
            component="backend",
        )
        return True

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except Exception as exc:
            logger = get_logger("backend")
            logger.exception("Unhandled backend exception", exc=exc, event_code="GENERAL_ERROR")
            logger.exception("حدث استثناء غير معالج في الخادم الموحد", exc=exc, event_code="GENERAL_ERROR")
            raise
        finally:
            clear_context()

    def end_headers(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Filename, X-Source-System, Cache-Control")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, PATCH, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Filename, X-Source-System, Cache-Control, X-Request-ID, X-Correlation-ID, X-Job-ID")
        self.send_header("Access-Control-Expose-Headers", "X-Request-ID, X-Correlation-ID")
        ctx = get_current_context()
        if ctx.get("request_id"):
            self.send_header("X-Request-ID", ctx["request_id"])
        if ctx.get("correlation_id"):
            self.send_header("X-Correlation-ID", ctx["correlation_id"])
        super().end_headers()

    def _headers_dict(self) -> dict[str, str]:
        if not hasattr(self, "headers") or self.headers is None:
            return {}
        if hasattr(self.headers, "items"):
            return {str(k): str(v) for k, v in self.headers.items()}
        try:
            return {str(k): str(self.headers[k]) for k in self.headers}
        except Exception:
            return {}

    def do_OPTIONS(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin and origin not in ALLOWED_ORIGINS:
            self._json(403, {"error": "Origin is not allowed"})
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/system/health":
            self._json(200, {
                "status": "ok",
                "service": "security-backend",
                "applications": {"flowscope": "ok", "threatscope": "ok", "logscope": "ok"},
            })
            return
        if path == "/api/platform/health":
            self._json(200, _get_platform_health_data())
            return
        if path == "/api/platform/health/history":
            samples = enterprise.ClusterHealthManager.get_history(limit=60)
            self._json(200, {"samples": samples, "total": len(samples)})
            return
        if path == "/api/settings/public":
            self._json(200, platform_config.public_config())
            return
        if path == "/api/auth/status":
            identity = security_auth.request_identity(self.headers)
            self._json(200, {"authenticated": bool(identity), "user": identity})
            return
        if path.startswith("/api/v1/"):
            identity = security_auth.request_identity(self.headers)
            auth_ctx = {"authenticated": bool(identity), "user": identity}
            resp = v1_api_router.dispatch(
                method="GET",
                raw_url=self.path,
                headers=self._headers_dict(),
                auth_context=auth_ctx,
            )
            self._json(resp.status_code, resp.to_dict())
            return
        identity = self._require_authentication()
        if not identity:
            return
        if path in ("/api/platform/logs", "/api/platform-logs"):
            ctx = authorization.build_security_context(identity)
            can_view_all = ctx.has_permission("platform_logs.view_all") or ctx.has_permission("system.status") or ctx.has_permission("users.manage")
            can_view_shared = ctx.has_permission("platform_logs.view_shared")
            can_view_own = ctx.has_permission("platform_logs.view_own")
            if not (can_view_all or can_view_shared or can_view_own):
                self._json(403, {"error": "ليست لديك صلاحية لاستعراض سجلات المنصة والتدقيق.", "code": "permission_denied"})
                return
            params = parse_qs(urlparse(self.path).query)
            page = max(1, int(params.get("page", [1])[0]))
            limit = min(200, max(1, int(params.get("limit", [50])[0])))
            level = params.get("level", [None])[0]
            component = params.get("component", [None])[0]
            event_type = params.get("event_type", [None])[0]
            event_code = params.get("event_code", [None])[0]
            search = params.get("search", [None])[0] or params.get("q", [None])[0]
            correlation_id = params.get("correlation_id", [None])[0]
            request_id = params.get("request_id", [None])[0]
            job_id = params.get("job_id", [None])[0]
            date_from = params.get("from", [None])[0]
            date_to = params.get("to", [None])[0]
            sort_dir = params.get("sort_dir", ["DESC"])[0]

            if not can_view_all and not can_view_shared and can_view_own:
                search = identity["username"]

            storage = get_log_storage()
            res = storage.query_logs(
                page=page,
                limit=limit,
                level=level,
                component=component,
                event_type=event_type,
                event_code=event_code,
                search=search,
                correlation_id=correlation_id,
                request_id=request_id,
                job_id=job_id,
                date_from=date_from,
                date_to=date_to,
                sort_dir=sort_dir,
            )
            kpis = storage.get_kpis()
            metrics = get_metrics().snapshot()
            self._json(200, {
                "logs": res.get("logs", []),
                "total": res.get("total", 0),
                "page": res.get("page", page),
                "limit": res.get("limit", limit),
                "total_pages": res.get("total_pages", 1),
                "kpis": kpis,
                "metrics": metrics,
                "current_level": get_platform_log_level(),
            })
            return
        if path.startswith("/api/platform/logs/correlation/"):
            if not self._require_permission(identity, "system.status"):
                return
            corr_id = path.replace("/api/platform/logs/correlation/", "").strip()
            storage = get_log_storage()
            timeline = storage.get_correlation_timeline(corr_id)
            self._json(200, {
                "correlation_id": corr_id,
                "total": len(timeline),
                "timeline": timeline,
            })
            return
        if path == "/api/platform/performance":
            if not self._require_permission(identity, "system.status"):
                return
            metrics = get_metrics().snapshot()
            storage = get_log_storage()
            kpis = storage.get_kpis()
            mem_bytes = _get_process_memory()
            self._json(200, {
                "metrics": metrics,
                "kpis": kpis,
                "memory_mb": round(mem_bytes / (1024 * 1024), 2) if mem_bytes else 0.0,
                "active_threads": threading.active_count(),
            })
            return
        if path == "/api/platform/time":
            self._json(200, time_service.get_time_service().get_status())
            return
        if path == "/api/licensing/status":
            mgr = LicenseManager.get_instance()
            self._json(200, mgr.get_license_info().to_dict())
            return
        if path == "/api/admin/users":
            if not self._require_permission(identity, "users.manage"):
                return
            self._json(200, {"users": security_auth.list_users(), "catalog": security_auth.permission_catalog()})
            return
        if path == "/api/authorization/roles":
            if not self._require_permission(identity, "roles.view", "users.manage"):
                return
            self._json(200, {"roles": authorization.list_all_roles()})
            return
        if path == "/api/authorization/groups":
            if not self._require_permission(identity, "groups.view", "users.manage"):
                return
            self._json(200, {"groups": authorization.list_all_groups()})
            return
        if path == "/api/authorization/scopes":
            self._json(200, {"scopes": authorization.get_available_scopes()})
            return
        if path == "/api/authorization/catalog":
            self._json(200, {
                "catalog": authorization.get_permission_catalog(),
                "roles": authorization.list_all_roles(),
                "groups": authorization.list_all_groups(),
                "scopes": authorization.get_available_scopes(),
            })
            return
        if path == "/api/authorization/my-profile":
            ctx = authorization.build_security_context(identity)
            self._json(200, authorization.get_my_access_profile(ctx))
            return
        sim_match = re.fullmatch(r"/api/authorization/simulate/([A-Za-z0-9_-]+)", path)
        if sim_match:
            if not self._require_permission(identity, "users.manage"):
                return
            try:
                ctx = authorization.build_security_context(identity)
                res = authorization.simulate_user_access(ctx, sim_match.group(1))
                audit_engine.record_engine_event(
                    action="authorization.view_as_user",
                    user=identity["username"],
                    details={"target_user": sim_match.group(1)},
                )
                self._json(200, res)
            except Exception as e:
                self._json(404, {"error": str(e)})
            return
        if path == "/api/authorization/sharing/my-shared":
            ctx = authorization.build_security_context(identity)
            self._json(200, {"shared_resources": authorization.get_user_shares(ctx.user_id, ctx.groups)})
            return
        if path == "/api/authorization/sharing/resource":
            if not self._require_permission(identity, "sharing.view", "incidents.view", "users.manage"):
                return
            params = parse_qs(urlparse(self.path).query)
            res_type = str(params.get("type", [""])[0])
            res_id = str(params.get("id", [""])[0])
            shares = authorization.get_shares(res_type, res_id)
            self._json(200, {"shares": shares, "total": len(shares)})
            return
        if path == "/api/system/services":
            self._json(200, {
                "flowscope": security_auth.has_permission(identity, "flowscope.view"),
                "threatscope": security_auth.has_permission(identity, "threatscope.view"),
                "logscope": security_auth.has_permission(identity, "logscope.view"),
            })
            return
        if path == "/api/history":
            if not self._require_permission(identity, "history.view"):
                return
            operations = operation_history()
            operations = [item for item in operations if security_auth.has_permission(identity, f"{item['application']}.view")]
            ctx = authorization.build_security_context(identity)
            operations = authorization.filter_dataset(ctx, operations, "logs")
            self._json(200, {"total": len(operations), "operations": operations})
            return
        if path == "/api/learning/status":
            if not self._require_permission(identity, "system.status"):
                return
            self._json(200, learning_engine.model_status())
            return
        if path == "/api/model/status":
            if not self._require_permission(identity, "system.status"):
                return
            self._json(200, ollama_advisor.service_status(force=True))
            return
        if path == "/api/settings":
            if not self._require_permission(identity, "users.manage"):
                return
            self._json(200, {
                "config": platform_config.public_config(include_admin=True),
                "defaults": platform_config.public_config(platform_config.DEFAULTS, include_admin=True),
            })
            return
        if path == "/api/settings/storage-stats":
            if not self._require_permission(identity, "users.manage"):
                return
            self._json(200, platform_config.storage_stats())
            return
        if path == "/api/settings/history":
            if not self._require_permission(identity, "users.manage"):
                return
            params = parse_qs(urlparse(self.path).query)
            try:
                limit_val = int(params.get("limit", [50])[0])
            except Exception:
                limit_val = 50
            history = platform_config.get_config_history(limit=limit_val)
            self._json(200, {"history": history, "total": len(history)})
            return
        if path == "/api/incidents":
            if not self._require_permission(identity, "incidents.view"):
                return
            params = parse_qs(urlparse(self.path).query)
            status = params.get("status", [None])[0]
            severity = params.get("severity", [None])[0]
            priority = params.get("priority", [None])[0]
            source_app = params.get("source_app", [None])[0]
            assigned_to = params.get("assigned_to", [None])[0]
            search = params.get("search", [None])[0] or params.get("q", [None])[0]
            limit = int(params.get("limit", [25])[0])
            offset = int(params.get("offset", [0])[0])
            if "page" in params:
                page = max(1, int(params["page"][0]))
                offset = (page - 1) * limit
            items, total = incident_manager.list_incidents(
                status=status, severity=severity, priority=priority,
                source_app=source_app, assigned_to=assigned_to, search=search,
                limit=limit, offset=offset
            )
            self._json(200, {"incidents": items, "total": total, "limit": limit, "offset": offset})
            ctx = authorization.build_security_context(identity)
            items = authorization.filter_dataset(ctx, items, "incidents")
            self._json(200, {"incidents": items, "total": len(items) if ctx.data_scope != "all" else total, "limit": limit, "offset": offset})
            return
        if path == "/api/incidents/summary":
            if not self._require_permission(identity, "incidents.view"):
                return
            self._json(200, incident_manager.get_incidents_summary())
            return
        if path == "/api/copilot/status":
            if not self._require_permission(identity, "incidents.view"):
                return
            self._json(200, ai_copilot.get_copilot_status())
            return
        if path == "/api/database/status":
            if not self._require_permission(identity, "database.status"):
                return
            mgr = database.DatabaseManager.get_instance()
            self._json(200, mgr.get_status())
            return
        if path == "/api/enterprise/status":
            if not self._require_permission(identity, "enterprise.view"):
                return
            status = {
                "cluster": enterprise.ClusterHealthManager.get_cluster_status(),
                "queue": enterprise.EnterpriseTaskQueue.get_instance().get_metrics(),
                "storage": enterprise.StorageGovernanceManager.get_storage_breakdown(),
                "tenants_count": len(enterprise.TenantManager.get_instance().list_tenants()),
            }
            self._json(200, status)
            return
        if path == "/api/enterprise/tenants":
            if not self._require_permission(identity, "enterprise.view"):
                return
            tenants = [t.to_dict() for t in enterprise.TenantManager.get_instance().list_tenants()]
            self._json(200, {"tenants": tenants, "total": len(tenants)})
            return
        if path == "/api/enterprise/tasks":
            if not self._require_permission(identity, "enterprise.view"):
                return
            params = parse_qs(urlparse(self.path).query)
            status_param = params.get("status", [None])[0]
            tenant_param = params.get("tenant_id", [None])[0]
            search_param = params.get("search", [None])[0]
            try:
                limit_val = int(params.get("limit", [50])[0])
            except Exception:
                limit_val = 50
            try:
                offset_val = int(params.get("offset", [0])[0])
            except Exception:
                offset_val = 0
            q = enterprise.EnterpriseTaskQueue.get_instance()
            tasks = q.list_tasks(tenant_id=tenant_param, status=status_param, search=search_param, limit=limit_val, offset=offset_val)
            total = q.count_tasks(tenant_id=tenant_param, status=status_param, search=search_param)
            metrics = q.get_metrics()
            self._json(200, {"tasks": tasks, "total": total, "metrics": metrics})
            return
        if path == "/api/enterprise/storage":
            if not self._require_permission(identity, "enterprise.view"):
                return
            breakdown = enterprise.StorageGovernanceManager.get_storage_breakdown()
            self._json(200, breakdown)
            return
        if path == "/api/platform/backups":
            if not self._require_permission(identity, "enterprise.view"):
                return
            backups = backup_manager.BackupManager.get_instance().list_backups()
            self._json(200, {"backups": backups})
            return
        if path == "/api/platform/backup/download":
            if not self._require_permission(identity, "enterprise.view"):
                return
            params = parse_qs(urlparse(self.path).query)
            fn = params.get("filename", [""])[0]
            if not fn:
                self._json(400, {"error": "Missing filename parameter"})
                return
            try:
                bm = backup_manager.BackupManager.get_instance()
                file_path = bm.get_backup_path(fn)
                if not file_path.exists():
                    self._json(404, {"error": "Backup file not found"})
                    return
                data = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{file_path.name}"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            except Exception as e:
                self._json(500, {"error": str(e)})
                return
        if path == "/api/platform/search":
            params = parse_qs(urlparse(self.path).query)
            q = params.get("q", [""])[0] or params.get("query", [""])[0]
            ent_param = params.get("entities", [None])[0]
            entities = [e.strip() for e in ent_param.split(",")] if ent_param else None
            try:
                limit = int(params.get("limit", [5])[0])
            except Exception:
                limit = 5
            se = search_engine.GlobalSearchEngine.get_instance()
            res = se.search(query=q, entities=entities, limit_per_entity=limit)
            self._json(200, res)
            return
        if path == "/api/audit/verify":
            if not self._require_permission(identity, "history.view"):
                return
            ok, msg = audit_engine.verify_audit_integrity()
            self._json(200, {"verified": ok, "message": msg})
            return
        if path == "/api/notifications":
            params = parse_qs(urlparse(self.path).query)
            user_val = identity.get("username", "*")
            unread_only = params.get("unread", ["false"])[0].lower() in ("true", "1")
            cat = params.get("category", [None])[0]
            try:
                lim = int(params.get("limit", [50])[0])
            except Exception:
                lim = 50
            try:
                off = int(params.get("offset", [0])[0])
            except Exception:
                off = 0
            notifs = notification_engine.list_notifications(user=user_val, unread_only=unread_only, category=cat, limit=lim, offset=off)
            unread_cnt = notification_engine.get_unread_count(user=user_val)
            self._json(200, {"notifications": notifs, "unread_count": unread_cnt, "total": len(notifs)})
            return
        if path == "/api/investigations/summary":
            if not self._require_permission(identity, "incidents.view"):
                return
            summary = investigation_manager.InvestigationManager.get_instance().get_summary()
            self._json(200, summary)
            return
        if path == "/api/investigations":
            if not self._require_permission(identity, "incidents.view"):
                return
            params = parse_qs(urlparse(self.path).query)
            st = params.get("status", [None])[0]
            prio = params.get("priority", [None])[0]
            lead = params.get("lead_analyst", [None])[0]
            search = params.get("search", [None])[0] or params.get("q", [None])[0]
            try:
                lim = int(params.get("limit", [25])[0])
            except Exception:
                lim = 25
            try:
                off = int(params.get("offset", [0])[0])
            except Exception:
                off = 0
            if "page" in params:
                try:
                    page = max(1, int(params["page"][0]))
                    off = (page - 1) * lim
                except Exception:
                    pass
            mgr = investigation_manager.InvestigationManager.get_instance()
            items, total = mgr.list_investigations(
                status=st, priority=prio, lead_analyst=lead, search=search, limit=lim, offset=off
            )
            self._json(200, {"investigations": items, "total": total, "limit": lim, "offset": off})
            return
        inv_match = re.fullmatch(r"/api/investigations/([A-Za-z0-9_-]+)", path)
        if inv_match:
            if not self._require_permission(identity, "incidents.view"):
                return
            inv_id = inv_match.group(1)
            inv = investigation_manager.InvestigationManager.get_instance().get_investigation(inv_id)
            if not inv:
                self._json(404, {"error": "Investigation not found"})
                return
            self._json(200, inv)
            return
        inc_match = re.fullmatch(r"/api/incidents/([A-Za-z0-9_-]+)", path)
        if inc_match:
            if not self._require_permission(identity, "incidents.view"):
                return
            inc = incident_manager.get_incident(inc_match.group(1))
            if not inc:
                self._json(404, {"error": "الحادث الأمني غير موجود."})
                return
            ctx = authorization.build_security_context(identity)
            decision = authorization.evaluate_policy(ctx, action="incidents.view", resource_type="incidents", resource_data=inc)
            if not decision.allowed:
                self._json(403, {"error": decision.reason, "code": decision.code})
                return
            self._json(200, inc)
            return
        evi_download_match = re.fullmatch(r"/api/incidents/([A-Za-z0-9_-]+)/evidence/([A-Za-z0-9_-]+)/download", path)
        if evi_download_match:
            if not self._require_permission(identity, "incidents.view"):
                return
            self._serve_evidence_file(evi_download_match.group(1), evi_download_match.group(2))
            return
        inc_case_match = re.fullmatch(r"/api/incidents/([A-Za-z0-9_-]+)/case-export", path)
        if inc_case_match:
            if not self._require_permission(identity, "incidents.export"):
                return
            inc_id = inc_case_match.group(1)
            try:
                zip_bytes, filename = case_export.SecurityCaseExporter.export_case(inc_id, actor=identity.get("username", "analyst"))
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(zip_bytes)))
                self.end_headers()
                self.wfile.write(zip_bytes)
            except ValueError as e:
                self._json(404, {"error": str(e)})
            except Exception as e:
                self._json(500, {"error": f"فشل تصدير ملف التحقيق: {str(e)}"})
            return
        if path == "/api/detections":
            if not self._require_permission(identity, "detections.view"):
                return
            params = parse_qs(urlparse(self.path).query)
            category = params.get("category", [None])[0]
            severity = params.get("severity", [None])[0]
            lifecycle = params.get("lifecycle", [None])[0]
            status = params.get("status", [None])[0]
            search = params.get("search", [None])[0] or params.get("q", [None])[0]
            tactic = params.get("tactic", [None])[0]
            include_deleted = params.get("include_deleted", ["false"])[0].lower() in {"1", "true"}

            engine = detection_engine.get_detection_engine()
            rules = engine.get_all_rules(include_deleted=include_deleted)

            if category and category != "all":
                if category.lower() == "sigma":
                    rules = [
                        r for r in rules
                        if getattr(r, "source_format", "").lower() == "sigma"
                        or r.id.startswith("SIGMA-")
                        or r.category.lower() == "sigma"
                    ]
                else:
                    rules = [r for r in rules if r.category.lower() == category.lower()]
            if severity and severity != "all":
                rules = [r for r in rules if r.severity.lower() == severity.lower()]
            if lifecycle and lifecycle != "all":
                rules = [r for r in rules if r.lifecycle.lower() == lifecycle.lower()]
            if status and status != "all":
                if status in {"enabled", "active"}:
                    rules = [r for r in rules if r.enabled]
                elif status in {"disabled", "inactive"}:
                    rules = [r for r in rules if not r.enabled]
            if tactic and tactic != "all":
                rules = [r for r in rules if tactic.lower() in [t.lower() for t in r.mitre_attack.get("tactics", [])]]
            if search:
                s_lower = search.lower()
                rules = [
                    r for r in rules
                    if s_lower in r.id.lower() or s_lower in r.name.lower() or s_lower in r.name_en.lower() or s_lower in r.description.lower()
                ]

            total = len(rules)
            limit = int(params.get("limit", [100])[0])
            offset = int(params.get("offset", [0])[0])
            if "page" in params:
                page = max(1, int(params["page"][0]))
                offset = (page - 1) * limit

            paged = rules[offset:offset + limit]
            self._json(200, {
                "rules": [r.to_dict() for r in paged],
                "total": total,
                "limit": limit,
                "offset": offset,
                "summary": engine.get_summary()
            })
            return
        if path == "/api/detections/summary":
            if not self._require_permission(identity, "detections.view"):
                return
            self._json(200, detection_engine.get_detection_engine().get_summary())
            return
        if path == "/api/detections/export":
            if not self._require_permission(identity, "detections.view"):
                return
            pkg = detection_engine.get_detection_engine().export_rules_package()
            self._json(200, pkg)
            return
        det_match = re.fullmatch(r"/api/detections/([A-Za-z0-9_-]+)", path)
        if det_match:
            if not self._require_permission(identity, "detections.view"):
                return
            rule = detection_engine.get_detection_engine().get_rule(det_match.group(1))
            if not rule:
                self._json(404, {"error": "قاعدة الكشف غير موجودة."})
                return
            self._json(200, rule.to_dict())
            return
        if path == "/api/sigma/rules":
            if not self._require_permission(identity, "detections.view"):
                return
            params = parse_qs(urlparse(self.path).query)
            source_type = params.get("source_type", [None])[0]
            status = params.get("status", [None])[0]
            level = params.get("level", [None])[0]
            search = params.get("search", [None])[0] or params.get("q", [None])[0]

            eng = sigma_engine.SigmaEngine.get_instance()
            rules = eng.get_all_rules_summary()
            if source_type and source_type != "all":
                rules = [r for r in rules if r.get("source_type") == source_type]
            if status and status != "all":
                rules = [r for r in rules if r.get("status") == status]
            if level and level != "all":
                rules = [r for r in rules if r.get("level") == level]
            if search:
                s_lower = search.lower()
                rules = [
                    r for r in rules
                    if s_lower in r.get("title", "").lower() or s_lower in r.get("id", "").lower()
                ]

            self._json(200, {"rules": rules, "total": len(rules)})
            return
        sigma_rule_match = re.fullmatch(r"/api/sigma/rules/([A-Za-z0-9_-]+)", path)
        if sigma_rule_match:
            if not self._require_permission(identity, "detections.view"):
                return
            try:
                details = sigma_engine.SigmaEngine.get_instance().get_rule_details(sigma_rule_match.group(1))
                self._json(200, details)
            except ValueError as err:
                self._json(404, {"error": str(err)})
            return
        # Threat Intelligence GET Routes
        if path == "/api/intel/iocs":
            if not self._require_permission(identity, "intel.view"):
                return
            params = parse_qs(urlparse(self.path).query)
            ioc_type = params.get("type", [None])[0]
            severity = params.get("severity", [None])[0]
            threat_type = params.get("threat_type", [None])[0]
            tlp = params.get("tlp", [None])[0]
            search = params.get("search", [None])[0] or params.get("q", [None])[0]
            limit = min(1000, max(1, int(params.get("limit", [50])[0])))
            offset = int(params.get("offset", [0])[0])
            if "page" in params:
                page = max(1, int(params["page"][0]))
                offset = (page - 1) * limit

            is_active = None
            if "is_active" in params:
                is_active = params["is_active"][0].lower() in {"1", "true", "yes"}

            mgr = threat_intel.ThreatIntelManager.get_instance()
            iocs, total = mgr.list_iocs(
                ioc_type=ioc_type,
                severity=severity,
                threat_type=threat_type,
                tlp=tlp,
                is_active=is_active,
                query=search,
                limit=limit,
                offset=offset,
            )
            next_cursor = str(offset + len(iocs)) if (offset + len(iocs) < total) else None
            self._json(200, {
                "iocs": [i.to_dict() for i in iocs],
                "total": total,
                "next_cursor": next_cursor,
                "limit": limit,
                "offset": offset,
            })
            return
        if path in {"/api/intel/summary", "/api/intel/iocs/summary"}:
            if not self._require_permission(identity, "intel.view"):
                return
            mgr = threat_intel.ThreatIntelManager.get_instance()
            self._json(200, mgr.get_summary())
            return
        if path == "/api/intel/export":
            if not self._require_permission(identity, "intel.view"):
                return
            params = parse_qs(urlparse(self.path).query)
            fmt = (params.get("format", ["json"])[0] or "json").lower()
            ioc_type = params.get("type", [None])[0]
            mgr = threat_intel.ThreatIntelManager.get_instance()
            if fmt == "csv":
                csv_data = mgr.export_csv(ioc_type=ioc_type)
                content = csv_data.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="threat_intel_iocs.csv"')
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            elif fmt == "stix":
                stix_data = mgr.export_stix(ioc_type=ioc_type)
                content = stix_data.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="threat_intel_stix21.json"')
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                json_data = mgr.export_json(ioc_type=ioc_type)
                content = json_data.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="threat_intel_iocs.json"')
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
        intel_hits_match = re.fullmatch(r"/api/intel/iocs/([A-Za-z0-9_-]+)/hits", path)
        if intel_hits_match:
            if not self._require_permission(identity, "intel.view"):
                return
            ioc_id = intel_hits_match.group(1)
            mgr = threat_intel.ThreatIntelManager.get_instance()
            hits = mgr.get_ioc_hits(ioc_id)
            self._json(200, {"ioc_id": ioc_id, "hits": hits, "total": len(hits)})
            return
        intel_get_match = re.fullmatch(r"/api/intel/iocs/([A-Za-z0-9_-]+)", path)
        if intel_get_match:
            if not self._require_permission(identity, "intel.view"):
                return
            ioc_id = intel_get_match.group(1)
            mgr = threat_intel.ThreatIntelManager.get_instance()
            ioc = mgr.get_ioc(ioc_id)
            if not ioc:
                self._json(404, {"error": "مؤشر التهديد غير موجود."})
                return
            self._json(200, ioc.to_dict())
            return
        if path == "/api/assets":
            if not self._require_permission(identity, "assets.view"):
                return
            qs = parse_qs(urlparse(self.path).query)
            search = qs.get("search", [None])[0]
            criticality = qs.get("criticality", [None])[0]
            asset_type = qs.get("asset_type", [None])[0]
            status = qs.get("status", [None])[0]
            department = qs.get("department", [None])[0]
            min_risk = int(qs.get("min_risk", [0])[0]) if qs.get("min_risk") else None
            limit = int(qs.get("limit", [50])[0]) if qs.get("limit") else 50
            offset = int(qs.get("offset", [0])[0]) if qs.get("offset") else 0
            sort_by = qs.get("sort_by", ["risk_score"])[0]
            sort_order = qs.get("sort_order", ["desc"])[0]
            data = asset_manager.list_assets(
                search=search, criticality=criticality, asset_type=asset_type,
                status=status, department=department, min_risk=min_risk,
                limit=limit, offset=offset, sort_by=sort_by, sort_order=sort_order
            )
            ctx = authorization.build_security_context(identity)
            if ctx.data_scope != "all" and "assets" in data:
                data["assets"] = authorization.filter_dataset(ctx, data["assets"], "assets")
                data["total"] = len(data["assets"])
            self._json(200, data)
            return
        if path == "/api/assets/summary":
            if not self._require_permission(identity, "assets.view"):
                return
            self._json(200, asset_manager.get_assets_summary())
            return
        if path == "/api/assets/export":
            if not self._require_permission(identity, "assets.view"):
                return
            qs = parse_qs(urlparse(self.path).query)
            fmt = qs.get("format", ["json"])[0]
            exported = asset_manager.export_assets(fmt)
            content = exported.encode("utf-8")
            self.send_response(200)
            if fmt == "csv":
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="assets_inventory.csv"')
            else:
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="assets_inventory.json"')
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        asset_get_match = re.fullmatch(r"/api/assets/([A-Za-z0-9_-]+)", path)
        if asset_get_match:
            if not self._require_permission(identity, "assets.view"):
                return
            asset_id = asset_get_match.group(1)
            ast = asset_manager.get_asset(asset_id)
            if not ast:
                self._json(404, {"error": "الأصل الأمني غير موجود."})
                return
            ctx = authorization.build_security_context(identity)
            decision = authorization.evaluate_policy(ctx, action="assets.view", resource_type="assets", resource_data=ast)
            if not decision.allowed:
                self._json(403, {"error": decision.reason, "code": decision.code})
                return
            self._json(200, ast)
            return
        # Graph Correlation GET Routes
        if path == "/api/correlation/summary":
            if not self._require_permission(identity, "correlation.view"):
                return
            eng = graph_correlation.get_graph_correlation_engine()
            self._json(200, eng.get_summary())
            return
        if path == "/api/correlation/graph":
            if not self._require_permission(identity, "correlation.view"):
                return
            qs = parse_qs(urlparse(self.path).query)
            limit = int(qs.get("limit", [300])[0]) if qs.get("limit") else 300
            incident_id = qs.get("incident_id", [None])[0]
            asset_id = qs.get("asset_id", [None])[0]
            eng = graph_correlation.get_graph_correlation_engine()
            if incident_id:
                inc = incident_manager.get_incident(incident_id)
                entity_nodes = set()
                if inc:
                    for ent in inc.get("entities", []):
                        val = ent.get("value", "")
                        for nid in eng.graph._nodes.keys():
                            if val.lower() in nid.lower():
                                entity_nodes.add(nid)
                if entity_nodes:
                    snapshot = eng.graph.extract_subgraph(entity_nodes, max_hops=2)
                else:
                    snapshot = eng.graph.get_snapshot(limit_nodes=limit)
            elif asset_id:
                ast = asset_manager.get_asset(asset_id)
                entity_nodes = set()
                if ast:
                    h_val = ast.get("hostname", "")
                    ip_val = ast.get("primary_ip", "")
                    for nid in eng.graph._nodes.keys():
                        if (h_val and h_val.lower() in nid.lower()) or (ip_val and ip_val in nid):
                            entity_nodes.add(nid)
                if entity_nodes:
                    snapshot = eng.graph.extract_subgraph(entity_nodes, max_hops=2)
                else:
                    snapshot = eng.graph.get_snapshot(limit_nodes=limit)
            else:
                snapshot = eng.graph.get_snapshot(limit_nodes=limit)
            self._json(200, snapshot)
            return
        if path == "/api/correlation/attack-chains":
            if not self._require_permission(identity, "correlation.view"):
                return
            eng = graph_correlation.get_graph_correlation_engine()
            chains = eng.find_attack_chains()
            self._json(200, {"attack_chains": [c.to_dict() for c in chains]})
            return
        if path == "/api/correlation/lateral-movements":
            if not self._require_permission(identity, "correlation.view"):
                return
            eng = graph_correlation.get_graph_correlation_engine()
            laterals = eng.find_lateral_movements()
            self._json(200, {"lateral_movements": [lm.to_dict() for lm in laterals]})
            return
        if path == "/api/correlation/insider-threats":
            if not self._require_permission(identity, "correlation.view"):
                return
            eng = graph_correlation.get_graph_correlation_engine()
            threats = eng.find_insider_threats()
            self._json(200, {"insider_threats": [it.to_dict() for it in threats]})
            return
        # Graph Correlation GET Routes
        if path == "/api/correlation/summary":
            if not self._require_permission(identity, "correlation.view"):
                return
            eng = graph_correlation.get_graph_correlation_engine()
            self._json(200, eng.get_summary())
            return
        if path == "/api/correlation/graph":
            if not self._require_permission(identity, "correlation.view"):
                return
            qs = parse_qs(urlparse(self.path).query)
            limit = int(qs.get("limit", [300])[0]) if qs.get("limit") else 300
            incident_id = qs.get("incident_id", [None])[0]
            asset_id = qs.get("asset_id", [None])[0]
            eng = graph_correlation.get_graph_correlation_engine()
            if incident_id:
                inc = incident_manager.get_incident(incident_id)
                entity_nodes = set()
                if inc:
                    for ent in inc.get("entities", []):
                        val = ent.get("value", "")
                        for nid in eng.graph._nodes.keys():
                            if val.lower() in nid.lower():
                                entity_nodes.add(nid)
                if entity_nodes:
                    snapshot = eng.graph.extract_subgraph(entity_nodes, max_hops=2)
                else:
                    snapshot = eng.graph.get_snapshot(limit_nodes=limit)
            elif asset_id:
                ast = asset_manager.get_asset(asset_id)
                entity_nodes = set()
                if ast:
                    h_val = ast.get("hostname", "")
                    ip_val = ast.get("primary_ip", "")
                    for nid in eng.graph._nodes.keys():
                        if (h_val and h_val.lower() in nid.lower()) or (ip_val and ip_val in nid):
                            entity_nodes.add(nid)
                if entity_nodes:
                    snapshot = eng.graph.extract_subgraph(entity_nodes, max_hops=2)
                else:
                    snapshot = eng.graph.get_snapshot(limit_nodes=limit)
            else:
                snapshot = eng.graph.get_snapshot(limit_nodes=limit)
            self._json(200, snapshot)
            return
        if path == "/api/correlation/attack-chains":
            if not self._require_permission(identity, "correlation.view"):
                return
            eng = graph_correlation.get_graph_correlation_engine()
            chains = eng.find_attack_chains()
            self._json(200, {"attack_chains": [c.to_dict() for c in chains]})
            return
        if path == "/api/correlation/lateral-movements":
            if not self._require_permission(identity, "correlation.view"):
                return
            eng = graph_correlation.get_graph_correlation_engine()
            laterals = eng.find_lateral_movements()
            self._json(200, {"lateral_movements": [lm.to_dict() for lm in laterals]})
            return
        if path == "/api/correlation/insider-threats":
            if not self._require_permission(identity, "correlation.view"):
                return
            eng = graph_correlation.get_graph_correlation_engine()
            threats = eng.find_insider_threats()
            self._json(200, {"insider_threats": [it.to_dict() for it in threats]})
            return
        permission = self._route_permission("GET", path)
        if permission and not self._require_permission(identity, permission):
            return
        if self._flow_route("GET", path):
            self._delegate_flow(flow_server.RequestHandler.do_GET)
            return
        if self._threat_route("GET", path):
            self._delegate_threat(threat_server.Handler.do_GET)
            return
        if self._log_route("GET", path):
            self._delegate_log(log_server.RequestHandler.do_GET)
            return
        asset_patch_match = re.fullmatch(r"/api/assets/([A-Za-z0-9_-]+)", path)
        if asset_patch_match:
            if not self._require_permission(identity, "assets.manage"):
                return
            asset_id = asset_patch_match.group(1)
            payload = self._read_json_body(65_536)
            updated = asset_manager.update_asset(asset_id, payload, actor=identity["username"])
            if not updated:
                self._json(404, {"error": "الأصل الأمني غير موجود."})
                return
            self._json(200, updated)
            return
        self._json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/auth/login":
            self._login()
            return
        if path == "/api/auth/logout":
            self._json_with_cookie(200, {"authenticated": False}, security_auth.expired_cookie())
            return
        if path.startswith("/api/v1/"):
            identity = security_auth.request_identity(self.headers)
            auth_ctx = {"authenticated": bool(identity), "user": identity}
            length = int(self.headers.get("Content-Length") or 0)
            body_bytes = self.rfile.read(length) if length > 0 else None
            resp = v1_api_router.dispatch(
                method="POST",
                raw_url=self.path,
                headers=self._headers_dict(),
                body_bytes=body_bytes,
                auth_context=auth_ctx,
            )
            self._json(resp.status_code, resp.to_dict())
            return
        identity = self._require_authentication()
        if not identity:
            return
        if path == "/api/settings":
            if not self._require_permission(identity, "users.manage"):
                return
            try:
                payload = self._read_json_body(262_144)
                previous = platform_config.load()
                restart_required = any(payload.get(section) != previous.get(section) for section in ("network", "security"))
                actor = identity.get("username", "admin")
                summary = str(payload.get("change_summary") or "تحديث إعدادات المنصة")
                config = platform_config.save(payload, actor=actor, summary=summary)
                audit_engine.record_engine_event(application="platform", action="configuration_update", message="تم تحديث إعدادات المنصة", category="administration", details={"version": config.get("version"), "actor": actor})
                self._json(200, {"config": config, "restart_required": restart_required})
            except (ValueError, TypeError, json.JSONDecodeError) as error:
                self._json(400, {"error": str(error)})
            return
        if path == "/api/settings/rollback":
            if not self._require_permission(identity, "users.manage"):
                return
            try:
                payload = self._read_json_body(16_384)
                revision_id = payload.get("revision_id")
                version = payload.get("version")
                actor = identity.get("username", "admin")
                config = platform_config.rollback_config(revision_id=revision_id, version=version, actor=actor)
                audit_engine.record_engine_event(
                    application="platform",
                    action="configuration_rollback",
                    message=f"تم استرجاع إعدادات المنصة بواسطة {actor}",
                    category="administration",
                    details={"revision_id": revision_id, "version": version, "actor": actor},
                )
                self._json(200, {"config": config, "success": True, "message": "تم استرجاع الإعدادات بنجاح"})
            except Exception as error:
                self._json(400, {"error": str(error)})
            return
        if path == "/api/settings/test":
            if not self._require_permission(identity, "users.manage"):
                return
            try:
                self._json(200, platform_config.test_connection(self._read_json_body(65_536)))
            except (ValueError, TypeError, json.JSONDecodeError) as error:
                self._json(400, {"error": str(error)})
            return
        if path == "/api/platform/logs/level":
            if not self._require_permission(identity, "users.manage"):
                return
            try:
                payload = self._read_json_body(4096)
                level = str(payload.get("level") or "INFO").strip().upper()
                old_level = get_platform_log_level()
                set_platform_log_level(level)
                audit_engine.record_engine_event(
                    application="platform",
                    action="log_level_change",
                    message=f"تم تغيير مستوى تسجيل المنصة من {old_level} إلى {level}",
                    category="administration",
                    details={"old_level": old_level, "new_level": level},
                )
                logger = get_logger("backend")
                logger.info(
                    f"Platform log level changed from {old_level} to {level}",
                    f"تم تغيير مستوى تسجيل المنصة من {old_level} إلى {level}",
                    event_code="LOG_LEVEL_CHANGED",
                    old_level=old_level,
                    new_level=level,
                )
                self._json(200, {"status": "ok", "level": level, "old_level": old_level})
            except (ValueError, TypeError, json.JSONDecodeError) as error:
                self._json(400, {"error": str(error)})
            return
        if path == "/api/platform/time/sync":
            if not self._require_permission(identity, "users.manage"):
                return
            try:
                payload = self._read_json_body(4096) if int(self.headers.get("Content-Length") or 0) > 0 else {}
                server = payload.get("server") or payload.get("ntp_server") or None
                port = int(payload.get("port") or payload.get("ntp_port") or 123) if (payload.get("port") or payload.get("ntp_port")) else None
                success, msg, status = time_service.get_time_service().sync_now(server=server, port=port)
                audit_engine.record_engine_event(
                    application="platform",
                    action="time_sync",
                    message=f"مزامنة توقيت المنصة عبر NTP: {msg}",
                    category="administration",
                    details={"success": success, "server": server, "status": status},
                )
                self._json(200 if success else 400, {
                    "ok": success,
                    "message": msg,
                    "status": status,
                })
            except Exception as error:
                self._json(500, {"ok": False, "error": str(error)})
            return
        if path == "/api/licensing/request":
            mgr = LicenseManager.get_instance()
            self._json(200, mgr.generate_activation_request())
            return
        if path == "/api/licensing/activate":
            try:
                payload = self._read_json_body(262_144)
                envelope = str(payload.get("license_text") or payload.get("license") or "").strip()
                if not envelope:
                    self._json(400, {"error": "نص ملف الترخيص (license_text) مطلوب."})
                    return
                mgr = LicenseManager.get_instance()
                ok, msg = mgr.activate_license(envelope)
                if ok:
                    self._json(200, {
                        "success": True,
                        "message": msg,
                        "license": mgr.get_license_info(force_refresh=True).to_dict()
                    })
                else:
                    self._json(400, {"success": False, "error": msg})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        if path == "/api/licensing/refresh":
            mgr = LicenseManager.get_instance()
            self._json(200, mgr.get_license_info(force_refresh=True).to_dict())
            return
        if path == "/api/incidents/case-verify":
            if not self._require_permission(identity, "incidents.view"):
                return
            try:
                content_len = int(self.headers.get("Content-Length") or 0)
                if content_len <= 0 or content_len > 100 * 1024 * 1024:
                    self._json(400, {"valid": False, "error": "حجم ملف التحقيق غير صالح أو يتجاوز 100 ميجابايت."})
                    return
                zip_data = self.rfile.read(content_len)
                res = case_export.SecurityCaseVerifier.verify_case(zip_data)
                self._json(200 if res.get("valid") else 422, res)
            except Exception as exc:
                self._json(500, {"valid": False, "error": f"فشل التحقق من نزاهة ملف التحقيق: {str(exc)}"})
            return
        if path == "/api/auth/account":
            self._update_account(identity)
            return
        if path == "/api/admin/users":
            if not self._require_permission(identity, "users.manage"):
                return
            self._create_user()
            return
        admin_match = re.fullmatch(r"/api/admin/users/([0-9a-f]{16})", path)
        if admin_match:
            if not self._require_permission(identity, "users.manage"):
                return
            self._update_user(admin_match.group(1))
            return
        task_action_match = re.fullmatch(r"/api/enterprise/tasks/([A-Za-z0-9_-]+)/(cancel|retry)", path)
        if task_action_match:
            if not self._require_permission(identity, "users.manage"):
                return
            task_id, action = task_action_match.groups()
            queue = enterprise.EnterpriseTaskQueue.get_instance()
            if action == "cancel":
                ok = queue.cancel_task(task_id)
                if ok:
                    audit_engine.record_activity(
                        actor=identity.get("username", "admin"),
                        action="cancel_task",
                        target=task_id,
                        details={"status": "cancelled"},
                    )
                    self._json(200, {"success": True, "message": f"تم إلغاء المهمة '{task_id}' بنجاح"})
                else:
                    self._json(400, {"error": f"لا يمكن إلغاء المهمة '{task_id}' أو أنها غير موجودة"})
                return
            elif action == "retry":
                ok = queue.retry_task(task_id)
                if ok:
                    audit_engine.record_activity(
                        actor=identity.get("username", "admin"),
                        action="retry_task",
                        target=task_id,
                        details={"status": "queued"},
                    )
                    self._json(200, {"success": True, "message": f"تمت إعادة جدولة المهمة '{task_id}' بنجاح"})
                else:
                    self._json(400, {"error": f"لا يمكن إعادة جدولة المهمة '{task_id}' أو أنها غير موجودة"})
                return
        if path == "/api/enterprise/storage/vacuum":
            if not self._require_permission(identity, "users.manage", "enterprise.view"):
                return
            try:
                res = enterprise.StorageGovernanceManager.vacuum_databases()
                audit_engine.record_engine_event(
                    application="platform",
                    action="storage_vacuum",
                    message="تنفيذ عملية تفريغ وتحسين قواعد البيانات (VACUUM)",
                    category="administration",
                    details=res,
                )
                self._json(200, res)
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/enterprise/storage/cleanup":
            if not self._require_permission(identity, "users.manage", "enterprise.view"):
                return
            try:
                payload = self._read_json_body(16_384) if int(self.headers.get("Content-Length") or 0) > 0 else {}
                jobs_days = int(payload.get("jobs_days") or 30)
                audit_days = int(payload.get("audit_days") or 90)
                dry_run = bool(payload.get("dry_run", False))
                res = enterprise.StorageGovernanceManager.cleanup_storage(jobs_days=jobs_days, audit_days=audit_days, dry_run=dry_run)
                if not dry_run:
                    audit_engine.record_engine_event(
                        application="platform",
                        action="storage_cleanup",
                        message="تنفيذ دورة تنظيف وحوكمة مساحات التخزين",
                        category="administration",
                        details=res,
                    )
                self._json(200, res)
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/platform/backup":
            if not self._require_permission(identity, "users.manage", "enterprise.manage"):
                return
            body = self._read_json_body(16_384) or {}
            actor = identity.get("username", "system")
            note = str(body.get("note", ""))
            include_det = bool(body.get("include_detections", True))
            include_db = bool(body.get("include_databases", True))
            include_cfg = bool(body.get("include_configs", True))
            try:
                res = backup_manager.BackupManager.get_instance().create_backup(
                    actor=actor,
                    note=note,
                    include_detections=include_det,
                    include_databases=include_db,
                    include_configs=include_cfg,
                )
                self._json(200, res)
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if path == "/api/platform/restore":
            if not self._require_permission(identity, "users.manage", "enterprise.manage"):
                return
            body = self._read_json_body(16_384) or {}
            actor = identity.get("username", "system")
            backup_id = str(body.get("backup_id", ""))
            create_safety = bool(body.get("create_safety_snapshot", True))
            if not backup_id:
                self._json(400, {"error": "Missing backup_id"})
                return
            try:
                res = backup_manager.BackupManager.get_instance().restore_backup(
                    filename_or_path=backup_id,
                    actor=actor,
                    create_safety_snapshot=create_safety,
                )
                self._json(200, res)
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if path == "/api/platform/backup/delete":
            if not self._require_permission(identity, "users.manage", "enterprise.manage"):
                return
            body = self._read_json_body(16_384) or {}
            actor = identity.get("username", "system")
            backup_id = str(body.get("backup_id", ""))
            if not backup_id:
                self._json(400, {"error": "Missing backup_id"})
                return
            try:
                ok = backup_manager.BackupManager.get_instance().delete_backup(backup_id, actor=actor)
                self._json(200, {"success": ok, "backup_id": backup_id})
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if path == "/api/notifications/read-all":
            user_val = identity.get("username", "*")
            cnt = notification_engine.mark_all_as_read(user=user_val)
            self._json(200, {"success": True, "read_count": cnt})
            return
        notif_read_match = re.fullmatch(r"/api/notifications/([A-Za-z0-9_-]+)/read", path)
        if notif_read_match:
            notif_id = notif_read_match.group(1)
            user_val = identity.get("username", "*")
            ok = notification_engine.mark_as_read(notif_id, user=user_val)
            self._json(200, {"success": ok})
            return
        if path == "/api/notifications":
            if not self._require_permission(identity, "users.manage"):
                return
            try:
                body = self._read_json_body(16_384)
                created = notification_engine.create_notification(
                    title=body.get("title", "تنبيه جديد"),
                    message=body.get("message", ""),
                    category=body.get("category", "system"),
                    severity=body.get("severity", "info"),
                    target_user=body.get("target_user", "*"),
                    link=body.get("link"),
                    metadata=body.get("metadata"),
                )
                self._json(201, {"success": True, "notification": created})
            except Exception as e:
                self._json(400, {"error": str(e)})
            return
        if path == "/api/investigations":
            if not self._require_permission(identity, "incidents.view"):
                return
            body = self._read_json_body(32_768) or {}
            actor = identity.get("username", "system")
            title = str(body.get("title", "")).strip()
            if not title:
                self._json(400, {"error": "Missing investigation title"})
                return
            desc = str(body.get("description", ""))
            prio = str(body.get("priority", "P2"))
            lead = str(body.get("lead_analyst", actor))
            tags = body.get("tags") or []
            hypothesis = str(body.get("hypothesis", ""))
            mgr = investigation_manager.InvestigationManager.get_instance()
            inv = mgr.create_investigation(
                title=title,
                description=desc,
                priority=prio,
                lead_analyst=lead,
                tags=tags,
                hypothesis=hypothesis,
                actor=actor,
            )
            self._json(201, inv)
            return
        inv_item_match = re.fullmatch(r"/api/investigations/([A-Za-z0-9_-]+)/items", path)
        if inv_item_match:
            if not self._require_permission(identity, "incidents.view"):
                return
            inv_id = inv_item_match.group(1)
            body = self._read_json_body(16_384) or {}
            actor = identity.get("username", "system")
            item_type = str(body.get("item_type", "evidence"))
            item_id = str(body.get("item_id", ""))
            title = str(body.get("title", item_id))
            meta = body.get("metadata") or {}
            if not item_id:
                self._json(400, {"error": "Missing item_id"})
                return
            mgr = investigation_manager.InvestigationManager.get_instance()
            res = mgr.add_item(
                investigation_id=inv_id,
                item_type=item_type,
                item_id=item_id,
                title=title,
                metadata=meta,
                actor=actor,
            )
            self._json(201, res)
            return
        inv_note_match = re.fullmatch(r"/api/investigations/([A-Za-z0-9_-]+)/notes", path)
        if inv_note_match:
            if not self._require_permission(identity, "incidents.view"):
                return
            inv_id = inv_note_match.group(1)
            body = self._read_json_body(16_384) or {}
            actor = identity.get("username", "system")
            content = str(body.get("content", "")).strip()
            if not content:
                self._json(400, {"error": "Missing note content"})
                return
            mgr = investigation_manager.InvestigationManager.get_instance()
            res = mgr.add_note(investigation_id=inv_id, content=content, author=actor)
            self._json(201, res)
            return
        if path == "/api/authorization/roles":
            if not self._require_permission(identity, "roles.manage", "users.manage"):
                return
            try:
                payload = self._read_json_body(65_536)
                role = authorization.create_custom_role(
                    name=payload.get("name", ""),
                    label_ar=payload.get("label_ar", ""),
                    description=payload.get("description", ""),
                    permissions=payload.get("permissions", []),
                    default_scope=payload.get("default_scope", "own_shared"),
                )
                audit_engine.record_engine_event(
                    action="authorization.role_create",
                    user=identity["username"],
                    details={"role": role},
                )
                self._json(201, {"role": role})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        clone_match = re.fullmatch(r"/api/authorization/roles/([A-Za-z0-9_-]+)/clone", path)
        if clone_match:
            if not self._require_permission(identity, "roles.manage", "users.manage"):
                return
            try:
                payload = self._read_json_body(65_536)
                cloned = authorization.clone_role(
                    source_role_id=clone_match.group(1),
                    new_name=payload.get("name", ""),
                    new_label_ar=payload.get("label_ar", ""),
                    description=payload.get("description", ""),
                )
                audit_engine.record_engine_event(
                    action="authorization.role_clone",
                    user=identity["username"],
                    details={"source_role": clone_match.group(1), "new_role": cloned["id"]},
                )
                self._json(201, {"role": cloned})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        if path == "/api/authorization/groups":
            if not self._require_permission(identity, "groups.manage", "users.manage"):
                return
            try:
                payload = self._read_json_body(65_536)
                grp = authorization.create_group(
                    name=payload.get("name", ""),
                    label_ar=payload.get("label_ar", ""),
                    description=payload.get("description", ""),
                    roles=payload.get("roles", []),
                    default_scope=payload.get("default_scope", "group"),
                    department=payload.get("department", ""),
                    members=payload.get("members", []),
                )
                audit_engine.record_engine_event(
                    action="authorization.group_create",
                    user=identity["username"],
                    details={"group": grp},
                )
                self._json(201, {"group": grp})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        if path == "/api/authorization/sharing/share":
            try:
                payload = self._read_json_body(65_536)
                sh = authorization.share_resource(
                    resource_type=payload.get("resource_type", ""),
                    resource_id=payload.get("resource_id", ""),
                    shared_by=identity["username"],
                    grantee_type=payload.get("grantee_type", "user"),
                    grantee_id=payload.get("grantee_id", ""),
                    permissions=payload.get("permissions", ["view"]),
                    expires_at=payload.get("expires_at"),
                )
                audit_engine.record_engine_event(
                    action="authorization.resource_shared",
                    user=identity["username"],
                    details={"share": sh},
                )
                self._json(201, {"share": sh})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        if path == "/api/authorization/sharing/revoke":
            try:
                payload = self._read_json_body(65_536)
                share_id = str(payload.get("share_id", "")).strip()
                authorization.revoke_share(share_id)
                audit_engine.record_engine_event(
                    action="authorization.share_revoked",
                    user=identity["username"],
                    details={"share_id": share_id},
                )
                self._json(200, {"revoked": True})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        if path == "/api/incidents":
            if not self._require_permission(identity, "incidents.manage"):
                return
            try:
                payload = self._read_json_body(262_144)
                inc = incident_manager.create_incident(
                    title=str(payload.get("title") or ""),
                    severity=str(payload.get("severity") or "medium"),
                    source_app=str(payload.get("source_app") or "manual"),
                    description=str(payload.get("description") or ""),
                    source_job_id=payload.get("source_job_id"),
                    correlation_id=payload.get("correlation_id"),
                    asset_criticality=str(payload.get("asset_criticality") or "medium"),
                    business_impact=str(payload.get("business_impact") or "medium"),
                    assigned_to=payload.get("assigned_to"),
                    mitre_tactics=payload.get("mitre_tactics"),
                    mitre_techniques=payload.get("mitre_techniques"),
                    entities=payload.get("entities"),
                    detection_rule=payload.get("detection_rule"),
                    confidence=float(payload.get("confidence") or 80.0),
                    actor=identity["username"],
                    reason=str(payload.get("reason") or "Manual incident created by analyst"),
                )
                self._json(201, inc)
            except (ValueError, TypeError, json.JSONDecodeError) as error:
                self._json(400, {"error": str(error)})
            return
        if path == "/api/incidents/sync":
            if not self._require_permission(identity, "incidents.manage"):
                return
            count = incident_manager.sync_all_existing_jobs()
            self._json(200, {"synced": count})
            return
        if path == "/api/incidents/case-verify":
            if not self._require_permission(identity, "incidents.export"):
                return
            try:
                content_type = self.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    payload = self._read_json_body(50 * 1024 * 1024)
                    zip_b64 = payload.get("zip_base64") or payload.get("file_b64") or ""
                    import base64
                    zip_bytes = base64.b64decode(zip_b64)
                elif "application/zip" in content_type or "application/octet-stream" in content_type:
                    content_length = int(self.headers.get("Content-Length", 0))
                    zip_bytes = self.rfile.read(content_length)
                else:
                    payload = self._read_json_body(50 * 1024 * 1024)
                    zip_b64 = payload.get("zip_base64") or payload.get("file_b64") or ""
                    import base64
                    zip_bytes = base64.b64decode(zip_b64)

                res = case_export.SecurityCaseVerifier.verify_case(zip_bytes)
                self._json(200, res)
            except Exception as e:
                self._json(400, {"valid": False, "error": f"فشل قراءة وفحص حزمة التحقيق: {str(e)}"})
            return
        if path == "/api/copilot/investigate":
            if not self._require_permission(identity, "copilot.query"):
                return
            try:
                payload = self._read_json_body(131_072)
                incident_id = str(payload.get("incident_id") or "").strip()
                intent = str(payload.get("intent") or "explain_severity").strip()
                custom_query = payload.get("custom_query")
                if not incident_id:
                    self._json(400, {"error": "incident_id is required"})
                    return
                res = ai_copilot.SecurityCopilotEngine.investigate(
                    incident_id=incident_id,
                    intent=intent,
                    custom_query=custom_query,
                    actor=identity["username"],
                )
                self._json(200, res)
            except ValueError as err:
                self._json(404, {"error": str(err)})
            except Exception as err:
                self._json(500, {"error": str(err)})
            return
        if path == "/api/copilot/apply-note":
            if not self._require_permission(identity, "incidents.manage"):
                return
            try:
                payload = self._read_json_body(131_072)
                incident_id = str(payload.get("incident_id") or "").strip()
                note_text = str(payload.get("note_text") or "").strip()
                if not incident_id or not note_text:
                    self._json(400, {"error": "incident_id and note_text are required"})
                    return
                updated_inc = ai_copilot.SecurityCopilotEngine.apply_recommendation_as_note(
                    incident_id=incident_id,
                    note_text=note_text,
                    actor=identity["username"],
                )
                self._json(200, updated_inc)
            except ValueError as err:
                self._json(400, {"error": str(err)})
            except Exception as err:
                self._json(500, {"error": str(err)})
            return
        if path == "/api/enterprise/tenants":
            if not self._require_permission(identity, "enterprise.manage"):
                return
            try:
                payload = self._read_json_body(65_536)
                tenant_id = str(payload.get("id") or "").strip()
                name = str(payload.get("name") or "").strip()
                if not tenant_id or not name:
                    self._json(400, {"error": "معرف المستأجر واسمه مطلوبان"})
                    return
                quotas_input = payload.get("quotas") or {}
                quotas = enterprise.TenantQuotas(**quotas_input) if quotas_input else None
                t = enterprise.TenantManager.get_instance().create_tenant(
                    tenant_id=tenant_id,
                    name=name,
                    quotas=quotas,
                    metadata=payload.get("metadata") or {},
                )
                audit_engine.record_engine_event(
                    action="enterprise.tenant_created",
                    user=identity["username"],
                    details={"tenant_id": tenant_id, "name": name},
                )
                self._json(201, t.to_dict())
            except ValueError as err:
                self._json(400, {"error": str(err)})
            except Exception as err:
                self._json(500, {"error": str(err)})
            return
        if path == "/api/enterprise/storage/archive":
            if not self._require_permission(identity, "enterprise.manage"):
                return
            try:
                payload = self._read_json_body(16_384)
                days = int(payload.get("days_threshold", 90))
                dry_run = bool(payload.get("dry_run", True))
                res = enterprise.StorageGovernanceManager.archive_cold_jobs(days_threshold=days, dry_run=dry_run)
                audit_engine.record_engine_event(
                    action="enterprise.storage_archived",
                    user=identity["username"],
                    details={"days_threshold": days, "dry_run": dry_run, "archived": res.get("archived_jobs_count", 0)},
                )
                self._json(200, res)
            except Exception as err:
                self._json(500, {"error": str(err)})
            return
        if path == "/api/incidents/promote":
            if not self._require_permission(identity, "incidents.manage"):
                return
            try:
                payload = self._read_json_body(262_144)
                inc = incident_manager.promote_detection_to_incident(
                    source_app=str(payload.get("source_app") or "manual"),
                    source_job_id=str(payload.get("source_job_id") or ""),
                    detection_data=payload.get("detection") or {},
                    actor=identity["username"],
                    reason=str(payload.get("reason") or "Analyst promoted detection to incident"),
                    auto=bool(payload.get("auto", False)),
                )
                self._json(201, inc)
            except (ValueError, TypeError, json.JSONDecodeError) as error:
                self._json(400, {"error": str(error)})
            return
        note_match = re.fullmatch(r"/api/incidents/([A-Za-z0-9_-]+)/notes", path)
        if note_match:
            if not self._require_permission(identity, "incidents.manage"):
                return
            try:
                payload = self._read_json_body(65_536)
                text = str(payload.get("note") or payload.get("note_text") or "")
                inc = incident_manager.add_note(note_match.group(1), text, identity["username"])
                self._json(200, inc)
            except LookupError as error:
                self._json(404, {"error": str(error)})
            except ValueError as error:
                self._json(400, {"error": str(error)})
            return
        evi_match = re.fullmatch(r"/api/incidents/([A-Za-z0-9_-]+)/evidence", path)
        if evi_match:
            if not self._require_permission(identity, "incidents.manage"):
                return
            self._add_incident_evidence(evi_match.group(1), identity["username"])
            return
        if path == "/api/detections":
            if not self._require_permission(identity, "detections.manage"):
                return
            try:
                payload = self._read_json_body(262_144)
                rule = detection_engine.get_detection_engine().create_or_update_rule(
                    payload,
                    changed_by=identity["username"],
                    reason=str(payload.get("change_reason") or "Rule created/updated via API")
                )
                self._json(201, rule.to_dict())
            except Exception as ex:
                self._json(400, {"error": str(ex)})
            return
        if path == "/api/detections/reload":
            if not self._require_permission(identity, "detections.manage"):
                return
            count = detection_engine.get_detection_engine().load_all_rules()
            self._json(200, {"reloaded": True, "count": count})
            return
        if path == "/api/detections/import":
            if not self._require_permission(identity, "detections.manage"):
                return
            try:
                payload = self._read_json_body(5 * 1024 * 1024)
                res = detection_engine.get_detection_engine().import_rules_package(
                    payload,
                    overwrite=True,
                    imported_by=identity["username"]
                )
                self._json(200, res)
            except Exception as ex:
                self._json(400, {"error": str(ex)})
            return
        if path == "/api/detections/test":
            if not self._require_permission(identity, "detections.view"):
                return
            try:
                payload = self._read_json_body(262_144)
                rule_input = payload.get("rule")
                event_input = payload.get("event")
                if not rule_input or not event_input:
                    self._json(400, {"error": "rule and event are required."})
                    return

                condition = rule_input.get("condition") if isinstance(rule_input, dict) else {}
                if not condition and isinstance(rule_input, str):
                    r = detection_engine.get_detection_engine().get_rule(rule_input)
                    if r:
                        condition = r.condition

                t0 = time.perf_counter()
                matched = detection_engine.ConditionEvaluator.evaluate_node(event_input, condition)
                elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

                self._json(200, {
                    "matched": matched,
                    "execution_time_ms": elapsed_ms,
                    "event": event_input,
                })
            except Exception as ex:
                self._json(400, {"error": str(ex)})
            return
        run_tests_match = re.fullmatch(r"/api/detections/([A-Za-z0-9_-]+)/run-tests", path)
        if run_tests_match:
            if not self._require_permission(identity, "detections.view"):
                return
            res = detection_engine.get_detection_engine().run_rule_tests(run_tests_match.group(1))
            self._json(200, res)
            return
        if path == "/api/sigma/validate":
            if not self._require_permission(identity, "detections.view"):
                return
            try:
                body = self._read_json_body(1_048_576)
                content = body.get("content", "")
                data, fmt = sigma_engine.MultiStageSigmaParser.parse_text(content)
                v_res = sigma_engine.SigmaValidator.validate(data)
                self._json(200, {"valid": v_res["valid"], "errors": v_res["errors"], "warnings": v_res["warnings"], "format": fmt})
            except Exception as err:
                self._json(400, {"valid": False, "errors": [str(err)], "warnings": []})
            return
        if path == "/api/sigma/analyze-compatibility":
            if not self._require_permission(identity, "detections.view"):
                return
            try:
                body = self._read_json_body(1_048_576)
                content = body.get("content", "")
                data, fmt = sigma_engine.MultiStageSigmaParser.parse_text(content)
                compat = sigma_engine.SigmaCompatibilityAnalyzer.analyze(data)
                self._json(200, {"format": fmt, "compatibility": compat.to_dict()})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        if path == "/api/sigma/convert":
            if not self._require_permission(identity, "detections.view"):
                return
            try:
                body = self._read_json_body(1_048_576)
                content = body.get("content", "")
                data, fmt = sigma_engine.MultiStageSigmaParser.parse_text(content)
                v_res = sigma_engine.SigmaValidator.validate(data)
                compat = sigma_engine.SigmaCompatibilityAnalyzer.analyze(data)
                adapter = sigma_engine.SigmaRuleAdapter.to_detection_rule(data, source_type="custom")
                self._json(200, {
                    "valid": v_res["valid"],
                    "errors": v_res["errors"],
                    "format": fmt,
                    "compatibility": compat.to_dict(),
                    "adapter": adapter.to_dict(),
                })
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        if path == "/api/sigma/import":
            if not self._require_permission(identity, "detections.manage"):
                return
            try:
                # Enforce size limit 5MB
                body = self._read_json_body(5_242_880)
                content = body.get("content", "")
                force = bool(body.get("force", False))
                username = identity.get("username", "analyst")
                res = sigma_engine.SigmaEngine.get_instance().import_rule(content, author_username=username, force=force)
                if res.get("success"):
                    # Record audit log
                    audit_engine.record_engine_event(
                        application="sigma",
                        action="rule_import",
                        message=f"تم استيراد وتجميع قاعدة Sigma جديدة: {res.get('id')}",
                        category="detections",
                        details={"rule_id": res.get("id"), "format": res.get("format"), "user": username}
                    )
                    # Refresh DetectionEngine adapters
                    detection_engine.get_detection_engine().load_all_rules()
                    self._json(200, res)
                else:
                    self._json(409, res)
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        sigma_test_match = re.fullmatch(r"/api/sigma/rules/([A-Za-z0-9_-]+)/test", path)
        if sigma_test_match:
            if not self._require_permission(identity, "detections.view"):
                return
            try:
                rule_id = sigma_test_match.group(1)
                body = self._read_json_body(1_048_576)
                custom_event = body.get("custom_event")
                eng = sigma_engine.SigmaEngine.get_instance()
                if custom_event:
                    res = eng.test_custom_event(rule_id, custom_event)
                else:
                    res = eng.run_tests(rule_id)
                self._json(200, res)
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        # Threat Intelligence POST Routes
        if path == "/api/intel/iocs":
            if not self._require_permission(identity, "intel.manage"):
                return
            try:
                payload = self._read_json_body(262_144)
                ioc_type = payload.get("type") or payload.get("ioc_type") or "ip"
                value = payload.get("value")
                if not value:
                    self._json(400, {"error": "قيمة مؤشر التهديد (value) مطلوبة."})
                    return
                mgr = threat_intel.ThreatIntelManager.get_instance()
                ioc = mgr.add_ioc(
                    ioc_type=ioc_type,
                    value=value,
                    threat_type=payload.get("threat_type", "c2"),
                    severity=payload.get("severity", "high"),
                    confidence=int(payload.get("confidence", 80)),
                    source=payload.get("source", "Analyst Manual"),
                    tags=payload.get("tags", []),
                    tlp=payload.get("tlp", "amber"),
                    description=payload.get("description", ""),
                    mitre_attack=payload.get("mitre_attack", {}),
                    related_threat_actor=payload.get("related_threat_actor", ""),
                    is_active=bool(payload.get("is_active", True)),
                    created_by=identity.get("username", "analyst"),
                )
                self._json(201, ioc.to_dict())
            except ValueError as val_err:
                self._json(400, {"error": str(val_err)})
            except Exception as err:
                self._json(500, {"error": f"فشل في إنشاء مؤشر التهديد: {str(err)}"})
            return
        if path == "/api/intel/lookup":
            if not self._require_permission(identity, "intel.view"):
                return
            try:
                payload = self._read_json_body(262_144)
                raw_values = payload.get("values")
                if not raw_values and "value" in payload:
                    raw_values = [payload["value"]]
                if not isinstance(raw_values, list):
                    raw_values = [str(raw_values)]
                mgr = threat_intel.ThreatIntelManager.get_instance()
                results = mgr.lookup_batch(raw_values)
                self._json(200, {"results": results, "total": len(results)})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        if path == "/api/intel/import":
            if not self._require_permission(identity, "intel.manage"):
                return
            try:
                payload = self._read_json_body(15_728_640)
                fmt = (payload.get("format") or "csv").lower()
                content = payload.get("content") or ""
                on_dup = payload.get("on_duplicate") or "skip"
                if not content.strip():
                    self._json(400, {"error": "محتوى حزمة الاستيراد فارغ."})
                    return
                mgr = threat_intel.ThreatIntelManager.get_instance()
                actor = identity.get("username", "analyst")
                if fmt == "csv":
                    res = mgr.import_csv(content, on_duplicate=on_dup, actor=actor)
                elif fmt in {"json", "stix"}:
                    res = mgr.import_json(content, on_duplicate=on_dup, actor=actor)
                else:
                    self._json(400, {"error": f"صيغة غير مدعومة: {fmt}. الصيغ المدعومة: csv, json, stix."})
                    return
                self._json(200, res)
            except Exception as err:
                self._json(400, {"error": f"خطأ أثناء معالجة حزمة الاستيراد: {str(err)}"})
            return
        if path == "/api/assets":
            if not self._require_permission(identity, "assets.manage"):
                return
            payload = self._read_json_body(65_536)
            hostname = str(payload.get("hostname") or "").strip()
            primary_ip = str(payload.get("primary_ip") or "0.0.0.0").strip()
            if not hostname and not primary_ip:
                self._json(400, {"error": "يجب تحديد اسم المضيف أو عنوان الـ IP."})
                return
            ast = asset_manager.create_or_update_asset(
                hostname=hostname or primary_ip,
                primary_ip=primary_ip,
                mac_address=payload.get("mac_address"),
                ip_addresses=payload.get("ip_addresses"),
                os_name=payload.get("os"),
                asset_type=payload.get("asset_type", "server"),
                criticality=payload.get("criticality", "medium"),
                status=payload.get("status", "unknown"),
                environment=payload.get("environment", "production"),
                owner=payload.get("owner", "Unassigned"),
                department=payload.get("department", "IT Operations"),
                confidence_score=100,
                discovery_source="manual",
                tags=payload.get("tags"),
                metadata=payload.get("metadata"),
                actor=identity["username"]
            )
            self._json(201, ast)
            return
        if path == "/api/assets/discover":
            if not self._require_permission(identity, "assets.manage"):
                return
            res = asset_manager.discover_assets_from_jobs()
            self._json(200, res)
            return
        if path == "/api/assets/import":
            if not self._require_permission(identity, "assets.manage"):
                return
            payload = self._read_json_body(2_097_152)
            content = payload.get("content", "")
            fmt = payload.get("format", "json")
            dry_run = bool(payload.get("dry_run", False))
            res = asset_manager.import_assets(content, format=fmt, dry_run=dry_run, actor=identity["username"])
            self._json(200, res)
            return
        asset_contain_match = re.fullmatch(r"/api/assets/([A-Za-z0-9_-]+)/containment", path)
        if asset_contain_match:
            if not self._require_permission(identity, "assets.isolate"):
                return
            asset_id = asset_contain_match.group(1)
            payload = self._read_json_body(16_384)
            action_type = payload.get("action_type", "network_isolation")
            provider = payload.get("provider", "manual_playbook")
            try:
                action = asset_manager.create_containment_action(
                    asset_id=asset_id,
                    action_type=action_type,
                    provider=provider,
                    dispatched_by=identity["username"],
                    payload=payload.get("payload")
                )
                self._json(201, action)
            except ValueError as e:
                self._json(404, {"error": str(e)})
            return
        contain_confirm_match = re.fullmatch(r"/api/assets/containment/([A-Za-z0-9_-]+)/confirm", path)
        if contain_confirm_match:
            if not self._require_permission(identity, "assets.isolate"):
                return
            action_id = contain_confirm_match.group(1)
            try:
                res = asset_manager.confirm_containment_action(action_id, actor=identity["username"])
                self._json(200, res)
            except ValueError as e:
                self._json(404, {"error": str(e)})
            return
        contain_revoke_match = re.fullmatch(r"/api/assets/containment/([A-Za-z0-9_-]+)/revoke", path)
        if contain_revoke_match:
            if not self._require_permission(identity, "assets.isolate"):
                return
            action_id = contain_revoke_match.group(1)
            try:
                res = asset_manager.revoke_containment_action(action_id, actor=identity["username"])
                self._json(200, res)
            except ValueError as e:
                self._json(404, {"error": str(e)})
            return
        # Graph Correlation POST Routes
        if path == "/api/correlation/promote":
            if not self._require_permission(identity, "correlation.manage"):
                return
            payload = self._read_json_body(65_536)
            pattern_type = str(payload.get("pattern_type") or "").strip()
            pattern_id = str(payload.get("pattern_id") or "").strip()
            eng = graph_correlation.get_graph_correlation_engine()
            inc = eng.promote_pattern_to_incident(pattern_type, pattern_id)
            if not inc:
                self._json(400, {"error": "تعذر ترقية نمط الترابط الجنائي إلى حادث (قد يكون تمت ترقيته مسبقاً أو غير موجود)."})
                return
            self._json(200, {"success": True, "incident": inc})
            return
        if path == "/api/correlation/analyze":
            if not self._require_permission(identity, "correlation.manage"):
                return
            eng = graph_correlation.get_graph_correlation_engine()
            res = eng.correlate_all()
            self._json(200, {"success": True, "result": res})
            return
        # Graph Correlation POST Routes
        if path == "/api/correlation/promote":
            if not self._require_permission(identity, "correlation.manage"):
                return
            payload = self._read_json_body(65_536)
            pattern_type = str(payload.get("pattern_type") or "").strip()
            pattern_id = str(payload.get("pattern_id") or "").strip()
            eng = graph_correlation.get_graph_correlation_engine()
            inc = eng.promote_pattern_to_incident(pattern_type, pattern_id)
            if not inc:
                self._json(400, {"error": "تعذر ترقية نمط الترابط الجنائي إلى حادث (قد يكون تمت ترقيته مسبقاً أو غير موجود)."})
                return
            self._json(200, {"success": True, "incident": inc})
            return
        if path == "/api/correlation/analyze":
            if not self._require_permission(identity, "correlation.manage"):
                return
            eng = graph_correlation.get_graph_correlation_engine()
            res = eng.correlate_all()
            self._json(200, {"success": True, "result": res})
            return
        permission = self._route_permission("POST", path)
        if permission and not self._require_permission(identity, permission):
            return
        feedback_match = re.fullmatch(
            r"/api/(flowscope|threatscope|logscope)/feedback/([0-9a-f]{32})/(\d+)", path
        )
        if feedback_match:
            self._save_feedback(
                feedback_match.group(1), feedback_match.group(2), int(feedback_match.group(3))
            )
            return
        if self._flow_route("POST", path) or self._threat_route("POST", path) or self._log_route("POST", path):
            allowed, block_reason = LicenseManager.get_instance().is_operation_allowed("analysis")
            if not allowed:
                self._json(402, {"error": "LICENSE_RESTRICTED", "message": block_reason})
                return
        if self._flow_route("POST", path):
            self._delegate_flow(flow_server.RequestHandler.do_POST)
            return
        if self._threat_route("POST", path):
            self._delegate_threat(threat_server.Handler.do_POST)
            return
        if self._log_route("POST", path):
            self._delegate_log(log_server.RequestHandler.do_POST)
            return
        self._json(404, {"error": "Not found"})

    def _save_feedback(self, app: str, job_id: str, record_index: int) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 16_384:
                self._json(400, {"error": "Invalid feedback payload"})
                return
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            feedback = learning_engine.save_feedback(
                app, job_id, record_index, str(payload.get("label") or ""),
                str(payload.get("note") or ""),
            )
            if app == "flowscope":
                job_file = flow_server.JOBS_DIR / job_id / "analysis.json"
                data = flow_server._read_json(job_file)
                data["records"][record_index]["analyst_feedback"] = feedback
                flow_server._write_json_atomic(job_file, data)
            elif app == "logscope":
                job_file = log_server.JOBS_DIR / job_id / "analysis.json"
                data = log_server._read_json(job_file)
                records = data.get("records") or data.get("events") or []
                records[record_index]["analyst_feedback"] = feedback
                data["records"] = records
                data["events"] = records
                log_server._write_json_atomic(job_file, data)
            else:
                data = threat_server._read_analysis(job_id)
                data["records"][record_index]["analyst_feedback"] = feedback
                threat_server._write_analysis(job_id, data)
            self._json(200, {"saved": True, "feedback": feedback})
        except (ValueError, json.JSONDecodeError, IndexError):
            self._json(400, {"error": "Invalid feedback"})
        except (LookupError, FileNotFoundError):
            self._json(404, {"error": "Learning observation not found"})

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        identity = self._require_authentication()
        if not identity:
            return
        admin_match = re.fullmatch(r"/api/admin/users/([0-9a-f]{16})", path)
        if admin_match:
            if not self._require_permission(identity, "users.manage"):
                return
            if identity["id"] == admin_match.group(1):
                self._json(400, {"error": "لا يمكنك حذف حسابك أثناء استخدامه."})
                return
            try:
                security_auth.delete_user(admin_match.group(1))
                self._json(200, {"deleted": True})
            except LookupError as error:
                self._json(404, {"error": str(error)})
            except ValueError as error:
                self._json(400, {"error": str(error)})
            return
        evi_del_match = re.fullmatch(r"/api/incidents/([A-Za-z0-9_-]+)/evidence/([A-Za-z0-9_-]+)", path)
        if evi_del_match:
            if not self._require_permission(identity, "incidents.manage"):
                return
            try:
                inc = incident_manager.remove_evidence_record(evi_del_match.group(1), evi_del_match.group(2), identity["username"])
                self._json(200, inc)
            except LookupError as error:
                self._json(404, {"error": str(error)})
            return
        inv_item_del = re.fullmatch(r"/api/investigations/([A-Za-z0-9_-]+)/items/([A-Za-z0-9_-]+)", path)
        if inv_item_del:
            if not self._require_permission(identity, "incidents.manage"):
                return
            inv_id = inv_item_del.group(1)
            item_entry_id = inv_item_del.group(2)
            mgr = investigation_manager.InvestigationManager.get_instance()
            ok = mgr.remove_item(inv_id, item_entry_id, actor=identity.get("username", "system"))
            if not ok:
                self._json(404, {"error": "Item not found in investigation"})
                return
            self._json(200, {"deleted": True, "id": item_entry_id})
            return
        det_del_match = re.fullmatch(r"/api/detections/([A-Za-z0-9_-]+)", path)
        if det_del_match:
            if not self._require_permission(identity, "detections.manage"):
                return
            try:
                rule = detection_engine.get_detection_engine().soft_delete_rule(
                    det_del_match.group(1),
                    deleted_by=identity["username"],
                    reason="Soft deleted by analyst"
                )
                self._json(200, {"deleted": True, "rule": rule.to_dict()})
            except KeyError as error:
                self._json(404, {"error": str(error)})
            return
        sigma_del_match = re.fullmatch(r"/api/sigma/rules/([A-Za-z0-9_-]+)", path)
        if sigma_del_match:
            if not self._require_permission(identity, "detections.manage"):
                return
            rule_id = sigma_del_match.group(1)
            eng = sigma_engine.SigmaEngine.get_instance()
            details = None
            try:
                details = eng.get_rule_details(rule_id)
            except Exception:
                pass
            if not details:
                self._json(404, {"error": "القاعدة غير موجودة."})
                return
            if details.get("source_type") == "builtin":
                self._json(403, {"error": "لا يمكن حذف قواعد Sigma المعتمدة المدمجة (Built-in Rules)."})
                return
            f_path_str = details.get("file_path")
            if f_path_str:
                f_path = Path(f_path_str)
                if f_path.exists():
                    f_path.unlink()
                    eng.reload()
                    detection_engine.get_detection_engine().load_all_rules()
                    audit_engine.record_engine_event(
                        application="sigma",
                        action="rule_delete",
                        message=f"تم حذف قاعدة Sigma المخصصة: {rule_id}",
                        category="detections",
                        details={"rule_id": rule_id, "user": identity.get("username")}
                    )
                    self._json(200, {"deleted": True, "message": "تم حذف قاعدة Sigma المخصصة بنجاح."})
                    return
            self._json(404, {"error": "ملف القاعدة غير موجود على القرص."})
            return
        intel_del_match = re.fullmatch(r"/api/intel/iocs/([A-Za-z0-9_-]+)", path)
        if intel_del_match:
            if not self._require_permission(identity, "intel.manage"):
                return
            ioc_id = intel_del_match.group(1)
            mgr = threat_intel.ThreatIntelManager.get_instance()
            success = mgr.delete_ioc(ioc_id, actor=identity.get("username", "analyst"))
            if not success:
                self._json(404, {"error": "مؤشر التهديد غير موجود."})
                return
            self._json(200, {"deleted": True, "id": ioc_id})
            return
        asset_del_match = re.fullmatch(r"/api/assets/([A-Za-z0-9_-]+)", path)
        if asset_del_match:
            if not self._require_permission(identity, "assets.manage"):
                return
            asset_id = asset_del_match.group(1)
            success = asset_manager.delete_asset(asset_id, actor=identity["username"])
            self._json(200, {"deleted": True, "id": asset_id})
            return
        role_del_match = re.fullmatch(r"/api/authorization/roles/([A-Za-z0-9_-]+)", path)
        if role_del_match:
            if not self._require_permission(identity, "roles.manage", "users.manage"):
                return
            role_id = role_del_match.group(1)
            try:
                authorization.delete_custom_role(role_id)
                audit_engine.record_engine_event(
                    action="authorization.role_delete",
                    user=identity["username"],
                    details={"role_id": role_id},
                )
                self._json(200, {"deleted": True, "id": role_id})
            except LookupError as err:
                self._json(404, {"error": str(err)})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        group_del_match = re.fullmatch(r"/api/authorization/groups/([A-Za-z0-9_-]+)", path)
        if group_del_match:
            if not self._require_permission(identity, "groups.manage", "users.manage"):
                return
            group_id = group_del_match.group(1)
            try:
                authorization.delete_group(group_id)
                audit_engine.record_engine_event(
                    action="authorization.group_delete",
                    user=identity["username"],
                    details={"group_id": group_id},
                )
                self._json(200, {"deleted": True, "id": group_id})
            except LookupError as err:
                self._json(404, {"error": str(err)})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        permission = self._route_permission("DELETE", path)
        if permission and not self._require_permission(identity, permission):
            return
        if self._flow_route("DELETE", path):
            self._delegate_flow(flow_server.RequestHandler.do_DELETE)
            return
        if self._threat_route("DELETE", path):
            self._delegate_threat(threat_server.Handler.do_DELETE)
            return
        if self._log_route("DELETE", path):
            self._delegate_log(log_server.RequestHandler.do_DELETE)
            return
        self._json(404, {"error": "Not found"})

    def do_PATCH(self) -> None:
        path = urlparse(self.path).path
        identity = self._require_authentication()
        if not identity:
            return
        role_patch_match = re.fullmatch(r"/api/authorization/roles/([A-Za-z0-9_-]+)", path)
        if role_patch_match:
            if not self._require_permission(identity, "roles.manage", "users.manage"):
                return
            try:
                payload = self._read_json_body(65_536)
                role = authorization.update_custom_role(
                    role_id=role_patch_match.group(1),
                    label_ar=payload.get("label_ar"),
                    description=payload.get("description"),
                    permissions=payload.get("permissions"),
                    default_scope=payload.get("default_scope"),
                )
                audit_engine.record_engine_event(
                    action="authorization.role_update",
                    user=identity["username"],
                    details={"role": role},
                )
                self._json(200, {"role": role})
            except LookupError as err:
                self._json(404, {"error": str(err)})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        group_patch_match = re.fullmatch(r"/api/authorization/groups/([A-Za-z0-9_-]+)", path)
        if group_patch_match:
            if not self._require_permission(identity, "groups.manage", "users.manage"):
                return
            try:
                payload = self._read_json_body(65_536)
                grp = authorization.update_group(
                    group_id=group_patch_match.group(1),
                    label_ar=payload.get("label_ar"),
                    description=payload.get("description"),
                    roles=payload.get("roles"),
                    default_scope=payload.get("default_scope"),
                    department=payload.get("department"),
                    members=payload.get("members"),
                )
                audit_engine.record_engine_event(
                    action="authorization.group_update",
                    user=identity["username"],
                    details={"group": grp},
                )
                self._json(200, {"group": grp})
            except LookupError as err:
                self._json(404, {"error": str(err)})
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        status_match = re.fullmatch(r"/api/incidents/([A-Za-z0-9_-]+)/status", path)
        if status_match:
            if not self._require_permission(identity, "incidents.manage"):
                return
            try:
                payload = self._read_json_body(16_384)
                new_status = str(payload.get("status") or "")
                reason = str(payload.get("reason") or "")
                inc = incident_manager.update_status(status_match.group(1), new_status, reason, identity["username"])
                if new_status == "Rejected":
                    for ev in inc.get("raw_evidence", []):
                        if "DET-" in ev:
                            m_rid = re.search(r"\b(DET-[A-Z]+-\d+)\b", ev)
                            if m_rid:
                                detection_engine.get_detection_engine().record_false_positive(m_rid.group(1))
                self._json(200, inc)
            except LookupError as error:
                self._json(404, {"error": str(error)})
            except ValueError as error:
                self._json(400, {"error": str(error)})
            return
        assign_match = re.fullmatch(r"/api/incidents/([A-Za-z0-9_-]+)/assign", path)
        if assign_match:
            if not self._require_permission(identity, "incidents.manage"):
                return
            try:
                payload = self._read_json_body(16_384)
                assigned_to = payload.get("assigned_to")
                reason = str(payload.get("reason") or "Assignment update")
                inc = incident_manager.assign_analyst(assign_match.group(1), assigned_to, identity["username"], reason)
                self._json(200, inc)
            except LookupError as error:
                self._json(404, {"error": str(error)})
            except ValueError as error:
                self._json(400, {"error": str(error)})
            return
        prio_match = re.fullmatch(r"/api/incidents/([A-Za-z0-9_-]+)/priority", path)
        if prio_match:
            if not self._require_permission(identity, "incidents.manage"):
                return
            try:
                payload = self._read_json_body(16_384)
                inc = incident_manager.update_priority(
                    prio_match.group(1),
                    severity=payload.get("severity"),
                    asset_criticality=payload.get("asset_criticality"),
                    business_impact=payload.get("business_impact"),
                    actor=identity["username"],
                    justification=str(payload.get("justification") or payload.get("reason") or "Priority updated"),
                )
                self._json(200, inc)
            except LookupError as error:
                self._json(404, {"error": str(error)})
            except ValueError as error:
                self._json(400, {"error": str(error)})
            return
        det_toggle_match = re.fullmatch(r"/api/detections/([A-Za-z0-9_-]+)/toggle", path)
        if det_toggle_match:
            if not self._require_permission(identity, "detections.manage"):
                return
            try:
                payload = self._read_json_body(16_384)
                enabled = bool(payload.get("enabled", True))
                rule = detection_engine.get_detection_engine().toggle_rule(
                    det_toggle_match.group(1),
                    enabled=enabled,
                    changed_by=identity["username"]
                )
                self._json(200, rule.to_dict())
            except KeyError as error:
                self._json(404, {"error": str(error)})
            except Exception as error:
                self._json(400, {"error": str(error)})
            return
        det_lifecycle_match = re.fullmatch(r"/api/detections/([A-Za-z0-9_-]+)/lifecycle", path)
        if det_lifecycle_match:
            if not self._require_permission(identity, "detections.manage"):
                return
            try:
                payload = self._read_json_body(16_384)
                new_state = str(payload.get("lifecycle") or "")
                reason = str(payload.get("reason") or "Lifecycle transition")
                rule = detection_engine.get_detection_engine().update_lifecycle(
                    det_lifecycle_match.group(1),
                    new_lifecycle=new_state,
                    changed_by=identity["username"],
                    reason=reason
                )
                self._json(200, rule.to_dict())
            except KeyError as error:
                self._json(404, {"error": str(error)})
            except ValueError as error:
                self._json(400, {"error": str(error)})
            return
        det_update_match = re.fullmatch(r"/api/detections/([A-Za-z0-9_-]+)", path)
        if det_update_match:
            if not self._require_permission(identity, "detections.manage"):
                return
            try:
                payload = self._read_json_body(262_144)
                payload["id"] = det_update_match.group(1)
                rule = detection_engine.get_detection_engine().create_or_update_rule(
                    payload,
                    changed_by=identity["username"],
                    reason=str(payload.get("change_reason") or "Rule updated via API")
                )
                self._json(200, rule.to_dict())
            except Exception as error:
                self._json(400, {"error": str(error)})
            return
        intel_toggle_match = re.fullmatch(r"/api/intel/iocs/([A-Za-z0-9_-]+)/toggle", path)
        if intel_toggle_match:
            if not self._require_permission(identity, "intel.manage"):
                return
            try:
                payload = self._read_json_body(16_384)
                is_active = bool(payload.get("is_active", True))
                mgr = threat_intel.ThreatIntelManager.get_instance()
                ioc = mgr.update_ioc(
                    intel_toggle_match.group(1),
                    actor=identity.get("username", "analyst"),
                    is_active=is_active,
                )
                if not ioc:
                    self._json(404, {"error": "مؤشر التهديد غير موجود."})
                    return
                self._json(200, ioc.to_dict())
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        intel_patch_match = re.fullmatch(r"/api/intel/iocs/([A-Za-z0-9_-]+)", path)
        if intel_patch_match:
            if not self._require_permission(identity, "intel.manage"):
                return
            try:
                payload = self._read_json_body(65_536)
                mgr = threat_intel.ThreatIntelManager.get_instance()
                ioc = mgr.update_ioc(
                    intel_patch_match.group(1),
                    actor=identity.get("username", "analyst"),
                    **payload
                )
                if not ioc:
                    self._json(404, {"error": "مؤشر التهديد غير موجود."})
                    return
                self._json(200, ioc.to_dict())
            except Exception as err:
                self._json(400, {"error": str(err)})
            return
        inv_patch_match = re.fullmatch(r"/api/investigations/([A-Za-z0-9_-]+)", path)
        if inv_patch_match:
            if not self._require_permission(identity, "incidents.manage"):
                return
            inv_id = inv_patch_match.group(1)
            payload = self._read_json_body(65_536) or {}
            actor = identity.get("username", "system")
            mgr = investigation_manager.InvestigationManager.get_instance()
            updated = mgr.update_investigation(inv_id, payload, actor=actor)
            if not updated:
                self._json(404, {"error": "Investigation not found"})
                return
            self._json(200, updated)
            return
        self._json(404, {"error": "Not found"})

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/v1/"):
            identity = security_auth.request_identity(self.headers)
            auth_ctx = {"authenticated": bool(identity), "user": identity}
            content_length = int(self.headers.get("Content-Length") or 0)
            body_bytes = self.rfile.read(content_length) if content_length > 0 else None
            resp = v1_api_router.dispatch(
                method="PUT",
                raw_url=self.path,
                headers=self._headers_dict(),
                body_bytes=body_bytes,
                auth_context=auth_ctx,
            )
            self._json(resp.status_code, resp.to_dict())
            return
        self._json(404, {"error": "Not found"})

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/api/v1/"):
            identity = security_auth.request_identity(self.headers)
            auth_ctx = {"authenticated": bool(identity), "user": identity}
            content_length = int(self.headers.get("Content-Length") or 0)
            body_bytes = self.rfile.read(content_length) if content_length > 0 else None
            resp = v1_api_router.dispatch(
                method="DELETE",
                raw_url=self.path,
                headers=self._headers_dict(),
                body_bytes=body_bytes,
                auth_context=auth_ctx,
            )
            self._json(resp.status_code, resp.to_dict())
            return
        identity = self._require_authentication()
        if not identity:
            return
        permission = self._route_permission("DELETE", path)
        if permission and not self._require_permission(identity, permission):
            return
        if self._flow_route("DELETE", path):
            self._delegate_flow(flow_server.RequestHandler.do_DELETE)
            return
        if self._threat_route("DELETE", path):
            self._delegate_threat(threat_server.Handler.do_DELETE)
            return
        if self._log_route("DELETE", path):
            self._delegate_log(log_server.RequestHandler.do_DELETE)
            return
        self._json(404, {"error": "Not found"})


    def _add_incident_evidence(self, incident_id: str, actor: str) -> None:
        try:
            payload = self._read_json_body(10 * 1024 * 1024)
            evidence_type = str(payload.get("evidence_type") or "other")
            name = str(payload.get("name") or "Evidence Artifact")
            value = payload.get("value")
            notes = str(payload.get("notes") or "")
            file_bytes = None
            filename = payload.get("filename")
            mime_type = payload.get("mime_type")
            if payload.get("file_b64"):
                import base64
                file_bytes = base64.b64decode(payload["file_b64"])
            inc = incident_manager.add_evidence_record(
                incident_id=incident_id,
                evidence_type=evidence_type,
                name=name,
                value=value,
                file_bytes=file_bytes,
                filename=filename,
                mime_type=mime_type,
                notes=notes,
                added_by=actor,
            )
            self._json(201, inc)
        except LookupError as error:
            self._json(404, {"error": str(error)})
        except ValueError as error:
            self._json(400, {"error": str(error)})

    def _serve_evidence_file(self, incident_id: str, evidence_id: str) -> None:
        inc = incident_manager.get_incident(incident_id)
        if not inc:
            self._json(404, {"error": "الحادث الأمني غير موجود."})
            return
        evidence = next((e for e in inc.get("evidence", []) if e.get("id") == evidence_id), None)
        if not evidence or not evidence.get("file_path"):
            self._json(404, {"error": "الملف المطلوب غير موجود."})
            return
        full_path = incident_manager.get_evidence_file_path(evidence["file_path"])
        if not full_path.is_file():
            self._json(404, {"error": "ملف الدليل غير موجود على وحدة التخزين."})
            return
        content = full_path.read_bytes()
        mime = evidence.get("mime_type") or "application/octet-stream"
        filename = evidence.get("name") or "evidence.bin"
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self._cors()
        self.end_headers()
        self.wfile.write(content)

    def _require_authentication(self) -> dict | None:
        identity = security_auth.request_identity(self.headers)
        if identity:
            set_context(user_id=identity.get("username"))
            return identity
        self._json(401, {"error": "Authentication required", "code": "authentication_required"})
        return None

    def _require_permission(self, identity: dict, *permissions: str) -> bool:
        if any(security_auth.has_permission(identity, p) for p in permissions):
            return True
        perm_str = permissions[0] if len(permissions) == 1 else ",".join(permissions)
        self._json(403, {"error": "ليست لديك صلاحية لتنفيذ هذا الإجراء.", "code": "permission_denied", "permission": perm_str})
        return False

    def _login(self) -> None:
        client = self.client_address[0] if self.client_address else "unknown"
        now = time.monotonic()
        with _LOGIN_LOCK:
            recent = [stamp for stamp in _LOGIN_ATTEMPTS.get(client, []) if now - stamp < _LOGIN_WINDOW_SECONDS]
            _LOGIN_ATTEMPTS[client] = recent
            if len(recent) >= _LOGIN_MAX_ATTEMPTS:
                self._json(429, {"error": "محاولات كثيرة. حاول مجدداً بعد خمس دقائق."})
                return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 4096:
                raise ValueError
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            username = str(payload.get("username") or "")
            password = str(payload.get("password") or "")
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": "بيانات الدخول غير صالحة."})
            return
        identity = security_auth.authenticate(username, password)
        if not identity:
            with _LOGIN_LOCK:
                _LOGIN_ATTEMPTS.setdefault(client, []).append(now)
            self._json(401, {"error": "اسم المستخدم أو كلمة المرور غير صحيحة."})
            return
        with _LOGIN_LOCK:
            _LOGIN_ATTEMPTS.pop(client, None)
        token = security_auth.create_session(identity["username"])
        self._json_with_cookie(
            200,
            {"authenticated": True, "user": identity},
            security_auth.session_cookie(token),
        )

    def _read_json_body(self, maximum: int = 65_536) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > maximum:
            raise ValueError("حجم الطلب غير صالح.")
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("صيغة الطلب غير صالحة.")
        return payload

    def _create_user(self) -> None:
        try:
            payload = self._read_json_body()
            user = security_auth.create_user(
                username=str(payload.get("username") or ""),
                password=str(payload.get("password") or ""),
                display_name=str(payload.get("display_name") or ""),
                permissions=payload.get("permissions") or [],
                active=bool(payload.get("active", True)),
                role_id=payload.get("role_id") or payload.get("role"),
                data_scope=payload.get("data_scope"),
                department=payload.get("department"),
                custom_permissions=payload.get("custom_permissions"),
                group_ids=payload.get("groups") or payload.get("group_ids"),
            )
            self._json(201, {"user": user})
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as error:
            self._json(400, {"error": str(error)})

    def _update_user(self, user_id: str) -> None:
        try:
            payload = self._read_json_body()
            user = security_auth.update_user(
                user_id,
                username=payload.get("username"),
                display_name=payload.get("display_name"),
                password=payload.get("password"),
                permissions=payload.get("permissions"),
                active=payload.get("active"),
                role_id=payload.get("role_id") or payload.get("role"),
                data_scope=payload.get("data_scope"),
                department=payload.get("department"),
                custom_permissions=payload.get("custom_permissions"),
                group_ids=payload.get("groups") or payload.get("group_ids"),
            )
            self._json(200, {"user": user})
        except LookupError as error:
            self._json(404, {"error": str(error)})
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as error:
            self._json(400, {"error": str(error)})

    def _update_account(self, identity: dict) -> None:
        try:
            payload = self._read_json_body(16_384)
            user = security_auth.update_own_account(
                identity["username"], str(payload.get("current_password") or ""),
                str(payload.get("username") or identity["username"]), str(payload.get("new_password") or "") or None,
                str(payload.get("display_name") or identity["display_name"]),
            )
            token = security_auth.create_session(user["username"])
            self._json_with_cookie(200, {"user": user}, security_auth.session_cookie(token))
        except PermissionError as error:
            self._json(403, {"error": str(error)})
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as error:
            self._json(400, {"error": str(error)})

    @staticmethod
    def _route_permission(method: str, path: str) -> str | None:
        checks = (
            ("GET", r"/api/flowscope/(?:health|config|jobs/[0-9a-f]{32}(?:/records)?)", "flowscope.view"),
            ("GET", r"/api/flowscope/export/[0-9a-f]{32}\.(?:docx|xlsx)", "flowscope.export"),
            ("GET", r"/api/flowscope/preview/[0-9a-f]{32}(?:\.pdf)?", "flowscope.export"),
            ("POST", r"/api/flowscope/analyze", "flowscope.analyze"),
            ("POST", r"/api/flowscope/enrich/[0-9a-f]{32}", "flowscope.enrich"),
            ("POST", r"/api/flowscope/feedback/[0-9a-f]{32}/\d+", "flowscope.feedback"),
            ("DELETE", r"/api/flowscope/enrich/[0-9a-f]{32}", "flowscope.enrich"),
            ("DELETE", r"/api/flowscope/jobs/[0-9a-f]{32}", "flowscope.delete"),
            ("GET", r"/api/threatscope/(?:health|config|jobs/[0-9a-f]{32}(?:/records)?)", "threatscope.view"),
            ("GET", r"/api/threatscope/(?:report|preview|export)/[0-9a-f]{32}(?:\.(?:docx|xlsx|pdf))?", "threatscope.export"),
            ("POST", r"/api/threatscope/analyze", "threatscope.analyze"),
            ("POST", r"/api/threatscope/enrich/[0-9a-f]{32}", "threatscope.enrich"),
            ("POST", r"/api/threatscope/feedback/[0-9a-f]{32}/\d+", "threatscope.feedback"),
            ("DELETE", r"/api/threatscope/jobs/[0-9a-f]{32}", "threatscope.delete"),
            ("GET", r"/api/logscope/(?:health|config|jobs/[0-9a-f]{32}(?:/records)?)", "logscope.view"),
            ("GET", r"/api/logscope/export/[0-9a-f]{32}\.(?:docx|xlsx)", "logscope.export"),
            ("GET", r"/api/logscope/preview/[0-9a-f]{32}(?:\.pdf)?", "logscope.export"),
            ("POST", r"/api/logscope/analyze", "logscope.analyze"),
            ("POST", r"/api/logscope/enrich/[0-9a-f]{32}", "logscope.enrich"),
            ("POST", r"/api/logscope/feedback/[0-9a-f]{32}/\d+", "logscope.feedback"),
            ("DELETE", r"/api/logscope/enrich/[0-9a-f]{32}", "logscope.enrich"),
            ("DELETE", r"/api/logscope/jobs/[0-9a-f]{32}", "logscope.delete"),
        )
        return next((permission for verb, pattern, permission in checks if method == verb and re.fullmatch(pattern, path)), None)

    def _json_with_cookie(self, status: int, payload: dict, cookie: str) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _flow_route(method: str, path: str) -> bool:
        routes = {
            "GET": (
                r"/api/flowscope/(?:health|config)",
                r"/api/flowscope/jobs/[0-9a-f]{32}(?:/records)?",
                r"/api/flowscope/export/[0-9a-f]{32}\.(?:docx|xlsx)",
                r"/api/flowscope/preview/[0-9a-f]{32}(?:\.pdf)?",
            ),
            "POST": (r"/api/flowscope/analyze", r"/api/flowscope/enrich/[0-9a-f]{32}"),
            "DELETE": (r"/api/flowscope/(?:enrich|jobs)/[0-9a-f]{32}",),
        }
        return any(re.fullmatch(pattern, path) for pattern in routes[method])

    @staticmethod
    def _threat_route(method: str, path: str) -> bool:
        routes = {
            "GET": (
                r"/api/threatscope/(?:health|config)",
                r"/api/threatscope/jobs/[0-9a-f]{32}(?:/records)?",
                r"/api/threatscope/(?:report|preview)/[0-9a-f]{32}(?:\.pdf)?",
                r"/api/threatscope/export/[0-9a-f]{32}\.(?:docx|xlsx)",
            ),
            "POST": (r"/api/threatscope/analyze", r"/api/threatscope/enrich/[0-9a-f]{32}"),
            "DELETE": (r"/api/threatscope/jobs/[0-9a-f]{32}",),
        }
        return any(re.fullmatch(pattern, path) for pattern in routes[method])

    @staticmethod
    def _log_route(method: str, path: str) -> bool:
        routes = {
            "GET": (
                r"/api/logscope/(?:health|config)",
                r"/api/logscope/jobs/[0-9a-f]{32}(?:/(?:records|incidents|entities|mitre)(?:/.*)?)?",
                r"/api/logscope/export/[0-9a-f]{32}\.(?:docx|xlsx)",
                r"/api/logscope/preview/[0-9a-f]{32}(?:\.pdf)?",
            ),
            "POST": (r"/api/logscope/analyze", r"/api/logscope/enrich/[0-9a-f]{32}"),
            "DELETE": (r"/api/logscope/(?:enrich|jobs)/[0-9a-f]{32}",),
        }
        return any(re.fullmatch(pattern, path) for pattern in routes[method])

    def _delegate_flow(self, method) -> None:
        original = self.path
        original_get_records = getattr(self, "_handle_get_records", None)
        self.path = "/api" + self.path[len("/api/flowscope"):]
        self._handle_get_records = flow_server.RequestHandler._handle_get_records.__get__(self)
        try:
            method(self)
        finally:
            self.path = original
            if original_get_records is None:
                try:
                    del self._handle_get_records
                except AttributeError:
                    pass
            else:
                self._handle_get_records = original_get_records

    def _delegate_threat(self, method) -> None:
        original = self.path
        self.path = "/api" + self.path[len("/api/threatscope"):]
        try:
            method(self)
        finally:
            self.path = original


    def _delegate_log(self, method) -> None:
        original_path = self.path
        original_analysis = self._run_analysis
        original_enrichment = self._run_enrichment
        original_get_records = getattr(self, "_handle_get_records", None)
        original_get_incidents = getattr(self, "_handle_get_incidents", None)
        original_get_entity = getattr(self, "_handle_get_entity", None)
        original_get_mitre = getattr(self, "_handle_get_mitre", None)

        self.path = "/api" + self.path[len("/api/logscope"):]
        self._run_analysis = log_server.RequestHandler._run_analysis.__get__(self)
        self._run_enrichment = log_server.RequestHandler._run_enrichment.__get__(self)
        self._handle_get_records = log_server.RequestHandler._handle_get_records.__get__(self)
        self._handle_get_incidents = log_server.RequestHandler._handle_get_incidents.__get__(self)
        self._handle_get_entity = log_server.RequestHandler._handle_get_entity.__get__(self)
        self._handle_get_mitre = log_server.RequestHandler._handle_get_mitre.__get__(self)
        try:
            method(self)
        finally:
            self.path = original_path
            self._run_analysis = original_analysis
            self._run_enrichment = original_enrichment
            if original_get_records is None:
                try:
                    del self._handle_get_records
                except AttributeError:
                    pass
            else:
                self._handle_get_records = original_get_records

            if original_get_incidents is None:
                try:
                    del self._handle_get_incidents
                except AttributeError:
                    pass
            else:
                self._handle_get_incidents = original_get_incidents

            if original_get_entity is None:
                try:
                    del self._handle_get_entity
                except AttributeError:
                    pass
            else:
                self._handle_get_entity = original_get_entity

            if original_get_mitre is None:
                try:
                    del self._handle_get_mitre
                except AttributeError:
                    pass
            else:
                self._handle_get_mitre = original_get_mitre


def main() -> None:
    init_platform_logging()
    time_service.init_time_service()
    logger = get_logger("backend")
    logger.info("Unified backend server starting", event_code="SYS_START", host=HOST, port=PORT)
    logger.info("بدء تشغيل خادم المنصة الموحد", event_code="SYS_START", host=HOST, port=PORT)

    flow_server.JOBS_DIR.mkdir(parents=True, exist_ok=True)
    threat_server.JOBS.mkdir(parents=True, exist_ok=True)
    log_server.JOBS_DIR.mkdir(parents=True, exist_ok=True)
    flow_server._recover_interrupted_jobs()
    log_server._recover_interrupted_jobs()
    ollama_advisor.recover_jobs("flowscope", flow_server.JOBS_DIR)
    ollama_advisor.recover_jobs("threatscope", threat_server.JOBS)
    ollama_advisor.recover_jobs("logscope", log_server.JOBS_DIR)
    platform_config.apply_runtime()
    platform_config.apply_retention()
    incident_manager.init_db()
    threat_intel.init_db()
    threat_intel.ThreatIntelManager.get_instance()
    LicenseManager.get_instance()
    threading.Thread(target=incident_manager.sync_all_existing_jobs, daemon=True).start()
    threading.Thread(target=learning_engine.backfill_workspace, daemon=True).start()
    server = ExclusiveThreadingHTTPServer((HOST, PORT), UnifiedAPIHandler)
    print(f"Unified backend running on http://{HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Unified backend server shutting down", event_code="SYS_SHUTDOWN")
        logger.info("تم إيقاف خادم المنصة الموحد بنجاح", event_code="SYS_SHUTDOWN")
        server.server_close()



if __name__ == "__main__":
    main()
