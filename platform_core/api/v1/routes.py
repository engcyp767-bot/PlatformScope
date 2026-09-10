"""Standard v1 API Routes for Platform Scope.

Includes endpoints for Edition & Licensing, API Keys, EndpointScope agent management,
telemetry ingestion, response actions, and Plugin ecosystem.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from endpointscope.collector import EndpointCollector, get_endpoint_collector
from endpointscope.models import (
    AgentInfo,
    AgentState,
    EndpointEvent,
    EndpointEventType,
    ResponseAction,
    ResponseActionType,
)
from endpointscope.monitor import EndpointMonitor, get_endpoint_monitor
from platform_core.api.keys import APIKeyManager, APIScope, get_api_key_manager
from platform_core.api.router import (
    APIRouter,
    APIResponse,
    error_response,
    get_api_router,
    success_response,
)
from platform_core.feature_gate import FeatureGate, FeatureID, get_feature_gate
from platform_core.plugins import get_plugin_manager

try:
    from compliancescope import (
        get_all_frameworks,
        get_compliance_evaluator,
        ComplianceEvaluator,
    )
    _COMPLIANCESCOPE_AVAILABLE = True
except ImportError:
    _COMPLIANCESCOPE_AVAILABLE = False
    get_all_frameworks = None
    get_compliance_evaluator = None
    ComplianceEvaluator = None

from mailscope import (
    get_mail_analyzer,
    get_mail_store,
    MailParser,
)


def register_v1_routes(
    router: Optional[APIRouter] = None,
    collector: Optional[EndpointCollector] = None,
    monitor: Optional[EndpointMonitor] = None,
    key_manager: Optional[APIKeyManager] = None,
    feature_gate: Optional[FeatureGate] = None,
) -> APIRouter:
    """Register all official v1 API routes on the router."""
    r = router or get_api_router()
    c = collector or get_endpoint_collector()
    m = monitor or get_endpoint_monitor()
    km = key_manager or get_api_key_manager()
    gate = feature_gate or (r._feature_gate if hasattr(r, "_feature_gate") else get_feature_gate())
    pm = get_plugin_manager()

    # -------------------------------------------------------------
    # System & Edition Information
    # -------------------------------------------------------------
    @r.get(
        "/edition",
        summary="Get Current Platform Edition & License Details",
        tags=["Licensing"],
    )
    def get_edition_info() -> dict[str, Any]:
        edition = gate._get_edition()
        try:
            info = gate._license_manager.get_info()
            license_data = info.to_dict() if info else None
        except Exception:
            license_data = None
        return {
            "edition": edition.value,
            "license": license_data,
            "usage_summary": gate.get_usage_summary(),
            "gcc_compliance": {
                "nca_ecc": True,
                "sama_csf": True,
                "pdpl_ready": True,
                "offline_airgapped_certified": True,
            },
        }

    @r.get(
        "/features",
        summary="List all platform features and availability",
        tags=["Licensing"],
    )
    def list_features() -> dict[str, Any]:
        return {
            "usage_summary": gate.get_usage_summary(),
            "edition_comparison": gate.get_edition_comparison(),
            "edition": gate._get_edition().value,
        }

    @r.get(
        "/openapi.json",
        summary="Get OpenAPI 3.0 Specification",
        tags=["System"],
    )
    def get_openapi() -> dict[str, Any]:
        return r.generate_openapi_spec()

    # -------------------------------------------------------------
    # API Keys Management
    # -------------------------------------------------------------
    @r.get(
        "/keys",
        required_scope=APIScope.ADMIN,
        summary="List all API keys",
        tags=["API Keys"],
    )
    def list_api_keys() -> list[dict[str, Any]]:
        return [k.to_dict() for k in km.list_keys()]

    @r.post(
        "/keys",
        required_scope=APIScope.ADMIN,
        summary="Create a new API key",
        tags=["API Keys"],
    )
    def create_api_key(body: dict[str, Any]) -> APIResponse:
        name = body.get("name", "Default Key")
        scope = body.get("scope", APIScope.READ)
        expires_in_days = body.get("expires_in_days")
        rate_limit_rpm = body.get("rate_limit_rpm", 120)
        is_test = body.get("is_test", False)

        raw_key, record = km.generate_key(
            name=name,
            scope=scope,
            expires_in_days=expires_in_days,
            rate_limit_rpm=rate_limit_rpm,
            is_test=is_test,
        )
        return success_response(
            data={
                "raw_key": raw_key,
                "key": record.to_dict(),
                "warning": "Make sure to copy your API key now as you will not be able to see it again.",
            },
            status_code=201,
        )

    @r.delete(
        "/keys/{key_id}",
        required_scope=APIScope.ADMIN,
        summary="Revoke an API key",
        tags=["API Keys"],
    )
    def revoke_api_key(key_id: str) -> APIResponse:
        ok = km.revoke_key(key_id)
        if not ok:
            return error_response("KEY_NOT_FOUND", f"Key '{key_id}' not found", status_code=404)
        return success_response({"revoked": True, "key_id": key_id})

    # -------------------------------------------------------------
    # EndpointScope: Agent Management & Ingestion
    # -------------------------------------------------------------
    @r.post(
        "/endpoint/register",
        required_scope=APIScope.INGEST,
        required_feature=FeatureID.ENDPOINTS_BASIC,
        summary="Register or update an Endpoint Agent",
        tags=["EndpointScope"],
    )
    def register_endpoint_agent(body: dict[str, Any]) -> APIResponse:
        agent_id = body.get("agent_id") or f"agent-{uuid.uuid4().hex[:12]}"
        hostname = body.get("hostname", "unknown")
        os_type = body.get("os_type", body.get("os_family", "windows"))
        os_version = body.get("os_version", "")
        agent_version = body.get("version", body.get("agent_version", "1.0.0"))
        ip_addresses = body.get("ip_addresses", [])
        mac_addresses = body.get("mac_addresses", [])
        tags = body.get("tags", [])
        group = body.get("group", "default")

        # Check maximum agents limit for current edition
        current_res = c.list_agents()
        current_count = current_res.get("total", len(current_res.get("agents", [])))
        denial = gate.check_item_limit("endpointscope", current_count)
        if denial:
            return error_response(
                code="AGENT_LIMIT_REACHED",
                message=denial.reason_en,
                status_code=403,
                details=denial.to_dict(),
            )

        info = AgentInfo(
            agent_id=agent_id,
            hostname=hostname,
            os_type=os_type,
            os_version=os_version,
            agent_version=agent_version,
            ip_addresses=ip_addresses,
            mac_addresses=mac_addresses,
            tags=tags,
            group=group,
        )
        res = c.register_agent(info)
        return success_response(data=res, status_code=201)

    @r.post(
        "/endpoint/heartbeat",
        required_scope=APIScope.INGEST,
        required_feature=FeatureID.ENDPOINTS_BASIC,
        summary="Ingest Agent Heartbeat and return pending response actions",
        tags=["EndpointScope"],
    )
    def agent_heartbeat(body: dict[str, Any]) -> APIResponse:
        agent_id = body.get("agent_id")
        if not agent_id:
            return error_response("MISSING_AGENT_ID", "agent_id is required", status_code=400)

        metrics = body.get("metrics")
        hb_res = c.heartbeat(agent_id, metrics)
        return success_response(data=hb_res)

    @r.post(
        "/endpoint/events",
        required_scope=APIScope.INGEST,
        required_feature=FeatureID.ENDPOINTS_BASIC,
        summary="Ingest batch of endpoint security events",
        tags=["EndpointScope"],
    )
    def ingest_endpoint_events(body: dict[str, Any]) -> APIResponse:
        events_raw = body.get("events", [])
        if not isinstance(events_raw, list):
            return error_response("INVALID_EVENTS", "events must be a list", status_code=400)

        events: list[EndpointEvent] = []
        for raw in events_raw:
            try:
                evt_type_str = str(raw.get("event_type", "heartbeat")).lower()
                try:
                    etype = EndpointEventType(evt_type_str)
                except ValueError:
                    etype = EndpointEventType.HEARTBEAT
                evt = EndpointEvent(
                    event_id=raw.get("event_id") or str(uuid.uuid4()),
                    agent_id=raw.get("agent_id", "local"),
                    hostname=raw.get("hostname", ""),
                    event_type=etype,
                    timestamp=raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    severity=str(raw.get("severity", "info")).lower(),
                    process_name=raw.get("process_name", raw.get("source_process", "")),
                    command_line=raw.get("command_line", raw.get("details", {}).get("cmdline", "")),
                )
                events.append(evt)
            except Exception:
                pass

        ingest_res = c.ingest_events(events)
        return success_response(data=ingest_res)

    @r.get(
        "/endpoint/agents",
        required_scope=APIScope.READ,
        required_feature=FeatureID.ENDPOINTS_BASIC,
        summary="List all endpoint agents",
        tags=["EndpointScope"],
    )
    def list_endpoint_agents(query: dict[str, Any]) -> dict[str, Any]:
        status_filter = query.get("status") or query.get("state")
        group_filter = query.get("group")
        limit = int(query.get("limit", 100))
        offset = int(query.get("offset", 0))
        return c.list_agents(state=status_filter, group=group_filter, limit=limit, offset=offset)

    @r.get(
        "/endpoint/agents/{agent_id}",
        required_scope=APIScope.READ,
        required_feature=FeatureID.ENDPOINTS_BASIC,
        summary="Get details and recent events of an agent",
        tags=["EndpointScope"],
    )
    def get_agent_details(agent_id: str) -> APIResponse:
        agent = c.get_agent(agent_id)
        if not agent:
            return error_response("AGENT_NOT_FOUND", f"Agent '{agent_id}' not found", status_code=404)
        
        events = c.get_events(agent_id=agent_id, limit=50)
        return success_response({
            "agent": agent,
            "recent_events": events.get("events", []),
        })

    @r.get(
        "/endpoint/stats",
        required_scope=APIScope.READ,
        required_feature=FeatureID.ENDPOINTS_BASIC,
        summary="Get EndpointScope dashboard statistics",
        tags=["EndpointScope"],
    )
    def get_endpoint_stats() -> dict[str, Any]:
        return c.get_dashboard_stats()

    # -------------------------------------------------------------
    # EndpointScope: Response Actions (Feature Gated: Pro+)
    # -------------------------------------------------------------
    @r.post(
        "/endpoint/actions/isolate",
        required_scope=APIScope.WRITE,
        required_feature=FeatureID.RESPONSE_AUTOMATION,
        summary="Queue host network isolation action",
        tags=["Endpoint Actions"],
    )
    def isolate_host(body: dict[str, Any]) -> APIResponse:
        agent_id = body.get("agent_id")
        if not agent_id:
            return error_response("MISSING_AGENT_ID", "agent_id is required", status_code=400)

        action_type = ResponseActionType.ISOLATE_ENDPOINT if body.get("isolate", True) else ResponseActionType.UNISOLATE_ENDPOINT
        action_dict = c.create_response_action(
            agent_id=agent_id,
            action_type=action_type,
            parameters=body,
        )
        return success_response(data=action_dict)

    @r.post(
        "/endpoint/actions/kill-process",
        required_scope=APIScope.WRITE,
        required_feature=FeatureID.RESPONSE_AUTOMATION,
        summary="Queue process termination action on endpoint",
        tags=["Endpoint Actions"],
    )
    def kill_process(body: dict[str, Any]) -> APIResponse:
        agent_id = body.get("agent_id")
        pid = body.get("pid")
        if not agent_id or pid is None:
            return error_response("INVALID_PARAMS", "agent_id and pid are required", status_code=400)

        action_dict = c.create_response_action(
            agent_id=agent_id,
            action_type=ResponseActionType.KILL_PROCESS,
            parameters={"pid": int(pid), "process_name": body.get("process_name", "")},
        )
        return success_response(data=action_dict)

    # -------------------------------------------------------------
    # EndpointScope: Live Host Monitor Scan
    # -------------------------------------------------------------
    @r.post(
        "/endpoint/monitor/scan",
        required_scope=APIScope.READ,
        required_feature=FeatureID.ENDPOINTS_BASIC,
        summary="Perform an on-demand snapshot of the host",
        tags=["EndpointScope"],
    )
    def scan_host() -> dict[str, Any]:
        return m.collect_system_snapshot()

    # -------------------------------------------------------------
    # Plugins Management (Feature Gated: Enterprise for Custom SDK)
    # -------------------------------------------------------------
    @r.get(
        "/plugins",
        required_scope=APIScope.READ,
        summary="List all discovered plugins and their states",
        tags=["Plugins"],
    )
    def list_plugins() -> list[dict[str, Any]]:
        return [p.to_dict() for p in pm.list_plugins()]

    @r.post(
        "/plugins/{plugin_id}/enable",
        required_scope=APIScope.ADMIN,
        summary="Enable an installed plugin",
        tags=["Plugins"],
    )
    def enable_plugin(plugin_id: str) -> APIResponse:
        ok = pm.enable_plugin(plugin_id)
        if not ok:
            return error_response("PLUGIN_ERROR", f"Could not enable plugin '{plugin_id}'", status_code=400)
        return success_response({"enabled": True, "plugin_id": plugin_id})

    @r.post(
        "/plugins/{plugin_id}/disable",
        required_scope=APIScope.ADMIN,
        summary="Disable a plugin",
        tags=["Plugins"],
    )
    def disable_plugin(plugin_id: str) -> APIResponse:
        ok = pm.disable_plugin(plugin_id)
        if not ok:
            return error_response("PLUGIN_ERROR", f"Could not disable plugin '{plugin_id}'", status_code=400)
        return success_response({"disabled": True, "plugin_id": plugin_id})

    # -------------------------------------------------------------
    # ComplianceScope: Saudi & GCC Regulatory Frameworks (Pro+)
    # -------------------------------------------------------------
    if _COMPLIANCESCOPE_AVAILABLE and get_compliance_evaluator is not None and get_all_frameworks is not None:
        evaluator = get_compliance_evaluator()

        @r.get(
            "/compliance/frameworks",
            required_scope=APIScope.READ,
            required_feature=FeatureID.COMPLIANCESCOPE,
            summary="List all supported compliance frameworks and their controls",
            tags=["ComplianceScope"],
        )
        def list_compliance_frameworks() -> list[dict[str, Any]]:
            return [f.to_dict() for f in get_all_frameworks()]

        @r.post(
            "/compliance/assess",
            required_scope=APIScope.READ,
            required_feature=FeatureID.COMPLIANCESCOPE,
            summary="Run a live automated compliance posture assessment",
            tags=["ComplianceScope"],
        )
        def run_compliance_assessment(body: Optional[dict[str, Any]] = None) -> dict[str, Any]:
            fw_ids = body.get("framework_ids") if body else None
            report = evaluator.run_assessment(framework_ids=fw_ids)
            return report.to_dict()

        @r.get(
            "/compliance/scores",
            required_scope=APIScope.READ,
            required_feature=FeatureID.COMPLIANCESCOPE,
            summary="Get current compliance scores and domain posture summary",
            tags=["ComplianceScope"],
        )
        def get_compliance_scores() -> dict[str, Any]:
            report = evaluator.run_assessment()
            return {
                "overall_posture_score": report.overall_posture_score,
                "total_gaps": report.total_gaps,
                "critical_gaps": report.critical_gaps,
                "high_gaps": report.high_gaps,
                "framework_scores": [
                    {
                        "framework_id": f.framework_id.value,
                        "name_ar": f.name_ar,
                        "name_en": f.name_en,
                        "overall_score": f.overall_score,
                        "total_controls": f.total_controls,
                        "domains": [
                            {
                                "domain_id": d.domain_id,
                                "name_ar": d.name_ar,
                                "compliance_score": d.compliance_score,
                                "controls_count": len(d.controls),
                            }
                            for d in f.domains
                        ],
                    }
                    for f in report.frameworks
                ],
            }

        @r.get(
            "/compliance/gaps",
            required_scope=APIScope.READ,
            required_feature=FeatureID.COMPLIANCESCOPE,
            summary="Get list of compliance gaps and actionable remediation guidance",
            tags=["ComplianceScope"],
        )
        def get_compliance_gaps() -> list[dict[str, Any]]:
            report = evaluator.run_assessment()
            return [g.to_dict() for g in report.gaps]

    # -------------------------------------------------------------
    # MailScope: Email Forensics, Phishing & BEC Defense
    # -------------------------------------------------------------
    mail_analyzer = get_mail_analyzer()
    mail_store = get_mail_store()

    @r.get(
        "/mail/stats",
        required_scope=APIScope.READ,
        required_feature=FeatureID.MAILSCOPE,
        summary="Get email forensics dashboard KPIs and threat domain metrics",
        tags=["MailScope"],
    )
    def get_mail_stats() -> dict[str, Any]:
        return mail_store.get_dashboard_stats()

    @r.get(
        "/mail/reports",
        required_scope=APIScope.READ,
        required_feature=FeatureID.MAILSCOPE,
        summary="List analyzed email reports with filters",
        tags=["MailScope"],
    )
    def list_mail_reports(query_params: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
        qp = query_params or {}
        verdict = qp.get("verdict")
        search = qp.get("search")
        quarantined_only = qp.get("quarantined", "").lower() in {"1", "true", "yes"}
        limit = int(qp.get("limit", 50))
        offset = int(qp.get("offset", 0))
        return mail_store.list_reports(
            verdict=verdict,
            search=search,
            quarantined_only=quarantined_only,
            limit=limit,
            offset=offset,
        )

    @r.get(
        "/mail/reports/{report_id}",
        required_scope=APIScope.READ,
        required_feature=FeatureID.MAILSCOPE,
        summary="Get full email forensic report details and digital signature",
        tags=["MailScope"],
    )
    def get_mail_report(report_id: str) -> APIResponse:
        report = mail_store.get_report(report_id)
        if not report:
            return error_response("REPORT_NOT_FOUND", f"Report '{report_id}' not found", status_code=404)
        return success_response(data=report)

    @r.post(
        "/mail/analyze",
        required_scope=APIScope.WRITE,
        required_feature=FeatureID.MAILSCOPE,
        summary="Analyze raw RFC 822 email content or EML string for threats and BEC",
        tags=["MailScope"],
    )
    def analyze_mail(body: dict[str, Any]) -> APIResponse:
        raw_eml = body.get("raw_eml", "")
        if not raw_eml:
            return error_response("MISSING_CONTENT", "raw_eml field is required", status_code=400)

        try:
            parsed = MailParser.parse(raw_eml)
            report = mail_analyzer.analyze(parsed)
            mail_store.save_report(report)
            return success_response(data=report.to_dict())
        except Exception as e:
            return error_response("ANALYSIS_FAILED", f"Email parsing/analysis failed: {str(e)}", status_code=500)

    @r.post(
        "/mail/quarantine/{report_id}",
        required_scope=APIScope.WRITE,
        required_feature=FeatureID.MAILSCOPE,
        summary="Toggle quarantine state of an analyzed email",
        tags=["MailScope"],
    )
    def quarantine_mail(report_id: str, body: Optional[dict[str, Any]] = None) -> APIResponse:
        quarantine = (body.get("quarantine", True)) if body else True
        ok = mail_store.set_quarantine(report_id, quarantined=quarantine)
        if not ok:
            return error_response("REPORT_NOT_FOUND", f"Report '{report_id}' not found", status_code=404)
        return success_response(data={"report_id": report_id, "quarantined": quarantine})

    return r

