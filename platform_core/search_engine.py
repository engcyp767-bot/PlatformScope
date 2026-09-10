"""Enterprise Global Cross-Entity Search Engine.

Enables unified, high-speed scoped search across Incidents, Assets,
Detection/Sigma Rules, Threat Intelligence IOCs, and Background Tasks.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from platform_core import (
    incident_manager,
    asset_manager,
    detection_engine,
    threat_intel,
    enterprise,
)

logger = logging.getLogger("platform.search_engine")

_LOCK = threading.Lock()


class GlobalSearchEngine:
    _instance: GlobalSearchEngine | None = None

    @classmethod
    def get_instance(cls) -> GlobalSearchEngine:
        if cls._instance is None:
            with _LOCK:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def search(
        self,
        query: str,
        entities: list[str] | None = None,
        limit_per_entity: int = 5,
        user_context: Any = None,
    ) -> dict[str, Any]:
        """Perform unified search across security platform entities."""
        q = (query or "").strip()
        if len(q) < 2:
            return {
                "query": q,
                "total_matches": 0,
                "results": {
                    "incidents": [],
                    "assets": [],
                    "rules": [],
                    "iocs": [],
                    "tasks": [],
                },
            }

        limit = max(1, min(limit_per_entity, 50))
        target_entities = set(entities) if entities else {"incidents", "assets", "rules", "iocs", "tasks"}

        results: dict[str, list[dict[str, Any]]] = {
            "incidents": [],
            "assets": [],
            "rules": [],
            "iocs": [],
            "tasks": [],
        }
        total_matches = 0

        # 1. Incidents
        if "incidents" in target_entities:
            try:
                inc_list, _ = incident_manager.list_incidents(search=q, limit=limit)
                for inc in inc_list:
                    sev = (inc.get("severity") or "medium").lower()
                    color = "rose" if sev in ("critical", "high") else "amber" if sev == "medium" else "slate"
                    results["incidents"].append({
                        "id": inc["id"],
                        "entity_type": "incident",
                        "title": inc.get("title", inc["id"]),
                        "subtitle": f"{inc.get('source_app', 'SOC').upper()} • {inc.get('status', 'new')}",
                        "badge": inc.get("severity", "medium").upper(),
                        "badge_color": color,
                        "timestamp": inc.get("created_at"),
                        "url": f"/incidents?selected={inc['id']}",
                        "snippet": (inc.get("description") or "")[:140],
                    })
                total_matches += len(results["incidents"])
            except Exception as e:
                logger.error("Error searching incidents: %s", e)

        # 2. Assets
        if "assets" in target_entities:
            try:
                asset_res = asset_manager.list_assets(search=q, limit=limit)
                asset_items = asset_res.get("assets") or asset_res.get("items") or []
                for ast in asset_items:
                    risk = ast.get("risk_score", 0)
                    color = "rose" if risk >= 70 else "amber" if risk >= 40 else "emerald"
                    results["assets"].append({
                        "id": ast["id"],
                        "entity_type": "asset",
                        "title": ast.get("hostname") or ast.get("primary_ip") or ast["id"],
                        "subtitle": f"{ast.get('primary_ip', '')} • {ast.get('asset_type', 'host')}",
                        "badge": f"Risk {risk}",
                        "badge_color": color,
                        "timestamp": ast.get("last_seen"),
                        "url": f"/assets?search={ast.get('hostname') or ast.get('primary_ip') or ast['id']}",
                        "snippet": f"Dept: {ast.get('department', 'IT')} • {ast.get('criticality', 'medium')}",
                    })
                total_matches += len(results["assets"])
            except Exception as e:
                logger.error("Error searching assets: %s", e)

        # 3. Detection & Sigma Rules
        if "rules" in target_entities:
            try:
                engine = detection_engine.get_detection_engine()
                all_rules = engine.get_all_rules()
                q_lower = q.lower()
                matched_rules = []
                for r in all_rules:
                    if (
                        q_lower in r.id.lower()
                        or q_lower in r.name.lower()
                        or q_lower in (r.description or "").lower()
                        or q_lower in r.category.lower()
                    ):
                        matched_rules.append(r)
                        if len(matched_rules) >= limit:
                            break

                for r in matched_rules:
                    sev = (r.severity or "medium").lower()
                    color = "rose" if sev in ("critical", "high") else "amber" if sev == "medium" else "slate"
                    results["rules"].append({
                        "id": r.id,
                        "entity_type": "rule",
                        "title": r.name,
                        "subtitle": f"{r.category.upper()} • {r.threat_family}",
                        "badge": r.severity.upper(),
                        "badge_color": color,
                        "timestamp": getattr(r, "created_at", None),
                        "url": f"/detections?search={r.id}",
                        "snippet": (r.description or "")[:140],
                    })
                total_matches += len(results["rules"])
            except Exception as e:
                logger.error("Error searching detection rules: %s", e)

        # 4. Threat Intel IOCs
        if "iocs" in target_entities:
            try:
                ioc_mgr = threat_intel.ThreatIntelManager.get_instance()
                ioc_list, _ = ioc_mgr.list_iocs(query=q, limit=limit)
                for ioc in ioc_list:
                    sev = (ioc.severity or "medium").lower()
                    color = "rose" if sev in ("critical", "high") else "amber" if sev == "medium" else "cyan"
                    results["iocs"].append({
                        "id": ioc.id,
                        "entity_type": "ioc",
                        "title": ioc.value,
                        "subtitle": f"{ioc.type.upper()} • {ioc.threat_type.upper()}",
                        "badge": ioc.severity.upper(),
                        "badge_color": color,
                        "timestamp": ioc.last_seen,
                        "url": f"/intel?search={ioc.value}",
                        "snippet": f"TLP: {ioc.tlp.upper()} • Conf: {ioc.confidence}%",
                    })
                total_matches += len(results["iocs"])
            except Exception as e:
                logger.error("Error searching IOCs: %s", e)

        # 5. Background Tasks & Jobs
        if "tasks" in target_entities:
            try:
                tq = enterprise.EnterpriseTaskQueue.get_instance()
                task_list = tq.list_tasks(search=q, limit=limit)
                for t in task_list:
                    st = t.get("status", "pending")
                    color = "emerald" if st == "completed" else "rose" if st == "failed" else "cyan" if st == "running" else "amber"
                    results["tasks"].append({
                        "id": t["task_id"],
                        "entity_type": "task",
                        "title": t.get("name", t["task_id"]),
                        "subtitle": f"{t.get('task_type', 'job')} • {st}",
                        "badge": st.upper(),
                        "badge_color": color,
                        "timestamp": t.get("submitted_at"),
                        "url": f"/admin?tab=jobs&search={t['task_id']}",
                        "snippet": f"Progress: {t.get('progress', 0)}%",
                    })
                total_matches += len(results["tasks"])
            except Exception as e:
                logger.error("Error searching tasks: %s", e)

        return {
            "query": q,
            "total_matches": total_matches,
            "results": results,
        }
