"""Read-only operation history assembled from persisted analysis jobs."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def _timestamp(value: object, fallback: float) -> str:
    if isinstance(value, str) and value.strip():
        return value
    return datetime.fromtimestamp(fallback, timezone.utc).isoformat()


def operation_history(root: Path = WORKSPACE_ROOT) -> list[dict]:
    operations: list[dict] = []
    for application in ("flowscope", "threatscope", "logscope"):
        jobs_dir = root / application / "storage" / "jobs"
        if not jobs_dir.is_dir():
            continue
        for job_dir in jobs_dir.iterdir():
            if not job_dir.is_dir() or not re.fullmatch(r"[0-9a-f]{32}", job_dir.name):
                continue
            analysis_path = job_dir / "analysis.json"
            if not analysis_path.is_file():
                continue
            try:
                data = json.loads(analysis_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            metadata, summary = data.get("metadata") or {}, data.get("summary") or {}
            analysis_state = data.get("analysis") or {}
            analyzed_at = _timestamp(metadata.get("analyzed_at"), analysis_path.stat().st_mtime)
            status = analysis_state.get("status") or ("completed" if data.get("records") is not None or data.get("events") is not None else "unknown")
            source_system = str(metadata.get("source_system") or "unspecified")
            source_label = str(metadata.get("source_system_label") or "غير محدد — ملف سابق")
            common = {
                "application": application,
                "job_id": job_dir.name[:8].upper(),
                "target_url": f"/{application}/{job_dir.name}",
                "source_system": source_system,
                "source_system_label": source_label,
                "data_type": str(metadata.get("data_type") or metadata.get("sheet") or "data"),
            }
            operations.append({
                **common, "id": f"{application}:{job_dir.name}:analysis", "operation": "analysis",
                "status": status, "timestamp": analyzed_at,
                "records": int(summary.get("records") or data.get("total_records") or metadata.get("row_count") or 0),
                "indicators": int(
                    (summary.get("unique_hashes") if application == "threatscope" else summary.get("unique_ips") or data.get("unique_ips_count")) or 0
                ),
            })
            enrichment = data.get("enrichment") or {}
            enrichment_status = str(enrichment.get("status") or "not_started")
            if enrichment_status != "not_started":
                operations.append({
                    **common, "id": f"{application}:{job_dir.name}:enrichment",
                    "operation": "refresh" if enrichment.get("force_refresh") else "source_scan",
                    "status": enrichment_status,
                    "timestamp": _timestamp(enrichment.get("completed_at") or enrichment.get("started_at"), analysis_path.stat().st_mtime),
                    "records": int(enrichment.get("checked") or 0), "indicators": int(enrichment.get("total") or 0),
                    "cached": int(enrichment.get("cached") or 0), "new": int(enrichment.get("new") or 0),
                })
    operations.sort(key=lambda item: item["timestamp"], reverse=True)
    return operations
