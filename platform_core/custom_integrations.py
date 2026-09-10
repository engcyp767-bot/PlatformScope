"""Generic JSON intelligence providers configured from the administration UI."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any

from . import platform_config


def providers_for(application: str) -> list[dict[str, Any]]:
    return [
        item for item in platform_config.load().get("external_apis", [])
        if item.get("enabled") and (
            item.get("scope") in {application, "all"}
            or item.get("scope") == "both" and application in {"flowscope", "threatscope"}
        )
    ]


def _nested(payload: Any, path: str) -> Any:
    current = payload
    for part in str(path or "").split("."):
        if not part:
            continue
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def lookup(provider: dict[str, Any], indicator: str) -> dict[str, Any]:
    encoded = urllib.parse.quote(str(indicator), safe="")
    lookup_path = str(provider.get("lookup_path") or "/lookup/{indicator}").replace("{indicator}", encoded)
    url = str(provider["base_url"]).rstrip("/") + (lookup_path if lookup_path.startswith("/") else "/" + lookup_path)
    headers = {"Accept": "application/json", "User-Agent": "SecurityAnalysisCenter/2.0"}
    api_key = str(provider.get("api_key") or "")
    if api_key:
        headers[str(provider.get("auth_header") or "Authorization")] = api_key
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=int(provider.get("timeout_seconds") or 15)) as response:
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("Custom provider response exceeded 1 MiB")
        payload = json.loads(raw.decode("utf-8"))
    raw_verdict = _nested(payload, str(provider.get("verdict_path") or "verdict"))
    verdict_text = str(raw_verdict or "unknown").strip().lower()
    malicious = {item.strip().lower() for item in str(provider.get("malicious_values") or "malicious,suspicious,high").split(",") if item.strip()}
    verdict = "malicious" if verdict_text in malicious else "clean_or_unknown" if raw_verdict is not None else "unknown"
    return {
        "verdict": verdict, "provider_verdict": str(raw_verdict or "unknown"),
        "source_status": "ok", "provider": str(provider.get("name") or provider.get("id")),
        "response": payload if isinstance(payload, dict) else {"value": payload},
    }
