"""Threat-intelligence adapters with SQLite caching and fixed outbound targets."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
try:
    from platform_core import custom_integrations
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from platform_core import custom_integrations


# Zero keeps completed results until the cache is explicitly cleared. Set a
# positive THREATSCOPE_CACHE_TTL_DAYS value only when periodic refresh is wanted.
CACHE_TTL_SECONDS = max(int(os.environ.get("THREATSCOPE_CACHE_TTL_DAYS", "0")), 0) * 24 * 60 * 60
USER_AGENT = "ThreatScope-MVP/1.0"
TRANSIENT_SOURCE_STATUSES = {
    "error", "quota_exceeded", "quota_deferred", "provider_deferred", "unavailable"
}


def _snapshot_is_complete(snapshot: dict[str, Any], enabled: list[str]) -> bool:
    """A hash is reusable once at least one enabled source returned real data."""
    for provider in enabled:
        result = snapshot.get(provider)
        if not isinstance(result, dict):
            continue
        if str(result.get("source_status", "unavailable")).lower() not in TRANSIENT_SOURCE_STATUSES:
            return True
    return False


class IntelligenceCache:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS intel_cache "
            "(provider TEXT NOT NULL, hash TEXT NOT NULL, created REAL NOT NULL, payload TEXT NOT NULL, "
            "PRIMARY KEY(provider, hash))"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS hash_snapshots "
            "(hash TEXT PRIMARY KEY, created REAL NOT NULL, payload TEXT NOT NULL)"
        )
        self.connection.commit()

    @staticmethod
    def _is_expired(created: float) -> bool:
        return CACHE_TTL_SECONDS > 0 and time.time() - created > CACHE_TTL_SECONDS

    def get(self, provider: str, file_hash: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT created, payload FROM intel_cache WHERE provider=? AND hash=?", (provider, file_hash)
        ).fetchone()
        if not row or self._is_expired(row[0]):
            return None
        try:
            payload = json.loads(row[1])
        except (TypeError, json.JSONDecodeError):
            return None
        if str(payload.get("source_status", "unavailable")).lower() in TRANSIENT_SOURCE_STATUSES:
            return None
        # Refresh legacy malicious hits once so formal reports receive the
        # detailed evidence fields, while unknown hashes keep using the cache.
        if provider == "virustotal" and payload.get("verdict") == "malicious" and "detection_names" not in payload:
            return None
        return payload

    def get_snapshot(self, file_hash: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT created, payload FROM hash_snapshots WHERE hash=?", (file_hash,)
        ).fetchone()
        if not row or self._is_expired(row[0]):
            return None
        try:
            return json.loads(row[1])
        except (TypeError, json.JSONDecodeError):
            return None

    def put(self, provider: str, file_hash: str, payload: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO intel_cache(provider, hash, created, payload) VALUES(?,?,?,?)",
            (provider, file_hash, time.time(), json.dumps(payload, ensure_ascii=False)),
        )
        self.connection.commit()

    def put_snapshot(self, file_hash: str, payload: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO hash_snapshots(hash, created, payload) VALUES(?,?,?)",
            (file_hash, time.time(), json.dumps(payload, ensure_ascii=False)),
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


def _request(request: urllib.request.Request, timeout: int = 20) -> tuple[int, dict[str, Any]]:
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in {404, 429}:
                try:
                    payload = json.loads(exc.read().decode("utf-8"))
                except Exception:
                    payload = {}
                return exc.code, payload
            last_error = exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
        if attempt == 0:
            time.sleep(1.2)
    raise RuntimeError(str(last_error or "Threat intelligence request failed"))


def lookup_virustotal(file_hash: str, api_key: str) -> dict[str, Any]:
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{urllib.parse.quote(file_hash)}",
        headers={"x-apikey": api_key, "User-Agent": USER_AGENT},
    )
    status, payload = _request(request)
    if status == 404:
        return {"verdict": "unknown", "known": False, "source_status": "not_found"}
    if status == 429:
        return {"verdict": "unavailable", "source_status": "quota_exceeded"}
    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    verdict = "malicious" if malicious >= 3 else "suspicious" if malicious or suspicious else "clean_or_unknown"
    detection_names: dict[str, int] = {}
    detection_engines: list[dict[str, str]] = []
    for engine_name, engine in (attributes.get("last_analysis_results") or {}).items():
        if engine.get("category") not in {"malicious", "suspicious"}:
            continue
        result_name = str(engine.get("result") or "غير مسمى")
        detection_names[result_name] = detection_names.get(result_name, 0) + 1
        if len(detection_engines) < 15:
            detection_engines.append({"engine": str(engine_name), "result": result_name, "category": str(engine.get("category"))})
    popular = attributes.get("popular_threat_classification") or {}
    popular_names = [
        {"name": str(item.get("value") or ""), "count": int(item.get("count") or 0)}
        for item in (popular.get("popular_threat_name") or [])[:10]
    ]
    popular_categories = [
        {"category": str(item.get("value") or ""), "count": int(item.get("count") or 0)}
        for item in (popular.get("popular_threat_category") or [])[:10]
    ]
    signature = attributes.get("signature_info") or {}
    safe_signature = {
        key: signature.get(key)
        for key in ("verified", "description", "product", "file version", "signing date", "signers", "counter signers")
        if signature.get(key) not in (None, "")
    }
    yara = [
        {
            "rule_name": item.get("rule_name"),
            "ruleset_name": item.get("ruleset_name"),
            "description": item.get("description"),
            "author": item.get("author"),
        }
        for item in (attributes.get("crowdsourced_yara_results") or [])[:10]
    ]
    sandbox = []
    for sandbox_name, item in (attributes.get("sandbox_verdicts") or {}).items():
        sandbox.append({
            "sandbox": sandbox_name,
            "category": item.get("category"),
            "malware_classification": item.get("malware_classification"),
            "malware_names": item.get("malware_names") or [],
        })
    return {
        "verdict": verdict,
        "known": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "meaningful_name": attributes.get("meaningful_name"),
        "type_description": attributes.get("type_description"),
        "magic": attributes.get("magic"),
        "size": attributes.get("size"),
        "md5": attributes.get("md5"),
        "sha1": attributes.get("sha1"),
        "sha256": attributes.get("sha256"),
        "names": (attributes.get("names") or [])[:15],
        "tags": (attributes.get("tags") or [])[:20],
        "suggested_threat_label": popular.get("suggested_threat_label"),
        "popular_threat_names": popular_names,
        "popular_threat_categories": popular_categories,
        "detection_names": [
            {"name": name, "count": count}
            for name, count in sorted(detection_names.items(), key=lambda item: item[1], reverse=True)[:12]
        ],
        "detection_engines": detection_engines,
        "signature_info": safe_signature,
        "yara_rules": yara,
        "sandbox_verdicts": sandbox[:10],
        "reputation": attributes.get("reputation"),
        "total_votes": attributes.get("total_votes") or {},
        "first_submission_date": attributes.get("first_submission_date"),
        "last_submission_date": attributes.get("last_submission_date"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "source_status": "ok",
    }


def lookup_malwarebazaar(file_hash: str, auth_key: str) -> dict[str, Any]:
    body = urllib.parse.urlencode({"query": "get_info", "hash": file_hash}).encode("ascii")
    request = urllib.request.Request(
        "https://mb-api.abuse.ch/api/v1/",
        data=body,
        headers={
            "Auth-Key": auth_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )
    _, payload = _request(request)
    status = payload.get("query_status")
    if status == "hash_not_found":
        return {"verdict": "unknown", "known": False, "source_status": "not_found"}
    if status != "ok":
        return {"verdict": "unavailable", "source_status": str(status or "error")}
    item = (payload.get("data") or [{}])[0]
    return {
        "verdict": "malicious",
        "known": True,
        "signature": item.get("signature"),
        "file_type": item.get("file_type"),
        "first_seen": item.get("first_seen"),
        "last_seen": item.get("last_seen"),
        "tags": item.get("tags") or [],
        "source_status": "ok",
    }


def _load_env() -> None:
    env_path = Path(__file__).resolve().parent / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = value


def _virustotal_keys() -> list[str]:
    values = [
        os.environ.get("VIRUSTOTAL_API_KEY", ""),
        os.environ.get("VIRUSTOTAL_FALLBACK_API_KEY", ""),
        os.environ.get("VIRUSTOTAL_API_KEYS", ""),
    ]
    keys: list[str] = []
    for value in values:
        for key in re.split(r"[,;\s]+", value):
            if key and key not in keys:
                keys.append(key)
    return keys


def provider_configuration() -> dict[str, dict[str, Any]]:
    _load_env()
    virustotal_keys = _virustotal_keys()
    configuration = {
        "virustotal": {
            "enabled": bool(virustotal_keys),
            "key": virustotal_keys[0] if virustotal_keys else "",
            "keys": virustotal_keys,
        },
        "malwarebazaar": {
            "enabled": bool(os.environ.get("MALWAREBAZAAR_AUTH_KEY")),
            "key": os.environ.get("MALWAREBAZAAR_AUTH_KEY", ""),
        },
    }
    for item in custom_integrations.providers_for("threatscope"):
        configuration[f"custom:{item['id']}"] = {"enabled": True, "key": "", "custom": item}
    return configuration


def enrich_hashes(
    hashes: list[dict[str, str]], cache_path: Path, force_refresh: bool = False
) -> dict[str, Any]:
    cache = IntelligenceCache(cache_path)
    configuration = provider_configuration()
    enabled = [name for name, value in configuration.items() if value["enabled"]]
    output: dict[str, Any] = {
        "status": "running" if enabled else "disabled",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "total": len(hashes),
        "checked": 0,
        "cached": 0,
        "new": len(hashes),
        "successful": 0,
        "refresh_failures": 0,
        "fallback": 0,
        "unavailable": 0,
        "force_refresh": force_refresh,
        "providers": {
            name: {
                "enabled": value["enabled"],
                "queries": 0,
                "errors": 0,
                "cache_hits": 0,
                "successful": 0,
                "refresh_failures": 0,
                "fallback_hits": 0,
            }
            for name, value in configuration.items()
        },
        "results": {},
    }
    lookups = {"virustotal": lookup_virustotal, "malwarebazaar": lookup_malwarebazaar}
    for provider, settings in configuration.items():
        if settings.get("custom"):
            lookups[provider] = lambda indicator, _key, item=settings["custom"]: custom_integrations.lookup(item, indicator)

    if not enabled:
        output["completed_at"] = datetime.now(timezone.utc).isoformat()
        cache.close()
        return output

    pending: list[dict[str, str]] = []
    previous_snapshots: dict[str, dict[str, Any]] = {}
    for item in hashes:
        file_hash = item["hash"]
        stored_snapshot = cache.get_snapshot(file_hash)
        if force_refresh and isinstance(stored_snapshot, dict):
            previous_snapshots[file_hash] = stored_snapshot
        snapshot = None if force_refresh else stored_snapshot
        # Promote valid rows from the legacy provider cache into a durable
        # per-hash snapshot without issuing a new external request.
        if snapshot is None and not force_refresh:
            legacy = {}
            for provider in enabled:
                cached_result = cache.get(provider, file_hash)
                if cached_result is not None:
                    legacy[provider] = cached_result
            if _snapshot_is_complete(legacy, enabled):
                snapshot = legacy
                cache.put_snapshot(file_hash, snapshot)
        if snapshot is None or not _snapshot_is_complete(snapshot, enabled):
            pending.append(item)
            continue
        marked_snapshot = {}
        for provider, result in snapshot.items():
            if isinstance(result, dict):
                result = dict(result)
                result["cached"] = True
                if provider in output["providers"]:
                    output["providers"][provider]["cache_hits"] += 1
                    output["providers"][provider]["successful"] += 1
                    output["successful"] += 1
            marked_snapshot[provider] = result
        output["results"][file_hash] = marked_snapshot

    output["cached"] = len(hashes) - len(pending)
    output["new"] = len(pending)
    output["checked"] = output["cached"]
    virustotal_quota_exceeded = False
    virustotal_keys = configuration.get("virustotal", {}).get("keys") or [
        configuration.get("virustotal", {}).get("key", "")
    ]
    virustotal_keys = [key for key in virustotal_keys if key]
    virustotal_key_index = 0

    for index, item in enumerate(pending, 1):
        file_hash = item["hash"]
        hash_results: dict[str, Any] = {}
        for provider in enabled:
            cached = None if force_refresh else cache.get(provider, file_hash)
            if cached is not None:
                cached = dict(cached)
                cached["cached"] = True
                hash_results[provider] = cached
                output["providers"][provider]["cache_hits"] += 1
                output["providers"][provider]["successful"] += 1
                output["successful"] += 1
                continue
            if provider == "virustotal" and virustotal_quota_exceeded:
                result = {
                    "verdict": "unavailable", "source_status": "quota_deferred", "cached": False
                }
            else:
                try:
                    if provider == "virustotal":
                        while virustotal_key_index < len(virustotal_keys):
                            result = lookups[provider](file_hash, virustotal_keys[virustotal_key_index])
                            output["providers"][provider]["queries"] += 1
                            if str(result.get("source_status", "error")).lower() != "quota_exceeded":
                                break
                            virustotal_key_index += 1
                        if virustotal_key_index >= len(virustotal_keys):
                            virustotal_quota_exceeded = True
                    else:
                        result = lookups[provider](file_hash, configuration[provider]["key"])
                        output["providers"][provider]["queries"] += 1
                    result["cached"] = False
                    source_status = str(result.get("source_status", "error")).lower()
                    if source_status not in TRANSIENT_SOURCE_STATUSES:
                        cache.put(provider, file_hash, result)
                except Exception as exc:
                    result = {
                        "verdict": "unavailable",
                        "source_status": "error",
                        "error": str(exc)[:300],
                        "cached": False,
                    }
                    output["providers"][provider]["errors"] += 1

            source_status = str(result.get("source_status", "error")).lower()
            if source_status in TRANSIENT_SOURCE_STATUSES:
                output["refresh_failures"] += 1
                output["providers"][provider]["refresh_failures"] += 1
                previous = previous_snapshots.get(file_hash, {}).get(provider)
                previous_status = str(
                    previous.get("source_status", "unavailable") if isinstance(previous, dict) else "unavailable"
                ).lower()
                if isinstance(previous, dict) and previous_status not in TRANSIENT_SOURCE_STATUSES:
                    failed_refresh = result
                    result = dict(previous)
                    result.update({
                        "cached": True,
                        "stale": True,
                        "fallback": True,
                        "refresh_source_status": source_status,
                    })
                    if failed_refresh.get("error"):
                        result["refresh_error"] = failed_refresh["error"]
                    output["fallback"] += 1
                    output["providers"][provider]["fallback_hits"] += 1
                    output["providers"][provider]["cache_hits"] += 1
                    output["providers"][provider]["successful"] += 1
                    output["successful"] += 1
                else:
                    output["unavailable"] += 1
            else:
                output["providers"][provider]["successful"] += 1
                output["successful"] += 1
            hash_results[provider] = result
        output["results"][file_hash] = hash_results
        stored_results = dict(previous_snapshots.get(file_hash, {})) if force_refresh else {}
        stored_results.update({
            provider: result for provider, result in hash_results.items()
            if isinstance(result, dict)
            and str(result.get("source_status", "unavailable")).lower() not in TRANSIENT_SOURCE_STATUSES
        })
        if _snapshot_is_complete(stored_results, enabled):
            cache.put_snapshot(file_hash, stored_results)
        output["checked"] = output["cached"] + index

    output["status"] = "completed_partial" if output["refresh_failures"] else "completed"
    output["completed_at"] = datetime.now(timezone.utc).isoformat()
    cache.close()
    return output
