"""Threat-intelligence adapters for IPs with SQLite caching."""

from __future__ import annotations

import json
import ipaddress
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
try:
    from platform_core import custom_integrations
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from platform_core import custom_integrations

# Zero means persistent until the cache is explicitly cleared. A positive
# LOGSCOPE_CACHE_TTL_DAYS value can be used when periodic refresh is desired.
CACHE_TTL_SECONDS = max(int(os.environ.get("LOGSCOPE_CACHE_TTL_DAYS", "0")), 0) * 24 * 60 * 60
USER_AGENT = "LogScope/1.0"
TRANSIENT_SOURCE_STATUSES = {
    "error", "quota_exceeded", "quota_deferred", "provider_deferred", "unavailable"
}


def _snapshot_is_complete(snapshot: dict[str, Any], enabled: list[str]) -> bool:
    """A stored IP is reusable once at least one enabled source returned data."""
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
        self.lock = threading.Lock()
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS intel_cache "
            "(provider TEXT NOT NULL, ip TEXT NOT NULL, created REAL NOT NULL, payload TEXT NOT NULL, "
            "PRIMARY KEY(provider, ip))"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS ip_snapshots "
            "(ip TEXT PRIMARY KEY, created REAL NOT NULL, payload TEXT NOT NULL)"
        )
        self.connection.commit()

    @staticmethod
    def _is_expired(created: float) -> bool:
        return CACHE_TTL_SECONDS > 0 and time.time() - created > CACHE_TTL_SECONDS

    def get(self, provider: str, ip: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT created, payload FROM intel_cache WHERE provider=? AND ip=?", (provider, ip)
            ).fetchone()
        if not row or self._is_expired(row[0]):
            return None
        return json.loads(row[1])

    def get_snapshot(self, ip: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.connection.execute(
                "SELECT created, payload FROM ip_snapshots WHERE ip=?", (ip,)
            ).fetchone()
        if not row or self._is_expired(row[0]):
            return None
        try:
            return json.loads(row[1])
        except (TypeError, json.JSONDecodeError):
            return None

    def put(self, provider: str, ip: str, payload: dict[str, Any]) -> None:
        with self.lock:
            self.connection.execute(
                "INSERT OR REPLACE INTO intel_cache(provider, ip, created, payload) VALUES(?,?,?,?)",
                (provider, ip, time.time(), json.dumps(payload, ensure_ascii=False)),
            )
            self.connection.commit()

    def put_snapshot(self, ip: str, payload: dict[str, Any]) -> None:
        with self.lock:
            self.connection.execute(
                "INSERT OR REPLACE INTO ip_snapshots(ip, created, payload) VALUES(?,?,?)",
                (ip, time.time(), json.dumps(payload, ensure_ascii=False)),
            )
            self.connection.commit()

    def close(self) -> None:
        with self.lock:
            self.connection.close()


def _request(request: urllib.request.Request, timeout: int = 15, attempts: int = 2) -> tuple[int, dict[str, Any]]:
    last_error: Exception | None = None
    for attempt in range(attempts):
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
        if attempt + 1 < attempts:
            time.sleep(1.2)
    raise RuntimeError(str(last_error or "Threat intelligence request failed"))


def is_private_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return not address.is_global


def lookup_abuseipdb(ip: str, api_key: str) -> dict[str, Any]:
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}"
    request = urllib.request.Request(
        url,
        headers={"Key": api_key, "Accept": "application/json", "User-Agent": USER_AGENT},
    )
    status, payload = _request(request)
    
    if status == 429:
        return {"verdict": "unavailable", "source_status": "quota_exceeded"}
    
    data = payload.get("data", {})
    if not data:
        return {"verdict": "unknown", "source_status": "error"}

    score = data.get("abuseConfidenceScore", 0)
    verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
    
    return {
        "verdict": verdict,
        "score": score,
        "total_reports": data.get("totalReports", 0),
        "country": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "domain": data.get("domain", ""),
        "usage_type": data.get("usageType", ""),
        "last_reported": data.get("lastReportedAt", ""),
        "source_status": "ok"
    }


def lookup_virustotal(ip: str, api_key: str) -> dict[str, Any]:
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip)}",
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
    
    verdict = "malicious" if malicious >= 3 else "suspicious" if malicious or suspicious else "clean"
    
    return {
        "verdict": verdict,
        "known": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "country": attributes.get("country", ""),
        "as_owner": attributes.get("as_owner", ""),
        "network": attributes.get("network", ""),
        "reputation": attributes.get("reputation", 0),
        "source_status": "ok"
    }


def lookup_shodan(ip: str, api_key: str) -> dict[str, Any]:
    # Using InternetDB by default as it does not require an API key and is fast
    url = f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    
    # InternetDB is optional enrichment; do not let an unavailable service
    # block a whole job for the default 15-second timeout.
    status, payload = _request(request, timeout=6, attempts=1)
    
    if status == 404:
         return {"verdict": "normal", "known": False, "source_status": "not_found"}
    
    ports = payload.get("ports", [])
    vulns = payload.get("vulns", [])
    tags = payload.get("tags", [])
    
    if vulns or len(ports) > 20 or "malware" in tags or "c2" in tags:
        verdict = "exposed"
    elif len(ports) > 10:
        verdict = "notable"
    else:
        verdict = "normal"
        
    return {
        "verdict": verdict,
        "known": True,
        "ports": ports,
        "vulns": vulns,
        "tags": tags,
        "hostnames": payload.get("hostnames", []),
        "cpes": payload.get("cpes", []),
        "source_status": "ok"
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
        "abuseipdb": {
            "enabled": bool(os.environ.get("ABUSEIPDB_API_KEY")),
            "key": os.environ.get("ABUSEIPDB_API_KEY", ""),
        },
        "virustotal": {
            "enabled": bool(virustotal_keys),
            "key": virustotal_keys[0] if virustotal_keys else "",
            "keys": virustotal_keys,
        },
        "shodan": {
            "enabled": True, # InternetDB is free and requires no key
            "key": "",
        },
    }
    for item in custom_integrations.providers_for("logscope"):
        configuration[f"custom:{item['id']}"] = {"enabled": True, "key": "", "custom": item}
    return configuration


def public_provider_configuration() -> dict[str, dict[str, bool]]:
    """Return provider status without ever exposing API credentials."""
    return {
        name: {"enabled": bool(settings["enabled"])}
        for name, settings in provider_configuration().items()
    }


def enrich_ips(
    ips: set[str], cache_path: Path, progress_callback=None, cancel_event=None,
    force_refresh: bool = False,
) -> dict[str, Any]:
    cache = IntelligenceCache(cache_path)
    configuration = provider_configuration()
    enabled = [name for name, value in configuration.items() if value["enabled"]]
    
    # Filter out private IPs first to get accurate total
    public_ips = sorted(ip for ip in ips if not is_private_ip(ip))
    total = len(public_ips)
    
    output: dict[str, Any] = {
        "status": "running" if enabled else "disabled",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "total": total,
        "checked": 0,
        "cached": 0,
        "new": total,
        "force_refresh": force_refresh,
        "providers": {
            name: {"enabled": value["enabled"], "queries": 0, "errors": 0, "cache_hits": 0}
            for name, value in configuration.items()
        },
        "results": {},
    }
    
    # Add skipped private IPs
    for ip in ips:
        if is_private_ip(ip):
            output["results"][ip] = {"status": "skipped", "reason": "private_ip"}
    
    lookups = {
        "abuseipdb": lookup_abuseipdb, 
        "virustotal": lookup_virustotal,
        "shodan": lookup_shodan
    }
    for provider, settings in configuration.items():
        if settings.get("custom"):
            lookups[provider] = lambda indicator, _key, item=settings["custom"]: custom_integrations.lookup(item, indicator)

    if not enabled:
        output["completed_at"] = datetime.now(timezone.utc).isoformat()
        if progress_callback:
            progress_callback(output)
        cache.close()
        return output

    # A complete per-IP snapshot is the first lookup layer. It makes repeated
    # appearances across different uploaded files cost zero external requests.
    pending_ips = []
    previous_snapshots: dict[str, dict[str, Any]] = {}
    for ip in public_ips:
        stored_snapshot = cache.get_snapshot(ip)
        if force_refresh and isinstance(stored_snapshot, dict):
            previous_snapshots[ip] = stored_snapshot
        snapshot = None if force_refresh else stored_snapshot
        if snapshot is None or not _snapshot_is_complete(snapshot, enabled):
            pending_ips.append(ip)
            continue
        marked_snapshot = {}
        for provider, result in snapshot.items():
            if isinstance(result, dict):
                result = dict(result)
                result["cached"] = True
                if provider in output["providers"]:
                    output["providers"][provider]["cache_hits"] += 1
            marked_snapshot[provider] = result
        output["results"][ip] = marked_snapshot

    output["cached"] = len(public_ips) - len(pending_ips)
    output["new"] = len(pending_ips)
    output["checked"] = output["cached"]
    if progress_callback and output["cached"]:
        progress_callback(output)

    # VirusTotal commonly applies strict request quotas. Serialize its calls
    # and stop submitting more after the provider reports quota exhaustion.
    virustotal_lock = threading.Lock()
    virustotal_quota_exceeded = threading.Event()
    virustotal_keys = configuration.get("virustotal", {}).get("keys") or [
        configuration.get("virustotal", {}).get("key", "")
    ]
    virustotal_keys = [key for key in virustotal_keys if key]
    virustotal_key_index = 0
    shodan_lock = threading.Lock()
    shodan_unavailable = threading.Event()
    shodan_errors = 0

    def enrich_one(ip: str) -> tuple[str, dict[str, Any], dict[str, tuple[int, int]]]:
        nonlocal shodan_errors, virustotal_key_index
        ip_results: dict[str, Any] = {}
        provider_stats: dict[str, tuple[int, int]] = {}
        for provider in enabled:
            if cancel_event and cancel_event.is_set():
                break
            cached = None if force_refresh else cache.get(provider, ip)
            if cached is not None:
                cached = dict(cached)
                cached["cached"] = True
                ip_results[provider] = cached
                provider_stats[provider] = (0, 0)
                continue

            if provider == "virustotal" and virustotal_quota_exceeded.is_set():
                ip_results[provider] = {
                    "verdict": "unavailable", "source_status": "quota_deferred", "cached": False
                }
                provider_stats[provider] = (0, 0)
                continue
            if provider == "shodan" and shodan_unavailable.is_set():
                ip_results[provider] = {
                    "verdict": "unavailable", "source_status": "provider_deferred", "cached": False
                }
                provider_stats[provider] = (0, 0)
                continue

            try:
                if provider == "virustotal":
                    with virustotal_lock:
                        if virustotal_quota_exceeded.is_set():
                            result = {"verdict": "unavailable", "source_status": "quota_deferred"}
                            queried = 0
                        else:
                            queried = 0
                            while virustotal_key_index < len(virustotal_keys):
                                result = lookups[provider](ip, virustotal_keys[virustotal_key_index])
                                queried += 1
                                if result.get("source_status") != "quota_exceeded":
                                    break
                                virustotal_key_index += 1
                            if virustotal_key_index >= len(virustotal_keys):
                                virustotal_quota_exceeded.set()
                else:
                    result = lookups[provider](ip, configuration[provider]["key"])
                    queried = 1
                result["cached"] = False
                if result.get("source_status") not in {"quota_exceeded", "quota_deferred", "error"}:
                    cache.put(provider, ip, result)
                provider_stats[provider] = (queried, 0)
            except Exception as exc:
                result = {"verdict": "unavailable", "source_status": "error", "error": str(exc)[:300]}
                provider_stats[provider] = (1, 1)
                if provider == "shodan":
                    with shodan_lock:
                        shodan_errors += 1
                        if shodan_errors >= 3:
                            shodan_unavailable.set()
            ip_results[provider] = result
        return ip, ip_results, provider_stats

    worker_count = min(max(int(os.environ.get("LOGSCOPE_ENRICH_WORKERS", "8")), 1), len(pending_ips) or 1)
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="logscope-intel") as executor:
        futures = [executor.submit(enrich_one, ip) for ip in pending_ips]
        for index, future in enumerate(as_completed(futures), 1):
            ip, ip_results, stats = future.result()
            output["results"][ip] = ip_results
            if not (cancel_event and cancel_event.is_set()):
                stored_results = dict(previous_snapshots.get(ip, {})) if force_refresh else {}
                stored_results.update({
                    provider: result for provider, result in ip_results.items()
                    if isinstance(result, dict)
                    and str(result.get("source_status", "unavailable")).lower() not in TRANSIENT_SOURCE_STATUSES
                })
                if _snapshot_is_complete(stored_results, enabled):
                    cache.put_snapshot(ip, stored_results)
            for provider, (queries, errors) in stats.items():
                output["providers"][provider]["queries"] += queries
                output["providers"][provider]["errors"] += errors
            output["checked"] = output["cached"] + index
            if progress_callback:
                progress_callback(output)

    output["status"] = "cancelled" if cancel_event and cancel_event.is_set() else "completed"
    output["completed_at"] = datetime.now(timezone.utc).isoformat()
    if progress_callback:
        progress_callback(output)
    cache.close()
    return output
