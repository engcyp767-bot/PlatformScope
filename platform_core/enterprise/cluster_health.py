"""
Unified Enterprise Architecture - High Availability & Cluster Health Probes.

Provides standard Liveness and Readiness probes conforming to Kubernetes and cloud HA
load balancers, alongside real-time node heartbeat telemetry.
load balancers, alongside real-time node heartbeat telemetry and rolling health history.
"""

from __future__ import annotations

import collections
import os
import platform
import shutil
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = ROOT_DIR / "storage"
_NODE_ID = os.environ.get("PLATFORM_NODE_ID", f"{socket.gethostname()}_{os.getpid()}")
_START_TIME = time.time()

_CPU_LOCK = threading.Lock()
_LAST_CPU_CHECK = 0.0
_LAST_IDLE_TIME = 0
_LAST_TOTAL_TIME = 0
_LAST_CPU_PERCENT = 0.0

_HISTORY_BUFFER: collections.deque[dict[str, Any]] = collections.deque(maxlen=60)
_HISTORY_LOCK = threading.Lock()


def _compute_cpu_percent() -> float:
    global _LAST_CPU_CHECK, _LAST_IDLE_TIME, _LAST_TOTAL_TIME, _LAST_CPU_PERCENT
    with _CPU_LOCK:
        now = time.time()
        if now - _LAST_CPU_CHECK < 0.5 and _LAST_CPU_PERCENT > 0.0:
            return _LAST_CPU_PERCENT

        if sys.platform == "win32":
            try:
                import ctypes
                from ctypes import wintypes

                class FILETIME(ctypes.Structure):
                    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

                i, k, u = FILETIME(), FILETIME(), FILETIME()
                if ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u)):
                    idle = (i.dwHighDateTime << 32) + i.dwLowDateTime
                    kernel = (k.dwHighDateTime << 32) + k.dwLowDateTime
                    user = (u.dwHighDateTime << 32) + u.dwLowDateTime
                    total = kernel + user
                    if _LAST_TOTAL_TIME > 0:
                        delta_idle = idle - _LAST_IDLE_TIME
                        delta_total = total - _LAST_TOTAL_TIME
                        if delta_total > 0:
                            usage = max(0.0, min(100.0, (1.0 - (delta_idle / delta_total)) * 100.0))
                            _LAST_CPU_PERCENT = round(usage, 1)
                    _LAST_IDLE_TIME = idle
                    _LAST_TOTAL_TIME = total
                    _LAST_CPU_CHECK = now
                    return _LAST_CPU_PERCENT
            except Exception:
                pass
        elif sys.platform.startswith("linux"):
            try:
                with open("/proc/stat", "r", encoding="utf-8") as f:
                    fields = [float(x) for x in f.readline().strip().split()[1:8]]
                    idle = fields[3]
                    total = sum(fields)
                    if _LAST_TOTAL_TIME > 0:
                        delta_idle = idle - _LAST_IDLE_TIME
                        delta_total = total - _LAST_TOTAL_TIME
                        if delta_total > 0:
                            usage = max(0.0, min(100.0, (1.0 - (delta_idle / delta_total)) * 100.0))
                            _LAST_CPU_PERCENT = round(usage, 1)
                    _LAST_IDLE_TIME = idle
                    _LAST_TOTAL_TIME = total
                    _LAST_CPU_CHECK = now
                    return _LAST_CPU_PERCENT
            except Exception:
                pass

        return _LAST_CPU_PERCENT


def _compute_memory_metrics() -> dict[str, float]:
    res = {
        "ram_total_gb": 0.0,
        "ram_used_gb": 0.0,
        "ram_free_gb": 0.0,
        "ram_percent": 0.0,
    }
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wintypes.DWORD),
                    ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_uint64),
                    ("ullAvailPhys", ctypes.c_uint64),
                    ("ullTotalPageFile", ctypes.c_uint64),
                    ("ullAvailPageFile", ctypes.c_uint64),
                    ("ullTotalVirtual", ctypes.c_uint64),
                    ("ullAvailVirtual", ctypes.c_uint64),
                    ("ullAvailExtendedVirtual", ctypes.c_uint64),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                total_gb = stat.ullTotalPhys / (1024 ** 3)
                avail_gb = stat.ullAvailPhys / (1024 ** 3)
                used_gb = total_gb - avail_gb
                res["ram_total_gb"] = round(total_gb, 2)
                res["ram_used_gb"] = round(used_gb, 2)
                res["ram_free_gb"] = round(avail_gb, 2)
                res["ram_percent"] = float(stat.dwMemoryLoad)
                return res
        except Exception:
            pass
    elif sys.platform.startswith("linux"):
        try:
            meminfo: dict[str, int] = {}
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        meminfo[parts[0].strip()] = int(parts[1].split()[0])
            total_kb = meminfo.get("MemTotal", 0)
            avail_kb = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
            if total_kb > 0:
                total_gb = total_kb / (1024 * 1024)
                avail_gb = avail_kb / (1024 * 1024)
                used_gb = total_gb - avail_gb
                res["ram_total_gb"] = round(total_gb, 2)
                res["ram_used_gb"] = round(used_gb, 2)
                res["ram_free_gb"] = round(avail_gb, 2)
                res["ram_percent"] = round((used_gb / total_gb) * 100, 1)
                return res
        except Exception:
            pass

    return res


def _compute_disk_metrics() -> dict[str, float]:
    try:
        usage = shutil.disk_usage(str(ROOT_DIR))
        total_gb = usage.total / (1024 ** 3)
        free_gb = usage.free / (1024 ** 3)
        used_gb = usage.used / (1024 ** 3)
        percent = round((used_gb / total_gb) * 100.0, 1) if total_gb > 0 else 0.0
        return {
            "disk_total_gb": round(total_gb, 2),
            "disk_used_gb": round(used_gb, 2),
            "disk_free_gb": round(free_gb, 2),
            "disk_percent": percent,
        }
    except Exception:
        return {
            "disk_total_gb": 0.0,
            "disk_used_gb": 0.0,
            "disk_free_gb": 0.0,
            "disk_percent": 0.0,
        }


class ClusterHealthManager:
    """Evaluates multi-node and standalone health, liveness, and operational readiness."""
    """Evaluates multi-node and standalone health, liveness, readiness, and real-time telemetry."""

    @classmethod
    def get_node_id(cls) -> str:
        return _NODE_ID

    @classmethod
    def get_system_metrics(cls) -> dict[str, Any]:
        """Collects cross-platform CPU, RAM, Disk, and Process resource metrics."""
        cpu = _compute_cpu_percent()
        ram = _compute_memory_metrics()
        disk = _compute_disk_metrics()

        proc_mem_mb = 0.0
        if sys.platform == "win32":
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
                    proc_mem_mb = round(c.wss / (1024 * 1024), 2)
            except Exception:
                pass

        return {
            "cpu_percent": cpu,
            "ram_total_gb": ram["ram_total_gb"],
            "ram_used_gb": ram["ram_used_gb"],
            "ram_free_gb": ram["ram_free_gb"],
            "ram_percent": ram["ram_percent"],
            "disk_total_gb": disk["disk_total_gb"],
            "disk_used_gb": disk["disk_used_gb"],
            "disk_free_gb": disk["disk_free_gb"],
            "disk_percent": disk["disk_percent"],
            "process_memory_mb": proc_mem_mb,
            "active_threads": threading.active_count(),
            "uptime_seconds": round(time.time() - _START_TIME, 2),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    @classmethod
    def record_sample(cls, sample: dict[str, Any] | None = None) -> dict[str, Any]:
        """Records a rolling telemetry sample into circular memory buffer."""
        if sample is None:
            metrics = cls.get_system_metrics()
            sample = {
                "timestamp": metrics["timestamp"],
                "cpu_percent": metrics["cpu_percent"],
                "ram_percent": metrics["ram_percent"],
                "disk_percent": metrics["disk_percent"],
                "latency_ms": 1.0,
                "status": "healthy",
            }
        with _HISTORY_LOCK:
            _HISTORY_BUFFER.append(sample)
        return sample

    @classmethod
    def get_history(cls, limit: int = 60) -> list[dict[str, Any]]:
        """Returns the last N historical health samples for sparkline visualizations."""
        with _HISTORY_LOCK:
            samples = list(_HISTORY_BUFFER)
        if not samples:
            sample = cls.record_sample()
            return [sample]
        return samples[-limit:]

    @classmethod
    def check_liveness(cls) -> dict[str, Any]:
        """Liveness probe: verifies that the Python process and core runtime are responding."""
        return {
            "status": "live",
            "node_id": _NODE_ID,
            "uptime_seconds": round(time.time() - _START_TIME, 2),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    @classmethod
    def check_readiness(cls) -> dict[str, Any]:
        """Readiness probe: verifies write access to storage and database connectivity."""
        checks = {}
        is_ready = True

        # 1. Storage write test
        try:
            STORAGE_DIR.mkdir(parents=True, exist_ok=True)
            test_file = STORAGE_DIR / f".probe_{_NODE_ID}.tmp"
            test_file.write_text("probe_ok", encoding="utf-8")
            test_file.unlink(missing_ok=True)
            checks["storage_writable"] = True
        except Exception as e:
            checks["storage_writable"] = False
            checks["storage_error"] = str(e)
            is_ready = False

        # 2. Database connectivity
        try:
            from platform_core.database import DatabaseManager
            db_status = DatabaseManager.get_instance().get_status()
            checks["database_status"] = db_status.get("health", {}).get("status", "unknown")
            if checks["database_status"] != "healthy":
                is_ready = False
        except Exception as e:
            checks["database_status"] = "error"
            checks["database_error"] = str(e)
            is_ready = False

        return {
            "status": "ready" if is_ready else "not_ready",
            "node_id": _NODE_ID,
            "checks": checks,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    @classmethod
    def get_cluster_status(cls) -> dict[str, Any]:
        """Full cluster status payload detailing node environment and HA readiness."""
        """Full cluster status payload detailing node environment, HA readiness, and telemetry."""
        readiness = cls.check_readiness()
        liveness = cls.check_liveness()
        metrics = cls.get_system_metrics()

        return {
            "node_id": _NODE_ID,
            "role": os.environ.get("PLATFORM_NODE_ROLE", "primary"),
            "ha_mode": "single_node_ready" if os.environ.get("PLATFORM_HA_ENABLED") != "true" else "clustered",
            "liveness": liveness,
            "readiness": readiness,
            "metrics": metrics,
            "system_info": {
                "os": platform.system(),
                "release": platform.release(),
                "architecture": platform.machine(),
                "python_version": platform.python_version(),
                "pid": os.getpid(),
            },
        }
