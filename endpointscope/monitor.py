"""EndpointScope — Local Endpoint Monitor.

Lightweight system monitor that collects security-relevant events from
the local Windows/Linux endpoint. This is the agent-side component.

Monitors:
    - Process creation/termination (ETW on Windows, /proc on Linux)
    - File system changes (watchdog)
    - Network connections (netstat/ss polling)
    - Registry changes (Windows only)
    - Authentication events (Event Log / syslog)
    - USB device insertion
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from endpointscope.models import (
    AgentInfo,
    AgentState,
    EndpointEvent,
    EndpointEventType,
)

logger = logging.getLogger("endpointscope.monitor")


@dataclass
class MonitorConfig:
    """Configuration for the endpoint monitor."""
    # Collection toggles
    monitor_processes: bool = True
    monitor_files: bool = True
    monitor_network: bool = True
    monitor_registry: bool = True    # Windows only
    monitor_auth: bool = True
    monitor_services: bool = True
    monitor_usb: bool = True

    # File monitoring paths (directories to watch)
    watch_paths: list[str] = field(default_factory=lambda: [
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Users",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
    ] if platform.system() == "Windows" else [
        "/etc",
        "/usr/bin",
        "/usr/sbin",
        "/home",
        "/tmp",
    ])

    # File monitoring exclusions
    exclude_extensions: list[str] = field(default_factory=lambda: [
        ".tmp", ".log", ".etl", ".cache", ".db-journal",
    ])

    exclude_processes: list[str] = field(default_factory=lambda: [
        "svchost.exe", "System", "Idle", "csrss.exe",
        "wininit.exe", "winlogon.exe", "dwm.exe",
    ] if platform.system() == "Windows" else [
        "kworker", "ksoftirqd", "migration", "rcu_sched",
    ])

    # Network monitoring
    network_poll_interval: float = 5.0  # seconds
    ignore_loopback: bool = True
    ignore_private_dst: bool = False

    # Performance limits
    max_events_per_minute: int = 5000
    cpu_limit_percent: float = 5.0
    batch_size: int = 100
    heartbeat_interval: float = 60.0


class EndpointMonitor:
    """Local endpoint monitoring agent.

    Collects security-relevant system events and provides them for
    transmission to the central EndpointScope collector.
    """

    def __init__(self, config: MonitorConfig | None = None):
        self.config = config or MonitorConfig()
        self._agent_id = self._generate_agent_id()
        self._hostname = socket.gethostname()
        self._os_type = platform.system().lower()
        self._os_version = platform.version()
        self._event_queue: list[EndpointEvent] = []
        self._queue_lock = threading.Lock()
        self._running = False
        self._threads: list[threading.Thread] = []
        self._known_processes: dict[int, dict[str, Any]] = {}
        self._known_connections: set[str] = set()
        self._event_count_minute = 0
        self._minute_start = time.time()

    def _generate_agent_id(self) -> str:
        """Generate a deterministic agent ID based on hardware."""
        hostname = socket.gethostname()
        mac = uuid.getnode()
        seed = f"{hostname}:{mac}:{platform.machine()}"
        return f"agent-{hashlib.sha256(seed.encode()).hexdigest()[:16]}"

    @property
    def agent_id(self) -> str:
        return self._agent_id

    def get_agent_info(self) -> AgentInfo:
        """Get current agent information."""
        ip_addresses = []
        try:
            for info in socket.getaddrinfo(self._hostname, None):
                addr = info[4][0]
                if addr not in ip_addresses and addr != "127.0.0.1" and addr != "::1":
                    ip_addresses.append(addr)
        except Exception:
            pass

        return AgentInfo(
            agent_id=self._agent_id,
            hostname=self._hostname,
            os_type=self._os_type,
            os_version=self._os_version,
            agent_version="1.0.0",
            ip_addresses=ip_addresses[:10],
            state=AgentState.ONLINE if self._running else AgentState.OFFLINE,
        )

    def start(self) -> None:
        """Start all monitoring threads."""
        if self._running:
            return

        self._running = True
        logger.info("EndpointScope monitor starting on %s (%s)", self._hostname, self._agent_id)

        if self.config.monitor_processes:
            t = threading.Thread(target=self._monitor_processes, daemon=True, name="ep-proc-monitor")
            self._threads.append(t)
            t.start()

        if self.config.monitor_network:
            t = threading.Thread(target=self._monitor_network, daemon=True, name="ep-net-monitor")
            self._threads.append(t)
            t.start()

        logger.info("EndpointScope monitor started with %d monitoring threads.", len(self._threads))

    def stop(self) -> None:
        """Stop all monitoring threads."""
        self._running = False
        for t in self._threads:
            t.join(timeout=5.0)
        self._threads.clear()
        logger.info("EndpointScope monitor stopped.")

    def collect_events(self) -> list[EndpointEvent]:
        """Drain the event queue and return collected events."""
        with self._queue_lock:
            events = list(self._event_queue)
            self._event_queue.clear()
        return events

    def _add_event(self, event: EndpointEvent) -> None:
        """Add an event to the queue with rate limiting."""
        now = time.time()
        if now - self._minute_start >= 60.0:
            self._event_count_minute = 0
            self._minute_start = now

        if self._event_count_minute >= self.config.max_events_per_minute:
            return  # Rate limited

        self._event_count_minute += 1
        event.agent_id = self._agent_id
        event.hostname = self._hostname

        with self._queue_lock:
            self._event_queue.append(event)
            # Keep queue bounded
            if len(self._event_queue) > 10000:
                self._event_queue = self._event_queue[-5000:]

    # ── Process Monitoring ────────────────────────────────────────────────

    def _monitor_processes(self) -> None:
        """Monitor process creation and termination."""
        logger.debug("Process monitor started.")
        while self._running:
            try:
                current_procs = self._get_running_processes()
                current_pids = set(current_procs.keys())
                known_pids = set(self._known_processes.keys())

                # New processes
                for pid in current_pids - known_pids:
                    proc = current_procs[pid]
                    if proc.get("name", "") in self.config.exclude_processes:
                        continue
                    self._add_event(EndpointEvent(
                        event_type=EndpointEventType.PROCESS_CREATED,
                        severity=self._assess_process_severity(proc),
                        process_name=proc.get("name", ""),
                        process_id=pid,
                        parent_process_id=proc.get("ppid", 0),
                        command_line=proc.get("cmdline", ""),
                        user=proc.get("user", ""),
                    ))

                # Terminated processes
                for pid in known_pids - current_pids:
                    proc = self._known_processes[pid]
                    self._add_event(EndpointEvent(
                        event_type=EndpointEventType.PROCESS_TERMINATED,
                        process_name=proc.get("name", ""),
                        process_id=pid,
                    ))

                self._known_processes = current_procs

            except Exception as exc:
                logger.debug("Process monitor cycle error: %s", exc)

            time.sleep(2.0)

    def _get_running_processes(self) -> dict[int, dict[str, Any]]:
        """Get running processes (cross-platform)."""
        processes: dict[int, dict[str, Any]] = {}

        if self._os_type == "windows":
            try:
                output = subprocess.check_output(
                    ["wmic", "process", "get",
                     "ProcessId,Name,ParentProcessId,CommandLine,CreationDate",
                     "/FORMAT:CSV"],
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    text=True,
                )
                for line in output.strip().split("\n")[1:]:
                    parts = line.strip().split(",")
                    if len(parts) >= 5:
                        try:
                            pid = int(parts[-2])
                            processes[pid] = {
                                "name": parts[-3],
                                "ppid": int(parts[-4]) if parts[-4].strip().isdigit() else 0,
                                "cmdline": parts[-5] if len(parts) > 5 else "",
                            }
                        except (ValueError, IndexError):
                            pass
            except Exception:
                pass
        else:
            # Linux: parse /proc
            proc_path = Path("/proc")
            if proc_path.is_dir():
                for entry in proc_path.iterdir():
                    if entry.name.isdigit():
                        try:
                            pid = int(entry.name)
                            cmdline = (entry / "cmdline").read_text().replace("\x00", " ").strip()
                            status = {}
                            for line in (entry / "status").read_text().split("\n"):
                                if ":" in line:
                                    k, v = line.split(":", 1)
                                    status[k.strip()] = v.strip()
                            processes[pid] = {
                                "name": status.get("Name", ""),
                                "ppid": int(status.get("PPid", 0)),
                                "cmdline": cmdline,
                                "user": status.get("Uid", "").split()[0] if "Uid" in status else "",
                            }
                        except Exception:
                            pass

        return processes

    def _assess_process_severity(self, proc: dict[str, Any]) -> str:
        """Assess severity of a new process based on heuristics."""
        name = proc.get("name", "").lower()
        cmdline = proc.get("cmdline", "").lower()

        # Check for encoded commands (highest severity — always check first)
        if "-enc" in cmdline or "-encodedcommand" in cmdline or "base64" in cmdline:
            return "critical"

        # Check for common LOLBins patterns
        if "downloadstring" in cmdline or "invoke-expression" in cmdline:
            return "critical"

        # Suspicious process names
        high_risk_names = {
            "powershell", "cmd", "wscript", "cscript", "mshta",
            "regsvr32", "rundll32", "certutil", "bitsadmin",
            "mimikatz", "procdump", "psexec",
        }
        for risky in high_risk_names:
            if risky in name:
                return "high"

        return "info"

    # ── Network Monitoring ────────────────────────────────────────────────

    def _monitor_network(self) -> None:
        """Monitor network connections."""
        logger.debug("Network monitor started.")
        while self._running:
            try:
                connections = self._get_connections()
                current_conn_keys = set()

                for conn in connections:
                    key = f"{conn['src']}:{conn['sport']}-{conn['dst']}:{conn['dport']}-{conn['proto']}"
                    current_conn_keys.add(key)

                    if key not in self._known_connections:
                        if self.config.ignore_loopback and conn["dst"] in ("127.0.0.1", "::1"):
                            continue
                        self._add_event(EndpointEvent(
                            event_type=EndpointEventType.NETWORK_CONNECTION_ESTABLISHED,
                            severity=self._assess_connection_severity(conn),
                            src_ip=conn["src"],
                            src_port=int(conn["sport"]) if conn["sport"].isdigit() else 0,
                            dst_ip=conn["dst"],
                            dst_port=int(conn["dport"]) if conn["dport"].isdigit() else 0,
                            protocol=conn["proto"],
                            process_name=conn.get("process", ""),
                            process_id=int(conn.get("pid", 0)) if str(conn.get("pid", "")).isdigit() else 0,
                        ))

                # Closed connections
                for key in self._known_connections - current_conn_keys:
                    pass  # Optionally emit NETWORK_CONNECTION_CLOSED

                self._known_connections = current_conn_keys

            except Exception as exc:
                logger.debug("Network monitor cycle error: %s", exc)

            time.sleep(self.config.network_poll_interval)

    def _get_connections(self) -> list[dict[str, str]]:
        """Get active network connections (cross-platform)."""
        connections: list[dict[str, str]] = []

        try:
            if self._os_type == "windows":
                output = subprocess.check_output(
                    ["netstat", "-ano", "-p", "TCP"],
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    text=True,
                )
                for line in output.strip().split("\n")[4:]:
                    parts = line.split()
                    if len(parts) >= 5 and parts[3] == "ESTABLISHED":
                        local = parts[1].rsplit(":", 1)
                        remote = parts[2].rsplit(":", 1)
                        if len(local) == 2 and len(remote) == 2:
                            connections.append({
                                "proto": "tcp",
                                "src": local[0], "sport": local[1],
                                "dst": remote[0], "dport": remote[1],
                                "pid": parts[4],
                            })
            else:
                output = subprocess.check_output(
                    ["ss", "-tunp", "--no-header"],
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    text=True,
                )
                for line in output.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 6 and parts[0] in ("tcp", "udp"):
                        local = parts[4].rsplit(":", 1)
                        remote = parts[5].rsplit(":", 1)
                        if len(local) == 2 and len(remote) == 2:
                            connections.append({
                                "proto": parts[0],
                                "src": local[0], "sport": local[1],
                                "dst": remote[0], "dport": remote[1],
                            })
        except Exception:
            pass

        return connections

    def _assess_connection_severity(self, conn: dict[str, str]) -> str:
        """Assess severity of a network connection."""
        dport = int(conn.get("dport", "0")) if conn.get("dport", "").isdigit() else 0

        # Common C2 ports
        suspicious_ports = {4444, 5555, 8888, 1337, 31337, 6667, 6697}
        if dport in suspicious_ports:
            return "high"

        # Common exfiltration protocols on non-standard ports
        if dport > 10000:
            return "medium"

        return "info"

    # ── Snapshot Collection ───────────────────────────────────────────────

    def collect_system_snapshot(self) -> dict[str, Any]:
        """Collect a point-in-time system snapshot for baseline/forensics."""
        snapshot: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": self._agent_id,
            "hostname": self._hostname,
            "os": {"type": self._os_type, "version": self._os_version},
        }

        # Running processes
        snapshot["processes"] = list(self._get_running_processes().values())[:500]

        # Active connections
        snapshot["connections"] = self._get_connections()[:200]

        # Listening ports
        if self._os_type == "windows":
            try:
                output = subprocess.check_output(
                    ["netstat", "-ano", "-p", "TCP"],
                    stderr=subprocess.DEVNULL, timeout=10, text=True,
                )
                listening = []
                for line in output.split("\n"):
                    if "LISTENING" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            listening.append({
                                "port": parts[1].rsplit(":", 1)[-1],
                                "pid": parts[-1],
                            })
                snapshot["listening_ports"] = listening[:100]
            except Exception:
                snapshot["listening_ports"] = []

        return snapshot


_monitor_instance: Optional[EndpointMonitor] = None
_monitor_lock = threading.Lock()


def get_endpoint_monitor(config: Optional[MonitorConfig] = None) -> EndpointMonitor:
    """Get or create singleton EndpointMonitor."""
    global _monitor_instance
    if _monitor_instance is None:
        with _monitor_lock:
            if _monitor_instance is None:
                _monitor_instance = EndpointMonitor(config)
    return _monitor_instance

