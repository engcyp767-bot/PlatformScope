"""Platform Time and Synchronization Service.

Provides unified platform time management across the security platform:
- 'host': Synchronized with the underlying operating system clock (offset = 0).
- 'manual': Custom user-defined time anchor with real-time progression.
- 'ntp': Network Time Protocol (RFC 5905) synchronization over UDP port 123.
"""

from __future__ import annotations

import datetime
import math
import os
import re
import socket
import struct
import threading
import time
from typing import Any

# NTP Epoch is 1900-01-01, Unix Epoch is 1970-01-01
# Difference in seconds: 70 years * 365 days + 17 leap days = 2208988800 seconds
NTP_DELTA = 2208988800

DEFAULT_NTP_SERVERS = [
    "pool.ntp.org",
    "time.google.com",
    "time.cloudflare.com",
    "time.windows.com",
]


def _parse_iso_to_timestamp(val: str | None) -> float | None:
    """Parse an ISO 8601 string into Unix epoch seconds."""
    if not val or not isinstance(val, str):
        return None
    cleaned = val.strip()
    if not cleaned:
        return None
    try:
        # Handle trailing Z
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError, OverflowError):
        return None


def query_ntp_server(
    server: str = "pool.ntp.org",
    port: int = 123,
    timeout: float = 4.0,
) -> dict[str, Any]:
    """Query an NTP server using RFC 5905 client protocol without external dependencies.

    Returns dict with keys:
        - success: bool
        - offset: float (seconds: platform_offset = server_time - local_time)
        - delay_ms: float (round-trip delay in ms)
        - stratum: int
        - precision: int
        - server: str
        - server_time_iso: str
        - error: str | None
    """
    server = (server or "").strip()
    if not server:
        return {
            "success": False,
            "error": "اسم خادم NTP فارغ",
            "server": server,
            "port": port,
        }

    # Packet layout RFC 5905:
    # Byte 0: LI=0 (2 bits), VN=3 (3 bits), Mode=3 (3 bits, client) -> 0b00011011 = 0x1B = 27
    # Bytes 1-47: 0s
    client_packet = bytearray(48)
    client_packet[0] = 0x1B

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    t1 = time.time()  # Client transmit time
    # Store t1 in client packet transmit timestamp (bytes 40-47)
    sec = int(t1 + NTP_DELTA)
    frac = int((t1 + NTP_DELTA - sec) * (2**32))
    struct.pack_into("!II", client_packet, 40, sec, frac)

    try:
        sock.sendto(client_packet, (server, port))
        data, addr = sock.recvfrom(512)
        t4 = time.time()  # Client receive time
    except socket.timeout:
        return {
            "success": False,
            "error": f"انتهت مهلة الاتصال بخادم NTP ({server}:{port})",
            "server": server,
            "port": port,
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"فشل استعلام خادم NTP: {exc}",
            "server": server,
            "port": port,
        }
    finally:
        sock.close()

    if len(data) < 48:
        return {
            "success": False,
            "error": f"حزمة NTP غير صالحة من ({server}); الطول {len(data)} بايت",
            "server": server,
            "port": port,
        }

    # Unpack header and timestamps
    # Byte 0: LI, VN, Mode
    stratum = data[1]
    poll = data[2]
    precision = struct.unpack("!b", data[3:4])[0]

    # Originate Timestamp (t1 echoed by server): bytes 24-31
    # Receive Timestamp (t2 recorded by server): bytes 32-39
    # Transmit Timestamp (t3 recorded by server): bytes 40-47
    t2_sec, t2_frac = struct.unpack("!II", data[32:40])
    t3_sec, t3_frac = struct.unpack("!II", data[40:48])

    t2 = (t2_sec - NTP_DELTA) + (t2_frac / (2**32))
    t3 = (t3_sec - NTP_DELTA) + (t3_frac / (2**32))

    # Delay: delta = (t4 - t1) - (t3 - t2)
    # Offset: theta = ((t2 - t1) + (t3 - t4)) / 2
    delay = (t4 - t1) - (t3 - t2)
    offset = ((t2 - t1) + (t3 - t4)) / 2.0

    server_time = t4 + offset
    server_time_dt = datetime.datetime.fromtimestamp(server_time, tz=datetime.timezone.utc)

    return {
        "success": True,
        "offset": offset,
        "delay_ms": round(max(0.0, delay * 1000.0), 3),
        "stratum": stratum,
        "precision": precision,
        "server": server,
        "port": port,
        "server_time_iso": server_time_dt.isoformat().replace("+00:00", "Z"),
        "error": None,
    }


class PlatformTimeService:
    """Central singleton service managing platform system time and synchronization."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._source: str = "host"  # "host" | "manual" | "ntp"
        self._offset: float = 0.0  # seconds to add to host time

        # NTP settings & telemetry
        self._ntp_server: str = "pool.ntp.org"
        self._ntp_port: int = 123
        self._ntp_timeout: float = 4.0
        self._ntp_sync_interval: int = 3600  # seconds
        self._ntp_auto_sync: bool = True
        self._last_ntp_sync: float | None = None
        self._last_ntp_success: bool = False
        self._last_ntp_error: str | None = None
        self._last_ntp_delay_ms: float = 0.0
        self._last_ntp_stratum: int = 0

        # Manual settings
        self._manual_configured_iso: str | None = None
        self._manual_applied_at: float | None = None

        # Background worker
        self._worker_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()

    def apply_config(self, cfg: dict[str, Any] | None) -> None:
        """Apply runtime time configuration safely."""
        with self._lock:
            if not isinstance(cfg, dict):
                cfg = {}

            source = str(cfg.get("source") or "host").lower().strip()
            if source not in {"host", "manual", "ntp"}:
                source = "host"

            self._source = source
            self._ntp_server = str(cfg.get("ntp_server") or "pool.ntp.org").strip()[:180] or "pool.ntp.org"
            try:
                self._ntp_port = int(cfg.get("ntp_port") or 123)
            except (ValueError, TypeError):
                self._ntp_port = 123
            if not (1 <= self._ntp_port <= 65535):
                self._ntp_port = 123

            try:
                interval = int(cfg.get("ntp_sync_interval_seconds") or 3600)
            except (ValueError, TypeError):
                interval = 3600
            self._ntp_sync_interval = max(60, min(86400 * 7, interval))
            self._ntp_auto_sync = bool(cfg.get("auto_sync", True))

            if self._source == "host":
                self._offset = 0.0

            elif self._source == "manual":
                manual_iso = cfg.get("manual_time")
                if manual_iso:
                    ts = _parse_iso_to_timestamp(str(manual_iso))
                    if ts is not None:
                        now_host = time.time()
                        self._offset = ts - now_host
                        self._manual_configured_iso = str(manual_iso)
                        self._manual_applied_at = now_host

            elif self._source == "ntp":
                # Wake or start worker to perform initial sync
                self._ensure_worker_started()
                self._wake_event.set()

    def _ensure_worker_started(self) -> None:
        """Start the background auto-sync worker thread if not already running."""
        with self._lock:
            if self._worker_thread is None or not self._worker_thread.is_alive():
                self._stop_event.clear()
                self._worker_thread = threading.Thread(
                    target=self._worker_loop,
                    name="PlatformTime-NTPWorker",
                    daemon=True,
                )
                self._worker_thread.start()

    def _worker_loop(self) -> None:
        """Background loop to periodically sync NTP time."""
        while not self._stop_event.is_set():
            with self._lock:
                should_sync = (self._source == "ntp" and self._ntp_auto_sync)
                interval = self._ntp_sync_interval
                server = self._ntp_server
                port = self._ntp_port

            if should_sync:
                self._perform_ntp_sync(server, port)

            # Wait for either next sync interval or explicit wake event
            self._wake_event.wait(timeout=float(interval))
            self._wake_event.clear()

    def _perform_ntp_sync(self, server: str, port: int) -> tuple[bool, str]:
        """Perform NTP query and adjust platform offset on success."""
        res = query_ntp_server(server=server, port=port, timeout=self._ntp_timeout)
        with self._lock:
            self._last_ntp_sync = time.time()
            if res.get("success"):
                self._last_ntp_success = True
                self._last_ntp_error = None
                self._last_ntp_delay_ms = float(res.get("delay_ms") or 0.0)
                self._last_ntp_stratum = int(res.get("stratum") or 0)
                if self._source == "ntp":
                    self._offset = float(res.get("offset") or 0.0)
                return True, f"تمت المزامنة بنجاح مع {server} (انحراف {res.get('offset'):+.3f} ثانية)"
            else:
                self._last_ntp_success = False
                err = str(res.get("error") or "فشل مزامنة NTP")
                self._last_ntp_error = err
                return False, err

    def sync_now(
        self,
        server: str | None = None,
        port: int | None = None,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Trigger an immediate NTP synchronization."""
        target_server = (server or self._ntp_server).strip() or "pool.ntp.org"
        target_port = port or self._ntp_port
        success, message = self._perform_ntp_sync(target_server, target_port)
        status = self.get_status()
        return success, message, status

    def time(self) -> float:
        """Return current platform timestamp in epoch seconds."""
        return time.time() + self._offset

    def now(self, tz: datetime.tzinfo = datetime.timezone.utc) -> datetime.datetime:
        """Return current platform datetime."""
        ts = self.time()
        return datetime.datetime.fromtimestamp(ts, tz=tz)

    def utcnow_iso(self) -> str:
        """Return current platform UTC datetime in standard ISO-8601 format."""
        return self.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    def host_time(self) -> float:
        """Return underlying host OS epoch seconds."""
        return time.time()

    def host_now(self, tz: datetime.tzinfo = datetime.timezone.utc) -> datetime.datetime:
        """Return underlying host OS datetime."""
        return datetime.datetime.fromtimestamp(time.time(), tz=tz)

    def host_now_iso(self) -> str:
        """Return underlying host OS UTC datetime in standard ISO-8601 format."""
        return self.host_now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    def get_status(self) -> dict[str, Any]:
        """Return complete runtime telemetry and status of platform time."""
        with self._lock:
            cur_time = self.time()
            hst_time = self.host_time()
            offset = self._offset

            cur_dt = datetime.datetime.fromtimestamp(cur_time, tz=datetime.timezone.utc)
            hst_dt = datetime.datetime.fromtimestamp(hst_time, tz=datetime.timezone.utc)

            last_sync_iso = None
            if self._last_ntp_sync is not None:
                last_sync_iso = (
                    datetime.datetime.fromtimestamp(self._last_ntp_sync, tz=datetime.timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                )

            next_sync_sec = None
            if self._source == "ntp" and self._ntp_auto_sync:
                if self._last_ntp_sync is not None:
                    elapsed = time.time() - self._last_ntp_sync
                    next_sync_sec = max(0, int(self._ntp_sync_interval - elapsed))
                else:
                    next_sync_sec = 0

            return {
                "source": self._source,
                "current_time_iso": cur_dt.isoformat().replace("+00:00", "Z"),
                "current_timestamp": round(cur_time, 3),
                "host_time_iso": hst_dt.isoformat().replace("+00:00", "Z"),
                "host_timestamp": round(hst_time, 3),
                "offset_seconds": round(offset, 4),
                "offset_formatted": f"{offset:+.3f}s",
                "ntp": {
                    "server": self._ntp_server,
                    "port": self._ntp_port,
                    "stratum": self._last_ntp_stratum,
                    "delay_ms": self._last_ntp_delay_ms,
                    "last_sync_iso": last_sync_iso,
                    "last_sync_success": self._last_ntp_success,
                    "last_sync_error": self._last_ntp_error,
                    "auto_sync": self._ntp_auto_sync,
                    "sync_interval_seconds": self._ntp_sync_interval,
                    "next_sync_seconds": next_sync_sec,
                },
                "manual": {
                    "configured_time_iso": self._manual_configured_iso,
                    "applied_at_iso": (
                        datetime.datetime.fromtimestamp(self._manual_applied_at, tz=datetime.timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z")
                        if self._manual_applied_at
                        else None
                    ),
                },
            }


_GLOBAL_TIME_SERVICE: PlatformTimeService | None = None
_GLOBAL_LOCK = threading.Lock()


def get_time_service() -> PlatformTimeService:
    """Retrieve global singleton instance of PlatformTimeService."""
    global _GLOBAL_TIME_SERVICE
    if _GLOBAL_TIME_SERVICE is None:
        with _GLOBAL_LOCK:
            if _GLOBAL_TIME_SERVICE is None:
                _GLOBAL_TIME_SERVICE = PlatformTimeService()
    return _GLOBAL_TIME_SERVICE


def init_time_service(config: dict[str, Any] | None = None) -> PlatformTimeService:
    """Initialize or update the global time service with platform configuration."""
    service = get_time_service()
    if config:
        service.apply_config(config.get("time", config))
    return service


def platform_time() -> float:
    """Return current platform timestamp in epoch seconds."""
    return get_time_service().time()


def platform_now(tz: datetime.tzinfo = datetime.timezone.utc) -> datetime.datetime:
    """Return current platform datetime."""
    return get_time_service().now(tz=tz)


def platform_iso() -> str:
    """Return current platform UTC datetime in standard ISO-8601 format."""
    return get_time_service().utcnow_iso()

