"""Unit tests for Platform Time & Synchronization Service."""

import datetime
import socket
import struct
import time
import unittest
from unittest.mock import MagicMock, patch

from platform_core import platform_config, time_service
from platform_core.time_service import (
    PlatformTimeService,
    query_ntp_server,
    NTP_DELTA,
    get_time_service,
    platform_time,
    platform_now,
    platform_iso,
)


class TestPlatformTimeService(unittest.TestCase):
    """Test suite for PlatformTimeService and NTP protocol implementation."""

    def setUp(self) -> None:
        self.service = PlatformTimeService()

    def test_default_state(self) -> None:
        """Initial state should default to 'host' clock with zero offset."""
        status = self.service.get_status()
        self.assertEqual(status["source"], "host")
        self.assertEqual(status["offset_seconds"], 0.0)
        self.assertAlmostEqual(self.service.time(), time.time(), delta=1.0)
        self.assertEqual(status["ntp"]["server"], "pool.ntp.org")
        self.assertEqual(status["ntp"]["port"], 123)

    def test_manual_time_configuration(self) -> None:
        """Manual time mode should compute correct offset and advance continuously."""
        # Set manual time to 1 hour (3600s) in the future
        target_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        target_iso = target_dt.isoformat().replace("+00:00", "Z")

        self.service.apply_config({
            "source": "manual",
            "manual_time": target_iso,
        })

        status = self.service.get_status()
        self.assertEqual(status["source"], "manual")
        self.assertAlmostEqual(status["offset_seconds"], 3600.0, delta=2.0)

        # Ensure platform_time() is ~3600 seconds ahead of host time
        self.assertAlmostEqual(self.service.time() - time.time(), 3600.0, delta=2.0)

        # Check ISO timestamp format
        dt = self.service.now()
        self.assertAlmostEqual((dt - target_dt).total_seconds(), 0.0, delta=2.0)

    def test_host_time_reversion(self) -> None:
        """Switching from manual back to host resets the offset to 0."""
        self.service.apply_config({
            "source": "manual",
            "manual_time": "2030-01-01T00:00:00Z",
        })
        self.assertNotEqual(self.service.get_status()["offset_seconds"], 0.0)

        self.service.apply_config({"source": "host"})
        status = self.service.get_status()
        self.assertEqual(status["source"], "host")
        self.assertEqual(status["offset_seconds"], 0.0)

    def test_ntp_config_sanitization(self) -> None:
        """NTP parameters are bounded and sanitized."""
        self.service.apply_config({
            "source": "ntp",
            "ntp_server": "   time.google.com   ",
            "ntp_port": 999999,  # invalid port, should default to 123
            "ntp_sync_interval_seconds": 10,  # below min (60), should bound to 60
            "auto_sync": True,
        })
        status = self.service.get_status()
        self.assertEqual(status["source"], "ntp")
        self.assertEqual(status["ntp"]["server"], "time.google.com")
        self.assertEqual(status["ntp"]["port"], 123)
        self.assertEqual(status["ntp"]["sync_interval_seconds"], 60)
        self.assertTrue(status["ntp"]["auto_sync"])

    def test_query_ntp_empty_server(self) -> None:
        """Empty server returns clear error."""
        res = query_ntp_server(server="", port=123)
        self.assertFalse(res["success"])
        self.assertIn("فارغ", res["error"])

    @patch("socket.socket")
    def test_query_ntp_server_mocked_success(self, mock_socket_cls: MagicMock) -> None:
        """Mock UDP exchange to test RFC 5905 unpacking and offset calculation."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Prepare a 48-byte NTP response packet
        # Byte 0: LI=0, VN=3, Mode=4 (server) -> 0x1C
        # Byte 1: Stratum = 2
        # Byte 2: Poll = 6
        # Byte 3: Precision = -20
        response_packet = bytearray(48)
        response_packet[0] = 0x1C
        response_packet[1] = 2
        response_packet[2] = 6
        response_packet[3] = 0xEC  # signed -20

        now = time.time()
        # Server receive (t2) = now + 5.0
        # Server transmit (t3) = now + 5.001
        t2_val = now + 5.0 + NTP_DELTA
        t3_val = now + 5.001 + NTP_DELTA

        struct.pack_into("!II", response_packet, 32, int(t2_val), int((t2_val % 1) * (2**32)))
        struct.pack_into("!II", response_packet, 40, int(t3_val), int((t3_val % 1) * (2**32)))

        mock_sock.recvfrom.return_value = (bytes(response_packet), ("1.2.3.4", 123))

        res = query_ntp_server(server="time.mock.org", port=123, timeout=2.0)
        self.assertTrue(res["success"])
        self.assertEqual(res["stratum"], 2)
        self.assertAlmostEqual(res["offset"], 5.0, delta=0.1)
        self.assertGreaterEqual(res["delay_ms"], 0.0)
        self.assertIsNotNone(res["server_time_iso"])

    def test_platform_config_integration(self) -> None:
        """Verify platform_config DEFAULTS, save, and test_connection for NTP."""
        defaults = platform_config.DEFAULTS
        self.assertIn("time", defaults)
        self.assertEqual(defaults["time"]["source"], "host")
        self.assertEqual(defaults["time"]["ntp_server"], "pool.ntp.org")

        # Test NTP connection helper in platform_config with mock
        with patch("platform_core.time_service.query_ntp_server") as mock_query:
            mock_query.return_value = {
                "success": True,
                "stratum": 1,
                "delay_ms": 12.5,
                "offset": 0.002,
                "server_time_iso": "2026-09-08T01:00:00Z",
                "error": None,
            }
            test_res = platform_config.test_connection({
                "kind": "ntp",
                "ntp_server": "pool.ntp.org",
                "ntp_port": 123,
            })
            self.assertTrue(test_res["ok"])
            self.assertIn("بنجاح", test_res["message"])

    def test_global_helpers(self) -> None:
        """Global helper functions return consistent timestamps."""
        t = platform_time()
        self.assertIsInstance(t, float)
        dt = platform_now()
        self.assertIsInstance(dt, datetime.datetime)
        iso = platform_iso()
        self.assertTrue(iso.endswith("Z"))


if __name__ == "__main__":
    unittest.main()

