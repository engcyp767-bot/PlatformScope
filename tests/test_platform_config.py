import tempfile
import os
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from platform_core import platform_config


class PlatformConfigurationTests(unittest.TestCase):
    def test_settings_round_trip_masks_secrets_and_public_view_is_safe(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            platform_config, "CONFIG_FILE", Path(directory) / "platform_config.json"
        ), patch.object(platform_config, "apply_runtime"):
            saved = platform_config.save({
                "appearance": {"theme": "navy", "primary_color": "#112233"},
                "providers": {
                    "virustotal": {"enabled": True, "api_keys": ["first-key", "second-key"]},
                    "abuseipdb": {"enabled": True, "api_key": "abuse-secret"},
                },
                "ai_providers": [{
                    "id": "ai-one", "name": "Internal AI", "base_url": "https://ai.example.test",
                    "model": "secure-model", "api_key": "ai-secret", "priority": 2,
                }],
            })
            self.assertEqual(saved["appearance"]["theme"], "navy")
            self.assertEqual(saved["providers"]["virustotal"]["configured_keys"], 2)
            self.assertEqual(saved["providers"]["virustotal"]["api_keys"], [platform_config.MASK] * 2)
            self.assertEqual(saved["providers"]["abuseipdb"]["api_key"], platform_config.MASK)
            self.assertEqual(saved["ai_providers"][0]["api_key"], platform_config.MASK)
            self.assertEqual(saved["ai_providers"][0]["priority"], 2)
            public = platform_config.public_config()
            self.assertEqual(set(public), {"version", "appearance", "general", "features", "source_systems", "uploads"})
            self.assertNotIn("providers", public)

    def test_operational_settings_are_bounded_and_source_systems_are_cleaned(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            platform_config, "CONFIG_FILE", Path(directory) / "platform_config.json"
        ), patch.object(platform_config, "apply_runtime"):
            saved = platform_config.save({
                "uploads": {"flowscope_max_mb": 99999, "threatscope_max_mb": 0, "logscope_max_mb": 2048},
                "analysis": {"medium_threshold": 50, "high_threshold": 70, "critical_threshold": 90, "log_max_external_ips": 200000, "log_cache_ttl_days": 5000},
                "source_systems": {
                    "flowscope": [{"id": "flow custom!", "label": "EDGE", "description": "بوابة الشبكة"}],
                    "logscope": [{"id": "manage engine!", "label": "ManageEngine", "description": "SIEM"}],
                },
                "network": {"frontend_port": 3100, "gateway_port": 8101, "analysis_port": 8102},
            })
            self.assertEqual(saved["uploads"]["flowscope_max_mb"], 4096)
            self.assertEqual(saved["uploads"]["threatscope_max_mb"], 1)
            self.assertEqual(saved["uploads"]["logscope_max_mb"], 2048)
            self.assertEqual(saved["analysis"]["log_max_external_ips"], 100000)
            self.assertEqual(saved["analysis"]["log_cache_ttl_days"], 3650)
            self.assertEqual(saved["source_systems"]["flowscope"][0]["id"], "flowcustom")
            self.assertEqual(saved["source_systems"]["flowscope"][0]["label"], "EDGE")
            self.assertEqual(saved["source_systems"]["logscope"][0]["id"], "manageengine")

    def test_service_ports_must_be_distinct(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            platform_config, "CONFIG_FILE", Path(directory) / "platform_config.json"
        ), patch.object(platform_config, "apply_runtime"):
            with self.assertRaises(ValueError):
                platform_config.save({"network": {"frontend_port": 3000, "gateway_port": 3000, "analysis_port": 8082}})

    def test_retention_is_opt_in_and_scoped_to_valid_job_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "flowscope" / "storage" / "jobs" / ("a" * 32)
            invalid = root / "flowscope" / "storage" / "jobs" / "keep-me"
            valid.mkdir(parents=True)
            invalid.mkdir()
            marker = valid / "analysis.json"
            marker.write_text("{}", encoding="utf-8")
            old = time.time() - 3 * 86400
            os.utime(marker, (old, old))
            with patch.object(platform_config, "ROOT", root):
                untouched = platform_config.apply_retention({"storage": {"job_retention_days": 0, "audit_retention_days": 0, "preview_retention_hours": 0}})
                self.assertTrue(valid.exists())
                self.assertEqual(untouched["jobs"], 0)
                removed = platform_config.apply_retention({"storage": {"job_retention_days": 1, "audit_retention_days": 0, "preview_retention_hours": 0}})
            self.assertFalse(valid.exists())
            self.assertTrue(invalid.exists())
            self.assertEqual(removed["jobs"], 1)

    def test_invalid_external_url_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            platform_config, "CONFIG_FILE", Path(directory) / "platform_config.json"
        ), patch.object(platform_config, "apply_runtime"):
            with self.assertRaises(ValueError):
                platform_config.save({"external_apis": [{"name": "bad", "base_url": "file:///tmp/data"}]})

    def test_light_theme_is_supported(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            platform_config, "CONFIG_FILE", Path(directory) / "platform_config.json"
        ), patch.object(platform_config, "apply_runtime"):
            saved = platform_config.save({"appearance": {"theme": "light"}})
            self.assertEqual(saved["appearance"]["theme"], "light")

    def test_storage_stats_returns_expected_structure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            job_dir = root / "flowscope" / "storage" / "jobs" / ("b" * 32)
            job_dir.mkdir(parents=True)
            (job_dir / "analysis.json").write_text("{}", encoding="utf-8")
            with patch.object(platform_config, "ROOT", root):
                stats = platform_config.storage_stats()
                self.assertIn("disk", stats)
                self.assertIn("jobs", stats)
                self.assertIn("audit", stats)
                self.assertIn("previews", stats)
                self.assertEqual(stats["jobs"]["flowscope"]["count"], 1)
                self.assertGreater(stats["jobs"]["flowscope"]["bytes"], 0)

    def test_config_history_and_rollback(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as directory:
            root = Path(directory)
            cfg_file = root / "storage" / "platform_config.json"
            hist_db = root / "storage" / "config_history.db"
            with patch.object(platform_config, "ROOT", root), \
                 patch.object(platform_config, "CONFIG_FILE", cfg_file), \
                 patch.object(platform_config, "CONFIG_HISTORY_DB", hist_db):
                # 1. First save
                c1 = platform_config.save({"general": {"items_per_page": 30}}, actor="analyst1", summary="Initial setup")
                v1 = c1["version"]
                self.assertGreaterEqual(v1, 1)

                # 2. Second save
                c2 = platform_config.save({"general": {"items_per_page": 60}}, actor="analyst2", summary="Double page size")
                v2 = c2["version"]
                self.assertGreater(v2, v1)

                # 3. Check history
                hist = platform_config.get_config_history()
                self.assertGreaterEqual(len(hist), 2)
                self.assertEqual(hist[0]["version"], v2)
                self.assertEqual(hist[0]["actor"], "analyst2")

                # 4. Rollback to v1
                rolled = platform_config.rollback_config(version=v1, actor="admin")
                self.assertEqual(rolled["general"]["items_per_page"], 30)


if __name__ == "__main__":
    unittest.main()
