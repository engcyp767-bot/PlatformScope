"""
Comprehensive Unit & Integration Test Suite for Database Abstraction Layer (Phase 9).
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from platform_core.database import (
    BaseSearchRepository,
    BaseTimeSeriesRepository,
    DatabaseBackend,
    DatabaseConfig,
    DatabaseManager,
    DatabaseType,
    OpenSearchBackend,
    OpenSearchRepository,
    PostgreSQLBackend,
    SchemaMigrationManager,
    SQLiteBackend,
    SQLiteSearchRepository,
    SQLiteTimeSeriesRepository,
)


class TestDatabaseDAL(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="platform_db_test_")
        self.storage_path = Path(self.tmp_dir)
        DatabaseManager.reset_instance()

    def tearDown(self):
        DatabaseManager.reset_instance()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_sqlite_backend_lifecycle(self):
        db_path = self.storage_path / "test_lifecycle.sqlite3"
        cfg = DatabaseConfig(db_type=DatabaseType.SQLITE, storage_dir=self.storage_path)
        backend = SQLiteBackend(db_path, cfg)
        backend.initialize()

        # DDL and execution
        backend.executescript(
            """
            CREATE TABLE test_items (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                score INTEGER DEFAULT 0
            );
            """
        )

        # Single insert
        row_id = backend.execute(
            "INSERT INTO test_items (id, name, score) VALUES (?, ?, ?)",
            ("item-1", "Test Item Alpha", 95),
        )
        self.assertGreaterEqual(row_id, 0)

        # fetch_one
        item = backend.fetch_one("SELECT * FROM test_items WHERE id = ?", ("item-1",))
        self.assertIsNotNone(item)
        self.assertEqual(item["name"], "Test Item Alpha")
        self.assertEqual(item["score"], 95)

        # execute_batch
        batch = [
            ("item-2", "Test Item Beta", 80),
            ("item-3", "Test Item Gamma", 70),
        ]
        count = backend.execute_batch(
            "INSERT INTO test_items (id, name, score) VALUES (?, ?, ?)",
            batch,
        )
        self.assertEqual(count, 2)

        # fetch_all
        all_items = backend.fetch_all("SELECT * FROM test_items ORDER BY score DESC;")
        self.assertEqual(len(all_items), 3)
        self.assertEqual(all_items[0]["id"], "item-1")

        # transaction commit
        with backend.transaction():
            backend.execute("UPDATE test_items SET score = 100 WHERE id = ?", ("item-1",))
        item_updated = backend.fetch_one("SELECT score FROM test_items WHERE id = ?", ("item-1",))
        self.assertEqual(item_updated["score"], 100)

        # transaction rollback on exception
        try:
            with backend.transaction():
                backend.execute("UPDATE test_items SET score = 50 WHERE id = ?", ("item-1",))
                raise ValueError("Forced error for rollback verification")
        except ValueError:
            pass

        item_rolled_back = backend.fetch_one("SELECT score FROM test_items WHERE id = ?", ("item-1",))
        self.assertEqual(item_rolled_back["score"], 100)

        # Health check
        health = backend.health_check()
        self.assertEqual(health["status"], "healthy")
        self.assertEqual(health["backend"], "sqlite")
        self.assertGreater(health["latency_ms"], 0.0)

        backend.close()

    def test_database_config_loading_and_overrides(self):
        # Default
        cfg = DatabaseConfig()
        self.assertEqual(cfg.db_type, DatabaseType.SQLITE)
        self.assertTrue(cfg.wal_mode)

        # Env overrides
        os.environ["PLATFORM_DB_TYPE"] = "postgresql"
        os.environ["PLATFORM_PG_HOST"] = "192.168.1.50"
        os.environ["PLATFORM_PG_PORT"] = "5433"
        os.environ["PLATFORM_TIMESCALE_ENABLED"] = "true"

        try:
            loaded = DatabaseConfig.from_env_and_file()
            self.assertEqual(loaded.db_type, DatabaseType.POSTGRESQL)
            self.assertEqual(loaded.pg_host, "192.168.1.50")
            self.assertEqual(loaded.pg_port, 5433)
            self.assertTrue(loaded.timescale_enabled)

            d = loaded.to_dict()
            self.assertEqual(d["db_type"], "postgresql")
            self.assertEqual(d["pg_host"], "192.168.1.50")
            self.assertTrue(d["timescale_enabled"])
        finally:
            os.environ.pop("PLATFORM_DB_TYPE", None)
            os.environ.pop("PLATFORM_PG_HOST", None)
            os.environ.pop("PLATFORM_PG_PORT", None)
            os.environ.pop("PLATFORM_TIMESCALE_ENABLED", None)

    def test_database_manager_singleton(self):
        cfg = DatabaseConfig(storage_dir=self.storage_path)
        mgr1 = DatabaseManager(cfg)
        self.assertIsNotNone(mgr1.get_backend())
        self.assertEqual(mgr1.get_backend().backend_type, DatabaseType.SQLITE)

        mgr1.close()

    def test_graceful_degradation_when_driver_missing(self):
        # Configure PostgreSQL without requiring psycopg2 to exist in env
        cfg = DatabaseConfig(
            db_type=DatabaseType.POSTGRESQL,
            storage_dir=self.storage_path,
        )
        mgr = DatabaseManager(cfg)
        status = mgr.get_status()

        self.assertIsInstance(status, dict)
        self.assertEqual(status["active_engine"], "sqlite")
        self.assertEqual(status["configured_engine"], "postgresql")
        # Should gracefully fall back to SQLite without crashing
        self.assertTrue(status["is_fallback_active"])
        self.assertIn("Gracefully fell back to SQLite", status["fallback_reason"])
        self.assertEqual(status["health"]["status"], "healthy")

        mgr.close()

    def test_sqlite_fts_search_repository(self):
        db_path = self.storage_path / "test_search.sqlite3"
        backend = SQLiteBackend(db_path)
        backend.initialize()

        search_repo = SQLiteSearchRepository(backend)

        doc1 = {
            "title": "Cobalt Strike Beacon Execution",
            "body": "PowerShell encoded command invoking mimikatz credential dumping",
            "threat_actor": "APT29",
            "severity": "critical",
        }
        doc2 = {
            "title": "Routine SSH Login",
            "body": "User admin logged into backup server",
            "severity": "low",
        }

        search_repo.index_document("alerts", "alert-001", doc1)
        search_repo.index_document("alerts", "alert-002", doc2)

        # Search match
        hits = search_repo.search("alerts", "mimikatz")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["_doc_id"], "alert-001")
        self.assertEqual(hits[0]["threat_actor"], "APT29")

        # Search no match
        no_hits = search_repo.search("alerts", "ransomware")
        self.assertEqual(len(no_hits), 0)

        backend.close()

    def test_sqlite_timeseries_repository(self):
        db_path = self.storage_path / "test_ts.sqlite3"
        backend = SQLiteBackend(db_path)
        backend.initialize()

        ts_repo = SQLiteTimeSeriesRepository(backend)

        events = [
            {"timestamp": "2026-09-07T10:00:00Z", "event_type": "logon", "severity": "low", "user": "alice"},
            {"timestamp": "2026-09-07T10:05:00Z", "event_type": "privilege_escalation", "severity": "high", "user": "alice"},
            {"timestamp": "2026-09-07T10:15:00Z", "event_type": "c2_beacon", "severity": "critical", "user": "system"},
        ]

        inserted = ts_repo.insert_events_batch("stream-corp-dc", events)
        self.assertEqual(inserted, 3)

        # Window query
        window = ts_repo.query_events_window(
            stream_id="stream-corp-dc",
            start_time="2026-09-07T10:00:00Z",
            end_time="2026-09-07T10:10:00Z",
        )
        self.assertEqual(len(window), 2)
        self.assertEqual(window[0]["event_type"], "logon")
        self.assertEqual(window[1]["event_type"], "privilege_escalation")

        backend.close()

    def test_postgres_and_timescale_ddl_manifest(self):
        cfg_pg = DatabaseConfig(db_type=DatabaseType.POSTGRESQL, timescale_enabled=False)
        pg_backend = PostgreSQLBackend(cfg_pg)
        ddl_pg = pg_backend.get_ddl_manifest()

        self.assertIn("incidents", ddl_pg)
        self.assertIn("JSONB", ddl_pg["incidents"])
        self.assertIn("TIMESTAMPTZ", ddl_pg["incidents"])
        self.assertIn("telemetry_table", ddl_pg)

        # Timescale enabled
        cfg_ts = DatabaseConfig(db_type=DatabaseType.TIMESCALEDB, timescale_enabled=True)
        ts_backend = PostgreSQLBackend(cfg_ts)
        ddl_ts = ts_backend.get_ddl_manifest()
        self.assertIn("telemetry_hypertable", ddl_ts)
        self.assertIn("create_hypertable", ddl_ts["telemetry_hypertable"])

        health = ts_backend.health_check()
        self.assertEqual(health["backend"], "timescaledb")
        self.assertTrue(health["timescale_enabled"])

    def test_opensearch_adapter_and_query_dsl(self):
        cfg = DatabaseConfig(db_type=DatabaseType.OPENSEARCH, opensearch_url="http://127.0.0.1:9200")
        os_backend = OpenSearchBackend(cfg)
        self.assertEqual(os_backend.backend_type, DatabaseType.OPENSEARCH)

        health = os_backend.health_check()
        self.assertEqual(health["backend"], "opensearch")
        self.assertEqual(health["status"], "configured_offline")

        repo = OpenSearchRepository(os_backend)
        target = repo._get_target_index("SOC-Alerts")
        self.assertEqual(target, "platform_soc_soc_alerts")

    def test_schema_migration_manager(self):
        db_path = self.storage_path / "test_migrations.sqlite3"
        backend = SQLiteBackend(db_path)
        backend.initialize()

        mgr = SchemaMigrationManager(backend)
        applied_first = mgr.apply_pending_migrations()
        self.assertEqual(len(applied_first), 3)

        # Idempotent re-run
        applied_second = mgr.apply_pending_migrations()
        self.assertEqual(len(applied_second), 0)

        # Check records
        all_migrations = mgr.get_applied_migrations()
        self.assertEqual(len(all_migrations), 3)
        self.assertEqual(all_migrations[0]["version"], 1)

        # Test bundle export
        backend.execute("CREATE TABLE sample (id INT, val TEXT);")
        backend.execute("INSERT INTO sample VALUES (1, 'hello');")
        bundle = mgr.export_data_bundle(["sample"])
        self.assertIn("sample", bundle["tables"])
        self.assertEqual(len(bundle["tables"]["sample"]), 1)
        self.assertEqual(bundle["tables"]["sample"][0]["val"], "hello")

        backend.close()

    def test_database_manager_status_matrix(self):
        cfg = DatabaseConfig(storage_dir=self.storage_path)
        mgr = DatabaseManager(cfg)
        status = mgr.get_status()

        self.assertEqual(status["active_engine"], "sqlite")
        self.assertIn("engines_matrix", status)
        self.assertIn("sqlite", status["engines_matrix"])
        self.assertIn("postgresql", status["engines_matrix"])
        self.assertIn("timescaledb", status["engines_matrix"])
        self.assertIn("opensearch", status["engines_matrix"])
        self.assertTrue(status["features"]["horizontal_readiness"])

        mgr.close()


if __name__ == "__main__":
    unittest.main()
