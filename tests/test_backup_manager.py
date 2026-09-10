"""Unit tests for platform_core/backup_manager.py."""

import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from platform_core.backup_manager import BackupManager


class TestBackupManager(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.base_path = Path(self.tmp_dir.name)
        self.storage_dir = self.base_path / "storage"
        self.detections_dir = self.base_path / "detections"
        self.backup_dir = self.storage_dir / "backups"

        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.detections_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Seed test db
        self.test_db = self.storage_dir / "test_data.sqlite3"
        con = sqlite3.connect(str(self.test_db))
        con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);")
        con.execute("INSERT INTO users (name) VALUES ('analyst_1');")
        con.commit()
        con.close()

        # Seed test config
        self.test_cfg = self.storage_dir / "platform_config.json"
        self.test_cfg.write_text(json.dumps({"version": "1.0", "theme": "dark"}), encoding="utf-8")

        # Seed test detection
        self.test_rule = self.detections_dir / "rule_01.json"
        self.test_rule.write_text(json.dumps({"id": "RULE-1", "title": "Test Rule"}), encoding="utf-8")

        self.manager = BackupManager(
            backup_dir=self.backup_dir,
            storage_dir=self.storage_dir,
            detections_dir=self.detections_dir,
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_create_and_list_backups(self):
        backup_meta = self.manager.create_backup(actor="admin_user", note="Initial test backup")
        self.assertIn("backup_id", backup_meta)
        self.assertTrue((self.backup_dir / backup_meta["filename"]).exists())
        self.assertEqual(backup_meta["file_count"], 3)

        backups = self.manager.list_backups()
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0]["filename"], backup_meta["filename"])
        self.assertEqual(backups[0]["actor"], "admin_user")
        self.assertEqual(backups[0]["note"], "Initial test backup")
        self.assertTrue(backups[0]["valid"])

    def test_validate_backup_integrity(self):
        backup_meta = self.manager.create_backup(actor="tester")
        filename = backup_meta["filename"]

        # Valid archive
        res = self.manager.validate_backup(filename)
        self.assertTrue(res["valid"])
        self.assertEqual(len(res["errors"]), 0)

        # Tampered archive test: corrupt a file inside
        archive_path = self.backup_dir / filename
        # Read all files, modify one, re-write without updating manifest
        content_map = {}
        with zipfile.ZipFile(archive_path, "r") as zf:
            for name in zf.namelist():
                content_map[name] = zf.read(name)

        content_map["storage/platform_config.json"] = b'{"tampered": true}'
        with zipfile.ZipFile(archive_path, "w") as zf:
            for name, data in content_map.items():
                zf.writestr(name, data)

        res_tampered = self.manager.validate_backup(filename)
        self.assertFalse(res_tampered["valid"])
        self.assertTrue(any("integrity violation" in err for err in res_tampered["errors"]))

    def test_restore_backup(self):
        backup_meta = self.manager.create_backup(actor="tester", note="Before mutation")
        filename = backup_meta["filename"]

        # Mutate local state
        self.test_cfg.write_text(json.dumps({"version": "99.0", "theme": "corrupted"}), encoding="utf-8")
        con = sqlite3.connect(str(self.test_db))
        con.execute("INSERT INTO users (name) VALUES ('attacker');")
        con.commit()
        con.close()

        # Restore
        restore_result = self.manager.restore_backup(filename, actor="tester_restore")
        self.assertTrue(restore_result["restored"])

        # Verify config restored
        restored_cfg = json.loads(self.test_cfg.read_text(encoding="utf-8"))
        self.assertEqual(restored_cfg["version"], "1.0")
        self.assertEqual(restored_cfg["theme"], "dark")

        # Verify database restored
        con = sqlite3.connect(str(self.test_db))
        cur = con.cursor()
        cur.execute("SELECT name FROM users;")
        rows = [r[0] for r in cur.fetchall()]
        con.close()
        self.assertEqual(rows, ["analyst_1"])

    def test_delete_backup(self):
        backup_meta = self.manager.create_backup()
        filename = backup_meta["filename"]
        self.assertTrue((self.backup_dir / filename).exists())

        deleted = self.manager.delete_backup(filename)
        self.assertTrue(deleted)
        self.assertFalse((self.backup_dir / filename).exists())


if __name__ == "__main__":
    unittest.main()
