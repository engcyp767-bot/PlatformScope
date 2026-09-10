from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from platform_core import security_auth


class SecurityAuthTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.auth_file = Path(self.directory.name) / "auth.json"
        security_auth._CONFIG = None
        security_auth._CONFIG_MTIME_NS = 0
        self.patches = [
            patch.object(security_auth, "AUTH_FILE", self.auth_file),
            patch.dict("os.environ", {"SECURITY_USERNAME": "analyst", "SECURITY_PASSWORD": "StrongPass!42"}),
        ]
        for active_patch in self.patches:
            active_patch.start()

    def tearDown(self):
        security_auth._CONFIG = None
        security_auth._CONFIG_MTIME_NS = 0
        for active_patch in reversed(self.patches):
            active_patch.stop()
        self.directory.cleanup()

    def test_credentials_are_hashed_and_sessions_are_signed(self):
        self.assertTrue(security_auth.verify_credentials("analyst", "StrongPass!42"))
        self.assertFalse(security_auth.verify_credentials("analyst", "wrong"))
        self.assertNotIn("StrongPass!42", self.auth_file.read_text(encoding="utf-8"))
        token = security_auth.create_session("analyst")
        self.assertEqual(security_auth.verify_session(token), "analyst")
        self.assertIsNone(security_auth.verify_session(token + "tampered"))

    def test_multiple_users_permissions_and_session_invalidation(self):
        user = security_auth.create_user("operator", "AnotherPass!84", "Operator", ["portal.access", "flowscope.view"])
        self.assertTrue(security_auth.verify_credentials("operator", "AnotherPass!84"))
        self.assertEqual(user["permissions"], ["portal.access", "flowscope.view"])
        token = security_auth.create_session("operator")
        security_auth.update_user(user["id"], password="ChangedPass!96")
        self.assertIsNone(security_auth.verify_session(token))
        self.assertTrue(security_auth.verify_credentials("operator", "ChangedPass!96"))

    def test_last_administrator_cannot_be_disabled_or_deleted(self):
        admin = security_auth.list_users()[0]
        with self.assertRaises(ValueError):
            security_auth.update_user(admin["id"], permissions=["portal.access"])
        with self.assertRaises(ValueError):
            security_auth.delete_user(admin["id"])

    def test_own_account_can_change_username_and_password(self):
        updated = security_auth.update_own_account("analyst", "StrongPass!42", "analyst2", "NewStrong!55", "Lead Analyst")
        self.assertEqual(updated["username"], "analyst2")
        self.assertTrue(security_auth.verify_credentials("analyst2", "NewStrong!55"))


if __name__ == "__main__":
    unittest.main()
