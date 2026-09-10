from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from platform_core.authorization import (
    BUILTIN_ROLES,
    DataScope,
    SCOPE_HIERARCHY,
    SecurityContext,
    build_security_context,
    clone_role,
    create_custom_role,
    create_group,
    delete_custom_role,
    delete_group,
    evaluate_policy,
    filter_dataset,
    get_all_permissions,
    get_anonymous_context,
    get_builtin_roles,
    get_group_by_id,
    get_my_access_profile,
    get_permission_catalog,
    get_role_by_id,
    get_user_group_ids,
    get_user_profile,
    get_user_shares,
    init_authorization_db,
    is_builtin_role,
    is_shared_with,
    is_valid_permission,
    list_all_groups,
    list_all_roles,
    register_permission,
    revoke_share,
    save_user_profile,
    scope_allows_resource,
    share_resource,
    simulate_user_access,
    storage,
    update_custom_role,
    update_group,
    validate_role_permissions,
)


class TestPermissions(unittest.TestCase):
    def test_permission_catalog_count_and_validity(self):
        perms = get_all_permissions()
        self.assertGreaterEqual(len(perms), 50)
        self.assertTrue(is_valid_permission("incidents.view"))
        self.assertTrue(is_valid_permission("users.manage"))
        self.assertTrue(is_valid_permission("flowscope.view"))
        self.assertFalse(is_valid_permission("non_existent.action"))

    def test_catalog_structure(self):
        catalog = get_permission_catalog()
        self.assertIn("الحوادث الأمنية", catalog)
        self.assertIn("إدارة المستخدمين والأدوار", catalog)
        self.assertIn("FlowScope", catalog)

        # Dynamic registration
        register_permission("custom_tool.execute", "تشغيل أداة مخصصة", group="أدوات خاصة", action="execute")
        self.assertTrue(is_valid_permission("custom_tool.execute"))
        cat_after = get_permission_catalog()
        self.assertIn("أدوات خاصة", cat_after)



class TestScopes(unittest.TestCase):
    def test_scope_hierarchy(self):
        self.assertEqual(SCOPE_HIERARCHY[DataScope.OWN.value], 1)
        self.assertEqual(SCOPE_HIERARCHY[DataScope.OWN_SHARED.value], 2)
        self.assertEqual(SCOPE_HIERARCHY[DataScope.GROUP.value], 3)
        self.assertEqual(SCOPE_HIERARCHY[DataScope.DEPARTMENT.value], 4)
        self.assertEqual(SCOPE_HIERARCHY[DataScope.ORGANIZATION.value], 5)
        self.assertEqual(SCOPE_HIERARCHY[DataScope.ALL.value], 6)

    def test_scope_allows_resource(self):
        # 1. Own scope
        self.assertTrue(scope_allows_resource(
            user_scope=DataScope.OWN.value,
            user_id="u1",
            username="alice",
            resource_owner_id="u1",
        ))
        self.assertTrue(scope_allows_resource(
            user_scope=DataScope.OWN.value,
            user_id="u1",
            username="alice",
            resource_creator="alice",
        ))
        self.assertFalse(scope_allows_resource(
            user_scope=DataScope.OWN.value,
            user_id="u1",
            username="alice",
            resource_owner_id="u2",
        ))

        # 2. Own + Shared scope
        self.assertTrue(scope_allows_resource(
            user_scope=DataScope.OWN_SHARED.value,
            user_id="u1",
            resource_owner_id="u2",
            is_shared_with_user=True,
        ))
        self.assertFalse(scope_allows_resource(
            user_scope=DataScope.OWN_SHARED.value,
            user_id="u1",
            resource_owner_id="u2",
            is_shared_with_user=False,
        ))

        # 3. Group scope
        self.assertTrue(scope_allows_resource(
            user_scope=DataScope.GROUP.value,
            user_id="u1",
            user_groups=["soc_team", "it_team"],
            resource_group_id="soc_team",
        ))
        self.assertFalse(scope_allows_resource(
            user_scope=DataScope.GROUP.value,
            user_id="u1",
            user_groups=["soc_team"],
            resource_group_id="hr_team",
        ))

        # 4. Department scope
        self.assertTrue(scope_allows_resource(
            user_scope=DataScope.DEPARTMENT.value,
            user_id="u1",
            user_department="SOC",
            resource_department="SOC",
        ))
        self.assertFalse(scope_allows_resource(
            user_scope=DataScope.DEPARTMENT.value,
            user_id="u1",
            user_department="SOC",
            resource_department="Finance",
        ))

        # 5. Organization scope
        self.assertTrue(scope_allows_resource(
            user_scope=DataScope.ORGANIZATION.value,
            user_id="u1",
            resource_owner_id="u99",
        ))

        # 6. ALL scope
        self.assertTrue(scope_allows_resource(
            user_scope=DataScope.ALL.value,
            user_id="u1",
        ))


class TestRoles(unittest.TestCase):
    def test_builtin_roles(self):
        roles = get_builtin_roles()
        expected = ["viewer", "analyst", "security_analyst", "operator", "supervisor", "administrator"]
        for r in expected:
            self.assertIn(r, roles)
            self.assertTrue(is_builtin_role(r))

        # Check permissions validity
        for r_id, r_def in roles.items():
            valid = validate_role_permissions(r_def["permissions"])
            self.assertEqual(len(valid), len(r_def["permissions"]), f"Role {r_id} has invalid permissions")

        # Administrator has all permissions
        admin_perms = roles["administrator"]["permissions"]
        self.assertEqual(admin_perms, get_all_permissions())


class TestAuthorizationStorage(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db_path = Path(self.directory.name) / "test_auth.sqlite3"
        storage._PROFILE_CACHE.clear()
        self.patch = patch.object(storage, "DB_PATH", self.db_path)
        self.patch.start()
        init_authorization_db()

    def tearDown(self):
        self.patch.stop()
        storage._PROFILE_CACHE.clear()
        self.directory.cleanup()

    def test_database_initialization_seeds_groups(self):
        groups = list_all_groups()
        group_names = [g["name"] for g in groups]
        self.assertIn("soc_team", group_names)
        self.assertIn("security_team", group_names)
        self.assertIn("it_team", group_names)
        self.assertIn("management", group_names)

    def test_custom_roles_crud_and_cloning(self):
        # Create custom role
        role = create_custom_role(
            name="custom_auditor",
            label_ar="مدقق مخصص",
            description="دور تدقيق مخصص",
            default_scope="organization",
            permissions=["incidents.view", "platform_logs.view_all"],
        )
        role_id = role["id"]
        self.assertTrue(role_id.startswith("custom_"))
        self.assertFalse(is_builtin_role(role_id))

        # Cannot create duplicate name
        with self.assertRaises(ValueError):
            create_custom_role(name="custom_auditor", label_ar="مكرر", permissions=["incidents.view"])

        # Update role
        updated = update_custom_role(role_id, label_ar="مدقق مالي مخصص", permissions=["incidents.view"])
        self.assertEqual(updated["label_ar"], "مدقق مالي مخصص")
        self.assertEqual(updated["permissions"], ["incidents.view"])

        # Clone role
        cloned = clone_role(
            source_role_id=role_id,
            new_name="cloned_auditor",
            new_label_ar="مدقق مستنسخ",
        )
        cloned_id = cloned["id"]
        self.assertEqual(cloned["label_ar"], "مدقق مستنسخ")
        self.assertEqual(cloned["permissions"], ["incidents.view"])

        # Cannot delete builtin role
        with self.assertRaises(ValueError):
            delete_custom_role("administrator")

        # Delete custom role
        delete_custom_role(role_id)
        self.assertIsNone(get_role_by_id(role_id))

    def test_groups_and_membership(self):
        # Create custom group
        grp = create_group(
            name="forensics_unit",
            label_ar="وحدة الأدلة الجنائية",
            description="وحدة التحقيق الجنائي",
            roles=["security_analyst"],
            default_scope="group",
            department="الأمن السيبراني",
            members=["user_101", "user_102"],
        )
        grp_id = grp["id"]
        self.assertEqual(grp["name"], "forensics_unit")

        # Check members
        self.assertIn(grp_id, get_user_group_ids("user_101"))
        self.assertIn(grp_id, get_user_group_ids("user_102"))

        # Update group
        update_group(grp_id, label_ar="وحدة الفحص الجنائي المتقدم", members=["user_101"])
        refetched = get_group_by_id(grp_id)
        self.assertEqual(refetched["label_ar"], "وحدة الفحص الجنائي المتقدم")
        self.assertEqual(refetched["members"], ["user_101"])

        # Delete group
        delete_group(grp_id)
        self.assertNotIn(grp_id, get_user_group_ids("user_101"))

    def test_user_profiles(self):
        profile = save_user_profile(
            user_id="usr_test",
            role_id="security_analyst",
            data_scope="group",
            department="SOC",
            custom_permissions=["flowscope.analyze"],
        )
        self.assertEqual(profile["role_id"], "security_analyst")
        self.assertEqual(profile["data_scope"], "group")
        self.assertIn("flowscope.analyze", profile["custom_permissions"])

        cached = get_user_profile("usr_test")
        self.assertEqual(cached["department"], "SOC")

    def test_resource_sharing_and_ttl(self):
        # Share resource with user
        share = share_resource(
            resource_type="incidents",
            resource_id="INC-9999",
            shared_by="admin",
            grantee_type="user",
            grantee_id="alice",
            permissions=["view", "edit"],
        )
        self.assertIsNotNone(share["id"])

        self.assertTrue(is_shared_with("incidents", "INC-9999", user_id="alice", required_permission="view"))
        self.assertTrue(is_shared_with("incidents", "INC-9999", user_id="alice", required_permission="edit"))
        self.assertFalse(is_shared_with("incidents", "INC-9999", user_id="alice", required_permission="delete"))
        self.assertFalse(is_shared_with("incidents", "INC-9999", user_id="bob", required_permission="view"))

        # Revoke share
        revoke_share(share["id"])
        self.assertFalse(is_shared_with("incidents", "INC-9999", user_id="alice", required_permission="view"))

        # Test TTL expiration
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        share_resource(
            resource_type="incidents",
            resource_id="INC-EXPIRED",
            shared_by="admin",
            grantee_type="user",
            grantee_id="alice",
            permissions=["view"],
            expires_at=past,
        )
        # Because it is expired, is_shared_with must return False
        self.assertFalse(is_shared_with("incidents", "INC-EXPIRED", user_id="alice"))



class TestPoliciesAndAccessControl(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db_path = Path(self.directory.name) / "test_auth.sqlite3"
        storage._PROFILE_CACHE.clear()
        self.patch = patch.object(storage, "DB_PATH", self.db_path)
        self.patch.start()
        init_authorization_db()

    def tearDown(self):
        self.patch.stop()
        storage._PROFILE_CACHE.clear()
        self.directory.cleanup()

    def test_deny_by_default(self):
        # Anonymous context
        anon = get_anonymous_context()
        decision = evaluate_policy(anon, "incidents.view")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "unauthenticated")

        # Inactive user
        user_inactive = SecurityContext(
            user_id="u_off",
            username="disabled_user",
            display_name="معطل",
            is_authenticated=True,
            is_active=False,
            role_id="analyst",
            role_name="analyst",
            role_label_ar="محلل",
            data_scope="own",
            department="SOC",
            groups=[],
            custom_permissions=[],
            effective_permissions={"incidents.view"},
        )
        dec_inactive = evaluate_policy(user_inactive, "incidents.view")
        self.assertFalse(dec_inactive.allowed)
        self.assertEqual(dec_inactive.code, "account_disabled")

        # Missing permission
        user_no_perm = SecurityContext(
            user_id="u_view",
            username="viewer",
            display_name="مشاهد",
            is_authenticated=True,
            is_active=True,
            role_id="viewer",
            role_name="viewer",
            role_label_ar="مشاهد",
            data_scope="all",
            department="IT",
            groups=[],
            custom_permissions=[],
            effective_permissions={"portal.access", "incidents.view"},
        )
        dec_forbidden = evaluate_policy(user_no_perm, "incidents.delete")
        self.assertFalse(dec_forbidden.allowed)
        self.assertEqual(dec_forbidden.code, "permission_denied")

    def test_idor_protection_on_isolated_incident(self):
        user = SecurityContext(
            user_id="analyst_1",
            username="analyst_1",
            display_name="محلل 1",
            is_authenticated=True,
            is_active=True,
            role_id="analyst",
            role_name="analyst",
            role_label_ar="محلل",
            data_scope="own",
            department="SOC",
            groups=[],
            custom_permissions=[],
            effective_permissions={"incidents.view"},
        )

        # Incident belonging to someone else
        foreign_incident = {
            "id": "INC-SECRET-777",
            "owner_id": "analyst_2",
            "created_by": "analyst_2",
            "department": "Finance",
        }

        decision = evaluate_policy(
            user,
            action="incidents.view",
            resource_type="incidents",
            resource_data=foreign_incident,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "scope_violation")

        # Incident belonging to analyst_1
        own_incident = {
            "id": "INC-OWN-111",
            "owner_id": "analyst_1",
            "created_by": "analyst_1",
            "department": "SOC",
        }
        dec_own = evaluate_policy(
            user,
            action="incidents.view",
            resource_type="incidents",
            resource_data=own_incident,
        )
        self.assertTrue(dec_own.allowed)

    def test_dataset_filtering(self):
        user = SecurityContext(
            user_id="analyst_1",
            username="analyst_1",
            display_name="محلل 1",
            is_authenticated=True,
            is_active=True,
            role_id="analyst",
            role_name="analyst",
            role_label_ar="محلل",
            data_scope="own",
            department="SOC",
            groups=[],
            custom_permissions=[],
            effective_permissions={"incidents.view"},
        )

        dataset = [
            {"id": "1", "owner_id": "analyst_1", "title": "Own 1"},
            {"id": "2", "owner_id": "analyst_2", "title": "Other 2"},
            {"id": "3", "owner_id": "analyst_1", "title": "Own 3"},
        ]

        filtered = filter_dataset(user, dataset, resource_type="incidents")
        self.assertEqual(len(filtered), 2)
        self.assertEqual([i["id"] for i in filtered], ["1", "3"])

    def test_my_access_profile(self):
        user = SecurityContext(
            user_id="u_prof",
            username="profile_user",
            display_name="مستخدم الحساب",
            is_authenticated=True,
            is_active=True,
            role_id="analyst",
            role_name="analyst",
            role_label_ar="محلل",
            data_scope="own_shared",
            department="SOC",
            groups=["soc_team"],
            custom_permissions=["flowscope.export"],
            effective_permissions={"incidents.view", "flowscope.export"},
        )

        profile = get_my_access_profile(user)
        self.assertTrue(profile["authenticated"])
        self.assertEqual(profile["username"], "profile_user")
        self.assertEqual(profile["data_scope"], "own_shared")
        self.assertIn("flowscope.export", profile["effective_permissions"])

    def test_simulate_user_access_permission_check(self):
        # Non-admin context trying to simulate access should be denied
        analyst = SecurityContext(
            user_id="u_ana",
            username="analyst_joe",
            display_name="محلل",
            is_authenticated=True,
            is_active=True,
            role_id="analyst",
            role_name="analyst",
            role_label_ar="محلل",
            data_scope="own",
            department="SOC",
            groups=[],
            custom_permissions=[],
            effective_permissions={"incidents.view"},
        )
        from platform_core.authorization import AuthorizationError
        with self.assertRaises(AuthorizationError):
            simulate_user_access(analyst, "target_user_id")


if __name__ == "__main__":
    unittest.main()
