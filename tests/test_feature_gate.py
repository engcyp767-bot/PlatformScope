"""Tests for Feature Gate system."""

from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from platform_core.feature_gate import (
    FEATURE_REGISTRY,
    EditionTier,
    FeatureGate,
    FeatureNotAvailableError,
    FeatureSpec,
    GateDenial,
    UsageTracker,
    _edition_tier,
    check_quota_or_deny,
    gate,
    require_edition,
    require_feature,
)
from platform_core.licensing.models import (
    Entitlements,
    LicenseInfo,
    LicenseState,
    LicenseType,
    PlatformEdition,
)


def _make_license_info(edition: PlatformEdition, is_valid: bool = True) -> LicenseInfo:
    return LicenseInfo(
        state=LicenseState.LICENSE_ACTIVE if is_valid else LicenseState.TRIAL_EXPIRED,
        license_type=LicenseType.SUBSCRIPTION,
        product="PlatformScope",
        edition=edition,
        installation_id="test-install-id",
        instance_id="test-instance-id",
        start_utc="2026-01-01T00:00:00Z",
        expires_utc="2027-01-01T00:00:00Z",
        days_remaining=365,
        grace_days=0,
        entitlements=Entitlements(),
        is_valid=is_valid,
    )


class TestEditionTier(unittest.TestCase):
    def test_tier_ordering(self):
        self.assertLess(EditionTier.COMMUNITY, EditionTier.STANDARD)
        self.assertLess(EditionTier.STANDARD, EditionTier.PROFESSIONAL)
        self.assertLess(EditionTier.PROFESSIONAL, EditionTier.ENTERPRISE)

    def test_edition_to_tier_mapping(self):
        self.assertEqual(_edition_tier(PlatformEdition.COMMUNITY), EditionTier.COMMUNITY)
        self.assertEqual(_edition_tier(PlatformEdition.ENTERPRISE), EditionTier.ENTERPRISE)


class TestFeatureRegistry(unittest.TestCase):
    def test_registry_not_empty(self):
        self.assertGreater(len(FEATURE_REGISTRY), 0)

    def test_core_features_registered(self):
        core_features = ["flowscope", "logscope", "threatscope", "sigma_rules",
                         "incidents", "ai_analysis", "correlation", "endpointscope"]
        for feat in core_features:
            self.assertIn(feat, FEATURE_REGISTRY, f"Feature '{feat}' not registered")

    def test_feature_spec_has_required_fields(self):
        for name, spec in FEATURE_REGISTRY.items():
            self.assertTrue(spec.display_name_ar, f"{name}: missing Arabic name")
            self.assertTrue(spec.display_name_en, f"{name}: missing English name")
            self.assertIsInstance(spec.min_edition, PlatformEdition, f"{name}: bad min_edition")

    def test_community_features_exist(self):
        community_features = [
            name for name, spec in FEATURE_REGISTRY.items()
            if spec.min_edition == PlatformEdition.COMMUNITY
        ]
        self.assertGreater(len(community_features), 3, "Too few Community features")

    def test_endpointscope_requires_professional(self):
        spec = FEATURE_REGISTRY.get("endpointscope")
        self.assertIsNotNone(spec)
        self.assertEqual(spec.min_edition, PlatformEdition.PROFESSIONAL)


class TestUsageTracker(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test_usage.sqlite3"
        self.tracker = UsageTracker(self.db_path)

    def test_increment_and_get(self):
        result = self.tracker.increment("flowscope", 5)
        self.assertEqual(result, 5)
        self.assertEqual(self.tracker.get_count("flowscope"), 5)

    def test_multiple_increments(self):
        self.tracker.increment("logscope", 10)
        self.tracker.increment("logscope", 20)
        self.assertEqual(self.tracker.get_count("logscope"), 30)

    def test_separate_features(self):
        self.tracker.increment("flowscope", 100)
        self.tracker.increment("logscope", 200)
        self.assertEqual(self.tracker.get_count("flowscope"), 100)
        self.assertEqual(self.tracker.get_count("logscope"), 200)

    def test_get_all_usage(self):
        self.tracker.increment("flowscope", 10)
        self.tracker.increment("logscope", 20)
        usage = self.tracker.get_all_usage()
        self.assertEqual(usage.get("flowscope"), 10)
        self.assertEqual(usage.get("logscope"), 20)

    def test_reset(self):
        self.tracker.increment("flowscope", 100)
        self.tracker.reset("flowscope")
        self.assertEqual(self.tracker.get_count("flowscope"), 0)

    def test_thread_safety(self):
        errors = []
        def inc():
            try:
                for _ in range(100):
                    self.tracker.increment("concurrent_test", 1)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=inc) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(self.tracker.get_count("concurrent_test"), 500)


class TestFeatureGate(unittest.TestCase):
    def setUp(self):
        FeatureGate.reset_instance()
        self.tmpdir = tempfile.mkdtemp()
        self.storage = Path(self.tmpdir) / "storage"
        self.storage.mkdir()

    def _make_gate(self, edition: PlatformEdition) -> FeatureGate:
        gate_instance = FeatureGate(self.storage)
        mock_info = _make_license_info(edition)
        gate_instance._license_manager = MagicMock()
        gate_instance._license_manager.get_info.return_value = mock_info
        return gate_instance

    def test_community_can_access_flowscope(self):
        g = self._make_gate(PlatformEdition.COMMUNITY)
        denial = g.check_feature("flowscope")
        self.assertIsNone(denial)

    def test_community_cannot_access_ai_analysis(self):
        g = self._make_gate(PlatformEdition.COMMUNITY)
        denial = g.check_feature("ai_analysis")
        self.assertIsNotNone(denial)
        self.assertEqual(denial.reason, "edition_too_low")
        self.assertEqual(denial.required_edition, PlatformEdition.STANDARD)

    def test_community_cannot_access_endpointscope(self):
        g = self._make_gate(PlatformEdition.COMMUNITY)
        denial = g.check_feature("endpointscope")
        self.assertIsNotNone(denial)
        self.assertEqual(denial.required_edition, PlatformEdition.PROFESSIONAL)

    def test_professional_can_access_endpointscope(self):
        g = self._make_gate(PlatformEdition.PROFESSIONAL)
        denial = g.check_feature("endpointscope")
        self.assertIsNone(denial)

    def test_enterprise_can_access_everything(self):
        g = self._make_gate(PlatformEdition.ENTERPRISE)
        for name in FEATURE_REGISTRY:
            denial = g.check_feature(name)
            self.assertIsNone(denial, f"Enterprise denied access to {name}")

    def test_standard_can_access_correlation(self):
        g = self._make_gate(PlatformEdition.STANDARD)
        denial = g.check_feature("correlation")
        self.assertIsNone(denial)

    def test_community_cannot_access_multi_tenant(self):
        g = self._make_gate(PlatformEdition.COMMUNITY)
        denial = g.check_feature("multi_tenant")
        self.assertIsNotNone(denial)

    def test_unknown_feature_allowed(self):
        g = self._make_gate(PlatformEdition.COMMUNITY)
        denial = g.check_feature("nonexistent_feature")
        self.assertIsNone(denial)

    def test_is_feature_allowed_shortcut(self):
        g = self._make_gate(PlatformEdition.COMMUNITY)
        self.assertTrue(g.is_feature_allowed("flowscope"))
        self.assertFalse(g.is_feature_allowed("ai_analysis"))

    def test_quota_enforcement(self):
        g = self._make_gate(PlatformEdition.COMMUNITY)
        # Community limit for flowscope is 1000
        denial = g.check_quota("flowscope", 500)
        self.assertIsNone(denial)

        # Record 900 events
        g.record_usage("flowscope", 900)

        # Now trying 200 more should exceed quota (900 + 200 > 1000)
        denial = g.check_quota("flowscope", 200)
        self.assertIsNotNone(denial)
        self.assertEqual(denial.reason, "daily_quota_exceeded")

    def test_item_limit_enforcement(self):
        g = self._make_gate(PlatformEdition.COMMUNITY)
        # Community limit for incidents is 10
        denial = g.check_item_limit("incidents", 9)
        self.assertIsNone(denial)

        denial = g.check_item_limit("incidents", 10)
        self.assertIsNotNone(denial)
        self.assertEqual(denial.reason, "item_limit_reached")

    def test_gate_denial_to_dict(self):
        denial = GateDenial(
            feature="ai_analysis",
            reason="edition_too_low",
            reason_ar="يتطلب طبعة Standard",
            reason_en="Requires Standard edition",
            required_edition=PlatformEdition.STANDARD,
            current_edition=PlatformEdition.COMMUNITY,
        )
        d = denial.to_dict()
        self.assertFalse(d["allowed"])
        self.assertEqual(d["feature"], "ai_analysis")
        self.assertEqual(d["required_edition"], "Standard")

    def test_usage_summary(self):
        g = self._make_gate(PlatformEdition.STANDARD)
        g.record_usage("flowscope", 50)
        summary = g.get_usage_summary()
        self.assertEqual(summary["edition"], "Standard")
        self.assertIn("flowscope", summary["features"])
        self.assertEqual(summary["features"]["flowscope"]["daily_usage"], 50)

    def test_edition_comparison(self):
        g = self._make_gate(PlatformEdition.STANDARD)
        comparison = g.get_edition_comparison()
        self.assertEqual(len(comparison), 4)
        edition_names = [e["edition"] for e in comparison]
        self.assertIn("Community", edition_names)
        self.assertIn("Enterprise", edition_names)


class TestDecorators(unittest.TestCase):
    def setUp(self):
        FeatureGate.reset_instance()
        self.tmpdir = tempfile.mkdtemp()
        self.storage = Path(self.tmpdir) / "storage"
        self.storage.mkdir()

    def _setup_gate(self, edition: PlatformEdition) -> None:
        g = FeatureGate(self.storage)
        mock_info = _make_license_info(edition)
        g._license_manager = MagicMock()
        g._license_manager.get_info.return_value = mock_info
        FeatureGate._instance = g

    def test_require_feature_allows(self):
        self._setup_gate(PlatformEdition.ENTERPRISE)

        @require_feature("ai_analysis")
        def my_func():
            return "success"

        result = my_func()
        self.assertEqual(result, "success")

    def test_require_feature_denies(self):
        self._setup_gate(PlatformEdition.COMMUNITY)

        @require_feature("ai_analysis")
        def my_func():
            return "success"

        with self.assertRaises(FeatureNotAvailableError) as ctx:
            my_func()
        self.assertEqual(ctx.exception.denial.reason, "edition_too_low")

    def test_require_edition_allows(self):
        self._setup_gate(PlatformEdition.PROFESSIONAL)

        @require_edition(PlatformEdition.STANDARD)
        def my_func():
            return "ok"

        self.assertEqual(my_func(), "ok")

    def test_require_edition_denies(self):
        self._setup_gate(PlatformEdition.COMMUNITY)

        @require_edition(PlatformEdition.PROFESSIONAL)
        def my_func():
            return "ok"

        with self.assertRaises(FeatureNotAvailableError):
            my_func()

    def test_decorator_preserves_function_name(self):
        self._setup_gate(PlatformEdition.ENTERPRISE)

        @require_feature("flowscope")
        def analyze_flow():
            """Docstring."""
            pass

        self.assertEqual(analyze_flow.__name__, "analyze_flow")
        self.assertEqual(analyze_flow.__doc__, "Docstring.")


if __name__ == "__main__":
    unittest.main()
