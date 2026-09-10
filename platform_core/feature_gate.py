"""Platform Scope — Central Feature Gate & Edition-Based Access Control.

Enforces feature availability, usage quotas, and rate limits based on
the active license edition (Community / Standard / Professional / Enterprise).

Architecture:
    LicenseManager → FeatureGate → @require_feature / @require_edition decorators
    
    Every module call passes through the gate which checks:
    1. Is the feature enabled for the current edition?
    2. Has the daily/monthly quota been exceeded?
    3. Is the rate limit respected?
    
Usage:
    from platform_core.feature_gate import require_feature, require_edition, gate

    @require_feature("ai_analysis")
    def run_ai_copilot(query): ...

    @require_edition(PlatformEdition.PROFESSIONAL)
    def export_forensic_case(incident_id): ...

    # Manual check
    if gate().is_feature_allowed("correlation"):
        run_correlation()
"""

from __future__ import annotations

import functools
import logging
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union

from platform_core.licensing.models import (
    Entitlements,
    LicenseState,
    LicenseType,
    PlatformEdition,
)

logger = logging.getLogger("platform.feature_gate")

F = TypeVar("F", bound=Callable[..., Any])


class FeatureID(str, Enum):
    """Enumeration of known platform feature identifiers."""
    FLOWSCOPE = "flowscope"
    LOGSCOPE = "logscope"
    THREATSCOPE = "threatscope"
    ENDPOINTSCOPE = "endpointscope"
    ENDPOINTS_BASIC = "endpointscope"
    SIGMA_RULES = "sigma_rules"
    CUSTOM_DETECTIONS = "custom_detections"
    CORRELATION = "correlation"
    DETECTION_CORRELATION = "detection_correlation"
    AI_ANALYSIS = "ai_analysis"
    THREAT_INTEL = "threat_intel"
    LEARNING_ENGINE = "learning_engine"
    INCIDENTS = "incidents"
    INVESTIGATIONS = "investigations"
    CASE_EXPORT = "case_export"
    MULTI_TENANT = "multi_tenant"
    RBAC_ADVANCED = "rbac_advanced"
    ENTERPRISE_REPORTS = "enterprise_reports"
    BACKUP_RESTORE = "backup_restore"
    API_ACCESS = "api_access"
    PLUGINS = "plugins"
    RESPONSE_AUTOMATION = "case_export"
    AIRGAP_MODE = "multi_tenant"
    COMPLIANCESCOPE = "compliancescope"
    COMPLIANCE = "compliancescope"
    MAILSCOPE = "mailscope"


# ---------------------------------------------------------------------------
# Edition Hierarchy (for comparison: COMMUNITY < STANDARD < PROFESSIONAL < ENTERPRISE)
# ---------------------------------------------------------------------------

class EditionTier(IntEnum):
    """Numeric tier for edition comparison."""
    COMMUNITY = 0
    STANDARD = 1
    PROFESSIONAL = 2
    ENTERPRISE = 3


_EDITION_TO_TIER: dict[PlatformEdition, EditionTier] = {
    PlatformEdition.COMMUNITY: EditionTier.COMMUNITY,
    PlatformEdition.STANDARD: EditionTier.STANDARD,
    PlatformEdition.PROFESSIONAL: EditionTier.PROFESSIONAL,
    PlatformEdition.ENTERPRISE: EditionTier.ENTERPRISE,
}


def _edition_tier(edition: PlatformEdition) -> EditionTier:
    return _EDITION_TO_TIER.get(edition, EditionTier.COMMUNITY)


# ---------------------------------------------------------------------------
# Feature Definitions per Edition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FeatureSpec:
    """Defines a gated feature with its availability and limits per edition."""
    name: str
    display_name_ar: str
    display_name_en: str
    description_ar: str
    description_en: str
    # Minimum edition required (features available at this tier and above)
    min_edition: PlatformEdition
    # Per-edition daily event/action limits (None = unlimited)
    daily_limits: dict[PlatformEdition, Optional[int]] = field(default_factory=dict)
    # Per-edition monthly limits (None = unlimited)
    monthly_limits: dict[PlatformEdition, Optional[int]] = field(default_factory=dict)
    # Per-edition max concurrent items (None = unlimited)
    max_items: dict[PlatformEdition, Optional[int]] = field(default_factory=dict)
    # Category for UI grouping
    category: str = "core"


# Master Feature Registry — single source of truth for all gated features
FEATURE_REGISTRY: dict[str, FeatureSpec] = {}


def _register(spec: FeatureSpec) -> FeatureSpec:
    FEATURE_REGISTRY[spec.name] = spec
    return spec


# ── Core Analysis Modules ─────────────────────────────────────────────────

_register(FeatureSpec(
    name="flowscope",
    display_name_ar="تحليل حركة الشبكة",
    display_name_en="FlowScope — Network Traffic Analysis",
    description_ar="تحليل ملفات PCAP وNetFlow وZeek للكشف عن الشذوذ في حركة الشبكة",
    description_en="Analyze PCAP, NetFlow, and Zeek files for network anomaly detection",
    min_edition=PlatformEdition.COMMUNITY,
    daily_limits={
        PlatformEdition.COMMUNITY: 1_000,
        PlatformEdition.STANDARD: 100_000,
        PlatformEdition.PROFESSIONAL: 1_000_000,
        PlatformEdition.ENTERPRISE: None,  # unlimited
    },
    category="analysis",
))

_register(FeatureSpec(
    name="logscope",
    display_name_ar="تحليل السجلات الأمنية",
    display_name_en="LogScope — Security Log Analysis",
    description_ar="تحليل سجلات Windows وLinux وSyslog للكشف عن التهديدات",
    description_en="Analyze Windows, Linux, and Syslog logs for threat detection",
    min_edition=PlatformEdition.COMMUNITY,
    daily_limits={
        PlatformEdition.COMMUNITY: 1_000,
        PlatformEdition.STANDARD: 100_000,
        PlatformEdition.PROFESSIONAL: 1_000_000,
        PlatformEdition.ENTERPRISE: None,
    },
    category="analysis",
))

_register(FeatureSpec(
    name="threatscope",
    display_name_ar="تحليل مؤشرات التهديد",
    display_name_en="ThreatScope — Threat Indicator Analysis",
    description_ar="تحليل مؤشرات الاختراق والملفات المشبوهة",
    description_en="Analyze IOCs and suspicious files for threat assessment",
    min_edition=PlatformEdition.COMMUNITY,
    daily_limits={
        PlatformEdition.COMMUNITY: 500,
        PlatformEdition.STANDARD: 50_000,
        PlatformEdition.PROFESSIONAL: 500_000,
        PlatformEdition.ENTERPRISE: None,
    },
    category="analysis",
))

_register(FeatureSpec(
    name="endpointscope",
    display_name_ar="مراقبة نقاط النهاية",
    display_name_en="EndpointScope — Endpoint Detection & Response",
    description_ar="مراقبة مستمرة لنقاط النهاية وكشف التهديدات في الوقت الحقيقي",
    description_en="Continuous endpoint monitoring and real-time threat detection",
    min_edition=PlatformEdition.PROFESSIONAL,
    max_items={
        PlatformEdition.PROFESSIONAL: 500,
        PlatformEdition.ENTERPRISE: None,
    },
    category="analysis",
))

_register(FeatureSpec(
    name="compliancescope",
    display_name_ar="إدارة الامتثال والضوابط السيبرانية",
    display_name_en="ComplianceScope — Regulatory Compliance Management",
    description_ar="تقييم وإدارة الامتثال لأطر NCA ECC وSAMA CSF وPDPL وISO 27001",
    description_en="Automated compliance assessment for NCA ECC, SAMA CSF, PDPL, and ISO 27001",
    min_edition=PlatformEdition.PROFESSIONAL,
    category="governance",
))

_register(FeatureSpec(
    name="mailscope",
    display_name_ar="التحليل الجنائي للبريد والتصيد والاحتيال",
    display_name_en="MailScope — Email Forensics & Phishing Defense",
    description_ar="تحليل عميق لرسائل البريد وفحص SPF/DKIM/DMARC واكتشاف احتيال BEC وانتحال الهوية",
    description_en="Deep RFC 822 email forensics, SPF/DKIM/DMARC validation, BEC impersonation detection, and phishing triage",
    min_edition=PlatformEdition.COMMUNITY,
    daily_limits={
        PlatformEdition.COMMUNITY: 50,
        PlatformEdition.STANDARD: 2_000,
        PlatformEdition.PROFESSIONAL: 50_000,
        PlatformEdition.ENTERPRISE: None,
    },
    category="analysis",
))

# ── Detection & Correlation ───────────────────────────────────────────────

_register(FeatureSpec(
    name="sigma_rules",
    display_name_ar="قواعد Sigma",
    display_name_en="Sigma Detection Rules",
    description_ar="محرك قواعد Sigma العالمي للكشف عن التهديدات",
    description_en="Global Sigma rules engine for threat detection",
    min_edition=PlatformEdition.COMMUNITY,
    max_items={
        PlatformEdition.COMMUNITY: 50,      # builtin only
        PlatformEdition.STANDARD: 150,       # builtin + 100 custom
        PlatformEdition.PROFESSIONAL: None,  # unlimited
        PlatformEdition.ENTERPRISE: None,
    },
    category="detection",
))

_register(FeatureSpec(
    name="custom_detections",
    display_name_ar="قواعد كشف مخصصة",
    display_name_en="Custom Detection Rules",
    description_ar="إنشاء وإدارة قواعد كشف مخصصة",
    description_en="Create and manage custom detection rules",
    min_edition=PlatformEdition.STANDARD,
    max_items={
        PlatformEdition.STANDARD: 100,
        PlatformEdition.PROFESSIONAL: None,
        PlatformEdition.ENTERPRISE: None,
    },
    category="detection",
))

_register(FeatureSpec(
    name="correlation",
    display_name_ar="الارتباط الرسومي وسلاسل الهجوم",
    display_name_en="Graph Correlation & Attack Chains",
    description_ar="كشف سلاسل الهجوم والحركة الجانبية عبر الرسم البياني الأمني",
    description_en="Attack chain detection and lateral movement via security graph",
    min_edition=PlatformEdition.STANDARD,
    category="detection",
))

_register(FeatureSpec(
    name="detection_correlation",
    display_name_ar="ارتباط قواعد الكشف",
    display_name_en="Detection Rule Correlation",
    description_ar="ربط قواعد الكشف المتعددة لتحديد أنماط الهجوم المعقدة",
    description_en="Cross-correlate multiple detection rules for complex attack patterns",
    min_edition=PlatformEdition.STANDARD,
    category="detection",
))

# ── AI & Intelligence ─────────────────────────────────────────────────────

_register(FeatureSpec(
    name="ai_analysis",
    display_name_ar="المساعد الأمني الذكي",
    display_name_en="AI Security Copilot",
    description_ar="مساعد ذكاء اصطناعي محلي للتحقيق الجنائي الرقمي",
    description_en="Local AI assistant for digital forensic investigation",
    min_edition=PlatformEdition.STANDARD,
    daily_limits={
        PlatformEdition.STANDARD: 50,        # basic queries
        PlatformEdition.PROFESSIONAL: 500,   # advanced
        PlatformEdition.ENTERPRISE: None,
    },
    category="intelligence",
))

_register(FeatureSpec(
    name="threat_intel",
    display_name_ar="استخبارات التهديدات",
    display_name_en="Threat Intelligence & IOC Management",
    description_ar="إدارة مؤشرات الاختراق وربطها بإطار MITRE ATT&CK",
    description_en="IOC management with MITRE ATT&CK mapping",
    min_edition=PlatformEdition.COMMUNITY,
    max_items={
        PlatformEdition.COMMUNITY: 500,
        PlatformEdition.STANDARD: 10_000,
        PlatformEdition.PROFESSIONAL: 100_000,
        PlatformEdition.ENTERPRISE: None,
    },
    category="intelligence",
))

_register(FeatureSpec(
    name="learning_engine",
    display_name_ar="محرك التعلم السلوكي",
    display_name_en="Behavioral Learning Engine",
    description_ar="تعلم سلوكي محلي لتحسين دقة الكشف",
    description_en="Local behavioral learning to improve detection accuracy",
    min_edition=PlatformEdition.PROFESSIONAL,
    category="intelligence",
))

# ── Incident & Investigation ──────────────────────────────────────────────

_register(FeatureSpec(
    name="incidents",
    display_name_ar="إدارة الحوادث الأمنية",
    display_name_en="Security Incident Management",
    description_ar="إدارة دورة حياة الحوادث الأمنية بالكامل",
    description_en="Full security incident lifecycle management",
    min_edition=PlatformEdition.COMMUNITY,
    max_items={
        PlatformEdition.COMMUNITY: 10,
        PlatformEdition.STANDARD: 500,
        PlatformEdition.PROFESSIONAL: 5_000,
        PlatformEdition.ENTERPRISE: None,
    },
    category="operations",
))

_register(FeatureSpec(
    name="investigations",
    display_name_ar="مساحة عمل التحقيق",
    display_name_en="SOC Investigation Workspace",
    description_ar="مساحة عمل تحقيق أمني تشمل الفرضيات والأدلة والجدول الزمني",
    description_en="Investigation workspace with hypotheses, evidence, and timeline",
    min_edition=PlatformEdition.STANDARD,
    category="operations",
))

_register(FeatureSpec(
    name="case_export",
    display_name_ar="تصدير الحزم الجنائية",
    display_name_en="Forensic Case Export",
    description_ar="تصدير حزم تحقيق جنائية موقّعة رقمياً مع سلسلة الحفظ",
    description_en="Digitally signed forensic case packages with chain of custody",
    min_edition=PlatformEdition.PROFESSIONAL,
    category="operations",
))

# ── Enterprise ─────────────────────────────────────────────────────────────

_register(FeatureSpec(
    name="multi_tenant",
    display_name_ar="تعدد المستأجرين",
    display_name_en="Multi-Tenancy",
    description_ar="فصل كامل للبيانات بين المستأجرين المتعددين",
    description_en="Complete data isolation between multiple tenants",
    min_edition=PlatformEdition.ENTERPRISE,
    category="enterprise",
))

_register(FeatureSpec(
    name="rbac_advanced",
    display_name_ar="صلاحيات متقدمة",
    display_name_en="Advanced RBAC & Policies",
    description_ar="نظام أدوار وصلاحيات متقدم مع سياسات مخصصة",
    description_en="Advanced role-based access control with custom policies",
    min_edition=PlatformEdition.PROFESSIONAL,
    category="enterprise",
))

_register(FeatureSpec(
    name="enterprise_reports",
    display_name_ar="تقارير المؤسسات",
    display_name_en="Enterprise Reports",
    description_ar="تقارير DOCX/XLSX احترافية للإدارة والجهات الرقابية",
    description_en="Professional DOCX/XLSX reports for management and regulators",
    min_edition=PlatformEdition.STANDARD,
    category="enterprise",
))

_register(FeatureSpec(
    name="backup_restore",
    display_name_ar="النسخ الاحتياطي والاستعادة",
    display_name_en="Backup & Disaster Recovery",
    description_ar="نسخ احتياطي مشفر مع تحقق من السلامة واستعادة كاملة",
    description_en="Encrypted backup with integrity verification and full restore",
    min_edition=PlatformEdition.STANDARD,
    category="enterprise",
))

_register(FeatureSpec(
    name="api_access",
    display_name_ar="واجهة API العامة",
    display_name_en="Public REST API Access",
    description_ar="وصول برمجي كامل عبر REST API مع مفاتيح API",
    description_en="Full programmatic access via REST API with API keys",
    min_edition=PlatformEdition.PROFESSIONAL,
    daily_limits={
        PlatformEdition.PROFESSIONAL: 10_000,
        PlatformEdition.ENTERPRISE: None,
    },
    category="enterprise",
))

_register(FeatureSpec(
    name="plugins",
    display_name_ar="نظام الإضافات",
    display_name_en="Plugin System",
    description_ar="تحميل وإدارة إضافات المجتمع والإضافات المخصصة",
    description_en="Load and manage community and custom plugins",
    min_edition=PlatformEdition.STANDARD,
    max_items={
        PlatformEdition.STANDARD: 5,
        PlatformEdition.PROFESSIONAL: 25,
        PlatformEdition.ENTERPRISE: None,
    },
    category="enterprise",
))

# ── Asset Management ───────────────────────────────────────────────────────

_register(FeatureSpec(
    name="assets",
    display_name_ar="إدارة الأصول",
    display_name_en="Asset Intelligence & Inventory",
    description_ar="إدارة جرد الأصول وتقييم المخاطر وعلاقات SOC",
    description_en="Asset inventory, risk scoring, and SOC relationship mesh",
    min_edition=PlatformEdition.COMMUNITY,
    max_items={
        PlatformEdition.COMMUNITY: 25,
        PlatformEdition.STANDARD: 500,
        PlatformEdition.PROFESSIONAL: 5_000,
        PlatformEdition.ENTERPRISE: None,
    },
    category="operations",
))

# ── Users ──────────────────────────────────────────────────────────────────

_register(FeatureSpec(
    name="users",
    display_name_ar="إدارة المستخدمين",
    display_name_en="User Management",
    description_ar="إنشاء وإدارة حسابات المستخدمين",
    description_en="Create and manage user accounts",
    min_edition=PlatformEdition.COMMUNITY,
    max_items={
        PlatformEdition.COMMUNITY: 1,
        PlatformEdition.STANDARD: 5,
        PlatformEdition.PROFESSIONAL: 25,
        PlatformEdition.ENTERPRISE: None,
    },
    category="core",
))


# ---------------------------------------------------------------------------
# Usage Tracker (SQLite-backed daily/monthly counters)
# ---------------------------------------------------------------------------

class UsageTracker:
    """Tracks feature usage counters in SQLite for quota enforcement."""

    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS usage_counters (
                    feature TEXT NOT NULL,
                    period TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    first_used TEXT NOT NULL,
                    last_used TEXT NOT NULL,
                    PRIMARY KEY (feature, period)
                );
            """)
            conn.commit()

    def _period_key(self, granularity: str = "daily") -> str:
        now = datetime.now(timezone.utc)
        if granularity == "monthly":
            return now.strftime("%Y-%m")
        return now.strftime("%Y-%m-%d")

    def increment(self, feature: str, amount: int = 1, granularity: str = "daily") -> int:
        """Increment usage counter and return new total for the period."""
        period = self._period_key(granularity)
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with sqlite3.connect(str(self._db_path)) as conn:
                conn.execute("""
                    INSERT INTO usage_counters (feature, period, count, first_used, last_used)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(feature, period)
                    DO UPDATE SET count = count + ?, last_used = ?;
                """, (feature, period, amount, now_iso, now_iso, amount, now_iso))
                cur = conn.execute(
                    "SELECT count FROM usage_counters WHERE feature = ? AND period = ?;",
                    (feature, period),
                )
                row = cur.fetchone()
                conn.commit()
                return row[0] if row else amount

    def get_count(self, feature: str, granularity: str = "daily") -> int:
        """Get current usage count for a feature in the current period."""
        period = self._period_key(granularity)
        with self._lock:
            with sqlite3.connect(str(self._db_path)) as conn:
                cur = conn.execute(
                    "SELECT count FROM usage_counters WHERE feature = ? AND period = ?;",
                    (feature, period),
                )
                row = cur.fetchone()
                return row[0] if row else 0

    def get_all_usage(self, granularity: str = "daily") -> dict[str, int]:
        """Get all feature usage counts for the current period."""
        period = self._period_key(granularity)
        with self._lock:
            with sqlite3.connect(str(self._db_path)) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.execute(
                    "SELECT feature, count FROM usage_counters WHERE period = ?;",
                    (period,),
                )
                return {row["feature"]: row["count"] for row in cur.fetchall()}

    def reset(self, feature: str, granularity: str = "daily") -> None:
        """Reset usage counter for a feature (admin only)."""
        period = self._period_key(granularity)
        with self._lock:
            with sqlite3.connect(str(self._db_path)) as conn:
                conn.execute(
                    "DELETE FROM usage_counters WHERE feature = ? AND period = ?;",
                    (feature, period),
                )
                conn.commit()


# ---------------------------------------------------------------------------
# Gate Denial Result
# ---------------------------------------------------------------------------

@dataclass
class GateDenial:
    """Structured denial result with localized messages."""
    feature: str
    reason: str
    reason_ar: str
    reason_en: str
    required_edition: PlatformEdition | None = None
    current_edition: PlatformEdition | None = None
    current_usage: int | None = None
    limit: int | None = None
    upgrade_url: str = "/settings#license"

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": False,
            "feature": self.feature,
            "reason": self.reason,
            "reason_ar": self.reason_ar,
            "reason_en": self.reason_en,
            "required_edition": self.required_edition.value if self.required_edition else None,
            "current_edition": self.current_edition.value if self.current_edition else None,
            "current_usage": self.current_usage,
            "limit": self.limit,
            "upgrade_url": self.upgrade_url,
        }


# ---------------------------------------------------------------------------
# FeatureGate — Central Authority
# ---------------------------------------------------------------------------

class FeatureGate:
    """Central feature gating authority.

    Thread-safe singleton that queries the LicenseManager for the current
    edition and enforces feature availability, usage quotas, and rate limits.
    """

    _instance: FeatureGate | None = None
    _init_lock = threading.Lock()

    def __init__(self, storage_dir: Path | None = None):
        from platform_core.licensing import LicenseManager

        root = Path(__file__).resolve().parent.parent
        self._storage_dir = storage_dir or (root / "storage")
        self._usage_db = self._storage_dir / "feature_usage.sqlite3"
        self._tracker = UsageTracker(self._usage_db)
        self._license_manager = LicenseManager.get_instance(self._storage_dir)
        self._rate_limiter: dict[str, float] = {}  # feature -> last_call_ts
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls, storage_dir: Path | None = None) -> FeatureGate:
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls(storage_dir)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton — for testing only."""
        with cls._init_lock:
            cls._instance = None

    def _get_edition(self) -> PlatformEdition:
        """Get current edition from LicenseManager."""
        try:
            info = self._license_manager.get_info()
            if info and info.is_valid:
                return info.edition
        except Exception:
            pass
        return PlatformEdition.COMMUNITY

    def _is_license_valid(self) -> bool:
        """Check if the current license is in a valid state."""
        try:
            info = self._license_manager.get_info()
            return info is not None and info.is_valid
        except Exception:
            return False

    def is_feature_allowed(self, feature_name: str) -> bool:
        """Quick check: is the feature available for the current edition?"""
        result = self.check_feature(feature_name)
        return result is None  # None means allowed

    def check_feature(self, feature_name: str) -> Optional[GateDenial]:
        """Check if a feature is allowed. Returns None if allowed, GateDenial if blocked."""
        spec = FEATURE_REGISTRY.get(feature_name)
        if spec is None:
            # Unknown features are allowed by default (no gate)
            return None

        edition = self._get_edition()
        edition_tier = _edition_tier(edition)
        required_tier = _edition_tier(spec.min_edition)

        # Check edition requirement
        if edition_tier < required_tier:
            return GateDenial(
                feature=feature_name,
                reason="edition_too_low",
                reason_ar=(
                    f"ميزة «{spec.display_name_ar}» تتطلب طبعة {spec.min_edition.value} أو أعلى. "
                    f"طبعتك الحالية: {edition.value}. يرجى الترقية."
                ),
                reason_en=(
                    f"Feature '{spec.display_name_en}' requires {spec.min_edition.value} edition or higher. "
                    f"Your current edition: {edition.value}. Please upgrade."
                ),
                required_edition=spec.min_edition,
                current_edition=edition,
            )

        return None

    def check_quota(self, feature_name: str, increment: int = 1) -> Optional[GateDenial]:
        """Check if the feature's daily quota allows the requested increment."""
        spec = FEATURE_REGISTRY.get(feature_name)
        if spec is None:
            return None

        # First check feature access
        denial = self.check_feature(feature_name)
        if denial:
            return denial

        edition = self._get_edition()

        # Check daily limit
        daily_limit = spec.daily_limits.get(edition)
        if daily_limit is not None:
            current = self._tracker.get_count(feature_name, "daily")
            if current + increment > daily_limit:
                return GateDenial(
                    feature=feature_name,
                    reason="daily_quota_exceeded",
                    reason_ar=(
                        f"تم تجاوز الحد اليومي لميزة «{spec.display_name_ar}» "
                        f"({current:,}/{daily_limit:,}). يرجى الترقية لزيادة الحدود."
                    ),
                    reason_en=(
                        f"Daily quota exceeded for '{spec.display_name_en}' "
                        f"({current:,}/{daily_limit:,}). Upgrade to increase limits."
                    ),
                    current_edition=edition,
                    current_usage=current,
                    limit=daily_limit,
                )

        return None

    def check_item_limit(self, feature_name: str, current_count: int) -> Optional[GateDenial]:
        """Check if the feature's max items limit allows adding more items."""
        spec = FEATURE_REGISTRY.get(feature_name)
        if spec is None:
            return None

        denial = self.check_feature(feature_name)
        if denial:
            return denial

        edition = self._get_edition()
        max_items = spec.max_items.get(edition)

        if max_items is not None and current_count >= max_items:
            return GateDenial(
                feature=feature_name,
                reason="item_limit_reached",
                reason_ar=(
                    f"تم الوصول للحد الأقصى لميزة «{spec.display_name_ar}» "
                    f"({current_count:,}/{max_items:,}). يرجى الترقية لزيادة الحد."
                ),
                reason_en=(
                    f"Item limit reached for '{spec.display_name_en}' "
                    f"({current_count:,}/{max_items:,}). Upgrade to increase the limit."
                ),
                current_edition=edition,
                current_usage=current_count,
                limit=max_items,
            )

        return None

    def record_usage(self, feature_name: str, amount: int = 1) -> int:
        """Record usage of a feature and return the new daily count."""
        return self._tracker.increment(feature_name, amount, "daily")

    def get_usage_summary(self) -> dict[str, Any]:
        """Get a full usage summary for the current period (for dashboards)."""
        edition = self._get_edition()
        daily_usage = self._tracker.get_all_usage("daily")

        summary: dict[str, Any] = {
            "edition": edition.value,
            "edition_tier": _edition_tier(edition).name,
            "features": {},
        }

        for name, spec in FEATURE_REGISTRY.items():
            is_available = _edition_tier(edition) >= _edition_tier(spec.min_edition)
            daily_limit = spec.daily_limits.get(edition)
            item_limit = spec.max_items.get(edition)
            current_daily = daily_usage.get(name, 0)

            summary["features"][name] = {
                "display_name_ar": spec.display_name_ar,
                "display_name_en": spec.display_name_en,
                "category": spec.category,
                "available": is_available,
                "min_edition": spec.min_edition.value,
                "daily_usage": current_daily,
                "daily_limit": daily_limit,
                "daily_remaining": (daily_limit - current_daily) if daily_limit else None,
                "item_limit": item_limit,
            }

        return summary

    def get_edition_comparison(self) -> list[dict[str, Any]]:
        """Get edition comparison data for the upgrade/pricing page."""
        editions = [
            PlatformEdition.COMMUNITY,
            PlatformEdition.STANDARD,
            PlatformEdition.PROFESSIONAL,
            PlatformEdition.ENTERPRISE,
        ]
        current_edition = self._get_edition()

        result = []
        for edition in editions:
            tier = _edition_tier(edition)
            features_list = []
            for name, spec in FEATURE_REGISTRY.items():
                available = tier >= _edition_tier(spec.min_edition)
                daily_limit = spec.daily_limits.get(edition)
                item_limit = spec.max_items.get(edition)
                features_list.append({
                    "name": name,
                    "display_name_ar": spec.display_name_ar,
                    "display_name_en": spec.display_name_en,
                    "category": spec.category,
                    "available": available,
                    "daily_limit": daily_limit,
                    "item_limit": item_limit,
                    "limit_display": (
                        "∞" if (available and daily_limit is None and item_limit is None)
                        else f"{daily_limit:,}/يوم" if daily_limit
                        else f"{item_limit:,} max" if item_limit
                        else "—"
                    ),
                })
            result.append({
                "edition": edition.value,
                "tier": tier.value,
                "is_current": edition == current_edition,
                "features": features_list,
            })

        return result


# ---------------------------------------------------------------------------
# Global accessor
# ---------------------------------------------------------------------------

def gate(storage_dir: Path | None = None) -> FeatureGate:
    """Get the singleton FeatureGate instance."""
    return FeatureGate.get_instance(storage_dir)


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

class FeatureNotAvailableError(Exception):
    """Raised when a gated feature is not available for the current edition."""

    def __init__(self, denial: GateDenial):
        self.denial = denial
        super().__init__(denial.reason_en)


def require_feature(feature_name: str) -> Callable[[F], F]:
    """Decorator that blocks execution if the feature is not available for the current edition.

    Usage:
        @require_feature("ai_analysis")
        def run_copilot_query(query: str) -> dict: ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            denial = gate().check_feature(feature_name)
            if denial:
                raise FeatureNotAvailableError(denial)
            return func(*args, **kwargs)
        return wrapper  # type: ignore[return-value]
    return decorator


def require_edition(min_edition: PlatformEdition) -> Callable[[F], F]:
    """Decorator that blocks execution below a minimum edition tier.

    Usage:
        @require_edition(PlatformEdition.PROFESSIONAL)
        def export_forensic_package(incident_id: str) -> bytes: ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            current = gate()._get_edition()
            if _edition_tier(current) < _edition_tier(min_edition):
                denial = GateDenial(
                    feature=func.__name__,
                    reason="edition_too_low",
                    reason_ar=f"هذه الوظيفة تتطلب طبعة {min_edition.value} أو أعلى.",
                    reason_en=f"This function requires {min_edition.value} edition or higher.",
                    required_edition=min_edition,
                    current_edition=current,
                )
                raise FeatureNotAvailableError(denial)
            return func(*args, **kwargs)
        return wrapper  # type: ignore[return-value]
    return decorator


def check_quota_or_deny(feature_name: str, amount: int = 1) -> Optional[GateDenial]:
    """Check quota and record usage if allowed. Returns None on success, GateDenial on block.

    Usage:
        denial = check_quota_or_deny("flowscope", event_count)
        if denial:
            return {"error": denial.to_dict()}, 429
        # proceed with analysis
    """
    g = gate()
    denial = g.check_quota(feature_name, amount)
    if denial:
        return denial
    g.record_usage(feature_name, amount)
    return None


get_feature_gate = gate

