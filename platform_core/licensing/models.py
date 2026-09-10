"""
Platform Scope - Licensing & Entitlements Models
Defines license states, types, and entitlement specifications.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class LicenseState(str, Enum):
    UNINITIALIZED = "UNINITIALIZED"
    TRIAL_ACTIVE = "TRIAL_ACTIVE"
    TRIAL_EXPIRING = "TRIAL_EXPIRING"
    TRIAL_EXPIRED = "TRIAL_EXPIRED"
    LICENSE_ACTIVE = "LICENSE_ACTIVE"
    LICENSE_EXPIRED = "LICENSE_EXPIRED"
    LICENSE_INVALID = "LICENSE_INVALID"
    LICENSE_REVOKED = "LICENSE_REVOKED"
    LICENSE_GRACE_PERIOD = "LICENSE_GRACE_PERIOD"
    LICENSE_SUSPENDED = "LICENSE_SUSPENDED"  # Used when clock rollback / tampering is detected


class LicenseType(str, Enum):
    TRIAL = "TRIAL"
    SUBSCRIPTION = "SUBSCRIPTION"
    PERPETUAL = "PERPETUAL"
    EVALUATION = "EVALUATION"


class PlatformEdition(str, Enum):
    COMMUNITY = "Community"
    STANDARD = "Standard"
    PROFESSIONAL = "Professional"
    ENTERPRISE = "Enterprise"


DEFAULT_FEATURES = [
    "flowscope",
    "threatscope",
    "logscope",
    "investigations",
    "sigma_rules",
    "correlation",
    "enterprise_reports",
    "ai_analysis",
]


@dataclass
class Entitlements:
    features: list[str] = field(default_factory=lambda: list(DEFAULT_FEATURES))
    max_users: int = 50
    max_assets: int = 5000
    max_daily_events: int = 10_000_000

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Entitlements:
        if not data or not isinstance(data, dict):
            return cls()
        return cls(
            features=list(data.get("features", DEFAULT_FEATURES)),
            max_users=int(data.get("max_users", 50)),
            max_assets=int(data.get("max_assets", 5000)),
            max_daily_events=int(data.get("max_daily_events", 10_000_000)),
        )


@dataclass
class LicenseInfo:
    state: LicenseState
    license_type: LicenseType
    product: str
    edition: PlatformEdition
    installation_id: str
    instance_id: str
    start_utc: str
    expires_utc: str
    days_remaining: int
    grace_days: int
    entitlements: Entitlements
    customer_org: str = "Platform Scope Customer"
    license_id: str = "PS-TRIAL-30D"
    is_valid: bool = True
    status_message: str = ""
    last_verified_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["state"] = self.state.value
        result["license_type"] = self.license_type.value
        result["edition"] = self.edition.value
        result["entitlements"] = self.entitlements.to_dict()
        return result

