"""
Platform Scope Licensing Package
"""

from platform_core.licensing.license_manager import LicenseManager
from platform_core.licensing.models import (
    Entitlements,
    LicenseInfo,
    LicenseState,
    LicenseType,
    PlatformEdition,
)

__all__ = [
    "LicenseManager",
    "LicenseState",
    "LicenseType",
    "PlatformEdition",
    "LicenseInfo",
    "Entitlements",
]

