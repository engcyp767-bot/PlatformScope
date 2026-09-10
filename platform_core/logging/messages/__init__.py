"""Bilingual message resolver and formatter."""

from __future__ import annotations

import re
from typing import Any
from .ar import MESSAGES_AR
from .en import MESSAGES_EN


class _SafeDict(dict):
    """Dictionary that returns empty string for missing keys during string formatting."""
    def __missing__(self, key: str) -> str:
        return ""


# Level name Arabic mapping
LEVEL_AR_MAP: dict[str, str] = {
    "CRITICAL": "حرج جداً",
    "ERROR": "خطأ",
    "WARNING": "تحذير",
    "INFO": "معلومات",
    "DEBUG": "تصحيح",
    "TRACE": "تتبع دقيق",
}


def _replace_level_change(match: re.Match[str]) -> str:
    old_lvl = match.group(1).upper()
    new_lvl = match.group(2).upper()
    old_ar = LEVEL_AR_MAP.get(old_lvl, old_lvl)
    new_ar = LEVEL_AR_MAP.get(new_lvl, new_lvl)
    return f"تم تغيير مستوى تسجيل المنصة من {old_lvl} ({old_ar}) إلى {new_lvl} ({new_ar})"


COMMON_ENGLISH_PATTERNS: list[tuple[re.Pattern[str], Any]] = [
    (
        re.compile(r"Platform log level changed from (\w+) to (\w+)", re.IGNORECASE),
        _replace_level_change,
    ),
    (
        re.compile(r"Unified backend server starting.*", re.IGNORECASE),
        "بدء تشغيل خادم المنصة الموحد",
    ),
    (
        re.compile(r"Unified backend server shutting down.*", re.IGNORECASE),
        "تم إيقاف خادم المنصة الموحد بنجاح",
    ),
    (
        re.compile(r"Unhandled backend exception.*", re.IGNORECASE),
        "حدث استثناء غير معالج في الخادم الموحد",
    ),
    (
        re.compile(r"^Server initialized$", re.IGNORECASE),
        "تمت تهيئة الخادم بنجاح",
    ),
    (
        re.compile(r"^test message$", re.IGNORECASE),
        "رسالة اختبار تشغيلية",
    ),
]


def translate_to_arabic_if_english(text: str) -> str:
    """Translate known English log sentences to Arabic if Arabic characters are missing."""
    if not text:
        return text
    if any("\u0600" <= c <= "\u06FF" for c in text):
        return text
    for pattern, replacement in COMMON_ENGLISH_PATTERNS:
        if pattern.search(text):
            return pattern.sub(replacement, text)
    return text


def get_message(event_code: str, lang: str = "ar", **params: Any) -> str:
    """Resolve and format parameterized message by event_code in requested language."""
    catalog = MESSAGES_AR if lang == "ar" else MESSAGES_EN
    template = catalog.get(event_code)
    if not template:
        if lang == "ar":
            template = MESSAGES_AR.get("GENERAL_EVENT", "{message}")
        else:
            template = MESSAGES_EN.get("GENERAL_EVENT", "{message}")

    safe_params = _SafeDict(**{k: str(v) for k, v in params.items()})
    try:
        res = template.format_map(safe_params)
        # Clean up empty colons/address patterns if host/port were omitted
        res = res.replace(" على :.", ".").replace(" on :.", ".").replace(" على :", "").replace(" on :", "").strip()
        if lang == "ar":
            res = translate_to_arabic_if_english(res)
        return res
    except Exception:
        fallback = params.get("message") or template
        if lang == "ar":
            return translate_to_arabic_if_english(str(fallback))
        return str(fallback)

