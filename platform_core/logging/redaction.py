"""Sensitive data redaction engine for platform logging."""

from __future__ import annotations

import re
from typing import Any

MASK = "[REDACTED]"

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "jwt",
    "private_key",
    "secret_key",
    "session_secret",
    "client_secret",
}

# Regex patterns for sensitive patterns inside free text
_BEARER_PATTERN = re.compile(r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{10,}")
_JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+")
_KEY_VALUE_PATTERN = re.compile(
    r"(?i)(['\"]?(?:password|token|api[_-]?key|secret|jwt|private[_-]?key)['\"]?\s*[:=]\s*['\"])([^'\"\s,]+)(['\"])"
)
_PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN [A-Z\s]+PRIVATE KEY-----[\s\S]*?-----END [A-Z\s]+PRIVATE KEY-----")


def redact_string(value: str) -> str:
    """Sanitize secrets from raw strings."""
    if not value or len(value) < 4:
        return value
    
    # 1. Private key blocks
    value = _PRIVATE_KEY_BLOCK.sub("-----BEGIN PRIVATE KEY [REDACTED]-----", value)
    
    # 2. Bearer tokens
    value = _BEARER_PATTERN.sub(r"\1" + MASK, value)
    
    # 3. JWT tokens
    value = _JWT_PATTERN.sub(MASK, value)
    
    # 4. Key-value pairs like password=xyz, "api_key": "xyz"
    value = _KEY_VALUE_PATTERN.sub(r"\1" + MASK + r"\3", value)
    
    return value


def redact_data(data: Any, depth: int = 0, max_depth: int = 6) -> Any:
    """Recursively scrub sensitive keys and text from data structures."""
    if depth > max_depth:
        return "[MaxDepth]"

    if isinstance(data, str):
        return redact_string(data)

    if isinstance(data, dict):
        cleaned: dict[str, Any] = {}
        for k, v in data.items():
            k_str = str(k)
            k_lower = k_str.lower().strip()
            if any(s in k_lower for s in SENSITIVE_KEYS):
                cleaned[k_str] = MASK
            else:
                cleaned[k_str] = redact_data(v, depth + 1, max_depth)
        return cleaned

    if isinstance(data, (list, tuple, set)):
        items = [redact_data(item, depth + 1, max_depth) for item in list(data)[:200]]
        return type(data)(items) if not isinstance(data, set) else set(items)

    return data

