"""YAML Adapter for Detection Rules (Optional import/export helper).

Uses PyYAML if available; otherwise provides JSON fallbacks.
Native format across the platform is JSON.
"""

from __future__ import annotations

import json
from typing import Any

try:
    import yaml  # type: ignore
    YAML_AVAILABLE = True
except ImportError:
    yaml = None  # type: ignore
    YAML_AVAILABLE = False


def is_yaml_supported() -> bool:
    return YAML_AVAILABLE


def dump_yaml(data: Any) -> str:
    """Serialize Python dictionary/list to YAML string if PyYAML is available, else JSON."""
    if YAML_AVAILABLE and yaml is not None:
        return yaml.dump(data, allow_unicode=True, sort_keys=False)
    return json.dumps(data, ensure_ascii=False, indent=2)


def load_yaml(yaml_str: str) -> Any:
    """Parse YAML or JSON string into a Python dict/list."""
    if YAML_AVAILABLE and yaml is not None:
        return yaml.safe_load(yaml_str)
    return json.loads(yaml_str)
