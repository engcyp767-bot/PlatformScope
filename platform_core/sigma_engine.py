"""Sigma Rules Engine for Unified Security Platform.

Implements the global Sigma standard with:
1. Multi-stage Parser (PyYAML -> Minimal Indentation Parser -> JSON fallback).
2. Sigma Compatibility Layer (Fully Compatible / Partial Mapping / Unsupported Fields) with Compatibility Score (0-100%).
3. Extended Metadata (date, modified, license, related, fields, references, falsepositives).
4. Duplicate Detection via Sigma ID (UUID) and SHA-256 Rule Hash.
5. Compilation Cache (Pre-compiling AST and Regexes once per rule for O(1) event throughput).
6. Test Corpus Runner (Positive & Negative samples regression testing).
7. Non-duplicative Adapter Pattern (Sigma Source on disk -> In-Memory DetectionRule -> DetectionEngine).
8. Separation of Built-in Approved rules and User Imported custom rules.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from logscope.canonical import CanonicalEvent
from platform_core.detection_engine import (
    ConditionEvaluator,
    DetectionRule,
    SafeRegexEvaluator,
    calculate_integrity_hash,
)

# Standard Sigma to CanonicalEvent Field Mappings
SIGMA_FIELD_MAPPINGS: dict[str, dict[str, Any]] = {
    # Windows Process Creation & Execution
    "image": {"target": "raw_fields.Image", "status": "fully_compatible", "desc": "Process executable path"},
    "processname": {"target": "raw_fields.Image", "status": "fully_compatible", "desc": "Process name"},
    "commandline": {"target": "raw_fields.CommandLine", "status": "fully_compatible", "desc": "Process command line arguments"},
    "parentimage": {"target": "raw_fields.ParentProcessName", "status": "fully_compatible", "desc": "Parent process image"},
    "parentcommandline": {"target": "raw_fields.ParentCommandLine", "status": "fully_compatible", "desc": "Parent command line"},
    "originalfilename": {"target": "raw_fields.OriginalFileName", "status": "fully_compatible", "desc": "Original PE filename"},
    "currentdirectory": {"target": "raw_fields.CurrentDirectory", "status": "fully_compatible", "desc": "Process working directory"},
    "hashes": {"target": "raw_fields.Hashes", "status": "fully_compatible", "desc": "File hashes (MD5, SHA256)"},
    "integritylevel": {"target": "raw_fields.IntegrityLevel", "status": "fully_compatible", "desc": "Process integrity level"},
    
    # Event & Identification
    "eventid": {"target": "event_id", "status": "fully_compatible", "desc": "Security Event ID"},
    "event_id": {"target": "event_id", "status": "fully_compatible", "desc": "Event ID"},
    "message": {"target": "message", "status": "fully_compatible", "desc": "Event log message"},
    "channel": {"target": "category", "status": "fully_compatible", "desc": "Windows log channel / category"},
    "provider_name": {"target": "product", "status": "fully_compatible", "desc": "Logging provider name"},
    "service": {"target": "service_name", "status": "fully_compatible", "desc": "Service name"},
    
    # Identities & Accounts
    "user": {"target": "username", "status": "fully_compatible", "desc": "Target or subject username"},
    "username": {"target": "username", "status": "fully_compatible", "desc": "Username"},
    "targetusername": {"target": "username", "status": "fully_compatible", "desc": "Target username"},
    "subjectusername": {"target": "raw_fields.SubjectUserName", "status": "fully_compatible", "desc": "Subject executing user"},
    "targetdomainname": {"target": "raw_fields.TargetDomainName", "status": "fully_compatible", "desc": "Target domain name"},
    "logontype": {"target": "raw_fields.LogonType", "status": "fully_compatible", "desc": "Windows logon type code"},
    "status": {"target": "status", "status": "fully_compatible", "desc": "Event status / result"},
    "substatus": {"target": "raw_fields.SubStatus", "status": "fully_compatible", "desc": "Logon failure substatus"},
    "workstationname": {"target": "hostname", "status": "fully_compatible", "desc": "Workstation / client hostname"},
    "computername": {"target": "hostname", "status": "fully_compatible", "desc": "Computer / host name"},
    "host": {"target": "hostname", "status": "fully_compatible", "desc": "Hostname"},
    "device": {"target": "device", "status": "fully_compatible", "desc": "Device name or IP"},
    
    # Network Connections & Firewalls
    "sourceip": {"target": "source_ip", "status": "fully_compatible", "desc": "Source IPv4 / IPv6 address"},
    "src_ip": {"target": "source_ip", "status": "fully_compatible", "desc": "Source IP"},
    "srcip": {"target": "source_ip", "status": "fully_compatible", "desc": "Source IP"},
    "ipaddress": {"target": "source_ip", "status": "fully_compatible", "desc": "Client IP address"},
    "destinationip": {"target": "destination_ip", "status": "fully_compatible", "desc": "Destination IPv4 / IPv6 address"},
    "dst_ip": {"target": "destination_ip", "status": "fully_compatible", "desc": "Destination IP"},
    "dstip": {"target": "destination_ip", "status": "fully_compatible", "desc": "Destination IP"},
    "sourceport": {"target": "source_port", "status": "fully_compatible", "desc": "Source TCP/UDP port"},
    "src_port": {"target": "source_port", "status": "fully_compatible", "desc": "Source port"},
    "destinationport": {"target": "destination_port", "status": "fully_compatible", "desc": "Destination TCP/UDP port"},
    "dst_port": {"target": "destination_port", "status": "fully_compatible", "desc": "Destination port"},
    "protocol": {"target": "protocol", "status": "fully_compatible", "desc": "Network protocol (TCP/UDP/ICMP)"},
    "action": {"target": "action", "status": "fully_compatible", "desc": "Action / disposition"},
    
    # Linux & Syslog Fields
    "program": {"target": "service_name", "status": "fully_compatible", "desc": "Syslog program / daemon"},
    "comm": {"target": "raw_fields.CommandLine", "status": "fully_compatible", "desc": "Linux audit command"},
    "exe": {"target": "raw_fields.Image", "status": "fully_compatible", "desc": "Linux binary path"},
    "syscall": {"target": "raw_fields.syscall", "status": "fully_compatible", "desc": "Linux system call"},
    "uid": {"target": "username", "status": "fully_compatible", "desc": "User identifier"},
}


class MinimalYamlParser:
    """Fast, safe fallback YAML parser for standard Sigma rule structures without external dependencies."""

    @classmethod
    def parse(cls, text: str) -> dict[str, Any]:
        lines = text.splitlines()
        root: dict[str, Any] = {}
        cls._parse_block(lines, 0, 0, root)
        return root

    @classmethod
    def _parse_block(cls, lines: list[str], start_idx: int, current_indent: int, parent_dict: dict[str, Any]) -> int:
        idx = start_idx
        while idx < len(lines):
            line = lines[idx]
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                idx += 1
                continue

            indent = len(line) - len(line.lstrip())
            if indent < current_indent:
                return idx

            if ":" in stripped:
                colon_idx = stripped.find(":")
                key = stripped[:colon_idx].strip().strip('"').strip("'")
                val_part = stripped[colon_idx + 1:].strip()

                if val_part:
                    # Scalar or inline list
                    if val_part.startswith("[") and val_part.endswith("]"):
                        items = [x.strip().strip('"').strip("'") for x in val_part[1:-1].split(",") if x.strip()]
                        parent_dict[key] = items
                        idx += 1
                    else:
                        parent_dict[key] = cls._cast_val(val_part)
                        idx += 1
                else:
                    # Check next line for block or list
                    next_idx = idx + 1
                    while next_idx < len(lines) and (not lines[next_idx].strip() or lines[next_idx].strip().startswith("#")):
                        next_idx += 1

                    if next_idx >= len(lines):
                        parent_dict[key] = None
                        return next_idx

                    next_line = lines[next_idx]
                    next_indent = len(next_line) - len(next_line.lstrip())
                    next_stripped = next_line.strip()

                    if next_indent <= indent:
                        parent_dict[key] = None
                        idx = next_idx
                        continue

                    if next_stripped.startswith("- "):
                        # Parse list
                        list_items: list[Any] = []
                        idx = cls._parse_list(lines, next_idx, next_indent, list_items)
                        parent_dict[key] = list_items
                    else:
                        # Nested dictionary
                        child_dict: dict[str, Any] = {}
                        idx = cls._parse_block(lines, next_idx, next_indent, child_dict)
                        parent_dict[key] = child_dict
            else:
                idx += 1

        return idx

    @classmethod
    def _parse_list(cls, lines: list[str], start_idx: int, list_indent: int, parent_list: list[Any]) -> int:
        idx = start_idx
        while idx < len(lines):
            line = lines[idx]
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                idx += 1
                continue

            indent = len(line) - len(line.lstrip())
            if indent < list_indent:
                return idx

            if stripped.startswith("- "):
                item_content = stripped[2:].strip()
                if ":" in item_content and not item_content.startswith("{"):
                    # Dictionary item inside list
                    item_dict: dict[str, Any] = {}
                    colon_idx = item_content.find(":")
                    d_key = item_content[:colon_idx].strip().strip('"').strip("'")
                    d_val = cls._cast_val(item_content[colon_idx + 1:].strip())
                    item_dict[d_key] = d_val
                    # Check if subsequent lines belong to this list item dict
                    idx += 1
                    sub_dict: dict[str, Any] = {}
                    idx = cls._parse_block(lines, idx, list_indent + 2, sub_dict)
                    item_dict.update(sub_dict)
                    parent_list.append(item_dict)
                else:
                    parent_list.append(cls._cast_val(item_content))
                    idx += 1
            else:
                idx += 1

        return idx

    @staticmethod
    def _cast_val(val_str: str) -> Any:
        v = val_str.strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            return v[1:-1]
        v_lower = v.lower()
        if v_lower in {"true", "yes", "on"}:
            return True
        if v_lower in {"false", "no", "off"}:
            return False
        if v_lower in {"null", "none", "~"}:
            return None
        try:
            if "." in v:
                return float(v)
            return int(v)
        except ValueError:
            return v


class MultiStageSigmaParser:
    """3-Stage resilient parser: PyYAML -> Minimal Parser -> JSON Fallback."""

    @classmethod
    def parse_text(cls, text: str) -> tuple[dict[str, Any], str]:
        stripped = text.strip()
        if not stripped:
            raise ValueError("نص قاعدة Sigma فارغ")

        # 1. Try JSON directly if starts with {
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    return data, "json"
            except Exception:
                pass

        # 2. Try PyYAML if available in Python environment
        try:
            import yaml
            data = yaml.safe_load(stripped)
            if isinstance(data, dict):
                return data, "pyyaml"
        except ImportError:
            pass
        except Exception:
            pass

        # 3. Try Minimal Indentation YAML Parser
        try:
            data = MinimalYamlParser.parse(stripped)
            if isinstance(data, dict) and "title" in data and "detection" in data:
                return data, "minimal_yaml"
        except Exception:
            pass

        # 4. Final JSON attempt
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                return data, "json_fallback"
        except Exception:
            pass

        raise ValueError("تعذر فك تشفير نص Sigma. يرجى التأكد من التنسيق الصحيح لـ YAML أو JSON.")


class SigmaValidator:
    """Validates structural and semantic requirements of a Sigma rule."""

    @classmethod
    def validate(cls, data: dict[str, Any]) -> dict[str, Any]:
        errors: list[str] = []
        warnings: list[str] = []

        if not isinstance(data, dict):
            return {"valid": False, "errors": ["قاعدة Sigma يجب أن تكون كائناً مهيكلاً (Dictionary)"], "warnings": []}

        # Mandatory fields
        if not data.get("title"):
            errors.append("حقل 'title' إلزامي في مواصفة Sigma")
        if not data.get("logsource"):
            errors.append("كتلة 'logsource' إلزامية لتحديد نوع وسياق السجل")
        elif not isinstance(data.get("logsource"), dict):
            errors.append("كتلة 'logsource' يجب أن تكون كائناً يحدد category أو product أو service")

        detection = data.get("detection")
        if not detection:
            errors.append("كتلة 'detection' إلزامية وتتضمن معايير الكشف")
        elif not isinstance(detection, dict):
            errors.append("كتلة 'detection' يجب أن تكون كائناً يحتوي على الشروط ومعيار condition")
        else:
            condition = detection.get("condition")
            if not condition:
                errors.append("معيار 'condition' داخل كتلة detection إلزامي")

        # Recommended fields
        if not data.get("id"):
            warnings.append("يوصى بتضمين معرّف UUID فريد في حقل 'id'")
        if not data.get("level"):
            warnings.append("لم يتم تحديد 'level' (سيتم اعتماد 'medium' افتراضياً)")
        if not data.get("tags"):
            warnings.append("يوصى بإضافة وسوم MITRE ATT&CK في حقل 'tags'")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
        }


@dataclass
class CompatibilityReport:
    """Granular breakdown of Sigma rule compatibility with the platform."""
    score: int                                      # 0 to 100%
    status: str                                     # "fully_compatible" | "partial_mapping" | "unsupported_fields"
    status_label_ar: str
    total_fields: int
    fully_compatible_fields: list[dict[str, str]]
    partial_fields: list[dict[str, str]]
    unsupported_fields: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "status": self.status,
            "status_label_ar": self.status_label_ar,
            "total_fields": self.total_fields,
            "fully_compatible_fields": self.fully_compatible_fields,
            "partial_fields": self.partial_fields,
            "unsupported_fields": self.unsupported_fields,
        }


class SigmaCompatibilityAnalyzer:
    """Evaluates field mappings and assigns Compatibility Scores without failing unknown fields."""

    @classmethod
    def analyze(cls, rule_data: dict[str, Any]) -> CompatibilityReport:
        detection = rule_data.get("detection", {})
        fields_found: set[str] = set()

        # Extract all fields referenced in selections and filters
        for key, val in detection.items():
            if key in {"condition", "timeframe"}:
                continue
            if isinstance(val, dict):
                for f_key in val.keys():
                    base_field = f_key.split("|")[0].strip()
                    if base_field:
                        fields_found.add(base_field)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        for f_key in item.keys():
                            base_field = f_key.split("|")[0].strip()
                            if base_field:
                                fields_found.add(base_field)

        if not fields_found:
            return CompatibilityReport(
                score=100,
                status="fully_compatible",
                status_label_ar="متوافقة كلياً (100%)",
                total_fields=0,
                fully_compatible_fields=[],
                partial_fields=[],
                unsupported_fields=[],
            )

        fully_compat: list[dict[str, str]] = []
        partial: list[dict[str, str]] = []
        unsupported: list[dict[str, str]] = []

        canonical_fields = {
            "event_id", "message", "source_ip", "destination_ip", "source_port",
            "destination_port", "protocol", "service_name", "username", "hostname",
            "device", "action", "status", "category", "product", "log_source",
        }

        for f_name in fields_found:
            f_lower = f_name.lower()
            if f_lower in SIGMA_FIELD_MAPPINGS:
                mapped = SIGMA_FIELD_MAPPINGS[f_lower]
                fully_compat.append({
                    "sigma_field": f_name,
                    "target": mapped["target"],
                    "description": mapped["desc"],
                })
            elif f_lower in canonical_fields:
                fully_compat.append({
                    "sigma_field": f_name,
                    "target": f_lower,
                    "description": "حقل قياسي في CanonicalEvent",
                })
            else:
                # Check if it contains unsupported complex concepts
                if f_lower.startswith("__") or "unsupported" in f_lower or "unknown" in f_lower:
                    unsupported.append({
                        "sigma_field": f_name,
                        "reason": "حقل غير مدعوم أو غير معروف في سجلات المنظومة الحالية",
                    })
                else:
                    # Dynamic partial mapping via raw_fields fallback
                    partial.append({
                        "sigma_field": f_name,
                        "target": f"raw_fields.{f_name}",
                        "description": "يتم فحصه تلقائياً وبمرونة داخل بيانات السجل الأصلية (raw_fields)",
                    })

        total = len(fields_found)
        if total == 0:
            score = 100
        else:
            # Fully compatible fields give full weight (1.0), partial give (0.75), unsupported give (0.0)
            score = int(round(((len(fully_compat) * 1.0 + len(partial) * 0.75) / total) * 100))

        if len(unsupported) > 0:
            status = "unsupported_fields"
            status_label = f"تحتوي على حقول غير مدعومة ({score}%)"
        elif len(partial) > 0:
            status = "partial_mapping"
            status_label = f"توافق جزئي مرن ({score}%)"
        else:
            status = "fully_compatible"
            status_label = "متوافقة كلياً (100%)"

        return CompatibilityReport(
            score=score,
            status=status,
            status_label_ar=status_label,
            total_fields=total,
            fully_compatible_fields=fully_compat,
            partial_fields=partial,
            unsupported_fields=unsupported,
        )


class SigmaConditionAST:
    """Translates Sigma Condition logic (1 of them, selection and not filter) to platform AST."""

    @classmethod
    def compile_selection(cls, selection_data: Any) -> dict[str, Any]:
        """Convert a single selection dict/list into a ConditionEvaluator clause."""
        if isinstance(selection_data, list):
            # List of alternatives -> OR of items
            clauses = [cls.compile_selection(item) for item in selection_data]
            return {"or": clauses}

        if not isinstance(selection_data, dict):
            return {}

        predicates: list[dict[str, Any]] = []

        for field_spec, target_val in selection_data.items():
            parts = field_spec.split("|")
            base_field = parts[0].strip()
            modifiers = [p.strip().lower() for p in parts[1:]]

            # Resolve mapped target path
            base_lower = base_field.lower()
            if base_lower in SIGMA_FIELD_MAPPINGS:
                target_field = SIGMA_FIELD_MAPPINGS[base_lower]["target"]
            else:
                target_field = f"raw_fields.{base_field}"

            # Determine Operator from modifiers
            if "contains" in modifiers:
                if "all" in modifiers and isinstance(target_val, (list, tuple)):
                    # All must be contained
                    sub_preds = [{"field": target_field, "operator": "contains_ci", "value": str(v)} for v in target_val]
                    predicates.append({"and": sub_preds})
                    continue
                elif isinstance(target_val, (list, tuple)):
                    sub_preds = [{"field": target_field, "operator": "contains_ci", "value": str(v)} for v in target_val]
                    predicates.append({"or": sub_preds})
                    continue
                else:
                    predicates.append({"field": target_field, "operator": "contains_ci", "value": str(target_val)})
                    continue

            if "startswith" in modifiers:
                if isinstance(target_val, (list, tuple)):
                    sub_preds = [{"field": target_field, "operator": "startswith", "value": str(v)} for v in target_val]
                    predicates.append({"or": sub_preds})
                    continue
                else:
                    predicates.append({"field": target_field, "operator": "startswith", "value": str(target_val)})
                    continue

            if "endswith" in modifiers:
                if isinstance(target_val, (list, tuple)):
                    sub_preds = [{"field": target_field, "operator": "endswith", "value": str(v)} for v in target_val]
                    predicates.append({"or": sub_preds})
                    continue
                else:
                    predicates.append({"field": target_field, "operator": "endswith", "value": str(target_val)})
                    continue

            if "re" in modifiers or "regex" in modifiers:
                predicates.append({"field": target_field, "operator": "regex", "value": str(target_val)})
                continue

            # Default equality or in list
            if isinstance(target_val, (list, tuple, set)):
                predicates.append({"field": target_field, "operator": "in", "value": [str(v) for v in target_val]})
            elif target_val is None:
                predicates.append({"field": target_field, "operator": "is_null", "value": None})
            else:
                predicates.append({"field": target_field, "operator": "eq", "value": target_val})

        if len(predicates) == 1:
            return predicates[0]
        return {"and": predicates}

    @classmethod
    def compile_condition(cls, condition_expr: str, detection_blocks: dict[str, Any]) -> dict[str, Any]:
        """Convert Sigma condition string expression to platform condition tree."""
        expr = condition_expr.strip()
        all_block_names = [k for k in detection_blocks.keys() if k not in {"condition", "timeframe"}]

        # Pre-compile selections
        compiled_blocks: dict[str, dict[str, Any]] = {}
        for b_name in all_block_names:
            compiled_blocks[b_name] = cls.compile_selection(detection_blocks[b_name])

        # Handle simple single block: "selection"
        if expr in compiled_blocks:
            return compiled_blocks[expr]

        # Handle "1 of them" or "all of them"
        if expr == "1 of them":
            return {"or": [compiled_blocks[k] for k in all_block_names]}
        if expr == "all of them":
            return {"and": [compiled_blocks[k] for k in all_block_names]}

        # Handle "1 of selection*"
        m_one_of = re.match(r"^1\s+of\s+([a-zA-Z0-9_]+)\*$", expr)
        if m_one_of:
            prefix = m_one_of.group(1)
            matching = [compiled_blocks[k] for k in all_block_names if k.startswith(prefix)]
            return {"or": matching} if matching else {}

        # Handle "all of selection*"
        m_all_of = re.match(r"^all\s+of\s+([a-zA-Z0-9_]+)\*$", expr)
        if m_all_of:
            prefix = m_all_of.group(1)
            matching = [compiled_blocks[k] for k in all_block_names if k.startswith(prefix)]
            return {"and": matching} if matching else {}

        # Handle "A and not B"
        m_and_not = re.match(r"^([a-zA-Z0-9_*]+)\s+and\s+not\s+([a-zA-Z0-9_*]+)$", expr)
        if m_and_not:
            part_a = m_and_not.group(1)
            part_b = m_and_not.group(2)
            cond_a = cls.compile_condition(part_a, detection_blocks)
            cond_b = cls.compile_condition(part_b, detection_blocks)
            return {"and": [cond_a, {"not": cond_b}]}

        # Handle "A and B"
        m_and = re.match(r"^([a-zA-Z0-9_*]+)\s+and\s+([a-zA-Z0-9_*]+)$", expr)
        if m_and:
            part_a = m_and.group(1)
            part_b = m_and.group(2)
            return {"and": [cls.compile_condition(part_a, detection_blocks), cls.compile_condition(part_b, detection_blocks)]}

        # Handle "A or B"
        m_or = re.match(r"^([a-zA-Z0-9_*]+)\s+or\s+([a-zA-Z0-9_*]+)$", expr)
        if m_or:
            part_a = m_or.group(1)
            part_b = m_or.group(2)
            return {"or": [cls.compile_condition(part_a, detection_blocks), cls.compile_condition(part_b, detection_blocks)]}

        # Multi-term tokenization fallback
        tokens = expr.replace("(", " ( ").replace(")", " ) ").split()
        and_parts: list[dict[str, Any]] = []
        or_parts: list[dict[str, Any]] = []
        current_op = "and"
        is_negated = False

        for tok in tokens:
            if tok.lower() == "and":
                current_op = "and"
                is_negated = False
            elif tok.lower() == "or":
                current_op = "or"
                is_negated = False
            elif tok.lower() == "not":
                is_negated = True
            elif tok in compiled_blocks:
                clause = compiled_blocks[tok]
                if is_negated:
                    clause = {"not": clause}
                    is_negated = False

                if current_op == "or":
                    or_parts.append(clause)
                else:
                    and_parts.append(clause)

        if or_parts and and_parts:
            return {"or": or_parts + [{"and": and_parts}]}
        if or_parts:
            return {"or": or_parts}
        if and_parts:
            return {"and": and_parts} if len(and_parts) > 1 else and_parts[0]

        # Default fallback to first block
        return compiled_blocks[all_block_names[0]] if all_block_names else {}


class SigmaRuleAdapter:
    """Non-duplicative adapter wrapping a Sigma rule as an in-memory DetectionRule."""

    @classmethod
    def to_detection_rule(cls, sigma_data: dict[str, Any], file_path: Path | None = None, source_type: str = "builtin") -> DetectionRule:
        rule_id = str(sigma_data.get("id") or "").strip()
        if not rule_id:
            # Generate deterministic ID from title
            title_hash = hashlib.sha256(str(sigma_data.get("title", "")).encode("utf-8")).hexdigest()[:8]
            rule_id = f"SIGMA-{title_hash}"
        else:
            if not rule_id.upper().startswith("SIGMA-"):
                rule_id = f"SIGMA-{rule_id.upper()}"

        title = str(sigma_data.get("title") or rule_id)
        description = str(sigma_data.get("description") or "")
        author = str(sigma_data.get("author") or "Sigma Community")

        # Map Status to Lifecycle
        status = str(sigma_data.get("status") or "testing").lower()
        lifecycle_map = {
            "stable": "production",
            "production": "production",
            "test": "testing",
            "experimental": "development",
            "development": "development",
            "deprecated": "deprecated",
        }
        lifecycle = lifecycle_map.get(status, "testing")

        # Map Level to Severity
        level = str(sigma_data.get("level") or "medium").lower()
        severity_map = {
            "informational": "info",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        }
        severity = severity_map.get(level, "medium")

        # Extract MITRE ATT&CK
        tags = [str(t) for t in sigma_data.get("tags", [])]
        tactics: list[str] = []
        techniques: list[str] = []

        for t in tags:
            t_lower = t.lower()
            if t_lower.startswith("attack.t"):
                tech_code = t[7:].upper()
                techniques.append(tech_code)
            elif t_lower.startswith("attack."):
                tactic_name = t[7:].replace("_", " ").title()
                tactics.append(tactic_name)

        # Map Category
        logsource = sigma_data.get("logsource", {})
        category = str(logsource.get("product") or logsource.get("category") or "windows").lower()
        if "linux" in category or "syslog" in category:
            category = "linux"
        elif "network" in category or "firewall" in category:
            category = "network"
        elif "cloud" in category or "azure" in category or "aws" in category:
            category = "cloud"
        else:
            category = "windows"

        # Compile Condition
        detection = sigma_data.get("detection", {})
        cond_expr = str(detection.get("condition") or "1 of them")
        compiled_condition = SigmaConditionAST.compile_condition(cond_expr, detection)

        # Incident Policy
        incident_policy = {
            "auto_promote": severity in {"critical", "high"},
            "threshold": 3 if severity == "medium" else (5 if severity in {"low", "info"} else 1),
            "time_window_seconds": 120,
            "min_confidence": 75 if severity in {"critical", "high"} else 70,
            "group_by": ["username", "src_ip", "device"],
        }

        # Test Samples
        test_samples = sigma_data.get("test_samples", {})
        if not isinstance(test_samples, dict):
            test_samples = {"positive": [], "negative": []}

        # Recommendations
        falsepos = sigma_data.get("falsepositives", [])
        if isinstance(falsepos, str):
            falsepos = [falsepos]
        recs = [f"مراجعة احتمالية الإيجابيات الكاذبة: {fp}" for fp in falsepos if fp and str(fp).lower() != "unknown"]
        if not recs:
            recs = [
                "التحقق من صحة ومبررات تنفيذ العملية أو الاتصال مع المستخدم أو مسؤول النظام.",
                "فحص سجلات النظام الجنائية المرتبطة لتتبع بقية سلسلة النشاط.",
            ]

        rule = DetectionRule(
            id=rule_id,
            name=title,
            name_en=title,
            description=description,
            category=category,
            severity=severity,
            confidence=85 if severity in {"critical", "high"} else 75,
            lifecycle=lifecycle,
            enabled=True,
            is_deleted=False,
            author=author,
            version="1.0.0",
            threat_family=f"Sigma: {logsource.get('category', 'Generic')}",
            mitre_attack={
                "version": "v14.1",
                "tactics": tactics or ["Execution"],
                "techniques": techniques or ["T1059"],
            },
            condition=compiled_condition,
            incident_policy=incident_policy,
            test_samples={
                "positive": test_samples.get("positive", []),
                "negative": test_samples.get("negative", []),
            },
            tags=tags + ["sigma", source_type],
            recommendations=recs,
            file_path=file_path,
            source_format="sigma",
            sigma_id=str(sigma_data.get("id") or ""),
            compatibility_score=100,
        )

        rule.integrity_hash = calculate_integrity_hash(rule.to_dict())
        return rule


class SigmaEngine:
    """Manages Built-in and Custom Sigma rules, compilation cache, and duplicate detection."""

    _instance: SigmaEngine | None = None
    _lock = threading.RLock()

    def __init__(self, workspace_root: Path | None = None):
        self._lock = threading.RLock()
        if workspace_root is None:
            workspace_root = Path(__file__).resolve().parent.parent
        self.workspace_root = workspace_root
        self.builtin_dir = self.workspace_root / "detections" / "sigma" / "builtin"
        self.custom_dir = self.workspace_root / "detections" / "sigma" / "custom"
        self.builtin_dir.mkdir(parents=True, exist_ok=True)
        self.custom_dir.mkdir(parents=True, exist_ok=True)

        # In-memory storage & compilation cache
        self._raw_rules: dict[str, dict[str, Any]] = {}
        self._rule_sources: dict[str, str] = {}           # raw text
        self._rule_types: dict[str, str] = {}             # "builtin" | "custom"
        self._rule_paths: dict[str, Path] = {}
        self._rule_hashes: dict[str, str] = {}
        self._adapters: dict[str, DetectionRule] = {}     # In-memory compiled DetectionRule
        self._compatibility_reports: dict[str, CompatibilityReport] = {}

        self.reload()

    @classmethod
    def get_instance(cls) -> SigmaEngine:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def reload(self) -> None:
        """Reload and pre-compile all built-in and custom Sigma rules."""
        with self._lock:
            self._raw_rules.clear()
            self._rule_sources.clear()
            self._rule_types.clear()
            self._rule_paths.clear()
            self._rule_hashes.clear()
            self._adapters.clear()
            self._compatibility_reports.clear()

            # 1. Load Built-in rules
            self._load_from_dir(self.builtin_dir, source_type="builtin")
            # 2. Load Custom rules
            self._load_from_dir(self.custom_dir, source_type="custom")

    def _load_from_dir(self, directory: Path, source_type: str) -> None:
        for ext in ("*.yml", "*.yaml", "*.json"):
            for file_path in directory.glob(ext):
                try:
                    content = file_path.read_text(encoding="utf-8")
                    data, _ = MultiStageSigmaParser.parse_text(content)
                    v_res = SigmaValidator.validate(data)
                    if not v_res["valid"]:
                        continue

                    rule_id = str(data.get("id") or file_path.stem).strip()
                    rule_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

                    # Analyze compatibility
                    compat = SigmaCompatibilityAnalyzer.analyze(data)

                    # Build in-memory adapter
                    adapter = SigmaRuleAdapter.to_detection_rule(data, file_path=file_path, source_type=source_type)

                    self._raw_rules[rule_id] = data
                    self._rule_sources[rule_id] = content
                    self._rule_types[rule_id] = source_type
                    self._rule_paths[rule_id] = file_path
                    self._rule_hashes[rule_id] = rule_hash
                    self._adapters[rule_id] = adapter
                    self._compatibility_reports[rule_id] = compat
                except Exception:
                    continue

    def check_duplicate(self, rule_data: dict[str, Any], raw_text: str) -> dict[str, Any]:
        """Check for existing rule by Sigma ID or SHA-256 Rule Hash."""
        rule_id = str(rule_data.get("id") or "").strip()
        rule_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        with self._lock:
            # Check by ID
            if rule_id and rule_id in self._raw_rules:
                return {
                    "is_duplicate": True,
                    "existing_id": rule_id,
                    "match_type": "id",
                    "source_type": self._rule_types.get(rule_id, "unknown"),
                    "message": f"توجد قاعدة مسجلة مسبقاً بنفس معرّف Sigma ID: {rule_id}",
                }

            # Check by Hash
            for existing_id, h in self._rule_hashes.items():
                if h == rule_hash:
                    return {
                        "is_duplicate": True,
                        "existing_id": existing_id,
                        "match_type": "hash",
                        "source_type": self._rule_types.get(existing_id, "unknown"),
                        "message": f"محتوى القاعدة متطابق تماماً مع القاعدة المسجلة: {existing_id}",
                    }

        return {"is_duplicate": False}

    def import_rule(self, raw_text: str, author_username: str = "analyst", force: bool = False) -> dict[str, Any]:
        """Validate, check compatibility, check duplicates, and save a custom Sigma rule."""
        if len(raw_text.encode("utf-8")) > 5 * 1024 * 1024:
            raise ValueError("حجم ملف القاعدة يتجاوز السقف المسموح (5 ميجابايت)")

        data, fmt = MultiStageSigmaParser.parse_text(raw_text)
        v_res = SigmaValidator.validate(data)
        if not v_res["valid"]:
            raise ValueError(f"أخطاء في مواصفة Sigma: {', '.join(v_res['errors'])}")

        dup_check = self.check_duplicate(data, raw_text)
        if dup_check["is_duplicate"] and not force:
            return {
                "success": False,
                "is_duplicate": True,
                "duplicate_info": dup_check,
                "message": dup_check["message"],
            }

        rule_id = str(data.get("id") or "").strip()
        if not rule_id:
            rule_id = f"custom_{hashlib.sha256(raw_text.encode('utf-8')).hexdigest()[:8]}"
            data["id"] = rule_id

        # Compatibility
        compat = SigmaCompatibilityAnalyzer.analyze(data)

        # File naming
        filename = f"{re.sub(r'[^a-zA-Z0-9_-]', '_', rule_id.lower())}.yml"
        target_path = self.custom_dir / filename
        target_path.write_text(raw_text, encoding="utf-8")

        # Reload state
        self.reload()

        return {
            "success": True,
            "id": rule_id,
            "filename": filename,
            "source_type": "custom",
            "format": fmt,
            "compatibility": compat.to_dict(),
            "message": "تم استيراد قاعدة Sigma وتجميعها بنجاح كـ Adapter",
        }

    def run_tests(self, rule_id: str) -> dict[str, Any]:
        """Run positive and negative regression test samples for a Sigma rule."""
        with self._lock:
            adapter = self._adapters.get(rule_id)
            if not adapter:
                # Try finding by adapter ID (SIGMA-...)
                for r_id, adp in self._adapters.items():
                    if adp.id == rule_id:
                        adapter = adp
                        rule_id = r_id
                        break

            if not adapter:
                raise ValueError(f"القاعدة غير موجودة: {rule_id}")

        pos_samples = adapter.test_samples.get("positive", [])
        neg_samples = adapter.test_samples.get("negative", [])

        pos_passed = 0
        neg_passed = 0
        details: list[dict[str, Any]] = []

        # Positive tests (Expect TRUE)
        for idx, sample in enumerate(pos_samples):
            match = ConditionEvaluator.evaluate(sample, adapter.condition)
            if match:
                pos_passed += 1
            details.append({
                "sample_type": "positive",
                "index": idx + 1,
                "matched": match,
                "passed": match is True,
                "expected": True,
            })

        # Negative tests (Expect FALSE)
        for idx, sample in enumerate(neg_samples):
            match = ConditionEvaluator.evaluate(sample, adapter.condition)
            if not match:
                neg_passed += 1
            details.append({
                "sample_type": "negative",
                "index": idx + 1,
                "matched": match,
                "passed": match is False,
                "expected": False,
            })

        total_samples = len(pos_samples) + len(neg_samples)
        passed_samples = pos_passed + neg_passed
        all_passed = (passed_samples == total_samples) if total_samples > 0 else True

        return {
            "rule_id": rule_id,
            "adapter_id": adapter.id,
            "passed": all_passed,
            "total_samples": total_samples,
            "passed_samples": passed_samples,
            "positive": {"total": len(pos_samples), "passed": pos_passed},
            "negative": {"total": len(neg_samples), "passed": neg_passed},
            "details": details,
        }

    def test_custom_event(self, rule_id: str, event_data: dict[str, Any]) -> dict[str, Any]:
        """Evaluate a specific event against a compiled Sigma rule adapter."""
        with self._lock:
            adapter = self._adapters.get(rule_id)
            if not adapter:
                for r_id, adp in self._adapters.items():
                    if adp.id == rule_id:
                        adapter = adp
                        break

            if not adapter:
                raise ValueError(f"القاعدة غير موجودة: {rule_id}")

        start_t = time.perf_counter()
        matched = ConditionEvaluator.evaluate(event_data, adapter.condition)
        exec_ms = round((time.perf_counter() - start_t) * 1000, 3)

        return {
            "rule_id": rule_id,
            "adapter_id": adapter.id,
            "matched": matched,
            "execution_time_ms": exec_ms,
        }

    def get_all_rules_summary(self) -> list[dict[str, Any]]:
        """List all Sigma rules with compatibility scores, metadata, and origin."""
        with self._lock:
            result: list[dict[str, Any]] = []
            for r_id, data in self._raw_rules.items():
                adapter = self._adapters.get(r_id)
                compat = self._compatibility_reports.get(r_id)
                s_type = self._rule_types.get(r_id, "builtin")

                result.append({
                    "id": r_id,
                    "adapter_id": adapter.id if adapter else r_id,
                    "title": data.get("title", r_id),
                    "description": data.get("description", ""),
                    "level": data.get("level", "medium"),
                    "status": data.get("status", "testing"),
                    "source_type": s_type,
                    "date": data.get("date", ""),
                    "modified": data.get("modified", ""),
                    "license": data.get("license", "Apache-2.0"),
                    "author": data.get("author", "Sigma Community"),
                    "tags": data.get("tags", []),
                    "mitre_attack": adapter.mitre_attack if adapter else {},
                    "compatibility": compat.to_dict() if compat else None,
                    "has_tests": bool(adapter and (adapter.test_samples.get("positive") or adapter.test_samples.get("negative"))),
                    "positive_samples_count": len(adapter.test_samples.get("positive", [])) if adapter else 0,
                    "negative_samples_count": len(adapter.test_samples.get("negative", [])) if adapter else 0,
                })
            return result

    def get_rule_details(self, rule_id: str) -> dict[str, Any]:
        """Fetch raw rule source, compiled adapter, compatibility breakdown, and AST."""
        with self._lock:
            data = self._raw_rules.get(rule_id)
            if not data:
                for r_id, adp in self._adapters.items():
                    if adp.id == rule_id:
                        rule_id = r_id
                        data = self._raw_rules.get(r_id)
                        break

            if not data:
                raise ValueError(f"القاعدة غير موجودة: {rule_id}")

            adapter = self._adapters.get(rule_id)
            compat = self._compatibility_reports.get(rule_id)

            return {
                "id": rule_id,
                "raw_source": self._rule_sources.get(rule_id, ""),
                "source_type": self._rule_types.get(rule_id, "builtin"),
                "file_path": str(self._rule_paths.get(rule_id, "")),
                "data": data,
                "adapter": adapter.to_dict() if adapter else None,
                "compatibility": compat.to_dict() if compat else None,
            }

    def get_all_adapters(self) -> list[DetectionRule]:
        """Return in-memory DetectionRule adapters for DetectionEngine evaluation."""
        with self._lock:
            return list(self._adapters.values())

    def get_builtin_rules(self) -> list[dict[str, Any]]:
        """Return all built-in approved Sigma rules."""
        return [r for r in self.get_all_rules_summary() if r.get("source_type") == "builtin"]

    def delete_custom_rule(self, rule_id: str) -> bool:
        """Delete a custom Sigma rule from disk. Built-in rules cannot be deleted."""
        with self._lock:
            details = self.get_rule_details(rule_id)
            if details.get("source_type") == "builtin":
                raise PermissionError("لا يمكن حذف قواعد Sigma المعتمدة المدمجة (Built-in Rules).")
            f_path_str = details.get("file_path")
            if f_path_str:
                p = Path(f_path_str)
                if p.exists():
                    p.unlink()
                    self.reload()
                    return True
            return False
