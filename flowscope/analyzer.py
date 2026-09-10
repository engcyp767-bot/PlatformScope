"""ADS Events Analyzer and Risk Scoring Engine."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

RISK_THRESHOLDS = (40, 70, 85)

try:
    from .file_parser import ParsedData
except ImportError:
    from file_parser import ParsedData

# Standardise column names
FIELD_ALIASES = {
    "event_id": {"event id", "id", "معرّف الحدث"},
    "event_time": {"event detection time", "detection time", "timestamp", "وقت الكشف", "time", "detection time (local)"},
    "event_type": {"event type", "type", "نوع الحدث"},
    "type_desc": {"type description", "description", "وصف النوع", "subtype", "category"},
    "perspective": {"perspective", "view", "المنظور"},
    "priority": {"priority", "severity", "الأولوية", "الخطورة"},
    "detail": {"event detail", "detail", "details", "تفاصيل الحدث"},
    "protocol": {"protocol", "proto", "البروتوكول"},
    "src_port": {"source port", "src port", "sport", "منفذ المصدر"},
    "dst_port": {"destination port", "dst port", "dport", "منفذ الوجهة"},
    "event_source": {"event source", "source", "source address", "src ip", "source ip", "مصدر الحدث", "عنوان المصدر"},
    "source_name": {"captured source name", "source name", "hostname", "اسم المصدر"},
    "event_targets": {"event targets", "targets", "destination", "destination address", "dst ip", "destination ip", "أهداف الحدث", "عنوان الوجهة"},
    "data_feed": {"data feed", "feed", "detection method", "مصدر الكشف"},
    "user_identity": {"user identity", "user", "username", "المستخدم"},
    "attributes": {"attributes", "خصائص"},
}

PROTOCOL_NAMES = {
    "1": "ICMP", "2": "IGMP", "6": "TCP", "17": "UDP", "41": "IPv6",
    "47": "GRE", "50": "ESP", "51": "AH", "58": "ICMPv6", "89": "OSPF",
    "132": "SCTP",
}


@dataclass
class NormalizedEvent:
    event_id: str = ""
    event_time: str = ""
    event_type: str = ""
    type_desc: str = ""
    priority: str = "Info"
    detail: str = ""
    event_source: str = ""
    event_targets: list[str] = field(default_factory=list)
    protocol: str = ""
    src_port: str = ""
    dst_port: str = ""
    attributes: str = ""
    
    # Analysis outputs
    risk_score: int = 0
    severity: str = "Info"
    extracted_ips: set[str] = field(default_factory=set)


def _find_column(headers: list[str], aliases: set[str]) -> int | None:
    for index, header in enumerate(headers):
        clean_header = str(header).strip().lower()
        if clean_header in aliases:
            return index
    return None


def _parse_targets(target_str: str) -> list[str]:
    """Parse comma separated IPs from Targets column."""
    if not target_str:
        return []
    # Could be comma separated or space separated
    parts = re.split(r'[,\s]+', target_str)
    return [p.strip() for p in parts if p.strip()]


def _extract_ips_from_attributes(attr_str: str) -> list[str]:
    """Extract IPs from attribute fields like TopTargets=["1.1.1.1"]"""
    if not attr_str:
        return []
    # Find all IPs inside quotes or brackets in the attributes
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    return re.findall(ip_pattern, attr_str)


def _protocol_label(value: str) -> str:
    tokens = [token.strip() for token in re.split(r"[,;/\s]+", str(value or "")) if token.strip()]
    return "، ".join(PROTOCOL_NAMES.get(token, f"IP-{token}" if token.isdigit() else token.upper()) for token in tokens)


def _extract_protocols_from_attributes(attr_str: str) -> str:
    match = re.search(r"\bProtocols?\s*=\s*\[([^\]]+)\]", str(attr_str or ""), re.IGNORECASE)
    return _protocol_label(match.group(1)) if match else ""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_events(data: ParsedData, progress_callback=None) -> list[NormalizedEvent]:
    """Convert raw tabular data into standardized objects."""
    headers = data.headers
    mapping: dict[str, int] = {}
    
    for field_name, aliases in FIELD_ALIASES.items():
        index = _find_column(headers, aliases)
        if index is not None:
            mapping[field_name] = index

    # Fallback to guessing from data format if mapping is empty
    if "event_source" not in mapping and "event_targets" not in mapping and "src_ip" not in mapping:
         raise ValueError("Could not identify source/destination IP columns in the file")

    events = []
    total_rows = len(data.rows)
    for row_index, row in enumerate(data.rows, 1):
        if not any(row):  # Skip entirely empty rows
            continue
            
        def get_val(key: str) -> str:
            if key in mapping and mapping[key] < len(row):
                val = row[mapping[key]]
                return str(val).strip() if val is not None else ""
            return ""

        attributes = get_val("attributes")
        protocol = _protocol_label(get_val("protocol")) or _extract_protocols_from_attributes(attributes)
        evt = NormalizedEvent(
            event_id=get_val("event_id"),
            event_time=get_val("event_time"),
            event_type=get_val("event_type").upper(),
            type_desc=get_val("type_desc"),
            priority=get_val("priority") or "Info",
            detail=get_val("detail"),
            event_source=get_val("event_source"),
            protocol=protocol,
            src_port=get_val("src_port"),
            dst_port=get_val("dst_port"),
            attributes=attributes,
        )
        
        target_raw = get_val("event_targets")
        evt.event_targets = _parse_targets(target_raw)
        
        # Build extracted IPs
        if evt.event_source and _is_ip(evt.event_source):
            evt.extracted_ips.add(evt.event_source)
        for t in evt.event_targets:
            if _is_ip(t):
                evt.extracted_ips.add(t)
        
        # If no explicit targets column, try to parse from attributes
        if not evt.event_targets:
            attr_ips = _extract_ips_from_attributes(evt.attributes)
            for ip in attr_ips:
                evt.extracted_ips.add(ip)
                if ip != evt.event_source:
                    evt.event_targets.append(ip)

        events.append(evt)

        if progress_callback and (row_index == total_rows or row_index % 100 == 0):
            progress_callback(row_index, total_rows)
        
    return events


def score_event_risk(event_type: str, priority: str, detail: str = "", attributes: str = "") -> int:
    """Calculate the base ADS risk before external reputation findings."""
    score = 0

    # 1. Event Type Scoring
    t = str(event_type or "").upper()
    if t in {"DOS", "RANSOMWARE", "EXFILTRATION"}:
        score += 45
    elif t in {"DICTATTACK", "BLACKLIST", "DNSANOMALY", "MALWARE"}:
        score += 35
    elif t in {"ANOMALY", "DIRINET", "ALIENDEV", "RANDOMDOMAIN", "HIGHTRANSF"}:
        score += 25
    elif t in {"BITTORRENT", "DHCPANOM", "BROKENSEN", "DIVCOM", "DNSQUERY"}:
        score += 15
    else:
        score += 10

    p = str(priority or "").upper()
    if p == "CRITICAL":
        score += 30
    elif p == "HIGH":
        score += 22
    elif p == "MEDIUM":
        score += 14
    elif p in {"LOW", "INFO"}:
        score += 5

    detail_lower = f"{detail} {attributes}".lower()
    if "gib" in detail_lower:
        score += 15
    elif "mib" in detail_lower:
        score += 8
    return min(max(score, 0), 100)


def calculate_risk(events: list[NormalizedEvent], progress_callback=None) -> None:
    """Score the risk of each event (0-100)."""
    total_events = len(events)
    for event_index, evt in enumerate(events, 1):
        evt.risk_score = score_event_risk(evt.event_type, evt.priority, evt.detail, evt.attributes)
        
        # Determine Severity based on initial score
        medium, high, critical = RISK_THRESHOLDS
        if evt.risk_score >= critical:
            evt.severity = "حرج"
        elif evt.risk_score >= high:
            evt.severity = "مرتفع"
        elif evt.risk_score >= medium:
            evt.severity = "متوسط"
        else:
            evt.severity = "منخفض"

        if progress_callback and (event_index == total_events or event_index % 100 == 0):
            progress_callback(event_index, total_events)


def analyze_ads_data(data: ParsedData, progress_callback=None) -> dict[str, Any]:
    """Perform a complete analysis on ADS events."""
    def report_range(start: int, end: int, stage: str):
        def report(processed: int, total: int) -> None:
            ratio = processed / total if total else 1
            if progress_callback:
                progress_callback(start + round((end - start) * ratio), stage, processed, total)
        return report

    events = normalize_events(data, report_range(20, 65, "توحيد سجلات الأحداث"))
    calculate_risk(events, report_range(65, 85, "حساب درجات الخطورة"))
    
    # Generate statistics
    unique_ips = set()
    unique_sources = set()
    unique_targets = set()
    types_dist: dict[str, int] = {}
    
    critical_count = 0
    high_count = 0
    
    total_events = len(events)
    for event_index, evt in enumerate(events, 1):
        unique_ips.update(evt.extracted_ips)
        if evt.event_source:
            unique_sources.add(evt.event_source)
        for t in evt.event_targets:
            unique_targets.add(t)
            
        types_dist[evt.event_type] = types_dist.get(evt.event_type, 0) + 1
        
        if evt.severity == "حرج":
            critical_count += 1
        elif evt.severity == "مرتفع":
            high_count += 1

        if progress_callback and (event_index == total_events or event_index % 100 == 0):
            ratio = event_index / total_events if total_events else 1
            progress_callback(85 + round(10 * ratio), "بناء الملخص", event_index, total_events)
            
    # Classify IP ranges (rudimentary)
    internal_ips = 0
    external_ips = 0
    for ip in unique_ips:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if address.is_private:
            internal_ips += 1
        elif not address.is_loopback and not address.is_unspecified:
            external_ips += 1

    return {
        "metadata": {
            "filename": data.filename,
            "data_type": "ads_events",
            "row_count": len(events),
            "analyzed_at": datetime.now().isoformat(),
        },
        "summary": {
            "records": len(events),
            "unique_ips": len(unique_ips),
            "unique_sources": len(unique_sources),
            "unique_targets": len(unique_targets),
            "critical": critical_count,
            "high": high_count,
            "event_types": types_dist,
            "internal_ips": internal_ips,
            "external_ips": external_ips,
        },
        "records": [
            {**evt.__dict__, "base_risk_score": evt.risk_score, "extracted_ips": list(evt.extracted_ips)}
            for evt in events
        ],
        "enrichment": {"status": "not_started"}
    }
