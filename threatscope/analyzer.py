"""Workbook normalisation, security analytics and risk scoring."""

from __future__ import annotations

import hashlib
import json
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from typing import Any

RISK_THRESHOLDS = (40, 70, 85)

try:
    from .xlsx_parser import SheetData
except ImportError:
    from xlsx_parser import SheetData


FIELD_ALIASES = {
    "status": {"status", "threat status", "alert status", "remediation status", "الحالة", "حالة التهديد"},
    "threat_name": {"threat details", "threat", "threat name", "file name", "filename", "detection name", "alert name", "alert title", "title", "malware name", "اسم التهديد", "اسم الملف", "اسم التنبيه"},
    "confidence": {"confidence level", "confidence", "verdict", "severity", "alert severity", "confidence score", "الثقة", "الحكم", "الخطورة"},
    "endpoint": {"endpoints", "endpoint", "host", "hostname", "device", "device name", "computer", "machine", "asset", "الجهاز", "اسم الجهاز", "المضيف"},
    "incident_status": {"incident status", "case status", "incident state", "alert state", "حالة الحادث", "حالة القضية"},
    "analyst_verdict": {"analyst verdict", "analyst decision", "investigation verdict", "حكم المحلل", "قرار المحلل"},
    "reported_at": {"reported time (utc)", "reported time", "reported at", "created time", "alert creation time", "وقت الإبلاغ", "وقت الإنشاء"},
    "identified_at": {"identifying time (utc)", "identifying time", "identified at", "detection time", "first seen", "وقت الاكتشاف", "وقت الرصد"},
    "engine": {"detecting engine", "engine", "detection engine", "detection source", "source", "محرك الكشف", "مصدر الكشف"},
    "classification": {"classification", "category", "threat category", "malware category", "threat type", "التصنيف", "الفئة", "نوع التهديد"},
    "hash": {"hash", "file hash", "sha1", "sha 1", "sha256", "sha 256", "md5", "filehash", "file sha256", "file sha1", "بصمة", "هاش", "تجزئة الملف"},
    "path": {"path", "file path", "folder path", "process path", "المسار", "مسار الملف"},
    "completed_actions": {"completed actions", "actions completed", "remediation action", "الإجراءات المكتملة"},
    "pending_actions": {"pending actions", "actions pending", "pending remediation", "الإجراءات المعلقة"},
    "reboot_required": {"reboot required", "restart required", "إعادة التشغيل مطلوبة"},
    "failed_actions": {"failed actions", "remediation failed", "الإجراءات الفاشلة"},
    "policy": {"policy at detection", "policy", "detection policy", "السياسة"},
    "mitigated_preemptively": {"mitigated preemptively", "preemptive mitigation", "تم الاحتواء مسبقًا"},
    "external_ticket": {"external ticket id", "ticket id", "external ticket", "incident id", "case id", "رقم التذكرة", "معرف الحادث"},
    "account": {"account", "user", "username", "user principal name", "الحساب", "المستخدم"},
    "site": {"site", "location", "tenant", "الموقع", "المستأجر"},
    "group": {"group", "device group", "asset group", "المجموعة"},
    "originating_process": {"originating process", "parent process", "initiating process", "process name", "العملية الأصلية", "العملية الأم"},
}

REQUIRED_FIELDS = {"hash"}
HASH_PATTERNS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


@dataclass
class NormalizedRecord:
    row_number: int
    status: Any = None
    threat_name: Any = None
    confidence: Any = None
    endpoint: Any = None
    incident_status: Any = None
    analyst_verdict: Any = None
    reported_at: Any = None
    identified_at: Any = None
    engine: Any = None
    classification: Any = None
    hash: Any = None
    hash_type: Any = None
    path: Any = None
    completed_actions: Any = None
    pending_actions: Any = None
    reboot_required: Any = None
    failed_actions: Any = None
    policy: Any = None
    mitigated_preemptively: Any = None
    external_ticket: Any = None
    account: Any = None
    site: Any = None
    group: Any = None
    originating_process: Any = None
    risk_score: int = 0
    risk_level: str = "غير معروف"
    risk_reasons: list[str] | None = None


def _clean_header(value: Any) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[_\-./()]+", " ", str(value or "").strip().lower())).strip()


def _serialise(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    return value


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "yes", "1", "pending", "required"}


def classify_hash(value: Any) -> tuple[str | None, str | None]:
    clean = re.sub(r"\s+", "", str(value or "")).lower()
    if not re.fullmatch(r"[0-9a-f]+", clean):
        return None, None
    return (clean, HASH_PATTERNS.get(len(clean))) if len(clean) in HASH_PATTERNS else (None, None)


def map_columns(headers: list[Any]) -> dict[str, int]:
    cleaned = [_clean_header(header) for header in headers]
    result: dict[str, int] = {}
    for target, aliases in FIELD_ALIASES.items():
        # Prefer the strongest file identifier when an XDR export includes
        # several digest columns on the same row.
        if target == "hash":
            priorities = ("sha 256", "sha256", "file sha256", "sha 1", "sha1", "file sha1", "md5", "file hash", "filehash", "hash", "بصمة", "هاش", "تجزئة الملف")
            for alias in priorities:
                if alias in cleaned:
                    result[target] = cleaned.index(alias)
                    break
            if target in result:
                continue
        for index, header in enumerate(cleaned):
            if header in {_clean_header(alias) for alias in aliases}:
                result[target] = index
                break
    return result


def _base_risk(record: NormalizedRecord) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    classification = str(record.classification or "").lower()
    confidence = str(record.confidence or "").lower()
    incident = str(record.incident_status or "").lower()
    status = str(record.status or "").lower()
    if "ransom" in classification:
        score += 28
        reasons.append("تصنيف برمجية فدية")
    elif "crypto" in classification:
        score += 20
        reasons.append("تصنيف تعدين غير مشروع")
    elif "malware" in classification:
        score += 16
        reasons.append("تصنيف برمجية ضارة")
    else:
        score += 8
    if confidence == "malicious":
        score += 18
        reasons.append("ثقة محلية: خبيث")
    elif confidence == "suspicious":
        score += 10
        reasons.append("ثقة محلية: مشبوه")
    if "unresolved" in incident:
        score += 15
        reasons.append("الحادث غير محلول")
    if "not mitigated" in status:
        score += 12
        reasons.append("التهديد غير مخفف")
    if _truthy(record.pending_actions):
        score += 8
        reasons.append("توجد إجراءات معلقة")
    if _truthy(record.failed_actions):
        score += 7
        reasons.append("فشل إجراء معالجة")
    return min(score, 75), reasons


def _risk_level(score: int) -> str:
    medium, high, critical = RISK_THRESHOLDS
    if score >= critical:
        return "حرج"
    if score >= high:
        return "مرتفع"
    if score >= medium:
        return "متوسط"
    if score > 0:
        return "منخفض"
    return "غير معروف"


def select_tabular_sheet(sheets: list[SheetData]) -> SheetData:
    candidates: list[tuple[int, SheetData]] = []
    for sheet in sheets:
        mapping = map_columns(sheet.rows[0]) if sheet.rows else {}
        candidates.append((len(mapping) * 1_000 + len(sheet.rows), sheet))
    return max(candidates, key=lambda item: item[0])[1]


def analyze_workbook(sheets: list[SheetData], source_bytes: bytes, filename: str) -> dict[str, Any]:
    sheet = select_tabular_sheet(sheets)
    headers = sheet.rows[0]
    mapping = map_columns(headers)
    missing_required = sorted(REQUIRED_FIELDS - mapping.keys())
    if missing_required:
        raise ValueError("Missing required columns: " + ", ".join(missing_required))
    records: list[NormalizedRecord] = []
    invalid_hashes = 0
    for row_number, row in enumerate(sheet.rows[1:], start=2):
        if not any(value not in (None, "") for value in row):
            continue
        values = {field: row[index] if index < len(row) else None for field, index in mapping.items()}
        clean_hash, hash_type = classify_hash(values.get("hash"))
        if values.get("hash") and not clean_hash:
            invalid_hashes += 1
        values["hash"] = clean_hash or values.get("hash")
        values["hash_type"] = hash_type
        values["threat_name"] = values.get("threat_name") or values.get("path") or "مؤشر غير مسمى"
        record = NormalizedRecord(row_number=row_number, **values)
        score, reasons = _base_risk(record)
        record.risk_score = score
        record.risk_level = _risk_level(score)
        record.risk_reasons = reasons
        records.append(record)

    serialised = [{key: _serialise(value) for key, value in asdict(record).items()} for record in records]
    row_fingerprints = Counter(
        json.dumps({key: value for key, value in item.items() if key != "row_number"}, sort_keys=True, ensure_ascii=False, default=str)
        for item in serialised
    )
    duplicate_rows = sum(count - 1 for count in row_fingerprints.values() if count > 1)
    valid_hashes = [record.hash for record in records if record.hash_type]
    unique_hashes = sorted(set(valid_hashes))

    def counter(field: str) -> dict[str, int]:
        return dict(Counter(str(getattr(record, field) or "غير محدد") for record in records).most_common())

    endpoint_hashes: dict[str, set[str]] = defaultdict(set)
    for record in records:
        if record.hash_type:
            endpoint_hashes[str(record.endpoint or "غير محدد")].add(str(record.hash))
    hash_counts = Counter(valid_hashes)
    repeated_hashes = [
        {"hash": item, "count": count, "endpoints": sorted({str(r.endpoint) for r in records if r.hash == item})}
        for item, count in hash_counts.most_common()
        if count > 1
    ]
    detection_lags: list[float] = []
    for record in records:
        if isinstance(record.reported_at, datetime) and isinstance(record.identified_at, datetime):
            detection_lags.append((record.reported_at - record.identified_at).total_seconds())

    return {
        "metadata": {
            "filename": filename,
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "sheet": sheet.name,
            "sheet_count": len(sheets),
            "formula_cells": sum(item.formulas for item in sheets),
            "row_count": len(records),
            "column_count": len(headers),
        },
        "mapping": {field: str(headers[index]) for field, index in mapping.items()},
        "summary": {
            "records": len(records),
            "unique_hashes": len(unique_hashes),
            "invalid_hashes": invalid_hashes,
            "duplicate_rows": duplicate_rows,
            "unresolved": sum("unresolved" in str(r.incident_status or "").lower() for r in records),
            "not_mitigated": sum("not mitigated" in str(r.status or "").lower() for r in records),
            "pending_actions": sum(_truthy(r.pending_actions) for r in records),
            "critical": sum(r.risk_level == "حرج" for r in records),
            "high": sum(r.risk_level == "مرتفع" for r in records),
        },
        "distributions": {
            "classification": counter("classification"),
            "confidence": counter("confidence"),
            "incident_status": counter("incident_status"),
            "endpoint": counter("endpoint"),
            "site": counter("site"),
            "engine": counter("engine"),
            "risk_level": counter("risk_level"),
        },
        "quality": {
            "blank_columns": [str(headers[index]) for index in range(len(headers)) if all(index >= len(row) or row[index] in (None, "") for row in sheet.rows[1:])],
            "duplicate_rows": duplicate_rows,
            "invalid_hashes": invalid_hashes,
            "formula_cells": sheet.formulas,
        },
        "timing": {
            "average_detection_to_report_seconds": round(statistics.mean(detection_lags), 2) if detection_lags else None,
            "maximum_detection_to_report_seconds": round(max(detection_lags), 2) if detection_lags else None,
        },
        "endpoint_unique_hashes": {name: len(items) for name, items in endpoint_hashes.items()},
        "repeated_hashes": repeated_hashes,
        "hashes": [{"hash": item, "type": HASH_PATTERNS[len(item)]} for item in unique_hashes],
        "records": serialised,
        "enrichment": {"status": "not_started", "providers": {}, "results": {}},
    }


def apply_enrichment(analysis: dict[str, Any], enrichment: dict[str, Any]) -> dict[str, Any]:
    analysis["enrichment"] = enrichment
    results = enrichment.get("results", {})
    record_fields = {item.name for item in fields(NormalizedRecord)}
    for record in analysis["records"]:
        intelligence = results.get(str(record.get("hash")), {})
        bonus = 0
        # Rebuild the local score on every refresh so external evidence is
        # replaced rather than accumulated across repeated provider scans.
        local_record = NormalizedRecord(**{
            name: record.get(name) for name in record_fields if name != "row_number"
        }, row_number=int(record.get("row_number") or 0))
        base_score, reasons = _base_risk(local_record)
        record["base_risk_score"] = base_score
        malicious_sources = 0
        suspicious_sources = 0
        for provider_result in intelligence.values():
            verdict = provider_result.get("verdict")
            if verdict == "malicious":
                malicious_sources += 1
            elif verdict == "suspicious":
                suspicious_sources += 1
        if malicious_sources >= 2:
            bonus = 25
            reasons.append("تأكيد خبيث من مصدرين خارجيين أو أكثر")
        elif malicious_sources == 1:
            bonus = 18
            reasons.append("تأكيد خبيث من مصدر خارجي")
        elif suspicious_sources:
            bonus = 10
            reasons.append("مؤشر مشبوه في استخبارات التهديدات")
        score = min(100, base_score + bonus)
        # External confirmation must establish a meaningful minimum severity even
        # when the uploaded row contains little or no local context.
        if malicious_sources >= 2:
            score = max(score, 85)
        elif malicious_sources == 1:
            score = max(score, 70)
        elif suspicious_sources:
            score = max(score, 40)
        record["risk_score"] = score
        record["risk_level"] = _risk_level(score)
        record["risk_reasons"] = reasons
        record["intelligence"] = intelligence
    analysis["summary"]["critical"] = sum(r["risk_level"] == "حرج" for r in analysis["records"])
    analysis["summary"]["high"] = sum(r["risk_level"] == "مرتفع" for r in analysis["records"])
    analysis["distributions"]["risk_level"] = dict(Counter(r["risk_level"] for r in analysis["records"]))
    return analysis
