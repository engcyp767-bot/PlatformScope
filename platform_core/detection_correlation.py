"""Detection Correlation Layer and Incident Policy Evaluation.

Features:
1. Multi-event Thresholding: Evaluates IncidentPolicy criteria (threshold within sliding time window).
2. Entity Grouping: Tracks matches aggregated by Username, Source IP, Device, or Destination.
3. Attack Pattern Correlation: Correlates multiple distinct detection rules across MITRE tactics
   (e.g., Credential Access -> Defense Evasion -> Execution) on the same entity before creating an Incident.
4. Seamless integration with IncidentManager for automated, evidence-backed incident creation.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from logscope.canonical import CanonicalEvent, DetectionFinding
from platform_core import incident_manager

# Multi-stage attack chain definitions across MITRE ATT&CK tactics
ATTACK_CHAIN_PATTERNS = [
    {
        "pattern_name": "Credential Access followed by Defense Evasion",
        "tactics": {"Credential Access", "Defense Evasion"},
        "min_severity": "high",
        "description_ar": "رصد محاولات وصول وسرقة بيانات اعتماد أعقبها مسح سجلات أو التفاف على الدفاعات لنفس الكيان."
    },
    {
        "pattern_name": "Execution and Lateral Movement",
        "tactics": {"Execution", "Lateral Movement"},
        "min_severity": "high",
        "description_ar": "رصد تنفيذ شيفرات أو برمجيات خبيثة متزامناً مع محاولات تنقل أفقي عبر الشبكة."
    },
    {
        "pattern_name": "Initial Access and Command & Control",
        "tactics": {"Initial Access", "Command and Control"},
        "min_severity": "critical",
        "description_ar": "رصد وصول أولي مشبوه متصل بقنوات تحكم خارجية C2 لنفس الكيان."
    }
]


@dataclass
class DetectionRecord:
    rule_id: str
    rule_name: str
    severity: str
    confidence: int
    timestamp: float
    event_id: str
    username: str
    src_ip: str
    destination_ip: str
    device: str
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


class DetectionCorrelationLayer:
    """Sliding-window correlator for declarative detection rules."""

    def __init__(self, max_retention_seconds: int = 3600):
        self.max_retention_seconds = max_retention_seconds
        self._history: list[DetectionRecord] = []
        self._entity_matches: dict[str, list[DetectionRecord]] = {}
        self._promoted_correlations: set[str] = set()
        self._lock = threading.RLock()

    def _cleanup_expired(self, now: float) -> None:
        cutoff = now - self.max_retention_seconds
        self._history = [r for r in self._history if r.timestamp >= cutoff]

        for k in list(self._entity_matches.keys()):
            valid = [r for r in self._entity_matches[k] if r.timestamp >= cutoff]
            if valid:
                self._entity_matches[k] = valid
            else:
                del self._entity_matches[k]

    def process_detection(
        self,
        finding: DetectionFinding,
        event: CanonicalEvent,
        rule_dict: dict[str, Any],
        incident_mgr: Any = None
    ) -> dict[str, Any] | None:
        """Process a detection finding, evaluate IncidentPolicy and Attack Chain patterns."""
        now = time.time()
        mgr = incident_mgr or incident_manager

        rule_id = finding.detection_id
        severity = str(rule_dict.get("severity") or "medium").lower()
        confidence = int(rule_dict.get("confidence", finding.confidence))
        policy = rule_dict.get("incident_policy") or {}

        username = str(event.username or event.user_account or "").strip()
        src_ip = str(event.source_ip or event.src_ip or "").strip()
        dst_ip = str(event.destination_ip or event.destination or "").strip()
        device = str(event.device or event.hostname or "").strip()

        record = DetectionRecord(
            rule_id=rule_id,
            rule_name=finding.title_ar,
            severity=severity,
            confidence=confidence,
            timestamp=now,
            event_id=event.event_id,
            username=username,
            src_ip=src_ip,
            destination_ip=dst_ip,
            device=device,
            tactics=list(finding.mitre_tactics),
            techniques=list(finding.mitre_techniques),
            evidence=list(finding.evidence),
        )

        with self._lock:
            self._cleanup_expired(now)
            self._history.append(record)

            # Index by available entity keys
            entity_keys = []
            if username:
                entity_keys.append(f"user:{username.lower()}")
            if src_ip:
                entity_keys.append(f"src:{src_ip}")
            if device:
                entity_keys.append(f"dev:{device.lower()}")

            for ek in entity_keys:
                if ek not in self._entity_matches:
                    self._entity_matches[ek] = []
                self._entity_matches[ek].append(record)

            # 1. Evaluate Rule Incident Policy
            auto_promote = bool(policy.get("auto_promote", False))
            threshold = int(policy.get("threshold", 1))
            window_sec = int(policy.get("time_window_seconds", 60))
            min_conf = int(policy.get("min_confidence", 75))
            group_fields = list(policy.get("group_by") or ["username", "src_ip"])

            # Check if threshold is met for this specific rule
            matching_entity_key = None
            for gf in group_fields:
                if gf in {"username", "user"} and username:
                    matching_entity_key = f"user:{username.lower()}"
                    break
                if gf in {"src_ip", "source_ip"} and src_ip:
                    matching_entity_key = f"src:{src_ip}"
                    break
                if gf in {"device", "hostname"} and device:
                    matching_entity_key = f"dev:{device.lower()}"
                    break

            if auto_promote and confidence >= min_conf:
                records_in_window = []
                if matching_entity_key and matching_entity_key in self._entity_matches:
                    records_in_window = [
                        r for r in self._entity_matches[matching_entity_key]
                        if r.rule_id == rule_id and (now - r.timestamp) <= window_sec
                    ]
                else:
                    records_in_window = [
                        r for r in self._history
                        if r.rule_id == rule_id and (now - r.timestamp) <= window_sec
                    ]

                if len(records_in_window) >= threshold:
                    corr_fingerprint = f"policy:{rule_id}:{matching_entity_key or 'all'}:{int(now // window_sec)}"
                    if corr_fingerprint not in self._promoted_correlations:
                        self._promoted_correlations.add(corr_fingerprint)

                        evidence_lines = [
                            f"Rule ID: {rule_id}",
                            f"Hit Count in Window: {len(records_in_window)} (Threshold: {threshold})",
                            f"Time Window: {window_sec} seconds",
                            f"Target Entity: {matching_entity_key or 'N/A'}",
                            f"Confidence: {confidence}%",
                        ]
                        for r in records_in_window[-3:]:
                            evidence_lines.append(f"Event ID: {r.event_id} at {time.strftime('%H:%M:%S', time.gmtime(r.timestamp))}")

                        incident = mgr.promote_detection_to_incident(
                            title=f"رصد متكرر: {finding.title_ar} [{len(records_in_window)} محاولات]",
                            description=f"{finding.description_ar}. تم استيفاء شرط السياسة ({threshold} مرات خلال {window_sec} ثانية).",
                            severity=severity,
                            source_app="DetectionEngine",
                            source_system=device or src_ip or "Network",
                            event_ids=[r.event_id for r in records_in_window if r.event_id],
                            raw_evidence=evidence_lines,
                            asset_criticality="High" if severity == "critical" else "Medium",
                            business_impact="Operational" if severity in {"critical", "high"} else "Minimal",
                            created_by="DetectionEngine (Policy Automation)",
                        )
                        return {"type": "policy_promotion", "incident": incident}

            # 2. Evaluate Multi-stage Attack Chain Correlation across entities
            for ek in entity_keys:
                entity_recs = self._entity_matches.get(ek, [])
                if len(entity_recs) < 2:
                    continue

                entity_tactics = set()
                for er in entity_recs:
                    for t in er.tactics:
                        entity_tactics.add(t)

                for pat in ATTACK_CHAIN_PATTERNS:
                    req_tactics = pat["tactics"]
                    if req_tactics.issubset(entity_tactics):
                        pat_fingerprint = f"attack_chain:{pat['pattern_name']}:{ek}:{int(now // 300)}"
                        if pat_fingerprint not in self._promoted_correlations:
                            self._promoted_correlations.add(pat_fingerprint)

                            chain_events = [er for er in entity_recs if any(t in req_tactics for t in er.tactics)]
                            evidence_chain = [
                                f"Attack Pattern: {pat['pattern_name']}",
                                f"Correlated Entity: {ek}",
                                f"Matched Tactics: {', '.join(sorted(list(req_tactics)))}",
                                f"Correlated Rules: {', '.join(sorted(list({er.rule_id for er in chain_events})))}",
                            ]

                            incident = mgr.promote_detection_to_incident(
                                title=f"سلسلة هجوم مترابطة: {pat['pattern_name']}",
                                description=f"{pat['description_ar']} - ارتبطت عدة كواشف أمنية متتالية على نفس الكيان ({ek}).",
                                severity="critical",
                                source_app="DetectionCorrelationLayer",
                                source_system=device or src_ip or "UnifiedSOC",
                                event_ids=[er.event_id for er in chain_events if er.event_id],
                                raw_evidence=evidence_chain,
                                asset_criticality="Critical",
                                business_impact="Operational",
                                created_by="DetectionCorrelationLayer (Attack Chain)",
                            )
                            return {"type": "attack_chain_promotion", "incident": incident}

        return None


# Global correlation layer singleton
_global_correlation_layer: DetectionCorrelationLayer | None = None
_correlation_lock = threading.Lock()


def get_detection_correlation_layer() -> DetectionCorrelationLayer:
    global _global_correlation_layer
    if _global_correlation_layer is None:
        with _correlation_lock:
            if _global_correlation_layer is None:
                _global_correlation_layer = DetectionCorrelationLayer()
    return _global_correlation_layer
