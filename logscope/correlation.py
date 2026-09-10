"""Bounded-Memory Forensic Correlation and Incident Engine operating on CanonicalEvent streams."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any
from logscope.canonical import CanonicalEvent, DetectionFinding, Incident, ConclusionLevel


class BoundedStateMap:
    """Least-Recently-Used (LRU) bounded dictionary to guarantee constant memory footprint."""
    def __init__(self, max_entries: int = 2000):
        self._max = max_entries
        self._data: OrderedDict[str, Any] = OrderedDict()

    def get(self, key: str, default: Any = None) -> Any:
        if key in self._data:
            self._data.move_to_end(key)
            return self._data[key]
        return default

    def set(self, key: str, value: Any) -> None:
        if key in self._data:
            self._data.move_to_end(key)
        self._data[key] = value
        if len(self._data) > self._max:
            self._data.popitem(last=False)

    def contains(self, key: str) -> bool:
        return key in self._data

    def remove(self, key: str) -> None:
        self._data.pop(key, None)


class CorrelationEngine:
    """Streams CanonicalEvents, detects multi-event attack sequences, and produces structured Incidents."""

    def __init__(self, max_state_entries: int = 2000):
        self._failed_logons = BoundedStateMap(max_entries=max_state_entries)
        self._logon_sessions = BoundedStateMap(max_entries=max_state_entries)
        self._network_scans = BoundedStateMap(max_entries=max_state_entries)
        self._incidents: dict[str, Incident] = {}
        self._incident_counter = 1

    def _next_incident_id(self, prefix: str = "INC") -> str:
        iid = f"{prefix}-2026-{self._incident_counter:05d}"
        self._incident_counter += 1
        return iid

    def process_event(self, event: CanonicalEvent) -> list[Incident]:
        """Correlate event in real-time, annotating event with incident_id and findings."""
        new_incidents: list[Incident] = []
        eid = str(event.event_id or "").strip()
        src = event.source_ip
        user = event.username

        # -------------------------------------------------------------
        # Pattern 1: Brute-Force to Compromise (Windows 4625 -> 4624 / Linux)
        # -------------------------------------------------------------
        if eid == "4625" or "failed password" in event.message.lower() or "an account failed to log on" in event.message.lower():
            key = f"{src}::{user}" if user else src
            if key:
                current_state = self._failed_logons.get(key, {"count": 0, "events": []})
                current_state["count"] += 1
                current_state["events"].append({
                    "time": event.event_time,
                    "event_id": eid,
                    "user": user,
                    "src": src,
                })
                # Cap tracked events per key to prevent unbounded growth
                if len(current_state["events"]) > 20:
                    current_state["events"] = current_state["events"][-20:]
                self._failed_logons.set(key, current_state)

                if current_state["count"] >= 5:
                    det_id = "DET-CORR-BRUTEFORCE-001"
                    event.detection_ids.append(det_id)
                    event.findings.append(DetectionFinding(
                        detection_id=det_id,
                        title_ar="هجوم تخمين كلمات مرور مترابط (Correlated Brute-Force)",
                        description_ar=f"تم رصد تكرار {current_state['count']} محاولات دخول فاشلة من المصدر [{src or 'غير محدد'}] ضد الحساب [{user or 'مستخدمين متعددين'}].",
                        base_severity=75,
                        confidence=90,
                        conclusion_level=ConclusionLevel.CORRELATED_SUSPICIOUS,
                        threat_family="سرقة بيانات الاعتماد (Credential Access)",
                        mitre_tactics=["Credential Access", "سرقة بيانات الاعتماد"],
                        mitre_techniques=["T1110.001 - Password Guessing"],
                        evidence=[f"Failures count: {current_state['count']}", f"Source IP: {src}", f"Target User: {user}"],
                    ))

        elif eid == "4624" or "accepted password" in event.message.lower() or "accepted publickey" in event.message.lower():
            key = f"{src}::{user}" if user else src
            prior_failures = self._failed_logons.get(key) if key else None
            
            if prior_failures and prior_failures.get("count", 0) >= 5:
                # COMPROMISE DETECTED: Successful logon after repeated brute force!
                iid = self._next_incident_id("INC-AUTH")
                event.incident_id = iid
                det_id = "DET-CORR-TAKEOVER-001"
                event.detection_ids.append(det_id)

                inc = Incident(
                    incident_id=iid,
                    title_ar="اشتباه اختراق حساب إثر هجوم تخمين ناجح (Brute-Force Account Takeover)",
                    description_ar=f"سلسلة هجوم حرجة: تم تسجيل دخول ناجح للحساب [{user}] من المصدر [{src}] بعد {prior_failures['count']} محاولات فاشلة متتالية.",
                    start_time=prior_failures["events"][0]["time"] if prior_failures["events"] else event.event_time,
                    end_time=event.event_time,
                    source_ips=[src] if src else [],
                    usernames=[user] if user else [],
                    event_count=prior_failures["count"] + 1,
                    detection_ids=["DET-CORR-BRUTEFORCE-001", det_id],
                    mitre_tactics=["Credential Access", "Initial Access"],
                    mitre_techniques=["T1110 - Brute Force", "T1078 - Valid Accounts"],
                    risk_score=95,
                    confidence_score=92,
                    conclusion_level=ConclusionLevel.LIKELY_SUCCESSFUL,
                    timeline_events=prior_failures["events"] + [{
                        "time": event.event_time, "event_id": eid, "user": user, "src": src, "status": "SUCCESS"
                    }],
                )
                self._incidents[iid] = inc
                new_incidents.append(inc)

                # Reset failure state
                self._failed_logons.remove(key)

                # Store session for privilege escalation tracking
                if user:
                    self._logon_sessions.set(user, {"time": event.event_time, "incident_id": iid, "src": src})

        # -------------------------------------------------------------
        # Pattern 2: Privilege Escalation on Freshly Compromised Session
        # -------------------------------------------------------------
        if eid in {"4672", "7045", "4728", "4732"} and user:
            session = self._logon_sessions.get(user)
            if session:
                linked_iid = session.get("incident_id")
                if linked_iid and linked_iid in self._incidents:
                    inc = self._incidents[linked_iid]
                    inc.title_ar += " متبوعاً بتصعيد صلاحيات أو تثبيت تواجد"
                    inc.risk_score = 98
                    inc.conclusion_level = ConclusionLevel.CONFIRMED
                    inc.detection_ids.append("DET-CORR-PRIVCHAIN-001")
                    inc.event_count += 1
                    inc.timeline_events.append({
                        "time": event.event_time, "event_id": eid, "user": user, "action": "Privilege Activity"
                    })
                    event.incident_id = linked_iid
                    event.detection_ids.append("DET-CORR-PRIVCHAIN-001")

        return new_incidents

    def get_all_incidents(self) -> list[Incident]:
        return list(self._incidents.values())
