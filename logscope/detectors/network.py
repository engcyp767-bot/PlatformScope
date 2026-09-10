"""Network and Firewall / UTM Domain Detector."""

from __future__ import annotations

import re
from logscope.canonical import CanonicalEvent, DetectionFinding, ConclusionLevel
from logscope.detectors import BaseDetector


class NetworkDetector(BaseDetector):
    """Detects network-level threats, port scanning, spoofing, floods, and unauthorized tunnels."""
    detector_name = "network_firewall"

    def analyze_event(self, event: CanonicalEvent) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        raw = event.message
        raw_lower = (raw + " " + " ".join(str(v) for v in event.raw_fields.values())).lower()

        # 1. ICMP Unreachable Attack (DDoS / Flood)
        if "icmp unreachable attack" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-NET-DOS-001",
                title_ar="هجوم حجب الخدمة عبر رسائل ICMP غير قابلة للوصول (ICMP Unreachable Attack)",
                description_ar="رصد سيل مكثف من رسائل بروتوكول ICMP بهدف استنزاف سعة روابط الشبكة وموارد جدار الحماية.",
                base_severity=85,
                confidence=95,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="هجمات حجب الخدمة (Denial of Service - DoS)",
                mitre_tactics=["Impact", "التأثير والتخريب"],
                mitre_techniques=["T1498.001 - Direct Network Flood"],
                evidence=["تطابق AttackType: ICMP unreachable attack", f"Source IP: {event.source_ip}"],
            ))

        # 2. IP Spoofing Attack
        elif "ip spoof attack" in raw_lower or "spoofed packet" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-NET-SPOOF-001",
                title_ar="هجوم انتحال العناوين الشبكية (IP Address Spoofing Attack)",
                description_ar="رصد حزم شبكية واردة بعناوين مصدر منتحلة لتجاوز سياسات الجدار الناري أو تضليل أجهزة التتبع.",
                base_severity=88,
                confidence=95,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="انتحال الهوية وتجاوز الدفاعات (Defense Evasion)",
                mitre_tactics=["Defense Evasion", "إخفاء الأثر والتمويه"],
                mitre_techniques=["T1036 - Masquerading"],
                evidence=["تطابق AttackType: IP spoof attack", f"Source IP: {event.source_ip}"],
            ))

        # 3. Trace Route Attack / Reconnaissance
        elif "trace route attack" in raw_lower or "traceroute scan" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-NET-SCAN-001",
                title_ar="استطلاع وتتبع مسار الشبكة المتقدم (Traceroute Reconnaissance Attack)",
                description_ar="رصد حزم استطلاع شبكي واسع لاستكشاف طوبولوجيا أجهزة التوجيه وجدران الحماية للشبكة.",
                base_severity=70,
                confidence=90,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="الاستطلاع والمسح الشبكي (Reconnaissance)",
                mitre_tactics=["Reconnaissance", "الاستطلاع والجمع المسبق"],
                mitre_techniques=["T1595.001 - Port Scan"],
                evidence=["تطابق AttackType: Trace route attack"],
            ))

        # 4. Syn Flood / UDP Flood / DoS
        elif any(f in raw_lower for f in ("syn flood", "udp flood", "tcp flood", "icmp flood")):
            findings.append(DetectionFinding(
                detection_id="DET-NET-DOS-002",
                title_ar="هجوم إغراق الحزم الشبكية (Network Packet Flood / DoS)",
                description_ar="محاولة استنزاف موارد جدول جلسات جدار الحماية عبر ضخ سيل هائل من الحزم الشبكية.",
                base_severity=85,
                confidence=90,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="هجمات حجب الخدمة (Denial of Service - DoS)",
                mitre_tactics=["Impact", "التأثير والتخريب"],
                mitre_techniques=["T1498 - Network Denial of Service"],
                evidence=["تطابق بصمة Network Flood"],
            ))

        # 5. Unauthorized Encrypted Tunnels (Zerotier, Tor, VPN Bypass)
        elif "zerotier" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-NET-P2P-001",
                title_ar="أدوات اختراق وتجاوز الشبكة الداخلية - نفق Zerotier P2P (Zerotier Penetration)",
                description_ar="رصد اتصالات نفق Zerotier المشفر لتجاوز ضوابط العزل بين الشبكات الداخلية.",
                base_severity=85,
                confidence=95,
                conclusion_level=ConclusionLevel.LIKELY_MALICIOUS,
                threat_family="أدوات اختراق (Penetration Tools / Tunneling)",
                mitre_tactics=["Command and Control", "القيادة والسيطرة"],
                mitre_techniques=["T1572 - Protocol Tunneling"],
                evidence=["رصد بروتوكول Zerotier P2P المشفر"],
            ))

        elif "tor exit" in raw_lower or "tor-exit" in raw_lower:
            findings.append(DetectionFinding(
                detection_id="DET-NET-ANON-001",
                title_ar="اتصال عبر عقدة شبكة تور المخفية (Tor Exit Node Connection)",
                description_ar="رصد اتصال شبكي وارد أو صادر عبر شبكة Tor المجهولة للالتفاف على الرقابة والتحليل.",
                base_severity=80,
                confidence=90,
                conclusion_level=ConclusionLevel.SUSPICIOUS,
                threat_family="تجاوز الضوابط والتمويه (Anonymization)",
                mitre_tactics=["Command and Control", "القيادة والسيطرة"],
                mitre_techniques=["T1090.003 - Multi-hop Proxy"],
                evidence=["تطابق عقدة Tor مع عناوين الشبكة"],
            ))

        return findings
