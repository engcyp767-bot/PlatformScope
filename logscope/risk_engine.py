"""Risk and Confidence Engine: Calculates decoupled Risk, Confidence, and explainable justifications."""

from __future__ import annotations

from logscope.canonical import (
    CanonicalEvent,
    ActionDisposition,
    ConclusionLevel,
    RiskExplanation,
)

RISK_THRESHOLDS = (40, 70, 85)  # medium, high, critical


class RiskEngine:
    """Computes independent Risk and Confidence scores with explainable forensic auditing."""

    def evaluate(self, event: CanonicalEvent) -> None:
        reasons_inc: list[str] = []
        reasons_dec: list[str] = []
        conf_factors: list[str] = []
        matched_rules: list[str] = []

        # 1. Base Severity from Findings or Priority
        if event.findings:
            base_score = max(f.base_severity for f in event.findings)
            for f in event.findings:
                matched_rules.append(f.detection_id)
                reasons_inc.append(f"تطابق قاعدة الكشف [{f.detection_id}]: {f.title_ar}")
        else:
            p = str(event.priority or "").strip().upper()
            if p in {"CRITICAL", "FATAL"}:
                base_score = 75
                reasons_inc.append("مستوى أولوية أمني حرج في السجل المصدري (Critical Priority)")
            elif p in {"HIGH", "ERROR"}:
                base_score = 55
                reasons_inc.append("مستوى أولوية أمني مرتفع في السجل المصدري (High Priority)")
            elif p in {"WARNING", "WARN", "MEDIUM"}:
                base_score = 35
            else:
                base_score = 15

        current_risk = base_score

        # 2. Action Disposition Impact (Blocked vs Allowed)
        if event.action_disposition == ActionDisposition.BLOCK:
            if current_risk > 35:
                current_risk = max(current_risk - 15, 30)
                reasons_dec.append("تم إحباط ومنع الهجوم بواسطة أجهزة الحماية (Action=Block/Drop)")
        elif event.action_disposition == ActionDisposition.ALLOW:
            if current_risk >= 50:
                current_risk = min(current_risk + 15, 100)
                reasons_inc.append("تم السماح بمرور حركة المرور / تنفيذ الأمر دون اعتراض (Action=Allow/Permit)")
        elif event.action_disposition == ActionDisposition.ALERT:
            if current_risk >= 50:
                current_risk = min(current_risk + 5, 100)
                reasons_inc.append("إصدار تنبيه أمني دون إحباط مباشر (Action=Alert)")

        # 3. Incident Context Impact
        if event.incident_id:
            current_risk = min(max(current_risk, 85) + 5, 100)
            reasons_inc.append(f"الحدث جزء من حادثة أمنية مترابطة متعددة المراحل [{event.incident_id}]")

        # 4. Decoupled Confidence Score Calculation
        if event.findings:
            base_conf = max(f.confidence for f in event.findings)
            conf_factors.append(f"موثوقية قواعد الكشف المطابقة ({base_conf}%)")
        else:
            base_conf = 45
            conf_factors.append("سجل مصدري بدون بصمة كشف متخصصة (Baseline Confidence 45%)")

        # Confidence Factors
        if event.source_ip and event.destination_ip:
            base_conf = min(base_conf + 10, 100)
            conf_factors.append("اكتمال بيانات المصدر والوجهة (Source & Destination IPs present)")

        if event.incident_id:
            base_conf = min(base_conf + 15, 100)
            conf_factors.append("توثيق تسلسل أدلة مترابط في الحادثة الأمنية (Multi-event corroboration)")

        if not event.source_ip and not event.username:
            base_conf = max(base_conf - 15, 20)
            conf_factors.append("غياب معلومات الفاعل وعنوان المصدر (Missing actor / IP)")

        final_risk = min(max(current_risk, 0), 100)
        final_conf = min(max(base_conf, 0), 100)

        # 5. Conclusion Level
        if event.incident_id:
            conclusion = ConclusionLevel.CONFIRMED if final_risk >= 90 else ConclusionLevel.LIKELY_SUCCESSFUL
        elif event.findings:
            # Highest certainty finding
            level_rank = {
                ConclusionLevel.OBSERVED: 1,
                ConclusionLevel.SUSPICIOUS: 2,
                ConclusionLevel.LIKELY_MALICIOUS: 3,
                ConclusionLevel.CORRELATED_SUSPICIOUS: 4,
                ConclusionLevel.LIKELY_SUCCESSFUL: 5,
                ConclusionLevel.CONFIRMED: 6,
            }
            best_finding = max(event.findings, key=lambda f: level_rank.get(f.conclusion_level, 0))
            conclusion = best_finding.conclusion_level
        else:
            conclusion = ConclusionLevel.OBSERVED

        # 6. Severity Label
        medium_thresh, high_thresh, crit_thresh = RISK_THRESHOLDS
        if final_risk >= crit_thresh:
            sev = "حرج"
        elif final_risk >= high_thresh:
            sev = "مرتفع"
        elif final_risk >= medium_thresh:
            sev = "متوسط"
        else:
            sev = "منخفض"

        # Apply to Event
        event.risk_score = final_risk
        event.confidence_score = final_conf
        event.severity = sev
        event.conclusion_level = conclusion
        event.risk_explanation = RiskExplanation(
            base_score=base_score,
            final_score=final_risk,
            confidence_score=final_conf,
            reasons_for_increase=reasons_inc,
            reasons_for_decrease=reasons_dec,
            matched_rules=matched_rules,
            contributing_events_count=len(event.findings) if event.findings else 1,
            confidence_factors=conf_factors,
        )
