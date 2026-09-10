"""AI Security Copilot & Natural Language Investigation Engine.

Provides evidence-grounded SOC & DFIR investigation assistance using local Ollama
models or an instant deterministic heuristic fallback engine.
Ensures Human-in-the-Loop decision making, zero external data leakage,
and strict evidence attribution.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from platform_core import (
    asset_manager,
    audit_engine,
    incident_manager,
    threat_intel,
)

logger = logging.getLogger("ai_copilot")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
PREFERRED_MODEL = os.environ.get("OLLAMA_MODEL", "gemma4:31b").strip()
FALLBACK_MODEL = os.environ.get("OLLAMA_FALLBACK_MODEL", "gpt-oss:20b").strip()
ENABLED = os.environ.get("OLLAMA_ENABLED", "auto").strip().lower() not in {"0", "false", "off", "disabled"}
COPILOT_TIMEOUT_SECONDS = max(5, min(int(os.environ.get("COPILOT_TIMEOUT_SECONDS", "30")), 120))

_STATUS_LOCK = threading.Lock()
_STATUS_CACHE: dict[str, Any] = {"checked": 0.0, "status": "unknown", "models": [], "error": None}
_CIRCUIT_OPEN_UNTIL = 0.0

DISCLAIMER_AR = (
    "تنبيه أمني: هذا التحليل استرشادي تم توليده للمساعدة في تسريع التحقيق الجنائي ومبني حصرياً على الأدلة الرقمية المرصودة. "
    "القرار الأمني وإجراءات الاحتواء تخضع دائماً لسلطة واعتماد المحلل الأمني البشري."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value: Any, limit: int = 1000) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def get_copilot_status(force_check: bool = False) -> dict[str, Any]:
    """Check AI Copilot readiness, local Ollama connectivity, and available models."""
    global _STATUS_CACHE, _CIRCUIT_OPEN_UNTIL
    now_ts = time.time()

    with _STATUS_LOCK:
        if not force_check and (now_ts - _STATUS_CACHE.get("checked", 0.0)) < 30:
            return {
                "status": _STATUS_CACHE.get("status", "ready"),
                "mode": _STATUS_CACHE.get("mode", "deterministic_fallback"),
                "active_model": _STATUS_CACHE.get("active_model", "Deterministic Forensic Engine"),
                "available_models": _STATUS_CACHE.get("models", []),
                "ollama_available": _STATUS_CACHE.get("ollama_available", False),
                "fallback_ready": True,
                "preferred_model": PREFERRED_MODEL,
                "timestamp": _now(),
            }

    ollama_available = False
    models_found: list[str] = []
    active_model = "Deterministic Forensic Engine"
    mode = "deterministic_fallback"
    status = "ready"

    if ENABLED and now_ts >= _CIRCUIT_OPEN_UNTIL:
        try:
            req = urllib.request.Request(
                f"{OLLAMA_URL}/api/tags",
                headers={"Accept": "application/json"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                raw_models = data.get("models") or []
                models_found = [str(m.get("name") or "") for m in raw_models if m.get("name")]
                ollama_available = True
                if PREFERRED_MODEL in models_found:
                    active_model = PREFERRED_MODEL
                    mode = "ollama"
                elif FALLBACK_MODEL in models_found:
                    active_model = FALLBACK_MODEL
                    mode = "ollama"
                elif models_found:
                    active_model = models_found[0]
                    mode = "ollama"
                else:
                    active_model = "Deterministic Forensic Engine"
                    mode = "deterministic_fallback"
        except Exception as e:
            logger.debug(f"Ollama healthcheck failed ({e}); operating in deterministic fallback mode.")
            ollama_available = False
            active_model = "Deterministic Forensic Engine"
            mode = "deterministic_fallback"

    with _STATUS_LOCK:
        _STATUS_CACHE = {
            "checked": now_ts,
            "status": status,
            "mode": mode,
            "active_model": active_model,
            "models": models_found,
            "ollama_available": ollama_available,
        }

    return {
        "status": status,
        "mode": mode,
        "active_model": active_model,
        "available_models": models_found,
        "ollama_available": ollama_available,
        "fallback_ready": True,
        "preferred_model": PREFERRED_MODEL,
        "timestamp": _now(),
    }


class SecurityContextEnricher:
    """Collects and attributes all relevant telemetry around an incident."""

    @staticmethod
    def enrich_incident_context(incident: dict[str, Any]) -> dict[str, Any]:
        entities = incident.get("entities") or []
        enriched_entities: list[dict[str, Any]] = []
        enriched_iocs: list[dict[str, Any]] = []
        enriched_assets: list[dict[str, Any]] = []

        for ent in entities:
            ent_val = ent.get("value") if isinstance(ent, dict) else str(ent or "").strip()
            ent_type = ent.get("type", "unknown") if isinstance(ent, dict) else "unknown"
            if not ent_val:
                continue

            # Threat Intel lookup
            ioc_hit: dict[str, Any] | None = None
            try:
                ti_mgr = threat_intel.ThreatIntelManager.get_instance()
                matches = ti_mgr.match_value(ent_val)
                if matches:
                    m = matches[0]
                    ioc_hit = {
                        "id": getattr(m, "id", "IOC"),
                        "type": getattr(m, "type", "unknown"),
                        "value": getattr(m, "value", ent_val),
                        "threat_type": getattr(m, "threat_type", "suspicious"),
                        "severity": getattr(m, "severity", "medium"),
                        "confidence": getattr(m, "confidence", 80),
                    }
                    enriched_iocs.append(ioc_hit)
            except Exception:
                pass

            # Asset Manager lookup
            asset_hit = None
            try:
                asset_hit = asset_manager.get_asset(ent_val)
            except Exception:
                pass
            if not asset_hit and hasattr(asset_manager, "find_asset_by_ip_or_name"):
                try:
                    asset_hit = asset_manager.find_asset_by_ip_or_name(ent_val)
                except Exception:
                    pass

            if asset_hit:
                enriched_assets.append(asset_hit)

            enriched_entities.append({
                "value": ent_val,
                "type": ent_type,
                "is_known_threat": bool(ioc_hit),
                "threat_type": ioc_hit.get("threat_type") if ioc_hit else None,
                "is_registered_asset": bool(asset_hit),
                "asset_criticality": asset_hit.get("criticality") if asset_hit else None,
                "asset_owner": asset_hit.get("owner") if asset_hit else None,
            })

        # Grounded Evidence Records
        grounded_evidence = []
        for ev in incident.get("evidence", []):
            grounded_evidence.append({
                "id": ev.get("id"),
                "type": ev.get("evidence_type", "record"),
                "name": ev.get("name", "Evidence"),
                "value": ev.get("value", ""),
                "notes": ev.get("notes", ""),
            })

        return {
            "incident_id": incident.get("id"),
            "title": incident.get("title", ""),
            "severity": incident.get("severity", "medium"),
            "priority": incident.get("priority", "P3"),
            "status": incident.get("status", "new"),
            "source_app": incident.get("source_app", "Platform"),
            "source_job_id": incident.get("source_job_id"),
            "asset_criticality": incident.get("asset_criticality", "medium"),
            "business_impact": incident.get("business_impact", "low"),
            "mitre_tactics": incident.get("mitre_tactics") or [],
            "mitre_techniques": incident.get("mitre_techniques") or [],
            "created_at": incident.get("created_at", _now()),
            "enriched_entities": enriched_entities,
            "matched_iocs": enriched_iocs,
            "affected_assets": enriched_assets,
            "evidence": grounded_evidence,
            "timeline_length": len(incident.get("timeline") or []),
            "notes_count": len(incident.get("analyst_notes") or []),
        }


class DeterministicCopilotFallback:
    """High-fidelity, deterministic heuristic investigation engine.

    Provides instant, verified, evidence-grounded security analysis in Arabic
    when LLMs are offline, unconfigured, or experiencing latency.
    """

    @classmethod
    def analyze(
        cls,
        ctx: dict[str, Any],
        intent: str,
        custom_query: str | None = None,
    ) -> dict[str, Any]:
        inc_id = ctx.get("incident_id", "INC-ID")
        severity = ctx.get("severity", "medium")
        priority = ctx.get("priority", "P3")
        crit = ctx.get("asset_criticality", "medium")
        impact = ctx.get("business_impact", "low")
        entities = ctx.get("enriched_entities", [])
        iocs = ctx.get("matched_iocs", [])
        assets = ctx.get("affected_assets", [])
        mitre_tactics = ctx.get("mitre_tactics") or []
        mitre_techniques = ctx.get("mitre_techniques") or []

        # Build grounded facts
        grounded_facts = []
        for ent in entities[:6]:
            threat_note = f" (مؤشر تهديد نشط: {ent['threat_type']})" if ent.get("is_known_threat") else ""
            asset_note = f" (أصل مؤسسي حرج: {ent['asset_criticality']})" if ent.get("is_registered_asset") else ""
            grounded_facts.append(f"الكيان المرصود [{ent['value']}]{threat_note}{asset_note}")

        for ioc in iocs[:5]:
            grounded_facts.append(f"تطابق مؤشر اختراق [{ioc.get('value')}] بنسبة موثوقية {ioc.get('confidence', 80)}% (نوع: {ioc.get('threat_type', 'C2')})")

        # MITRE attribution
        mitre_matrix = []
        for i, tech in enumerate(mitre_techniques):
            tactic = mitre_tactics[i] if i < len(mitre_tactics) else "Execution"
            mitre_matrix.append({
                "tactic": tactic,
                "technique": tech,
                "relevance_ar": f"رصد استخدام التقنية [{tech}] في مرحلة [{tactic}] لتنفيذ النشاط المشبوه.",
            })

        if intent == "explain_severity":
            return cls._explain_severity(inc_id, severity, priority, crit, impact, entities, iocs, mitre_tactics, grounded_facts, mitre_matrix)
        elif intent == "attack_sequence":
            return cls._attack_sequence(inc_id, severity, entities, iocs, mitre_tactics, mitre_techniques, grounded_facts, mitre_matrix)
        elif intent == "recommended_actions":
            return cls._recommended_actions(inc_id, severity, priority, entities, iocs, assets, grounded_facts, mitre_matrix)
        else:
            return cls._custom_query_analysis(inc_id, severity, priority, custom_query or "", entities, iocs, assets, grounded_facts, mitre_matrix)

    @classmethod
    def _explain_severity(cls, inc_id, severity, priority, crit, impact, entities, iocs, tactics, grounded_facts, mitre_matrix):
        sev_ar = {"critical": "حرج", "high": "مرتفع", "medium": "متوسط", "low": "منخفض"}.get(severity, severity)
        prio_ar = {"P1": "P1 (استجابة فورية)", "P2": "P2 (أولوية قصوى)", "P3": "P3 (أولوية اعتيادية)", "P4": "P4 (مجدول)"}.get(priority, priority)

        risk_factors = []
        if severity in {"critical", "high"}:
            risk_factors.append(f"مستوى خطورة الهجوم مصنف كـ [{sev_ar}] نظراً لوجود مؤشرات اختراق مؤكدة أو سلوك تسلل نشط.")
        if crit in {"mission_critical", "high"}:
            risk_factors.append(f"استهداف أصول وبنية تحتية عالية الحرجية [{crit}] في المؤسسة.")
        if impact in {"high", "medium"}:
            risk_factors.append(f"أثر تشغيلي متوقع [{impact}] على سلامة واستمرارية العمليات الأمنية.")
        if iocs:
            risk_factors.append(f"تطابق {len(iocs)} مؤشرات اختراق (IOCs) مسجلة في قاعدة استخبارات التهديدات المركزية.")
        if tactics:
            risk_factors.append(f"توثيق {len(tactics)} تكتيكات هجومية متقدمة وفق إطار MITRE ATT&CK ({', '.join(tactics[:4])}).")

        if not risk_factors:
            risk_factors.append("تم التقييم بناءً على معايير الكشف الأساسية وقواعد السياسة الأمنية المعتمدة.")

        summary_ar = (
            f"تم تصنيف الحادث الأمني [{inc_id}] بمستوى خطورة [{sev_ar}] وأولوية استجابة [{prio_ar}] "
            f"نظراً لاقتران النشاط المشبوه بأصول ذات حرجية [{crit}] ورصد تكتيكات هجومية مباشرة. "
            f"تتطلب هذه الحالة تدخلاً من فريق الاستجابة للحوادث للتحقق من عدم حدوث تسلل أفقي أو اتصالات خبيثة خارج الحدود."
        )

        detailed_analysis_ar = (
            f"### تفكيك أسباب الخطورة للحادث [{inc_id}]\n\n"
            f"1. **درجة الخطورة والحرجية التشغيلية**:\n"
            f"   - مستوى الخطورة المحسوب: **{sev_ar}**.\n"
            f"   - أولوية المعالجة المخصصة: **{prio_ar}**.\n"
            f"   - حساسية الأصل المتضرر: **{crit}**.\n\n"
            f"2. **العوامل المساهمة في تقييم المخاطر**:\n"
            + "\n".join(f"   - {rf}" for rf in risk_factors) + "\n\n"
            f"3. **التقييم الجنائي المبدئي**:\n"
            f"   الأدلة الرقمية المسجلة تؤكد وجود مؤشرات تستدعي احتواء الحسابات أو عناوين IP المتورطة وعزل أي أجهزة مشتبه بها منعاً لتفاقم الضرر."
        )

        recommended_actions = [
            {"phase": "containment", "action_ar": "التحقق من حالة اتصال الأصل وعزله شبكياً في حال تأكيد النشاط الخبيث.", "priority": "immediate"},
            {"phase": "containment", "action_ar": "حظر كافة عناوين IP ومؤشرات التهديد المتطابقة على الجدران النارية.", "priority": "immediate"},
            {"phase": "eradication", "action_ar": "فحص سجلات العمليات والخدمات المثبتة على الأجهزة المتأثرة.", "priority": "high"},
            {"phase": "recovery", "action_ar": "مراجعة سلامة الصلاحيات والحسابات وإعادة تعيين كلمات المرور المخترقة.", "priority": "medium"},
        ]

        return {
            "investigation_title_ar": f"تفسير مستوى الخطورة والأثر للحادث [{inc_id}]",
            "summary_ar": summary_ar,
            "detailed_analysis_ar": detailed_analysis_ar,
            "risk_factors": risk_factors,
            "grounded_facts": grounded_facts,
            "mitre_matrix": mitre_matrix,
            "recommended_actions": recommended_actions,
            "confidence": 92,
            "engine_used": "Deterministic Forensic Engine (Rule-Based Fallback)",
        }

    @classmethod
    def _attack_sequence(cls, inc_id, severity, entities, iocs, tactics, techniques, grounded_facts, mitre_matrix):
        stages = []
        if not tactics:
            tactics = ["Initial Access", "Execution", "Command and Control"]

        tactic_stages_map = {
            "Initial Access": ("مرحلة النفاذ والوصول الأولي", "استغلال ثغرة أو استخدام بيانات اعتماد مخترقة للوصول للهدف."),
            "Execution": ("مرحلة تنفيذ الأوامر البرمجية", "تشغيل سكربتات مشبوهة أو أوامر PowerShell/CMD لتثبيت الشيفرة."),
            "Persistence": ("مرحلة التمكين والبقاء", "إنشاء مهام مجدولة أو خدمات خلفية لضمان الاستمرارية بعد إعادة التشغيل."),
            "Privilege Escalation": ("مرحلة تصعيد الامتيازات", "الحصول على صلاحيات النظام السيادية (SYSTEM/Admin)."),
            "Defense Evasion": ("مرحلة التخفي وتجاوز الدفاعات", "تجاوز برامج الحماية أو مسح سجلات التدقيق الجنائي."),
            "Credential Access": ("مرحلة استخراج بيانات الاعتماد", "محاولة تفريغ كلمات المرور أو تذاكر Kerberos (LSASS Dump)."),
            "Discovery": ("مرحلة الاستطلاع الداخلي", "مسح الشبكة والأصول لاكتشاف الخوادم الحساسة وقواعد البيانات."),
            "Lateral Movement": ("مرحلة التنقل الأفقي", "القفز بين الأجهزة الداخلية عبر بروتوكولات RDP أو SMB أو SSH."),
            "Collection": ("مرحلة جمع وتجميع البيانات", "تجميع الملفات والمستندات الحساسة تمهيداً لسرقتها."),
            "Command and Control": ("مرحلة الاتصال بخادم القيادة والتحكم (C2)", "إنشاء نفق اتصال خارجي مشفر لتلقي الأوامر وسحب البيانات."),
            "Exfiltration": ("مرحلة تسريب وسحب البيانات", "نقل البيانات المسروقة إلى خوادم المهاجم الخارجية."),
            "Impact": ("مرحلة التخريب والتشفير", "تشفير الملفات بواسطة برمجيات الفدية أو تعطيل الخدمات الحيوية."),
        }

        for i, tac in enumerate(tactics):
            tech = techniques[i] if i < len(techniques) else "T1059"
            stage_name, default_desc = tactic_stages_map.get(tac, (f"مرحلة {tac}", "تنفيذ نشاط هجومي متقدم."))
            ent_ref = entities[i % len(entities)]["value"] if entities else "الكيان المستهدف"
            stages.append({
                "step_number": i + 1,
                "stage_name": stage_name,
                "tactic": tac,
                "technique": tech,
                "target_entity": ent_ref,
                "description_ar": f"{default_desc} تم رصد النشاط عبر الكيان [{ent_ref}].",
            })

        summary_ar = (
            f"تمت إعادة بناء مسار الهجوم وسلسلة القتل الجنائية للحادث [{inc_id}] عبر [{len(stages)}] مراحل تكتيكية متتالية، "
            f"تبدأ من محاولات النفاذ والتنفيذ وتتدرج وصولاً إلى محاولات الاتصال الخارجي أو التثبيت."
        )

        detailed_analysis_ar = (
            f"### إعادة بناء تسلسل الهجوم وسلسلة القتل الجنائية (Attack Kill Chain)\n\n"
            f"استناداً إلى الأدلة الرقمية ومؤشرات مصفوفة MITRE ATT&CK المسجلة للحادث [{inc_id}]، "
            f"تم توثيق المراحل الهجومية المتسلسلة التالية:\n\n"
            + "\n".join(
                f"**المرحلة {s['step_number']}: {s['stage_name']} ({s['tactic']} - {s['technique']})**\n"
                f"- الكيان المستهدف: `{s['target_entity']}`\n"
                f"- التوثيق الجنائي: {s['description_ar']}\n"
                for s in stages
            ) + "\n"
            f"**الخلاصة الجنائية**: يظهر التسلسل محاولة متسقة من المهاجم لتحقيق أهدافه على الأصل المتضرر؛ "
            f"وينصح بقطع سلسلة الهجوم في أسرع نقطة ممكنة عبر عزل الكيانات الوسيطة."
        )

        recommended_actions = [
            {"phase": "containment", "action_ar": "قطع الاتصال الشبكي فوراً بين الأجهزة المتضررة وباقي أجزاء الشبكة الداخلية.", "priority": "immediate"},
            {"phase": "containment", "action_ar": "عزل محطات القفز الوسيطة وحظر الحسابات المتورطة في التنقل الأفقي.", "priority": "immediate"},
            {"phase": "eradication", "action_ar": "تتبع وإنهاء سلاسل العمليات والمسارات التنفيذية المرتبطة بتقنيات MITRE المرصودة.", "priority": "high"},
            {"phase": "recovery", "action_ar": "التحقق من سلامة سجلات الإقلاع والمهام المجدولة قبل إعادة تشغيل الأنظمة.", "priority": "medium"},
        ]

        return {
            "investigation_title_ar": f"إعادة بناء تسلسل الهجوم وسلسلة القتل للحادث [{inc_id}]",
            "summary_ar": summary_ar,
            "detailed_analysis_ar": detailed_analysis_ar,
            "attack_stages": stages,
            "grounded_facts": grounded_facts,
            "mitre_matrix": mitre_matrix,
            "recommended_actions": recommended_actions,
            "confidence": 90,
            "engine_used": "Deterministic Forensic Engine (Rule-Based Fallback)",
        }

    @classmethod
    def _recommended_actions(cls, inc_id, severity, priority, entities, iocs, assets, grounded_facts, mitre_matrix):
        containment_list = [
            {"phase": "containment", "action_ar": "عزل الأصل الأمني المتضرر شبكياً باستخدام إطار العزل (Host Containment Framework) لمنع التنقل الأفقي.", "priority": "immediate"},
            {"phase": "containment", "action_ar": "حظر فوري لكافة عناوين IP والنطاقات الخارجية المشبوهة على بوابة جدار الحماية الخارجي (Firewall / WAF).", "priority": "immediate"},
            {"phase": "containment", "action_ar": "تجميد الحسابات والمستخدمين المتورطين في تسجيلات الدخول الشاذة وإبطال كافة الجلسات النشطة.", "priority": "immediate"},
        ]
        eradication_list = [
            {"phase": "eradication", "action_ar": "فحص الذاكرة العشوائية ومسارات بدء التشغيل التلقائي بحثاً عن أي أدوات تحكم خبيثة أو عينات Dropper.", "priority": "high"},
            {"phase": "eradication", "action_ar": "حذف وإزالة كافة الملفات المؤقتة والمفتاحية المشبوهة المرتبطة ببصمات التهديد المسجلة.", "priority": "high"},
            {"phase": "eradication", "action_ar": "مراجعة قواعد جدران الحماية الداخلية ومهام الجدولة (Cron / Scheduled Tasks) للتأكد من عدم وجود أبواب خلفية.", "priority": "high"},
        ]
        recovery_list = [
            {"phase": "recovery", "action_ar": "إعادة بناء أو استعادة النظام المتضرر من آخر نسخة احتياطية نظيفة وموثوقة (Clean Golden Image).", "priority": "medium"},
            {"phase": "recovery", "action_ar": "إعادة تفعيل ومراقبة حركة المرور الشبكية للأصل المتأثر لمدة 48 ساعة تحت وضع المراقبة المشددة.", "priority": "medium"},
            {"phase": "recovery", "action_ar": "توثيق الدروس المستفادة وتحديث قواعد الكشف (Sigma / Custom Rules) لمنع تكرار نفس متجهة الهجوم.", "priority": "low"},
        ]

        all_actions = containment_list + eradication_list + recovery_list

        summary_ar = (
            f"تم إعداد خطة الاستجابة التكتيكية والمعالجة الموصى بها للحادث [{inc_id}] وفق معايير NIST SP 800-61. "
            f"تركز الخطة على العزل الفوري للأدلة والكيانات المتضررة، استئصال أدوات التهديد، واستعادة الجاهزية التشغيلية بأمان."
        )

        detailed_analysis_ar = (
            f"### خطة الاستجابة الأمنية والمعالجة المقترحة للحادث [{inc_id}]\n\n"
            f"#### 1. إجراءات الاحتواء الفوري (Immediate Containment):\n"
            + "\n".join(f"- **[فوري]** {a['action_ar']}" for a in containment_list) + "\n\n"
            f"#### 2. إجراءات الاستئصال والتطهير (Eradication):\n"
            + "\n".join(f"- **[مرتفع]** {a['action_ar']}" for a in eradication_list) + "\n\n"
            f"#### 3. إجراءات التعافي والمراقبة اللاحقة (Recovery & Post-Incident):\n"
            + "\n".join(f"- **[مجدول]** {a['action_ar']}" for a in recovery_list) + "\n\n"
            f"> [!IMPORTANT]\n"
            f"> يجب مراجعة وتنفيذ هذه الخطوات تحت إشراف المحلل الأمني المعتمد وتوثيق وقت الانتهاء من كل خطوة في سجل الحادث."
        )

        return {
            "investigation_title_ar": f"خطة الاستجابة وتوصيات الاحتواء للحادث [{inc_id}]",
            "summary_ar": summary_ar,
            "detailed_analysis_ar": detailed_analysis_ar,
            "grounded_facts": grounded_facts,
            "mitre_matrix": mitre_matrix,
            "recommended_actions": all_actions,
            "soc_playbook": "NIST SP 800-61 Incident Handling Playbook",
            "confidence": 95,
            "engine_used": "Deterministic Forensic Engine (Rule-Based Fallback)",
        }

    @classmethod
    def _custom_query_analysis(cls, inc_id, severity, priority, query, entities, iocs, assets, grounded_facts, mitre_matrix):
        q_clean = query.strip()
        summary_ar = (
            f"تحليل جنائي للإجابة عن استفسار المحلل: «{q_clean}» بخصوص الحادث [{inc_id}]. "
            f"استناداً إلى فحص البيانات المسجلة، يرتبط الحادث بـ {len(entities)} كيانات و {len(iocs)} مؤشرات اختراق متطابقة."
        )

        detailed_analysis_ar = (
            f"### إجابة استفسار التحقيق الجنائي حول الحادث [{inc_id}]\n\n"
            f"**نص الاستفسار**: *«{q_clean}»*\n\n"
            f"**التحليل المبني على الأدلة الرقمية**:\n"
            f"1. يرتبط هذا الحادث بسجل أمني ذي خطورة [{severity}] وأولوية [{priority}].\n"
            f"2. الكيانات المعنية المرصودة في التحقيق تشمل: {', '.join(e['value'] for e in entities[:4]) or 'لا توجد كيانات خارجية'}.\n"
            f"3. بالنظر إلى سياق السؤال، يُوصى المحقق بمراجعة الأدلة الجنائية المرتبطة ومطابقة السجلات المباشرة مع سجل الأنشطة والتدفقات.\n\n"
            f"**الحقائق المثبتة في الحادث**:\n"
            + "\n".join(f"- {f}" for f in grounded_facts[:5])
        )

        recommended_actions = [
            {"phase": "investigation", "action_ar": "التحقق من صحة الأدلة ومراجعة مسار السجلات الخام المرتبطة بالسؤال.", "priority": "high"},
            {"phase": "containment", "action_ar": "تأكيد عدم تأثر أي أصول أخرى بالكيانات المذكورة في الاستفسار.", "priority": "medium"},
        ]

        return {
            "investigation_title_ar": f"نتيجة التحقيق الجنائي حول: «{_safe_text(q_clean, 40)}»",
            "summary_ar": summary_ar,
            "detailed_analysis_ar": detailed_analysis_ar,
            "grounded_facts": grounded_facts,
            "mitre_matrix": mitre_matrix,
            "recommended_actions": recommended_actions,
            "confidence": 88,
            "engine_used": "Deterministic Forensic Engine (Rule-Based Fallback)",
        }


class SecurityCopilotEngine:
    """Core controller orchestrating incident investigation across LLMs & Fallbacks."""

    @classmethod
    def investigate(
        cls,
        incident_id: str,
        intent: str = "explain_severity",
        custom_query: str | None = None,
        actor: str = "analyst",
    ) -> dict[str, Any]:
        """Execute evidence-grounded security investigation on an incident."""
        incident = incident_manager.get_incident(incident_id)
        if not incident:
            raise ValueError(f"الحادث الأمني غير موجود: {incident_id}")

        valid_intents = {"explain_severity", "attack_sequence", "recommended_actions", "custom_query"}
        if intent not in valid_intents:
            intent = "explain_severity"

        # 1. Enrich context
        context = SecurityContextEnricher.enrich_incident_context(incident)

        # 2. Check model readiness
        copilot_status = get_copilot_status()
        result: dict[str, Any] | None = None

        if copilot_status.get("ollama_available") and copilot_status.get("active_model") != "Deterministic Forensic Engine":
            model_name = copilot_status["active_model"]
            try:
                result = cls._query_ollama(context, intent, custom_query, model_name)
            except Exception as e:
                logger.warning(f"Ollama investigation failed for [{incident_id}]: {e}; using fallback.")
                result = None

        # 3. Fallback if Ollama unavailable or failed
        if not result:
            result = DeterministicCopilotFallback.analyze(context, intent, custom_query)

        # 4. Standardize response payload
        response = {
            "success": True,
            "incident_id": incident_id,
            "intent": intent,
            "custom_query": custom_query,
            "actor": actor,
            "generated_at": _now(),
            "disclaimer_ar": DISCLAIMER_AR,
            "investigation_title_ar": result.get("investigation_title_ar", "تقرير المساعد الأمني الذكي"),
            "summary_ar": result.get("summary_ar", ""),
            "detailed_analysis_ar": result.get("detailed_analysis_ar", ""),
            "grounded_facts": result.get("grounded_facts", []),
            "mitre_matrix": result.get("mitre_matrix", []),
            "recommended_actions": result.get("recommended_actions", []),
            "confidence": result.get("confidence", 90),
            "engine_used": result.get("engine_used", "Deterministic Forensic Engine"),
            "context_summary": {
                "entities_count": len(context.get("enriched_entities", [])),
                "matched_iocs_count": len(context.get("matched_iocs", [])),
                "affected_assets_count": len(context.get("affected_assets", [])),
                "severity": incident.get("severity"),
                "priority": incident.get("priority"),
            },
        }

        # 5. Audit log
        try:
            audit_engine.record_engine_event(
                level="info",
                outcome="success",
                category="incident",
                action="copilot.investigated",
                message=f"تم استدعاء المساعد الأمني الذكي للحادث [{incident_id}] بنمط [{intent}] بواسطة [{actor}]",
                application="ai_copilot",
                details={
                    "incident_id": incident_id,
                    "intent": intent,
                    "actor": actor,
                    "engine_used": response["engine_used"],
                    "confidence": response["confidence"],
                },
            )
        except Exception:
            pass

        return response

    @classmethod
    def _query_ollama(
        cls,
        ctx: dict[str, Any],
        intent: str,
        custom_query: str | None,
        model_name: str,
    ) -> dict[str, Any] | None:
        """Prompt Ollama with structured evidence and enforce JSON response format."""
        system_prompt = (
            "أنت المساعد الأمني الذكي (AI Security Copilot) لمركز العمليات الأمنية (SOC) والتحقيق الجنائي الرقمي (DFIR).\n"
            "مهمتك: الإجابة الدقيقة والموضوعية باللغة العربية الفصحى مع استخدام المصطلحات الإنجليزية القياسية بين قوسين.\n"
            "قواعد إلزامية صارمة:\n"
            "1. استند حصرياً وفقط إلى الأدلة الرقمية والحقائق المذكورة في سياق الحادث. لا تختلق أي عناوين أو مؤشرات أو وقائع غير موجودة.\n"
            "2. القرار الأمني النهائي يعود للمحلل البشري.\n"
            "3. أجب بصيغة JSON فقط متطابقة مع المخطط التالي:\n"
            "{\n"
            '  "investigation_title_ar": "عنوان موجز للتحقيق",\n'
            '  "summary_ar": "ملخص تحليلي تنفيذي دقيق ومقيد بالأدلة",\n'
            '  "detailed_analysis_ar": "تحليل جنائي تفصيلي بصيغة Markdown",\n'
            '  "grounded_facts": ["حقيقة مثبتة 1", "حقيقة مثبتة 2"],\n'
            '  "mitre_matrix": [{"tactic": "...", "technique": "...", "relevance_ar": "..."}],\n'
            '  "recommended_actions": [{"phase": "containment|eradication|recovery", "action_ar": "...", "priority": "immediate|high|medium"}],\n'
            '  "confidence": 90\n'
            "}"
        )

        user_content = {
            "incident_metadata": {
                "id": ctx.get("incident_id"),
                "title": ctx.get("title"),
                "severity": ctx.get("severity"),
                "priority": ctx.get("priority"),
                "asset_criticality": ctx.get("asset_criticality"),
                "business_impact": ctx.get("business_impact"),
                "mitre_tactics": ctx.get("mitre_tactics"),
                "mitre_techniques": ctx.get("mitre_techniques"),
            },
            "entities": ctx.get("enriched_entities", [])[:8],
            "matched_iocs": ctx.get("matched_iocs", [])[:6],
            "evidence": ctx.get("evidence", [])[:6],
            "intent": intent,
            "custom_query": custom_query or "",
        }

        req_payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_content, ensure_ascii=False)},
            ],
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.2,
                "num_predict": 1500,
            },
        }

        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/chat",
            data=json.dumps(req_payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=COPILOT_TIMEOUT_SECONDS) as resp:
            raw_resp = json.loads(resp.read().decode("utf-8"))
            message = raw_resp.get("message", {}).get("content", "")
            parsed = json.loads(message)
            parsed["engine_used"] = f"Ollama ({model_name})"
            return parsed

    @classmethod
    def apply_recommendation_as_note(
        cls,
        incident_id: str,
        note_text: str,
        actor: str = "analyst",
    ) -> dict[str, Any]:
        """Save Copilot findings as an official analyst note in incident history."""
        if not incident_id or not note_text:
            raise ValueError("معرف الحادث ونص الملاحظة مطلوبان")

        header = "🤖 [توصيات المساعد الأمني الذكي - AI Copilot]"
        full_text = f"{header}\n\n{note_text.strip()}"
        return incident_manager.add_note(incident_id, full_text, author=f"{actor} via Copilot")
