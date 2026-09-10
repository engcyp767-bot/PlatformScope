"""Formal, printable Arabic HTML report."""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any


def _e(value: Any) -> str:
    text = str(value if value not in (None, "") else "—")
    if any(marker in text for marker in ("Ø", "Ù", "Ã", "Â")):
        try:
            text = text.encode("latin1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    return html.escape(text)


def _rows(distribution: dict[str, int]) -> str:
    total = sum(distribution.values()) or 1
    return "".join(
        f"<tr><td>{_e(name)}</td><td>{count}</td><td>{count / total:.1%}</td></tr>"
        for name, count in distribution.items()
    )


def build_report_html(analysis: dict[str, Any], job_id: str) -> str:
    metadata = analysis["metadata"]
    summary = analysis["summary"]
    distributions = analysis["distributions"]
    quality = analysis["quality"]
    enrichment = analysis.get("enrichment", {})
    model_analysis = analysis.get("model_analysis") or {}
    model_result = model_analysis.get("result") or {} if model_analysis.get("status") == "completed" else {}
    records = sorted(analysis["records"], key=lambda item: item.get("risk_score", 0), reverse=True)
    top_records = records[:20]
    by_hash: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if record.get("hash_type"):
            by_hash.setdefault(str(record.get("hash")), []).append(record)
    confirmed_blocks = []
    for file_hash, related in by_hash.items():
        vt = enrichment.get("results", {}).get(file_hash, {}).get("virustotal", {})
        if vt.get("verdict") != "malicious" or int(vt.get("malicious") or 0) < 3:
            continue
        highest = max(related, key=lambda item: item.get("risk_score", 0))
        names = "، ".join(sorted({_e(item.get("threat_name")) for item in related}))
        endpoints = "، ".join(sorted({_e(item.get("endpoint")) for item in related}))
        families = "، ".join(f"{_e(item.get('name'))} ({item.get('count', 0)})" for item in (vt.get("detection_names") or [])[:6]) or "غير محددة"
        freshness_note = (
            '<p class="notice"><b>حالة النتيجة:</b> تعذر تحديث المصدر وقت إعداد التقرير؛ '
            'استُخدمت آخر نتيجة محفوظة صالحة، لذلك يجب إعادة التحقق المباشر عند توفر المصدر.</p>'
            if vt.get("fallback") else ""
        )
        confirmed_blocks.append(
            f'<section class="confirmed"><h3>{names} <span class="badge critical">{_e(highest.get("risk_level"))} - {highest.get("risk_score")}/100</span></h3>'
            f'<p><b>دليل التأكيد:</b> رصد خبيث بواسطة {vt.get("malicious", 0)} محركًا. '
            f'<b>الأجهزة:</b> {endpoints}. <b>الاسم الخارجي:</b> {_e(vt.get("meaningful_name"))}. '
            f'<b>العائلة المرجحة:</b> {_e(vt.get("suggested_threat_label"))}.</p>'
            f'<p><b>أسماء الكشف:</b> {families}</p>'
            f'<p><b>التقدير المهني:</b> كثافة الكشف والسياق المحلي يبرران الاحتواء الفوري، حفظ الأدلة، مراجعة سلسلة العمليات والاستمرارية والاتصالات الشبكية، ثم تنفيذ الاستئصال بعد اكتمال جمع الأدلة.</p>'
            f'{freshness_note}<p class="hash">{_e(file_hash)}</p></section>'
        )
    confirmed_html = "".join(confirmed_blocks) or '<p>لم تتوفر تهديدات مؤكدة بدرجة كافية وقت إعداد التقرير.</p>'
    executive_evidence = (
        "وأكدت نتائج التحقق وجود مؤشرات خبيثة عالية الموثوقية تستوجب الاحتواء والتحقيق الفوري."
        if confirmed_blocks else
        "ولم تثبت نتائج التحقق المتاحة وقت إعداد التقرير وجود مؤشر خبيث بدرجة تأكيد كافية؛ ولا يعني ذلك سلامة المؤشرات غير المعروفة."
    )
    provider_rows = "".join(
        f"<tr><td>{_e(name)}</td><td>{'مفعّل' if value.get('enabled') else 'غير مفعّل'}</td>"
        f"<td>{value.get('queries', 0)}</td><td>{value.get('errors', 0)}</td>"
        f"<td>{value.get('fallback_hits', 0)}</td><td>{value.get('refresh_failures', 0)}</td></tr>"
        for name, value in enrichment.get("providers", {}).items()
    ) or '<tr><td colspan="6">لم تُفعّل مصادر خارجية بعد.</td></tr>'
    partial_notice = (
        f'<div class="notice"><b>تنبيه حول حداثة النتائج:</b> اكتمل التحقق جزئيًا؛ تعذر تحديث '
        f'{enrichment.get("refresh_failures", 0)} نتيجة، واستُخدمت آخر نتيجة محفوظة صالحة لعدد '
        f'{enrichment.get("fallback", 0)} منها. النتائج البديلة ليست تحديثًا مباشرًا ويجب إعادة التحقق منها لاحقًا.</div>'
        if enrichment.get("status") == "completed_partial" else ""
    )
    findings = "".join(
        "<tr>"
        f"<td>{record.get('risk_score', 0)}</td>"
        f"<td><span class='badge {('critical' if record.get('risk_level') == 'حرج' else 'high' if record.get('risk_level') == 'مرتفع' else 'medium')}'>{_e(record.get('risk_level'))}</span></td>"
        f"<td>{_e(record.get('threat_name'))}</td><td>{_e(record.get('endpoint'))}</td>"
        f"<td>{_e(record.get('classification'))}</td><td class='hash'>{_e(record.get('hash'))}</td>"
        f"<td>{_e('، '.join(record.get('risk_reasons') or []))}</td></tr>"
        for record in top_records
    )
    blank_columns = "، ".join(quality.get("blank_columns", [])) or "لا يوجد"
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    recommendations: list[str] = []
    if summary.get("critical"):
        recommendations.append("البدء الفوري باحتواء السجلات الحرجة وعزل الأجهزة المتأثرة وفق صلاحيات فريق الاستجابة للحوادث.")
    if summary.get("unresolved"):
        recommendations.append(f"مراجعة وإغلاق {summary['unresolved']} حادثًا غير محلول بعد التحقق من المعالجة.")
    if summary.get("pending_actions"):
        recommendations.append(f"متابعة {summary['pending_actions']} إجراءً معلقًا والتحقق من سبب عدم اكتماله.")
    if enrichment.get("status") == "disabled":
        recommendations.append("تفعيل مفاتيح مصادر استخبارات التهديدات لاستكمال التحقق الخارجي من الهاشات؛ عدم وجود نتيجة خارجية لا يعني سلامة المؤشر.")
    elif enrichment.get("status") == "completed_partial":
        recommendations.append("إعادة التحقق المباشر من المؤشرات التي تعذر تحديثها عند استعادة المصدر الخارجي أو تجدد الحصة المتاحة.")
    recommendations.append("الاحتفاظ بالأدلة وسجل الإجراءات، ثم إجراء تحليل السبب الجذري وتوثيق الدروس المستفادة.")
    recommendation_items = "".join(f"<li>{_e(item)}</li>" for item in recommendations)
    return f"""<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>تقرير مراجعة وتحقيق XDR — {_e(job_id[:8])}</title>
<style>
@page {{ size: A4; margin: 18mm 14mm; }}
*{{box-sizing:border-box}} body{{font-family:Arial,'Segoe UI',sans-serif;color:#17231e;margin:0;background:#eef3f0;line-height:1.65}}
.report{{max-width:1120px;margin:24px auto;background:white;padding:48px;box-shadow:0 12px 40px #19382b1a}}
.cover{{min-height:620px;display:flex;flex-direction:column;justify-content:center;border-top:12px solid #12372a;padding:42px 0}}
.eyebrow{{color:#b7791f;font-weight:700;letter-spacing:.08em}}h1{{font-size:38px;line-height:1.25;color:#12372a;margin:.3em 0}}h2{{color:#12372a;border-bottom:2px solid #d9e6df;padding-bottom:8px;margin-top:38px}}
.meta{{display:grid;grid-template-columns:1fr 1fr;gap:12px 28px;background:#f5f8f6;padding:22px;border-right:5px solid #b7791f}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.card{{border:1px solid #dbe6e0;border-radius:10px;padding:16px;background:#fbfdfc}}.card b{{display:block;font-size:28px;color:#12372a}}.card span{{color:#617068}}
table{{width:100%;border-collapse:collapse;margin:14px 0;font-size:12px}}th{{background:#12372a;color:white;text-align:right;padding:9px}}td{{padding:8px;border-bottom:1px solid #dfe8e3;vertical-align:top}}tr:nth-child(even) td{{background:#f7faf8}}.hash{{font-family:Consolas,monospace;font-size:9px;direction:ltr;word-break:break-all}}
.badge{{display:inline-block;padding:3px 9px;border-radius:99px;font-weight:bold}}.critical{{background:#ffe0e0;color:#a20f0f}}.high{{background:#ffedd0;color:#984d00}}.medium{{background:#fff7c7;color:#725b00}}
.notice{{border:1px solid #e4d4a5;background:#fffaf0;padding:14px;border-radius:8px}}.confirmed{{border:1px solid #e2c5bd;border-right:5px solid #a52a20;background:#fffafa;padding:16px;margin:15px 0;border-radius:8px}}.confirmed h3{{color:#79251e;margin:0 0 8px}}.footer{{margin-top:40px;padding-top:14px;border-top:1px solid #ccd9d2;color:#64746c;font-size:11px}}.ltr{{direction:ltr;text-align:left;word-break:break-all}}
@media print{{body{{background:white}}.report{{box-shadow:none;margin:0;padding:0;max-width:none}}.no-print{{display:none}}h2{{break-after:avoid}}table{{break-inside:auto}}tr{{break-inside:avoid}}.cover{{break-after:page}}}}
@media(max-width:800px){{.report{{padding:22px;margin:0}}.cards{{grid-template-columns:1fr 1fr}}.meta{{grid-template-columns:1fr}}}}
</style></head><body><main class="report">
<section class="cover"><div class="eyebrow">سجل التحقيق الأمني</div><h1>تقرير مراجعة وتحقيق XDR</h1>
<div class="meta"><div><b>رقم التقرير:</b> IR-{_e(job_id[:8].upper())}</div><div><b>النظام المصدر:</b> {_e(metadata.get('source_system_label', 'غير محدد — ملف سابق'))}</div><div><b>التصنيف:</b> للاستخدام الداخلي</div><div><b>نطاق المراجعة:</b> التنبيهات والحوادث ومؤشرات الاختراق ضمن بيئة XDR</div><div><b>عدد السجلات:</b> {summary['records']}</div><div><b>تاريخ الإصدار:</b> {_e(generated)}</div><div><b>الحالة:</b> نهائي</div></div></section>

<h2>1. الملخص التنفيذي</h2><div class="cards"><div class="card"><b>{summary['records']}</b><span>إجمالي السجلات</span></div><div class="card"><b>{summary['unique_hashes']}</b><span>هاش فريد</span></div><div class="card"><b>{summary['unresolved']}</b><span>حادث غير محلول</span></div><div class="card"><b>{summary['critical']}</b><span>سجل حرج</span></div></div>
<p>تمت مراجعة التنبيهات والحوادث، وتم ربط المؤشرات بالأجهزة والعمليات وحالة المعالجة. {executive_evidence}</p>

<h2>2. التهديدات المؤكدة ذات الأولوية</h2>{confirmed_html}

{("<h2>التقييم التحليلي المتقدم</h2><p>" + _e(model_result.get("executive_summary_ar")) + "</p>" + "".join("<p>• " + _e(item) + "</p>" for item in model_result.get("patterns", [])[:6])) if model_result.get("executive_summary_ar") else ""}
<h2>3. سجل المراجعة والتحقق داخل XDR</h2><p>تمت مراجعة {summary['records']} تنبيهًا وسجلًا، وتم تحديد {summary['unique_hashes']} مؤشرًا فريدًا. شملت المراجعة ربط البصمات بالأجهزة والملفات وسلسلة العمليات وحالة الحادث، ثم مقارنة الأدلة مع مصادر استخبارات التهديدات في ضوء السياق التشغيلي المتاح.</p>

<h2>4. جودة البيانات</h2><table><thead><tr><th>الفحص</th><th>النتيجة</th></tr></thead><tbody><tr><td>الصفوف المكررة الإضافية</td><td>{quality['duplicate_rows']}</td></tr><tr><td>الهاشات غير الصالحة</td><td>{quality['invalid_hashes']}</td></tr><tr><td>خلايا تحتوي على صيغ</td><td>{quality['formula_cells']}</td></tr><tr><td>الأعمدة الفارغة بالكامل</td><td>{_e(blank_columns)}</td></tr></tbody></table>

<h2>5. التوزيع حسب التصنيف</h2><table><thead><tr><th>التصنيف</th><th>العدد</th><th>النسبة</th></tr></thead><tbody>{_rows(distributions['classification'])}</tbody></table>
<h2>6. الأجهزة الأكثر تعرضًا</h2><table><thead><tr><th>الجهاز</th><th>عدد السجلات</th><th>النسبة</th></tr></thead><tbody>{_rows(distributions['endpoint'])}</tbody></table>

<h2>7. النتائج ذات الأولوية</h2><table><thead><tr><th>الدرجة</th><th>المستوى</th><th>التهديد</th><th>الجهاز</th><th>التصنيف</th><th>الهاش</th><th>أسباب الخطورة</th></tr></thead><tbody>{findings}</tbody></table>

<h2>8. مصادر معلومات التهديدات</h2>{partial_notice}<table><thead><tr><th>المصدر</th><th>الحالة</th><th>طلبات جديدة</th><th>أخطاء</th><th>نتائج بديلة محفوظة</th><th>تعذر تحديثها</th></tr></thead><tbody>{provider_rows}</tbody></table>
<div class="notice">الهاش غير الموجود لدى المصادر الخارجية يصنّف «غير معروف»، ولا يصنّف سليمًا بصورة تلقائية. لم يتم رفع أي ملف تنفيذي أو معلومات جهاز إلى مزودي معلومات التهديدات.</div>

<h2>9. التوصيات</h2><ol>{recommendation_items}</ol>
<h2>10. القيود</h2><p>يعتمد التقرير على أحداث الحماية المتاحة وعلى نتائج المزودين وقت الفحص. قد تتغير سمعة الهاش لاحقًا، وقد تكون بعض التنبيهات إيجابية كاذبة. يجب التحقق من السياق التشغيلي والتوقيع الرقمي وسلسلة العمليات قبل اتخاذ إجراء مدمر.</p>
<div class="footer">تقرير تحليل التهديدات - للاستخدام الداخلي - رقم التقرير IR-{_e(job_id[:8].upper())}</div>
</main></body></html>"""
