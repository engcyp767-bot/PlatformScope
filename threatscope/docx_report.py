"""Generate a formal Arabic DOCX report using the supplied report as style source."""

from __future__ import annotations

import copy
import io
import json
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
W = "{" + W_NS + "}"


def _report_settings() -> dict[str, Any]:
    try:
        from platform_core import platform_config
        return platform_config.load().get("reports", {})
    except (ImportError, OSError, ValueError):
        return {}


def _human(value: Any) -> str:
    text = str(value if value not in (None, "") else "—")
    if any(marker in text for marker in ("Ø", "Ù", "Ã", "Â")):
        try:
            repaired = text.encode("latin1").decode("utf-8")
            if repaired:
                return repaired
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    return text


def _x(value: Any) -> str:
    return escape(_human(value))


def _date_from_epoch(value: Any) -> str:
    try:
        return datetime.fromtimestamp(int(value)).astimezone().strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError):
        return "غير متاح"


def _size_label(value: Any) -> str:
    try:
        size = int(value)
    except (TypeError, ValueError):
        return "غير متاح"
    if size >= 1024 * 1024:
        return f"{size / 1024 / 1024:.2f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} bytes"

_ARABIC_RANGES = {0x200F}  # Include RLM (Right-To-Left Mark)
for _start, _end in [(0x0600, 0x06FF), (0x0750, 0x077F), (0x08A0, 0x08FF),
                      (0xFB50, 0xFDFF), (0xFE70, 0xFEFF), (0x0610, 0x061A),
                      (0x064B, 0x065F), (0x0670, 0x0670)]:
    _ARABIC_RANGES.update(range(_start, _end + 1))


def _is_arabic(char: str) -> bool:
    return ord(char) in _ARABIC_RANGES


def _split_by_script(text: str) -> list[tuple[bool, str]]:
    """Split text into segments of (is_arabic, substring)."""
    if not text:
        return [(False, "")]
    segments: list[tuple[bool, str]] = []
    current_arabic = _is_arabic(text[0])
    start = 0
    for i, ch in enumerate(text):
        char_arabic = _is_arabic(ch)
        # Treat whitespace/punctuation as belonging to the current segment
        if ch.isspace() or ch in ".,;:!?()-/\\|–—·•٫٬،؛؟":
            continue
        if char_arabic != current_arabic:
            segments.append((current_arabic, text[start:i]))
            start = i
            current_arabic = char_arabic
    segments.append((current_arabic, text[start:]))
    return segments


def _single_run(text: str, *, bold: bool = False, color: str = "17231E",
                size: int = 22, is_arabic: bool = True,
                font_ascii: str = "Arial", font_cs: str = "Arial") -> str:
    size = max(size + 4, 22)  # +2pt boost, minimum 11pt (22 half-points)
    font = font_cs if is_arabic else font_ascii
    props = [f'<w:rFonts w:ascii="{font_ascii}" w:hAnsi="{font_ascii}" w:cs="{font_cs}"/>']
    if bold:
        props.extend(["<w:b/>", "<w:bCs/>"])
    if is_arabic:
        props.append('<w:rtl w:val="1"/>')
    else:
        props.append('<w:rtl w:val="0"/>')
    props.extend([f'<w:color w:val="{color}"/>',
                  f'<w:sz w:val="{size}"/>', f'<w:szCs w:val="{size}"/>',
                  '<w:lang w:bidi="ar-SA"/>' if is_arabic else '<w:lang w:val="en-US"/><w:noProof/>'])
    return f'<w:r><w:rPr>{"".join(props)}</w:rPr><w:t xml:space="preserve">{_x(text)}</w:t></w:r>'


def _run(text: Any, *, bold: bool = False, color: str = "17231E", size: int = 22,
         rtl: bool = True, font_ascii: str = "Arial", font_cs: str = "Arial") -> str:
    plain = _human(text)
    segments = _split_by_script(plain)
    
    # Ensure boundary spaces are ALWAYS treated as Arabic (RTL) runs.
    # Otherwise, Word's Bidi algorithm will visually place LTR spaces on the wrong side.
    refined_segments: list[tuple[bool, str]] = []
    for is_ar, seg in segments:
        if not is_ar:
            l_spaces = len(seg) - len(seg.lstrip(" "))
            r_spaces = len(seg) - len(seg.rstrip(" "))
            if l_spaces > 0:
                refined_segments.append((True, seg[:l_spaces]))
            stripped = seg.strip(" ")
            if stripped:
                refined_segments.append((False, stripped))
            if r_spaces > 0 and stripped:
                refined_segments.append((True, seg[-r_spaces:]))
        else:
            refined_segments.append((is_ar, seg))

    return "".join(
        _single_run(segment, bold=bold, color=color, size=size,
                     is_arabic=is_ar, font_ascii=font_ascii, font_cs=font_cs)
        for is_ar, segment in refined_segments
    )


def _paragraph(
    text: Any = "",
    *,
    bold: bool = False,
    size: int = 22,
    color: str = "17231E",
    align: str = "right",
    before: int = 0,
    after: int = 60,
    keep_next: bool = False,
    border_bottom: bool = False,
    rtl: bool = True,
    font_ascii: str = "Arial",
    font_cs: str = "Arial",
) -> str:
    # In a bidi Word section, physical paragraph alignment is mirrored by
    # Microsoft Word.  Emit the opposite OOXML edge so Arabic is rendered at
    # the visual right margin while preserving the logical RTL reading order.
    xml_align = {"right": "left", "left": "right"}.get(align, align) if rtl else align
    ppr = ['<w:bidi w:val="1"/>' if rtl else "", f'<w:jc w:val="{xml_align}"/>', f'<w:spacing w:before="{before}" w:after="{after}" w:line="285" w:lineRule="auto"/>']
    if keep_next:
        ppr.append("<w:keepNext/>")
    if border_bottom:
        ppr.append('<w:pBdr><w:bottom w:val="single" w:sz="10" w:space="5" w:color="C1882B"/></w:pBdr>')
    value = _human(text)
    if rtl and any(_is_arabic(char) for char in value) and not value.startswith("\u200f"):
        value = "\u200f" + value
    return f'<w:p><w:pPr>{"".join(ppr)}</w:pPr>{_run(value, bold=bold, color=color, size=size, rtl=rtl, font_ascii=font_ascii, font_cs=font_cs)}</w:p>'



def _heading(number: str, title: str) -> str:
    p_props = '<w:bidi w:val="1"/><w:jc w:val="left"/><w:spacing w:before="160" w:after="80" w:line="285" w:lineRule="auto"/><w:pBdr><w:bottom w:val="single" w:sz="10" w:space="5" w:color="C1882B"/></w:pBdr>'
    run_direction = _single_run("\u200f", bold=True, color="12372A", size=30, is_arabic=True, font_ascii="Arial", font_cs="Arial")
    run_num = _single_run(number, bold=True, color="12372A", size=30, is_arabic=False, font_ascii="Arial", font_cs="Arial")
    run_dot = _single_run(". " + title, bold=True, color="12372A", size=30, is_arabic=True, font_ascii="Arial", font_cs="Arial")
    return f'<w:p><w:pPr>{p_props}</w:pPr>{run_direction}{run_num}{run_dot}</w:p>'


def _page_break() -> str:
    return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


def _cell(text: Any, width: int, *, header: bool = False, align: str = "right", size: int = 19, color: str | None = None, rtl: bool = True, font_ascii: str = "Arial", font_cs: str = "Arial") -> str:
    fill = "12372A" if header else "FFFFFF"
    text_color = color or ("FFFFFF" if header else "17231E")
    p = _paragraph(text, bold=header, size=size, color=text_color, align=align, after=10, rtl=rtl, font_ascii=font_ascii, font_cs=font_cs)
    return (
        f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/><w:shd w:fill="{fill}"/>'
        '<w:tcMar><w:top w:w="55" w:type="dxa"/><w:left w:w="90" w:type="dxa"/><w:bottom w:w="55" w:type="dxa"/><w:right w:w="90" w:type="dxa"/></w:tcMar>'
        f'</w:tcPr>{p}</w:tc>'
    )


def _table(headers: list[str], rows: list[list[Any]], widths: list[int], *, font_size: int = 19, borders: bool = True, aligns: list[str] | None = None) -> str:
    grid = "".join(f'<w:gridCol w:w="{width}"/>' for width in widths)
    header_cells = "".join(_cell(value, widths[index], header=True, size=font_size) for index, value in enumerate(headers))
    header = f'<w:tr><w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>{header_cells}</w:tr>' if headers else ''
    body_rows = []
    for row in rows:
        cells = "".join(_cell(value, widths[index], align=(aligns[index] if aligns else "right"), size=font_size) for index, value in enumerate(row))
        # Body rows may span pages. Preventing row splits makes Word move a
        # complete detail row to the next page and leaves large blank areas.
        body_rows.append(f'<w:tr>{cells}</w:tr>')
    borders_xml = '<w:tblBorders><w:top w:val="single" w:sz="5" w:color="D9E5DF"/><w:left w:val="single" w:sz="5" w:color="D9E5DF"/><w:bottom w:val="single" w:sz="5" w:color="D9E5DF"/><w:right w:val="single" w:sz="5" w:color="D9E5DF"/><w:insideH w:val="single" w:sz="4" w:color="D9E5DF"/><w:insideV w:val="single" w:sz="4" w:color="D9E5DF"/></w:tblBorders>' if borders else ''
    return f'<w:tbl><w:tblPr><w:bidiVisual w:val="1"/><w:tblW w:w="0" w:type="auto"/><w:tblLayout w:type="fixed"/>{borders_xml}</w:tblPr><w:tblGrid>{grid}</w:tblGrid>{header}{"".join(body_rows)}</w:tbl>'


def _verdict_ar(value: str | None) -> str:
    return {
        "malicious": "خبيث",
        "suspicious": "مشبوه",
        "clean_or_unknown": "لا توجد دلالات كافية",
        "unknown": "غير معروف",
        "unavailable": "غير متاح",
    }.get(str(value or ""), "لم يتم الفحص")


def _build_body(analysis: dict[str, Any], job_id: str, sect_pr: str, reader: Any) -> str:
    settings = _report_settings()
    metadata = analysis.get("metadata") or {}
    summary = dict(analysis.get("summary") or {})
    distributions = dict(analysis.get("distributions") or {})
    enrichment = analysis.get("enrichment", {})
    
    # Pre-compute from reader
    total_records = 0
    hashes = set()
    critical = 0
    high = 0
    unresolved = 0
    not_mitigated = 0
    pending_actions = 0
    
    class_counter = Counter()
    endpoint_counter = Counter()
    by_hash = defaultdict(list)
    
    records = []
    
    for record in reader.iter_records(sort_by="risk_score_desc"):
        total_records += 1
        if record.get("hash"):
            hashes.add(str(record["hash"]))
        score = int(record.get("risk_score") or 0)
        if score >= 85: critical += 1
        elif score >= 70: high += 1
        
        inc_status = str(record.get("incident_status") or "").lower()
        if inc_status in {"unresolved", "open", "active", "new"}: unresolved += 1
        
        mit_status = str(record.get("mitigation_status") or "").lower()
        if mit_status in {"not mitigated", "not_mitigated", "failed"}: not_mitigated += 1
        
        if record.get("pending_action"): pending_actions += 1
        
        class_counter[_human(record.get("classification"))] += 1
        endpoint_counter[_human(record.get("endpoint"))] += 1
        
        if record.get("hash_type"):
            by_hash[str(record["hash"])].append(record)
            
        if len(records) < 20:
            records.append(record)
            
    summary.setdefault("records", total_records)
    summary.setdefault("unique_hashes", len(hashes))
    summary.setdefault("critical", critical)
    summary.setdefault("high", high)
    summary.setdefault("unresolved", unresolved)
    summary.setdefault("not_mitigated", not_mitigated)
    summary.setdefault("pending_actions", pending_actions)
    summary.setdefault("duplicate_rows", 0)
    
    distributions.setdefault("classification", dict(class_counter))
    distributions.setdefault("endpoint", dict(endpoint_counter))

    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")

    intel_by_hash = enrichment.get("results", {}) if settings.get("include_source_results", True) else {}
    vt_malicious = vt_unknown = vt_unavailable = 0
    for providers in intel_by_hash.values():
        vt = providers.get("virustotal", {})
        verdict = vt.get("verdict")
        if verdict == "malicious":
            vt_malicious += 1
        elif verdict == "unavailable":
            vt_unavailable += 1
        else:
            vt_unknown += 1

    parts: list[str] = []
    # Formal cover.
    parts.append(_paragraph("بسم الله الرحمن الرحيم", size=24, align="center", before=720, after=120))
    parts.append(_paragraph('"تحليل"', size=32, align="center", before=120, after=240, border_bottom=True))
    parts.append(_table(
        [],
        [["الأخ المحترم", "بعد التحية،"]],
        [4550, 4550], font_size=20, borders=False, aligns=["right", "right"]
    ))
    source_label = metadata.get("source_system_label", "غير محدد — ملف سابق")
    organization = str(settings.get("organization_name") or "").strip()
    parts.append(_paragraph(f"الموضوع: تحليل تنبيهات منصة XDR — {source_label}" + (f" — {organization}" if organization else ""), size=24, align="center", before=240, after=480))
    parts.append(_page_break())

    parts.append(_heading("1", "الخلاصة التنفيذية"))
    parts.append(_paragraph(
        f"تمت مراجعة {summary['records']} تنبيهًا وسجلًا ضمن سياق الحوادث، وتم ربط {summary['unique_hashes']} مؤشرًا فريدًا بالأجهزة والعمليات وحالات المعالجة المتاحة. "
        f"أسفرت المراجعة عن {summary['critical']} حالة حرجة و{summary['high']} حالات مرتفعة الخطورة، "
        f"مع بقاء {summary['unresolved']} حادثًا قيد المتابعة و{summary['not_mitigated']} تهديدًا دون تخفيف مكتمل و{summary['pending_actions']} إجراءات معالجة معلقة. "
        f"وعند التحقق من المؤشرات، ثبتت خُبثية {vt_malicious} منها، بينما بقي {vt_unknown} دون تأكيد و{vt_unavailable} غير متاح وقت الاستعلام."
    ))
    if vt_malicious:
        conclusion = "الاستنتاج المهني: أظهر الربط بين سياق الحادث ونتائج التحقق وجود تهديدات خبيثة تتطلب الاحتواء الفوري والتحقيق على الأجهزة المتأثرة. أما المؤشرات غير المعروفة فتبقى بحاجة إلى فحص إضافي، ولا يجوز اعتبارها سليمة دون أدلة فنية مساندة."
    else:
        conclusion = "الاستنتاج المهني: لم تتوفر وقت إعداد التقرير أدلة خارجية كافية لإثبات مؤشرات خبيثة بصورة قاطعة. وتبقى المؤشرات غير المعروفة بحاجة إلى فحص إضافي، ولا يجوز اعتبار غيابها عن المصادر العامة دليلًا على سلامتها."
    parts.append(_paragraph(conclusion, bold=True, color="8A3D12"))
    model_analysis = analysis.get("model_analysis") or {}
    if settings.get("include_ai_analysis", True) and model_analysis.get("status") == "completed":
        model_result = model_analysis.get("result") or {}
        model_summary = str(model_result.get("executive_summary_ar") or "").strip()
        if model_summary:
            parts.append(_paragraph("التقييم التحليلي المتقدم", bold=True, size=25, color="12372A", before=220, after=80, keep_next=True))
            parts.append(_paragraph(model_summary, size=21, after=100))
            for item in (model_result.get("patterns") or [])[:6]:
                if str(item).strip():
                    parts.append(_paragraph(f"• {str(item).strip()}", size=20, after=60))
            recommendations = [str(item).strip() for item in (model_result.get("recommendations") or []) if str(item).strip()]
            if recommendations:
                parts.append(_paragraph("إجراءات التحقق المقترحة", bold=True, size=22, color="12372A", before=100, after=60, keep_next=True))
                for index, item in enumerate(recommendations[:int(settings.get("recommendations") or 8)], 1):
                    parts.append(_paragraph(f"{index}. {item}", size=20, after=60))

    parts.append(_heading("2", "التهديدات المؤكدة ذات الأولوية"))
    confirmed = []
    for file_hash, related in by_hash.items():
        vt = intel_by_hash.get(file_hash, {}).get("virustotal", {})
        if vt.get("verdict") == "malicious" and int(vt.get("malicious") or 0) >= 3:
            highest = max(related, key=lambda item: item.get("risk_score", 0))
            confirmed.append((int(vt.get("malicious") or 0), highest.get("risk_score", 0), file_hash, related, vt, highest))
    confirmed.sort(reverse=True)
    if not confirmed:
        parts.append(_paragraph("لم تتوفر نتائج خارجية مؤكدة بدرجة كافية وقت إعداد التقرير.", bold=True))
    for index, (_, _, file_hash, related, vt, highest) in enumerate(confirmed[:int(settings.get("top_findings") or 15)], 1):
        local_names = sorted({_human(item.get("threat_name")) for item in related})
        endpoints = sorted({_human(item.get("endpoint")) for item in related})
        sites = sorted({_human(item.get("site")) for item in related if item.get("site")})
        processes = sorted({_human(item.get("originating_process")) for item in related if item.get("originating_process")})
        paths = sorted({_human(item.get("path")) for item in related if item.get("path")})
        classifications = sorted({_human(item.get("classification")) for item in related if item.get("classification")})
        external_name = _human(vt.get("meaningful_name"))
        family = _human(vt.get("suggested_threat_label")) if vt.get("suggested_threat_label") else "غير محددة"
        title_name = local_names[0] if local_names else external_name
        parts.append(_paragraph(f"2.{index} \u200f{title_name} \u200f- مستوى الخطورة: {highest.get('risk_level')}، التقييم: {highest.get('risk_score')}/100", bold=True, size=26, color="8A251B", before=220, after=120, keep_next=True))
        parts.append(_table(
            ["عنصر التقييم", "النتيجة"],
            [
                ["دليل التأكيد", f"رصد خبيث بواسطة {vt.get('malicious', 0)} محركًا، ومشبوه بواسطة {vt.get('suspicious', 0)}"],
                ["الاسم المرجح خارجيًا", external_name],
                ["عائلة التهديد المرجحة", family],
                ["نوع العينة", vt.get("type_description") or vt.get("magic")],
                ["حجم العينة", _size_label(vt.get("size"))],
                ["أول ظهور معروف", _date_from_epoch(vt.get("first_submission_date"))],
                ["آخر تحليل", _date_from_epoch(vt.get("last_analysis_date"))],
                ["الأجهزة المتأثرة", "، ".join(endpoints)],
                ["الموقع", "، ".join(sites) or "غير محدد"],
                ["التصنيف المحلي", "، ".join(classifications) or "غير محدد"],
            ],
            [3100, 6000], font_size=18,
        ))
        detection_names = vt.get("detection_names") or []
        if detection_names:
            names_text = "، ".join(f"{_human(item.get('name'))}: {item.get('count', 0)}" for item in detection_names[:8])
            parts.append(_paragraph(f"أسماء الكشف الأكثر تكرارًا: {names_text}", bold=True, size=19, color="4A5C53", before=100, after=70))
        popular_names = vt.get("popular_threat_names") or []
        popular_categories = vt.get("popular_threat_categories") or []
        if popular_names or popular_categories:
            aliases_text = "، ".join(f"{_human(item.get('name'))}: {item.get('count', 0)}" for item in popular_names[:6]) or "غير محددة"
            categories_text = "، ".join(f"{_human(item.get('category'))}: {item.get('count', 0)}" for item in popular_categories[:6]) or "غير محددة"
            parts.append(_paragraph(f"إجماع التصنيف الخارجي: {categories_text}. الأسماء والعائلات المتداولة: {aliases_text}.", size=19, after=70))
        parts.append(_table(
            ["المؤشر", "القيمة"],
            [
                ["MD5", vt.get("md5") or "غير متاح"],
                ["SHA-1", vt.get("sha1") or (file_hash if len(file_hash) == 40 else "غير متاح")],
                ["SHA-256", vt.get("sha256") or (file_hash if len(file_hash) == 64 else "غير متاح")],
                ["العملية الأصلية", "، ".join(processes) or "غير محددة"],
                ["المسار المرصود", "، ".join(paths[:3]) or "غير محدد"],
            ],
            [2200, 6900], font_size=16,
        ))
        signature = vt.get("signature_info") or {}
        signature_text = "موثق" if signature.get("verified") else "غير موثق أو غير متاح"
        if signature.get("description") or signature.get("product"):
            signature_text += f" - {_human(signature.get('description') or signature.get('product'))}"
        tags = "، ".join(_human(tag) for tag in (vt.get("tags") or [])[:12]) or "لا توجد وسوم متاحة"
        parts.append(_paragraph(f"التوقيع الرقمي: {signature_text}. الوسوم الفنية: {tags}.", size=19, after=70))
        yara_rules = vt.get("yara_rules") or []
        if yara_rules:
            yara_names = "، ".join(sorted({_human(item.get("rule_name")) for item in yara_rules if item.get("rule_name")}))
            parts.append(_paragraph(f"مطابقات YARA المجتمعية: {yara_names}. تُعامل المطابقة كقرينة فنية مساندة ولا تستبدل تحليل السلوك.", size=18, color="4A5C53", after=70))
        sandbox_verdicts = vt.get("sandbox_verdicts") or []
        if sandbox_verdicts:
            sandbox_text = "؛ ".join(
                f"{_human(item.get('sandbox'))}: {_human(item.get('category'))}"
                + (f" ({'، '.join(_human(value) for value in item.get('malware_classification', []))})" if item.get("malware_classification") else "")
                for item in sandbox_verdicts[:6]
            )
            parts.append(_paragraph(f"نتائج البيئات المعزولة المتاحة: {sandbox_text}. تُفسر هذه النتائج ضمن قيود مدة التنفيذ والتغطية؛ النتيجة غير المكتشفة أو السليمة في بيئة واحدة لا تنفي إجماع محركات الكشف.", size=18, color="4A5C53", after=70))
        mismatched_name = external_name not in {"—", "غير متاح"} and all(external_name.lower() != name.lower() for name in local_names)
        assessment = [f"تؤكد كثافة الكشف ({vt.get('malicious', 0)} محركًا) أن المؤشر عالي الموثوقية ولا يُعامل كإيجابية كاذبة دون دليل مضاد قوي."]
        if mismatched_name:
            assessment.append(f"لوحظ اختلاف بين الاسم المرصود محليًا ({'، '.join(local_names)}) والاسم المرجح خارجيًا ({external_name})، وهو مؤشر يستدعي فحص احتمال إعادة التسمية أو التمويه.")
        if any(str(item.get("incident_status", "")).lower() == "unresolved" for item in related):
            assessment.append("الحادث المرتبط ما زال غير محلول، مما يرفع أولوية الاحتواء وجمع الأدلة قبل أي تنظيف.")
        if any("ransom" in str(item.get("classification", "")).lower() for item in related):
            assessment.append("التصنيف المحلي يشير إلى سلوك فدية؛ يجب التحقق من حذف النسخ الظلية، تشفير الملفات، ومؤشرات الحركة الجانبية.")
        technical_tags = {str(tag).lower() for tag in (vt.get("tags") or [])}
        behavior_notes = []
        if "persistence" in technical_tags:
            behavior_notes.append("إنشاء آلية استمرارية")
        if technical_tags.intersection({"usb-autorun", "spreader"}):
            behavior_notes.append("الانتشار الذاتي أو عبر وسائط USB")
        if technical_tags.intersection({"long-sleeps", "direct-cpu-clock-access"}):
            behavior_notes.append("تأخير التنفيذ أو مراوغة التحليل")
        if "checks-user-input" in technical_tags:
            behavior_notes.append("اشتراط تفاعل المستخدم قبل إظهار السلوك")
        if behavior_notes:
            assessment.append("تشير الوسوم السلوكية المتاحة إلى احتمال " + "، ".join(behavior_notes) + "؛ وهي فرضيات تحقيق ينبغي إثباتها من القياس عن بُعد وصورة الذاكرة وآثار النظام.")
        parts.append(_paragraph("التقدير الفني: " + " ".join(assessment), bold=True, color="6F2B20", before=80, after=70))
        parts.append(_paragraph("الإجراء الموصى به: عزل الأجهزة المتأثرة، حظر جميع قيم الهاش، حفظ العينة وسلسلة العمليات، مراجعة نقاط الاستمرارية والمهام المجدولة والخدمات، تحليل الاتصالات الشبكية، ثم تنفيذ الاستئصال والاستعادة بعد توثيق الأدلة.", bold=True, color="12372A", after=120))

    parts.append(_heading("3", "سجل المراجعة والتحقق داخل XDR"))
    for item in [
        "تمت مراجعة قائمة التنبيهات والحوادث المفتوحة، وتحديد الحالات ذات الأولوية وفق مستوى الخطورة وحالة المعالجة.",
        "تمت مطابقة أسماء الملفات والبصمات الرقمية وسلسلة العمليات مع الجهاز المتأثر والمسار والسياق التشغيلي المتاح.",
        "تمت مراجعة التصنيف والثقة وحالة الحادث والإجراءات المنفذة والمعلقة لتحديد فجوات الاحتواء.",
        "تم التحقق من الهاشات الفريدة في مصادر معلومات التهديدات الخارجية؛ اقتصرت المشاركة الخارجية على البصمات الرقمية دون رفع ملفات أو بيانات أصول داخلية.",
        "تم توثيق قوة الدليل، والتمييز بين المؤشرات المؤكدة والمؤشرات التي تحتاج إلى جمع أدلة إضافية قبل اتخاذ قرار نهائي.",
    ]:
        parts.append(_paragraph(f"• {item}", after=45))

    parts.append(_heading("4", "المؤشرات الرئيسية"))
    parts.append(_table(
        ["المؤشر", "القيمة", "الملاحظة"],
        [
            ["إجمالي السجلات", summary["records"], "نطاق التحليل الكامل"],
            ["الهاشات الفريدة", summary["unique_hashes"], "تم منع تكرار الاستعلامات"],
            ["الحوادث غير المحلولة", summary["unresolved"], "تحتاج متابعة وإغلاقًا موثقًا"],
            ["التهديدات غير المخففة", summary["not_mitigated"], "تحتاج تقييم إجراءات الاحتواء"],
            ["الإجراءات المعلقة", summary["pending_actions"], "تحتاج تحققًا تشغيليًا"],
            ["حرج", summary["critical"], "أولوية استجابة فورية"],
            ["مرتفع", summary["high"], "معالجة عاجلة"],
            ["الصفوف المكررة", summary["duplicate_rows"], "ملاحظة جودة بيانات"],
        ],
        [3300, 1400, 4400], font_size=20,
    ))

    parts.append(_heading("5", "توزيع التهديدات والأجهزة"))
    class_rows = [[name, count, f"{count / max(summary['records'], 1):.1%}"] for name, count in distributions.get("classification", {}).items()]
    parts.append(_paragraph("التوزيع حسب التصنيف", bold=True, size=23, color="12372A", keep_next=True))
    parts.append(_table(["التصنيف", "العدد", "النسبة"], class_rows, [4600, 1800, 1800], font_size=20))
    endpoint_rows = [[name, count, analysis.get("endpoint_unique_hashes", {}).get(name, 0)] for name, count in list(distributions.get("endpoint", {}).items())[:12]]
    parts.append(_paragraph("الأجهزة الأكثر تعرضًا", bold=True, size=23, color="12372A", before=180, keep_next=True))
    parts.append(_table(["الجهاز", "عدد السجلات", "الهاشات الفريدة"], endpoint_rows, [4600, 1800, 1800], font_size=20))

    parts.append(_heading("6", "النتائج ذات الأولوية"))

    priority_rows = []
    for record in records[:20]:
        priority_rows.append([
            record.get("threat_name"),
            record.get("endpoint"),
            record.get("classification"),
            record.get("risk_level"),
            record.get("risk_score"),
        ])
    parts.append(_table(["الملف/التهديد", "الجهاز", "التصنيف", "التقييم", "الدرجة"], priority_rows, [2700, 1900, 1700, 1400, 1000], font_size=17))

    parts.append(_heading("7", "سجل مؤشرات الاختراق"))
    hash_rows = []
    for file_hash, related in by_hash.items():
        vt = intel_by_hash.get(file_hash, {}).get("virustotal", {})
        detection = ""
        if vt.get("source_status") == "ok":
            detection = f"{vt.get('malicious', 0)} خبيث / {vt.get('suspicious', 0)} مشبوه"
        elif vt.get("source_status") == "not_found":
            detection = "لا يوجد تقرير - غير معروف"
        else:
            detection = _verdict_ar(vt.get("verdict"))
        highest = max(related, key=lambda item: item.get("risk_score", 0))
        hash_rows.append([
            "، ".join(sorted({str(item.get("threat_name") or "—") for item in related})),
            file_hash,
            "، ".join(sorted({str(item.get("endpoint") or "—") for item in related})),
            detection,
            f"{highest.get('risk_level')} ({highest.get('risk_score')})",
        ])
    parts.append(_table(["الملف", "الهاش", "الجهاز", "نتيجة VirusTotal", "التقييم"], hash_rows, [1900, 3000, 1500, 1800, 1200], font_size=15))

    parts.append(_heading("8", "إجراءات الاستجابة والمتابعة الموصى بها"))
    recommendations = [
        "عزل الأجهزة المرتبطة بالسجلات الحرجة والتحقق من سلامتها قبل إعادتها إلى الشبكة.",
        "حظر الهاشات المؤكد خُبثها في أنظمة EDR و XDR وأدوات البريد والبوابات، بعد اعتماد الجهة المخولة.",
        "البحث الاستباقي عن الهاشات وأسماء الملفات والعمليات الأصلية على بقية الأجهزة.",
        f"متابعة {summary['pending_actions']} إجراءات معلقة وتوثيق سبب التأخر أو الفشل.",
        "التحقق من التوقيع الرقمي والناشر والمسار ومصدر التنزيل للنتائج غير المعروفة.",
        "فتح تذكرة لكل حادث عالي أو حرج وربطها برقم التقرير والإجراءات المتخذة.",
        "إجراء تحليل السبب الجذري وتوثيق إجراءات الاحتواء والاستئصال والاستعادة والدروس المستفادة.",
    ]
    for index, item in enumerate(recommendations, 1):
        parts.append(_paragraph(f"{index}. {item}", after=55))

    parts.append(_paragraph("نهاية التقرير", bold=True, size=20, color="12372A", align="right", before=300))
    parts.append(sect_pr)
    return "".join(parts)


def _footer_xml() -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:ftr xmlns:w="{W_NS}" xmlns:r="{R_NS}">'
        '<w:p><w:pPr><w:bidi w:val="1"/><w:jc w:val="center"/><w:pBdr><w:top w:val="single" w:sz="6" w:space="4" w:color="C1882B"/></w:pBdr></w:pPr>'
        + _run("تقرير تحليل التهديدات - للاستخدام الداخلي - صفحة ", size=17, color="52645B")
        + '<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>'
        + '</w:p></w:ftr>'
    ).encode("utf-8")


def build_report_docx(analysis: dict[str, Any], reader: Any, output_path: str) -> None:
    from pathlib import Path
    import os
    base_dir = Path(os.path.dirname(__file__)).parent
    template_path = base_dir / "data" / "XDR_VirusTotal_Hash_Report_AR.docx"
    if not template_path.is_file():
        template_path = Path("data/XDR_VirusTotal_Hash_Report_AR.docx")
        
    with zipfile.ZipFile(template_path, "r") as source:
        document = ET.fromstring(source.read("word/document.xml"))
        sect = document.find(".//" + W + "sectPr")
        if sect is None:
            sect_pr = '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1037" w:right="1181" w:bottom="1037" w:left="1181" w:header="720" w:footer="720"/></w:sectPr>'
        else:
            sect_pr = ET.tostring(copy.deepcopy(sect), encoding="unicode")
        if "<w:bidi" not in sect_pr:
            sect_pr = sect_pr.replace(">", "><w:bidi/>", 1)
            
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as target:
            for item in source.infolist():
                if item.filename == "word/document.xml":
                    content = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="{W_NS}" xmlns:r="{R_NS}"><w:body>'.encode("utf-8")
                    body_str = _build_body(analysis, "export", sect_pr, reader)
                    content += body_str.encode("utf-8")
                    content += b'</w:body></w:document>'
                    target.writestr(item, content)
                elif item.filename == "word/footer1.xml":
                    target.writestr(item, _footer_xml())
                else:
                    target.writestr(item, source.read(item.filename))
