"""Professional, dependency-free Arabic DOCX report writer for LogScope."""

from __future__ import annotations

import io
import re
import zipfile
from collections import Counter
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape


def _report_settings() -> dict[str, Any]:
    try:
        from platform_core import platform_config
        return platform_config.load().get("reports", {})
    except (ImportError, OSError, ValueError):
        return {}

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
BLUE, LIGHT_BLUE, PALE_BLUE = "1F4E78", "D9EAF7", "EEF5FA"
DARK, MUTED, WHITE = "17324D", "5B6573", "FFFFFF"
RED, ORANGE, GREEN = "C00000", "C65911", "217346"


def _clean(value: Any) -> str:
    text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", "" if value is None else str(value))
    return escape(text)


def _run(text: Any, *, bold: bool = False, color: str = DARK, size: int = 23) -> str:
    """Render Arabic with the report font and technical tokens with regular Arial."""
    bold_xml = "<w:b/><w:bCs/>" if bold else ""
    value = "" if text is None else str(text)
    # Keep composite LTR values in a single run. Splitting ``3.28 GiB`` or a
    # timestamp into separate runs lets Word's bidi algorithm reverse their
    # visual order inside Arabic paragraphs.
    token_pattern = re.compile(
        r"(\d{4}-\d{2}-\d{2}\s+\d{1,2}:\d{2}(?::\d{2})?"
        r"|\d+(?:[.,:/-]\d+)*(?:%)?(?:\s+(?:[KMGTPE]?i?B|bps|pps))?"
        r"|[A-Za-z][A-Za-z0-9._:/-]*(?:\s+[A-Za-z][A-Za-z0-9._:/-]*)*)"
    )
    runs = []
    for fragment in filter(None, token_pattern.split(value)):
        technical = bool(token_pattern.fullmatch(fragment))
        if technical:
            fonts = '<w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:cs="Arial"/>'
            direction = '<w:rtl w:val="0"/><w:lang w:val="en-US"/><w:noProof/>'
        else:
            fonts = '<w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:cs="Arial"/>'
            direction = '<w:rtl w:val="1"/><w:lang w:bidi="ar-SA"/>'
        runs.append(
            f'<w:r><w:rPr>{fonts}{bold_xml}<w:color w:val="{color}"/>'
            f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>{direction}</w:rPr>'
            f'<w:t xml:space="preserve">{_clean(fragment)}</w:t></w:r>'
        )
    return "".join(runs)


def _word_alignment(align: str) -> str:
    """Map logical RTL alignment to Word's physical OOXML edge."""
    return {"right": "left", "left": "right"}.get(align, align)


def _paragraph(
    text: Any = "", *, style: str | None = None, align: str = "right",
    bold: bool = False, color: str = DARK, size: int = 23,
    before: int = 0, after: int = 60, line: int = 285,
    keep_next: bool = False, page_break_before: bool = False,
    border_bottom: str | None = None,
) -> str:
    style_xml = f'<w:pStyle w:val="{style}"/>' if style else ""
    keep_xml = "<w:keepNext/>" if keep_next else ""
    page_xml = "<w:pageBreakBefore/>" if page_break_before else ""
    border_xml = (
        f'<w:pBdr><w:bottom w:val="single" w:sz="12" w:space="5" w:color="{border_bottom}"/></w:pBdr>'
        if border_bottom else ""
    )
    value = "" if text is None else str(text)
    has_arabic = bool(re.search(r"[\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff\ufb50-\ufeff]", value))
    if has_arabic and not value.startswith("\u200f"):
        value = "\u200f" + value
    bidi_xml = '<w:bidi w:val="1"/>' if has_arabic else '<w:bidi w:val="0"/>'
    return (
        f'<w:p><w:pPr>{style_xml}{keep_xml}{page_xml}{bidi_xml}<w:jc w:val="{_word_alignment(align)}"/>'
        f'<w:spacing w:before="{before}" w:after="{after}" w:line="{line}" w:lineRule="auto"/>{border_xml}'
        f'</w:pPr>{_run(value, bold=bold, color=color, size=size)}</w:p>'
    )


def _rich_paragraph(runs: list[dict[str, Any]], *, align: str = "right", after: int = 60) -> str:
    return (
        f'<w:p><w:pPr><w:bidi w:val="1"/><w:jc w:val="{_word_alignment(align)}"/><w:spacing w:after="{after}" '
        f'w:line="285" w:lineRule="auto"/></w:pPr>{_run(chr(0x200F))}{"".join(_run(**run) for run in runs)}</w:p>'
    )


def _page_break() -> str:
    return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


def _cell(
    content: Any, *, width: int, fill: str = WHITE, bold: bool = False,
    color: str = DARK, size: int = 21, align: str = "center", colspan: int = 1,
) -> str:
    grid_span = f'<w:gridSpan w:val="{colspan}"/>' if colspan > 1 else ""
    paragraphs = content if isinstance(content, list) else [
        _paragraph(content, align=align, bold=bold, color=color, size=size, after=10, line=270)
    ]
    return (
        f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>{grid_span}'
        f'<w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>'
        '<w:tcMar><w:top w:w="55" w:type="dxa"/><w:left w:w="100" w:type="dxa"/>'
        '<w:bottom w:w="55" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tcMar>'
        f'</w:tcPr>{"".join(paragraphs)}</w:tc>'
    )


def _table(rows: list[list[str]], widths: list[int], *, repeat_header: bool = False) -> str:
    grid = "".join(f'<w:gridCol w:w="{width}"/>' for width in widths)
    rendered = []
    for index, cells in enumerate(rows):
        is_header = repeat_header and index == 0
        row_properties = '<w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>' if is_header else ""
        rendered.append(f'<w:tr>{row_properties}{"".join(cells)}</w:tr>')
    return (
        '<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/><w:bidiVisual w:val="1"/><w:tblLayout w:type="fixed"/>'
        '<w:tblBorders><w:top w:val="single" w:sz="5" w:color="B8C7D6"/>'
        '<w:left w:val="single" w:sz="5" w:color="B8C7D6"/><w:bottom w:val="single" w:sz="5" w:color="B8C7D6"/>'
        '<w:right w:val="single" w:sz="5" w:color="B8C7D6"/><w:insideH w:val="single" w:sz="4" w:color="D5DEE7"/>'
        f'<w:insideV w:val="single" w:sz="4" w:color="D5DEE7"/></w:tblBorders></w:tblPr>'
        f'<w:tblGrid>{grid}</w:tblGrid>{"".join(rendered)}</w:tbl>'
    )


def _section_title(text: str, *, page_break_before: bool = False) -> str:
    return _paragraph(text, style="Heading1", bold=True, color=BLUE, size=31, before=150, after=80,
                      keep_next=True, page_break_before=page_break_before, border_bottom=BLUE)


def _subheading(text: str) -> str:
    return _paragraph(text, style="Heading2", bold=True, color=BLUE, size=26, before=110, after=50, keep_next=True)


def _metric_card(value: Any, label: str, color: str = BLUE) -> str:
    return _cell([
        _paragraph(value, align="center", bold=True, color=color, size=32, after=20, line=300),
        _paragraph(label, align="center", color=MUTED, size=19, after=20, line=260),
    ], width=2300, fill=PALE_BLUE)


def _format_date(value: Any) -> str:
    text = str(value or "غير متوفر")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return text


def _format_bytes(value: int | float) -> str:
    size = float(value or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:,.2f} {unit}"
        size /= 1024
    return f"{size:,.2f} TiB"


def _attribute_number(record: dict[str, Any], *names: str) -> int:
    attributes = str(record.get("attributes", ""))
    values = []
    for name in names:
        match = re.search(rf"(?:^|,){re.escape(name)}=(\d+)", attributes, re.IGNORECASE)
        if match:
            values.append(int(match.group(1)))
    return max(values, default=0)


def _record_volume(record: dict[str, Any]) -> int:
    return _attribute_number(record, "TransferredData", "BytesOut", "BytesIn") or int(record.get("bytes", 0) or 0)


def _ranked_events(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank events by risk first, then transferred volume."""
    return sorted(
        records,
        key=lambda item: (int(item.get("risk_score", 0) or 0), _record_volume(item)),
        reverse=True,
    )


def _arabic_detail(value: Any) -> str:
    """Translate the common Flowmon event descriptions into natural Arabic."""
    text = str(value or "").strip()
    if not text:
        return "لا تتوفر تفاصيل إضافية لهذا الحدث."

    match = re.fullmatch(
        r"Transferred:\s*([\d.]+)\s*(\w+),\s*top peer transfer:\s*([\d.]+)\s*(\w+)\.?",
        text,
        re.IGNORECASE,
    )
    if match:
        total, total_unit, peer, peer_unit = match.groups()
        return f"بلغ إجمالي البيانات المنقولة {total} {total_unit}، وكان أكبر حجم منقول إلى نظير واحد {peer} {peer_unit}."

    match = re.fullmatch(
        r"Diverse communication of the device, different destination IPs:\s*(\d+),\s*different destination ports:\s*(\d+)\.?",
        text,
        re.IGNORECASE,
    )
    if match:
        addresses, ports = match.groups()
        return f"رُصد نمط اتصال متنوع من الجهاز شمل {addresses} عنوان وجهة مختلفاً و{ports} منفذ وجهة مختلفاً."

    match = re.fullmatch(
        r"Number of DNS queries \(packets\):\s*(\d+) \(interval in minutes:\s*(\d+)\)\. "
        r"Hour average of the whole network:\s*(\d+)\. Highest number of DNS queries:\s*(\d+) in (\d+) minutes\.?",
        text,
        re.IGNORECASE,
    )
    if match:
        queries, interval, hourly_average, peak, peak_minutes = match.groups()
        return (
            f"بلغ عدد استعلامات DNS المرصودة {queries} استعلاماً خلال {interval} دقيقة، مقابل متوسط عام للشبكة "
            f"قدره {hourly_average} استعلام في الساعة. وسُجلت أعلى كثافة بواقع {peak} استعلاماً خلال {peak_minutes} دقائق."
        )

    match = re.fullmatch(r"Access to randomly generated domains was detected\. Domains:\s*(.+)\.?", text, re.IGNORECASE)
    if match:
        return f"رُصد وصول إلى نطاقات تبدو مولدة عشوائياً. النطاقات الظاهرة: {match.group(1).rstrip('.')} ."

    match = re.fullmatch(
        r"The following amount of data:\s*([\d.]+)\s*(\w+) has been (sent|received) in the network "
        r"\(that is ([\d.]+)% more than the predicted ([\d.]+)\s*(\w+)\)\. "
        r"Data (?:sent|received) by the device:\s*([\d.]+)\s*(\w+)\.?",
        text,
        re.IGNORECASE,
    )
    if match:
        amount, unit, direction, increase, predicted, predicted_unit, device_amount, device_unit = match.groups()
        direction_ar = "المرسلة" if direction.lower() == "sent" else "المستقبلة"
        return (
            f"بلغ حجم البيانات {direction_ar} على الشبكة {amount} {unit}، بزيادة قدرها {increase}% عن القيمة المتوقعة "
            f"البالغة {predicted} {predicted_unit}. وبلغ نصيب الجهاز من هذه البيانات {device_amount} {device_unit}."
        )

    match = re.fullmatch(
        r"The following number of packets:\s*(\d+) has been (sent|received) in the network "
        r"\(that is ([\d.]+)% more than the predicted (\d+) packets\)\. "
        r"Packets (?:sent|received) by the device:\s*(\d+)\.?",
        text,
        re.IGNORECASE,
    )
    if match:
        packets, direction, increase, predicted, device_packets = match.groups()
        direction_ar = "المرسلة" if direction.lower() == "sent" else "المستقبلة"
        return (
            f"بلغ عدد الحزم {direction_ar} على الشبكة {packets} حزمة، بزيادة قدرها {increase}% عن العدد المتوقع "
            f"البالغ {predicted} حزمة. وبلغ نصيب الجهاز {device_packets} حزمة."
        )

    return "تشير بيانات الحدث إلى نشاط غير اعتيادي يحتاج إلى مراجعة سجلات الشبكة المرتبطة بالمصدر والوجهة والتوقيت."


def _verdict_ar(value: Any) -> str:
    mapping = {"malicious": "ضار", "suspicious": "مشبوه", "clean": "سليم", "normal": "طبيعي",
               "exposed": "مكشوف", "notable": "جدير بالمراجعة", "unknown": "غير معروف",
               "unavailable": "غير متاح"}
    text = str(value or "غير متاح")
    return mapping.get(text.lower(), text)


def _overall_verdict(providers: dict[str, Any]) -> tuple[str, str]:
    verdicts = {str(item.get("verdict", "")).lower() for item in providers.values() if isinstance(item, dict)}
    if verdicts & {"malicious", "exposed"}:
        return "مرتفع الخطورة", RED
    if verdicts & {"suspicious", "notable"}:
        return "يحتاج مراجعة", ORANGE
    if verdicts & {"clean", "normal"}:
        return "لا توجد مؤشرات مباشرة", GREEN
    return "غير مكتمل", MUTED


def _provider_status_ar(value: Any) -> str:
    return {
        "ok": "مكتمل",
        "error": "تعذر الاتصال بالخدمة",
        "provider_deferred": "مؤجل بسبب حدود الخدمة",
        "quota_exhausted": "توقّف بسبب نفاد الحصة",
        "disabled": "الخدمة غير مفعلة",
        "unavailable": "غير متاح",
    }.get(str(value or "unavailable").lower(), "غير متاح")


def _source_reputation_details(providers: dict[str, Any] | None) -> list[str]:
    """Build Arabic provider details for embedding in an event card."""
    if not providers or "reason" in providers:
        return [_paragraph(
            "لم تتوفر نتيجة لفحص سمعة هذا المصدر ضمن نطاق الفحص الحالي.",
            color=MUTED, size=17, after=30,
        )]

    lines: list[str] = []
    vt = providers.get("virustotal")
    if isinstance(vt, dict):
        status = str(vt.get("source_status", "unavailable")).lower()
        if status == "ok":
            context = []
            if vt.get("country"):
                context.append(f"الدولة: {vt['country']}")
            if vt.get("as_owner"):
                context.append(f"الجهة المالكة: {vt['as_owner']}")
            text = (
                f"الحكم: {_verdict_ar(vt.get('verdict'))}؛ عدد المحركات المصنفة ضارة: "
                f"{vt.get('malicious', 0)}؛ والمشبوهة: {vt.get('suspicious', 0)}؛ "
                f"درجة السمعة: {vt.get('reputation', 0)}"
            )
        else:
            context = []
            text = f"لم تكتمل النتيجة: {_provider_status_ar(status)}"
        lines.append(_rich_paragraph([
            {"text": "نتيجة التحليل: ", "bold": True, "color": BLUE, "size": 17},
            {"text": text, "size": 17},
        ], after=25))
        if context:
            lines.append(_rich_paragraph([
                {"text": "سياق المصدر: ", "bold": True, "color": BLUE, "size": 16},
                {"text": "؛ ".join(context), "size": 16},
            ], after=25))

    abuse = providers.get("abuseipdb")
    if isinstance(abuse, dict):
        status = str(abuse.get("source_status", "unavailable")).lower()
        if status == "ok":
            context = []
            if abuse.get("country"):
                context.append(f"الدولة: {abuse['country']}")
            if abuse.get("isp"):
                context.append(f"مزود الخدمة: {abuse['isp']}")
            text = (
                f"الحكم: {_verdict_ar(abuse.get('verdict'))}؛ درجة البلاغات: "
                f"{abuse.get('score', 0)}%؛ عدد البلاغات: {abuse.get('total_reports', 0)}"
            )
        else:
            context = []
            text = f"لم تكتمل النتيجة: {_provider_status_ar(status)}"
        lines.append(_rich_paragraph([
            {"text": "نتيجة البلاغات: ", "bold": True, "color": BLUE, "size": 17},
            {"text": text, "size": 17},
        ], after=25))
        if context:
            lines.append(_rich_paragraph([
                {"text": "سياق المصدر: ", "bold": True, "color": BLUE, "size": 16},
                {"text": "؛ ".join(context), "size": 16},
            ], after=25))

    shodan = providers.get("shodan")
    if isinstance(shodan, dict):
        status = str(shodan.get("source_status", "unavailable")).lower()
        if status == "ok":
            context = []
            if shodan.get("ports"):
                context.append("المنافذ الظاهرة: " + ", ".join(map(str, shodan.get("ports", [])[:12])))
            if shodan.get("vulns"):
                context.append("الثغرات المسجلة: " + ", ".join(map(str, shodan.get("vulns", [])[:8])))
            owner = shodan.get("org") or shodan.get("isp")
            if owner:
                context.append(f"الجهة المالكة: {owner}")
            text = f"الحكم: {_verdict_ar(shodan.get('verdict'))}"
            if context:
                text += "؛ " + "؛ ".join(context)
        else:
            text = f"لم تكتمل النتيجة: {_provider_status_ar(status)}"
        lines.append(_rich_paragraph([
            {"text": "نتيجة التعرض الشبكي: ", "bold": True, "color": BLUE, "size": 17},
            {"text": text, "size": 17},
        ], after=25))

    return lines or [_paragraph(
        "لم تُرجع الخدمات المفعلة تفاصيل قابلة للعرض لهذا المصدر.",
        color=MUTED, size=17, after=30,
    )]


def _event_reputation_result(
    record: dict[str, Any], results: dict[str, Any]
) -> tuple[str | None, dict[str, Any], int]:
    """Select the most important available result related to an event."""
    source = str(record.get("src_ip") or record.get("event_source", "")).strip()
    source_result = results.get(source)
    if isinstance(source_result, dict) and source_result and "reason" not in source_result:
        return source, source_result, 1

    related = []
    seen = set()
    for value in record.get("extracted_ips", []):
        ip = str(value).strip()
        providers = results.get(ip)
        if ip in seen or not isinstance(providers, dict) or not providers or "reason" in providers:
            continue
        seen.add(ip)
        overall, color = _overall_verdict(providers)
        priority = {RED: 3, ORANGE: 2, GREEN: 1, MUTED: 0}.get(color, 0)
        related.append((priority, ip, providers, overall))
    if not related:
        return None, {}, 0
    related.sort(key=lambda item: item[0], reverse=True)
    _, ip, providers, _ = related[0]
    return ip, providers, len(related)


def _status_ar(value: Any) -> str:
    return {
        "completed": "مكتمل",
        "running": "قيد التنفيذ",
        "interrupted": "متوقف قبل الاكتمال",
        "cancelled": "ملغى",
        "cancelling": "جارٍ الإلغاء",
        "error": "تعذر إكماله",
        "not_started": "لم يبدأ",
        "disabled": "غير مفعل",
    }.get(str(value or "not_started"), "غير محدد")


def _intel_rows(analysis: dict[str, Any]) -> tuple[list[list[str]], Counter, int]:
    results = analysis.get("enrichment", {}).get("results", {})
    rows, counts, checked = [], Counter(), 0
    for ip, providers in sorted(results.items()):
        if not providers or "reason" in providers:
            continue
        checked += 1
        overall, overall_color = _overall_verdict(providers)
        counts[overall] += 1
        abuse, vt, shodan = providers.get("abuseipdb", {}), providers.get("virustotal", {}), providers.get("shodan", {})
        details = []
        if vt:
            if vt.get("source_status") == "ok":
                details.append(
                    f"تصنيفات ضارة: {vt.get('malicious', 0)}، ومشبوهة: {vt.get('suspicious', 0)}، "
                    f"ودرجة السمعة: {vt.get('reputation', 0)}"
                )
            else:
                details.append(f"نتيجة غير مكتملة: {_provider_status_ar(vt.get('source_status'))}")
        if abuse:
            if abuse.get("source_status") == "ok":
                details.append(
                    f"درجة البلاغات: {abuse.get('score', 0)}%، وعدد البلاغات: {abuse.get('total_reports', 0)}"
                )
            else:
                details.append(f"نتيجة بلاغات غير مكتملة: {_provider_status_ar(abuse.get('source_status'))}")
        if shodan:
            if shodan.get("source_status") == "ok":
                exposure = [f"الحكم على التعرض الشبكي: {_verdict_ar(shodan.get('verdict'))}"]
                if shodan.get("ports"):
                    exposure.append("المنافذ: " + ", ".join(map(str, shodan.get("ports", [])[:12])))
                if shodan.get("vulns"):
                    exposure.append("الثغرات: " + ", ".join(map(str, shodan.get("vulns", [])[:8])))
                details.append("، ".join(exposure))
            else:
                details.append(f"نتيجة تعرض غير مكتملة: {_provider_status_ar(shodan.get('source_status'))}")
        owner = abuse.get("isp") or vt.get("as_owner") or "-"
        country = abuse.get("country") or vt.get("country") or "-"
        rows.append([
            _cell(ip, width=1700, bold=True, size=16),
            _cell(overall, width=1500, bold=True, color=overall_color, size=18),
            _cell("؛ ".join(details) or "لم تتوفر نتيجة مكتملة", width=3600, size=16, align="right"),
            _cell(f"الدولة: {country}؛ الجهة المالكة: {owner}", width=2200, size=16, align="right"),
        ])
    return rows, counts, checked


def _executive_summary(analysis: dict[str, Any]) -> str:
    metadata, summary = analysis.get("metadata", {}), analysis.get("summary", {})
    events = analysis.get("events", [])
    enrich = analysis.get("enrichment", {})
    
    if metadata.get("data_type") == "siem_logs":
        critical_count = int(summary.get("critical") or len([e for e in events if e.get("severity") == "حرج"]))
        high_count = int(summary.get("high") or len([e for e in events if e.get("severity") == "مرتفع"]))
        high_risk = critical_count + high_count
        total_records = int(summary.get("records") or metadata.get("row_count", 0))
        unique_ips = int(summary.get("unique_ips") or analysis.get("unique_ips_count", 0))
        unique_accounts = int(summary.get("unique_accounts") or analysis.get("unique_accounts_count", 0))
        unique_devices = int(summary.get("unique_devices") or analysis.get("unique_devices_count", 0))

        _, intel_counts, checked = _intel_rows(analysis)
        if intel_counts.get("مرتفع الخطورة", 0):
            assessment = f"وأظهرت مراجعة السمعة وجود {intel_counts['مرتفع الخطورة']} مستخرج ذي مؤشرات مرتفعة الخطورة تستوجب التحقق العاجل."
        elif intel_counts.get("يحتاج مراجعة", 0):
            review_count = intel_counts["يحتاج مراجعة"]
            if review_count == 1:
                assessment = "كما ظهرت نتيجة واحدة تحتاج إلى مراجعة وربطها بالسياق التشغيلي."
            elif review_count == 2:
                assessment = "كما ظهرت نتيجتان تحتاجان إلى مراجعة وربطهما بالسياق التشغيلي."
            else:
                assessment = f"كما ظهرت {review_count} نتائج تحتاج إلى مراجعة وربطها بالسياق التشغيلي."
        elif checked:
            assessment = "ولم تظهر على المستخرجات التي اكتمل فحصها مؤشرات مباشرة تثبت نشاطاً ضاراً، مع بقاء الحاجة إلى التحقق من سياق الاتصال."
        else:
            assessment = "ولم تتوفر نتائج كافية لتكوين حكم على سمعة المستخرجات، لذلك يبقى التقييم أولياً."
            
        devices_clause = f" و {unique_devices} من الأجهزة الراصدة" if unique_devices > 0 else ""
        return (
            f"أظهرت مراجعة البيانات وجود {total_records} سجلاً أمنياً يتضمن "
            f"{unique_ips} عنوان IP فريداً و {unique_accounts} حساباً للمستخدمين{devices_clause}. "
            f"وبلغ عدد الأحداث المصنفة مرتفعة أو حرجة الخطورة {high_risk} حدثاً ({critical_count} حرج، {high_count} مرتفع). {assessment} "
            "ولا تكفي درجة الخطورة أو نتيجة السمعة منفردة لإثبات وقوع اختراق دون مطابقتها مع سجلات الشبكة والأصول."
        )
    return ""


def _cover(metadata: dict[str, Any]) -> str:
    settings = _report_settings()
    data_type = metadata.get("data_type")
    report_type = (
        "سجلات الأنظمة والأمان (SIEM)" if data_type == "siem_logs"
        else "أحداث أمن الأنظمة" if data_type == "ads_events"
        else "سجلات الأمان"
    )
    return "".join([
        _paragraph("بسم الله الرحمن الرحيم", align="center", bold=True, color=BLUE, size=24, before=350, after=600),
        _paragraph("تقرير تحليل سجلات الأمان", align="center", bold=True, color=BLUE, size=48, before=300, after=160),
        _paragraph("LogScope Security Analysis Report", align="center", bold=True, color=MUTED, size=25, after=500, border_bottom=BLUE),
        _paragraph(report_type, align="center", bold=True, size=31, before=350, after=450),
        _table([
            [_cell("تاريخ إعداد التقرير", width=2600, fill=LIGHT_BLUE, bold=True), _cell(_format_date(metadata.get("analyzed_at")), width=6500, align="right")],
            [_cell("النظام المصدر", width=2600, fill=LIGHT_BLUE, bold=True), _cell(metadata.get("source_system_label", "غير محدد — ملف سابق"), width=6500, align="right")],
            [_cell("نطاق المراجعة", width=2600, fill=LIGHT_BLUE, bold=True), _cell(report_type, width=6500, align="right")],
        ], [2600, 6500]),
        _paragraph(f"تصنيف المستند: {settings.get('classification') or 'للاستخدام الداخلي'}", align="center", bold=True, color=RED, size=22, before=600),
        _paragraph(f"إعداد: {settings.get('analyst_title') or 'فريق تحليل سجلات الأمان'} - LogScope", align="center", bold=True, color=MUTED, size=19),
        _page_break(),
    ])


def _summary_section(analysis: dict[str, Any]) -> str:
    metadata, enrich = analysis.get("metadata", {}), analysis.get("enrichment", {})
    summary = analysis.get("summary", {})
    events = analysis.get("events", [])
    
    if metadata.get("data_type") == "siem_logs":
        critical = int(summary.get("critical") or len([e for e in events if e.get("severity") == "حرج"]))
        high = int(summary.get("high") or len([e for e in events if e.get("severity") == "مرتفع"]))
        total_records = int(summary.get("records") or metadata.get("row_count", 0))
        unique_accounts = int(summary.get("unique_accounts") or analysis.get("unique_accounts_count", 0))
        unique_devices = int(summary.get("unique_devices") or analysis.get("unique_devices_count", 0))

        account_label = f"حسابات / أجهزة ({unique_accounts} / {unique_devices})" if unique_devices > 0 else "حسابات فريدة"
        account_val = f"{unique_accounts} / {unique_devices}" if unique_devices > 0 else unique_accounts

        cards = [_metric_card(total_records, "إجمالي السجلات"),
                 _metric_card(account_val, account_label),
                 _metric_card(critical, "أحداث حرجة", RED),
                 _metric_card(high, "أحداث مرتفعة", ORANGE)]
    else:
        cards = []
        
    return "".join([
        _section_title("الملخص التنفيذي"), _paragraph(_executive_summary(analysis), size=23, after=180, line=360),
        _table([cards], [2300] * 4), _subheading("نطاق التحليل ومنهجيته"),
        _paragraph("شمل التحليل توحيد السجلات واستخراج عناوين الـ IP والحسابات وحساب مؤشرات الخطورة بناءً على تصنيف الحدث، ثم إثراء المستخرجات عبر الخدمات المفعلة."),
        _rich_paragraph([{"text": "تغطية تحليل سمعة المستخرجات: ", "bold": True, "color": BLUE, "size": 22},
                         {"text": f"{enrich.get('checked', 0)} / {enrich.get('candidates', 0)}", "bold": True, "size": 22},
                         {"text": f" | الحالة: {_status_ar(enrich.get('status'))}", "color": MUTED, "size": 20}]),
    ])


def _top_events_section(analysis: dict[str, Any], reader: Any) -> str:
    metadata = analysis.get("metadata", {})
    limit = int(_report_settings().get("top_findings") or 15)
    if metadata.get("data_type") == "siem_logs":
        widths = [750, 900, 1150, 1550, 1500, 1250, 2600]
        labels = ["الدرجة", "الخطورة", "Event ID", "المصدر", "الحساب", "عنوان IP", "الوصف"]
        rows = [[_cell(label, width=width, fill=BLUE, bold=True, color=WHITE, size=17) for label, width in zip(labels, widths)]]
        
        for index, record in enumerate(reader.iter_records(sort_by="risk_score_desc", limit=limit)):
            fill = PALE_BLUE if index % 2 else WHITE
            severity = record.get("severity", "-")
            severity_color = RED if severity == "حرج" else ORANGE if severity == "مرتفع" else DARK
            rows.append([
                _cell(record.get("risk_score", 0), width=750, fill=fill, bold=True),
                _cell(severity, width=900, fill=fill, bold=True, color=severity_color),
                _cell(record.get("event_id", "-"), width=1150, fill=fill),
                _cell(record.get("event_source", "-"), width=1550, fill=fill),
                _cell(record.get("user_account", "-"), width=1500, fill=fill),
                _cell(record.get("src_ip", "-"), width=1250, fill=fill),
                _cell(record.get("description_ar") or record.get("description", "-"), width=2600, fill=fill, size=15)
            ])
        return _section_title("أعلى الأحداث أولوية للتحقيق") + _paragraph("رُتبت الأحداث حسب درجة الخطورة التي تم حسابها في المنصة.", color=MUTED, size=19) + _table(rows, widths, repeat_header=True)

    if metadata.get("data_type") == "network_flows":
        sources = analysis.get("distributions", {}).get("top_sources", [])
        rows = [[_cell("الترتيب", width=900, fill=BLUE, bold=True, color=WHITE), _cell("عنوان المصدر", width=3600, fill=BLUE, bold=True, color=WHITE), _cell("حجم البيانات", width=4600, fill=BLUE, bold=True, color=WHITE)]]
        for index, source in enumerate(sources, 1):
            fill = PALE_BLUE if index % 2 == 0 else WHITE
            rows.append([_cell(index, width=900, fill=fill), _cell(source.get("ip"), width=3600, fill=fill, bold=True), _cell(source.get("formatted"), width=4600, fill=fill)])
        return _section_title("أعلى مصادر حركة الشبكة") + _table(rows, [900, 3600, 4600], repeat_header=True)
    widths = [650, 850, 1400, 1350, 1350, 1900, 1500]
    labels = ["الدرجة", "الخطورة", "نوع الحدث", "المصدر", "حجم البيانات", "الأهداف الظاهرة", "وقت الكشف"]
    rows = [[_cell(label, width=width, fill=BLUE, bold=True, color=WHITE, size=18) for label, width in zip(labels, widths)]]
    for index, record in enumerate(reader.iter_records(sort_by="risk_score_desc", limit=limit)):
        fill, severity = (PALE_BLUE if index % 2 else WHITE), record.get("severity", "-")
        severity_color = RED if severity == "حرج" else ORANGE if severity == "مرتفع" else DARK
        rows.append([_cell(record.get("risk_score", 0), width=650, fill=fill, bold=True),
                     _cell(severity, width=850, fill=fill, bold=True, color=severity_color),
                     _cell(record.get("event_type", "-"), width=1400, fill=fill, size=16),
                     _cell(record.get("event_source", "-"), width=1350, fill=fill, size=16),
                     _cell(_format_bytes(_record_volume(record)), width=1350, fill=fill, size=16),
                     _cell("، ".join(record.get("event_targets", [])[:5]) or "-", width=1900, fill=fill, size=15, align="right"),
                     _cell(record.get("event_time", "-"), width=1500, fill=fill, size=15)])
    return _section_title("أعلى الأحداث أولوية للتحقيق") + _paragraph("رُتبت الأحداث حسب درجة الخطورة ثم حجم البيانات المستخرج من خصائص الحدث.", color=MUTED, size=19) + _table(rows, widths, repeat_header=True)


def _intel_section(analysis: dict[str, Any]) -> str:
    if not _report_settings().get("include_source_results", True):
        return ""
    enrich = analysis.get("enrichment", {})
    rows, counts, checked = _intel_rows(analysis)
    parts = [_section_title("نتائج تحليل سمعة المصادر", page_break_before=True)]
    if enrich.get("status") != "completed":
        parts.append(_paragraph(f"لم تكتمل مراجعة سمعة المصادر، والحالة الحالية: {_status_ar(enrich.get('status'))}. لذلك يجب التعامل مع النتائج أدناه بوصفها نتائج جزئية.", bold=True, color=ORANGE))
    parts.extend([_paragraph(f"تمت معالجة {checked} نتيجة مصدر. تعرض الأحكام التالية ملخصاً موحداً ولا تستبدل التحقق اليدوي من تفاصيل كل مزود وتاريخ آخر تحديث للبيانات."),
                  _table([[_metric_card(counts.get("مرتفع الخطورة", 0), "مرتفع الخطورة", RED),
                           _metric_card(counts.get("يحتاج مراجعة", 0), "يحتاج مراجعة", ORANGE),
                           _metric_card(counts.get("لا توجد مؤشرات مباشرة", 0), "دون مؤشرات مباشرة", GREEN),
                           _metric_card(counts.get("غير مكتمل", 0), "نتائج غير مكتملة", MUTED)]], [2300] * 4)])
    if not rows:
        parts.append(_paragraph("لا تتوفر نتائج مكتملة لتحليل سمعة المصادر ضمن نطاق المراجعة الحالية.", bold=True, color=MUTED, before=220))
        return "".join(parts)
    widths = [1700, 1500, 3600, 2200]
    labels = ["عنوان IP", "الحكم الموحد", "نتيجة التحليل", "السياق والتفاصيل"]
    header = [[_cell(label, width=width, fill=BLUE, bold=True, color=WHITE, size=17) for label, width in zip(labels, widths)]]
    parts.extend([_subheading("تفاصيل النتائج حسب المصدر"), _table(header + rows, widths, repeat_header=True)])
    return "".join(parts)


def _model_analysis_section(analysis: dict[str, Any]) -> str:
    settings = _report_settings()
    if not settings.get("include_ai_analysis", True):
        return ""
    model_analysis = analysis.get("model_analysis") or {}
    if model_analysis.get("status") != "completed":
        return ""
    result = model_analysis.get("result") or {}
    summary = str(result.get("executive_summary_ar") or "").strip()
    if not summary:
        return ""
    parts = [
        _section_title("التقييم التحليلي المتقدم"),
        _paragraph(summary, size=23, after=160, line=360),
    ]
    patterns = [str(item).strip() for item in result.get("patterns", []) if str(item).strip()]
    if patterns:
        parts.append(_subheading("الأنماط المترابطة"))
        parts.extend(_paragraph(f"• {item}", size=21, after=70) for item in patterns[:6])
    recommendations = [str(item).strip() for item in result.get("recommendations", []) if str(item).strip()]
    if recommendations:
        parts.append(_subheading("إجراءات التحقق المقترحة"))
        limit = int(settings.get("recommendations") or 8)
        parts.extend(_paragraph(f"{index}. {item}", size=21, after=70) for index, item in enumerate(recommendations[:limit], 1))
    return "".join(parts)


def _forensic_analysis_paragraphs(record: dict[str, Any]) -> list[str]:
    desc = str(record.get("description") or "").strip()
    desc_ar = str(record.get("description_ar") or "").strip()
    threat_fam = str(record.get("threat_family") or "نشاط أمني غير معتاد").strip()
    category = str(record.get("category") or "").strip()
    sev = str(record.get("severity") or "-").strip()
    score = record.get("risk_score", 0)
    action_raw = str(record.get("action") or "").strip()
    action_ar = str(record.get("action_ar") or action_raw or "-").strip()

    src_ip = str(record.get("src_ip") or record.get("event_source") or "-").strip()
    src_port = str(record.get("src_port") or "").strip()
    dst_ip = str(record.get("destination") or record.get("dst_ip") or "-").strip()
    dst_port = str(record.get("dst_port") or "").strip()
    proto = str(record.get("protocol") or record.get("transport") or "-").strip()
    app = str(record.get("service_name") or "").strip()
    device = str(record.get("device") or "").strip()

    raw = record.get("raw_fields") if isinstance(record.get("raw_fields"), dict) else {}
    if not app:
        app = str(raw.get("Application") or raw.get("app") or "").strip()
    if not proto or proto == "-":
        proto = str(raw.get("Transmission Protocol") or raw.get("Protocol") or "-").strip()
    if not device:
        device = str(raw.get("Device") or "").strip()

    policy = str(raw.get("Policy") or raw.get("Rule") or "").strip()
    src_zone = str(raw.get("Source Zone") or raw.get("SrcZone") or "").strip()
    dst_zone = str(raw.get("Destination Zone") or raw.get("DstZone") or "").strip()

    cve_match = re.search(r"CVE-\d{4}-\d+", desc + " " + desc_ar + " " + str(raw), re.IGNORECASE)
    cve = cve_match.group(0).upper() if cve_match else ""

    headline = desc_ar if desc_ar else desc
    if not headline or headline == "-":
        headline = threat_fam

    paragraphs = []

    # 1. Headline & Technical Identity
    title_color = RED if sev in ("حرج", "مرتفع") else DARK
    paragraphs.append(_rich_paragraph([
        {"text": "المسمى الأمني للحدث: ", "bold": True, "color": BLUE, "size": 18},
        {"text": headline, "bold": True, "color": title_color, "size": 18},
    ], after=25))

    if desc and desc != headline:
        paragraphs.append(_rich_paragraph([
            {"text": "التوقيع والاسم الفني الأصلي: ", "bold": True, "color": MUTED, "size": 16},
            {"text": desc, "color": DARK, "size": 16},
        ], after=25))

    if cve:
        paragraphs.append(_rich_paragraph([
            {"text": "المرجع الأمني الدولي: ", "bold": True, "color": RED, "size": 17},
            {"text": cve, "bold": True, "color": RED, "size": 17},
            {"text": " | ثغرة أمنية معتمدة دولياً ومصنفة عالية الخطورة لتجاوز الحماية وتفويض الصلاحيات.", "color": MUTED, "size": 15},
        ], after=25))

    # 2. Detailed Forensic Analysis
    fam_lower = threat_fam.lower()
    cat_lower = category.lower()
    if cve or "cve" in fam_lower or "exploit" in fam_lower or "ثغرة" in fam_lower:
        explanation = (
            "محاولة استغلال ثغرة أمنية لتجاوز آليات المصادقة وتفويض الصلاحيات (Authorization Bypass). "
            "يقوم المهاجم بإرسال حمولات مهيأة للتسلل إلى وظائف النظام الحساسة دون الحصول على تصريح شرعي."
        )
    elif "expiro" in fam_lower or "virus" in cat_lower or "فيروس" in fam_lower:
        explanation = (
            "نشاط برمجي خبيث ينتمي لعائلة الفيروسات الخبيثة (Expiro Virus)، "
            "حيث تحاول البرمجية الخبيثة إصابة الملفات والتواصل مع خوادم القيادة والتحكم (C2) لتسريب البيانات أو استقبال أوامر مشبوهة."
        )
    elif "trojan" in cat_lower or "تروجان" in fam_lower or "tiggre" in fam_lower or "miner" in fam_lower:
        explanation = (
            "نشاط تروجان خبيث (Trojan) يستهدف اختراق الجهاز والتواصل مع نطاقات خارجية لتنزيل برمجيات ضارة إضافية "
            "أو استغلال موارد المعالجة والحوسبة في تعدين العملات المشفرة."
        )
    elif "backdoor" in cat_lower or "أدوات اختراق" in fam_lower:
        explanation = (
            "محاولة تثبيت أو استخدام أدوات نفاذ خلفي (Backdoor / Remote Access Tools) تمنح المهاجم قدرة التحكم عن بُعد في النظام والتنقل الجانبي داخل الشبكة."
        )
    elif "recon" in fam_lower or "استطلاع" in fam_lower:
        explanation = (
            "عمليات استطلاع ومسح للشبكة (Network Reconnaissance) عبر إرسال حزم استكشافية متتالية لكشف المنافذ المفتوحة وبنية الشبكة تمهيداً لشن هجوم موجه."
        )
    elif "spoof" in fam_lower or "flood" in fam_lower or "انتحال" in fam_lower or "إغراق" in fam_lower:
        explanation = (
            "هجوم شبكي يعتمد على تزييف هوية العناوين (IP Spoofing) أو إغراق حركة البيانات بحزم غير مشروعة للتأثير على استقرار خدمات الشبكة."
        )
    else:
        explanation = (
            "نشاط أمني ذو نمط غير اعتيادي مصنف بدرجة خطورة عالية، يستوجب فحص سجلات الاتصال المرتبطة وتدقيق تدفقات البيانات الصادرة والواردة."
        )

    paragraphs.append(_rich_paragraph([
        {"text": "التحليل الجنائي: ", "bold": True, "color": BLUE, "size": 17},
        {"text": explanation, "color": DARK, "size": 17},
    ], after=30))

    # 3. Network Flow & Path
    src_disp = f"{src_ip}:{src_port}" if src_port else src_ip
    dst_disp = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
    net_parts = [
        {"text": "مسار التدفق الشبكي: ", "bold": True, "color": BLUE, "size": 17},
        {"text": f"انطلقت حركة البيانات من المصدر ({src_disp}) متجهة إلى الهدف ({dst_disp}) عبر بروتوكول ({proto})", "color": DARK, "size": 17},
    ]
    if app and app != "-":
        net_parts.append({"text": f" وتطبيق ({app})", "color": DARK, "size": 17})
    if src_zone and dst_zone:
        net_parts.append({"text": f" بين المنطقتين [{src_zone} -> {dst_zone}]", "color": DARK, "size": 17})
    if policy:
        net_parts.append({"text": f" بموجب سياسة الحماية [{policy}]", "color": DARK, "size": 17})
    net_parts.append({"text": ".", "color": DARK, "size": 17})
    if device:
        net_parts.append({"text": f" جهاز الرصد: ({device}).", "color": MUTED, "size": 16})
    paragraphs.append(_rich_paragraph(net_parts, after=30))

    # 4. Action & Enforcement
    action_lower = (action_raw + " " + action_ar).lower()
    if any(k in action_lower for k in ["block", "drop", "deny", "discard", "حظر", "إسقاط"]):
        paragraphs.append(_rich_paragraph([
            {"text": "حالة الإجراء: ", "bold": True, "color": GREEN, "size": 17},
            {"text": f"[تم الحظر والإسقاط بنجاح - {action_ar}] ", "bold": True, "color": GREEN, "size": 17},
            {"text": "قامت منظومة الحماية برصد الهجوم وإسقاط الحزم ومنع اكتمال الاتصال بالهدف.", "color": DARK, "size": 16},
        ], after=30))
    else:
        paragraphs.append(_rich_paragraph([
            {"text": "حالة الإجراء: ", "bold": True, "color": RED, "size": 17},
            {"text": f"[تنبيه أمني دون حظر - {action_ar}] ", "bold": True, "color": RED, "size": 17},
            {"text": "لم يتم حظر الاتصال آلياً؛ يمثل ذلك مؤشراً خطيراً يستوجب التحقق الفوري من سلامة الخادم المستهدف ومراجعة سجلات الدخول.", "color": RED, "size": 16},
        ], after=30))

    # 5. Analyst Guidance
    if cve:
        rec_text = f"عزل النظام المستهدف فوراً، وتطبيق الترقيع الأمني الخاص بالثغرة {cve}، والتحقق من سجلات نفاذ الويب (Web Access Logs)."
    elif "c2" in explanation.lower() or "control" in explanation.lower() or "فيروس" in fam_lower:
        rec_text = f"حظر عنوان النطاق/الوجهة الخبيثة {dst_ip} على الجدار الناري الخارجي، وعزل الجهاز المصدر {src_ip} وإجراء مسح جنائي شامل."
    else:
        rec_text = f"مراجعة سجلات الاتصال التفصيلية للعنوان {src_ip} وتدقيق صلاحيات الحسابات المرتبطة لمنع أي تسلل إضافي."

    paragraphs.append(_rich_paragraph([
        {"text": "التوصية الإجرائية المباشرة: ", "bold": True, "color": BLUE, "size": 17},
        {"text": rec_text, "bold": True, "color": DARK, "size": 16},
    ], after=15))

    return paragraphs


def _technical_context_paragraphs(record: dict[str, Any]) -> list[str]:
    raw_fields = record.get("raw_fields") if isinstance(record.get("raw_fields"), dict) else {}
    if not raw_fields:
        return [_paragraph("لا توجد حقول أصلية إضافية.", color=MUTED, size=15)]

    labels_map = {
        "Device": "الجهاز الراصد", "Time": "التوقيت المسجل", "Source Zone": "منطقة المصدر",
        "Destination Zone": "منطقة الوجهة", "Policy": "سياسة الأمان", "Rule": "قاعدة الحماية",
        "Application": "التطبيق", "Transmission Protocol": "بروتوكول النقل",
        "Attack Name": "اسم الهجوم", "Action": "الإجراء المنفذ", "Reference": "المرجع",
        "Message": "رسالة النظام", "SrcPort": "منفذ المصدر", "DstPort": "منفذ الوجهة",
        "SrcIp": "عنوان المصدر", "DstIp": "عنوان الوجهة", "SignName": "اسم التوقيع",
        "SignId": "معرف التوقيع", "User": "المستخدم", "Severity": "المستوى",
    }

    runs = []
    for key, value in raw_fields.items():
        val_str = str(value).strip()
        if not val_str:
            continue
        ar_key = labels_map.get(key, key)
        runs.append({"text": f"• {ar_key}: ", "bold": True, "color": BLUE, "size": 15})
        runs.append({"text": f"{val_str}   ", "color": DARK, "size": 15})

    if not runs:
        return [_paragraph("لا توجد حقول أصلية إضافية.", color=MUTED, size=15)]
    return [_rich_paragraph(runs, after=15)]


def _event_details_section(analysis: dict[str, Any], reader: Any) -> str:
    if analysis.get("metadata", {}).get("data_type") != "siem_logs":
        return ""
    intel_results = analysis.get("enrichment", {}).get("results", {})
    records = reader.iter_records(sort_by="risk_score_desc", limit=20)
    parts = [_section_title("تفاصيل وتحليل الأحداث الأمنية الأعلى خطورة", page_break_before=True),
             _paragraph("يقدم هذا القسم تحليلاً جنائياً مفصلاً لكل حدث عالي الخطورة مع مسار التدفق الشبكي، تقييم التأثير، والتوصيات الإجرائية المباشرة.", color=MUTED, size=19)]
    for index, record in enumerate(records, 1):
        source_disp = f"{record.get('src_ip', '-')}:{record.get('src_port', '')}" if record.get('src_port') else str(record.get('src_ip') or record.get('event_source') or '-')
        dest_disp = f"{record.get('destination', '-')}:{record.get('dst_port', '')}" if record.get('dst_port') else str(record.get('destination') or record.get('dst_ip') or '-')
        sev_color = RED if record.get("severity") in ("حرج", "مرتفع") else DARK
        act_ar = str(record.get("action_ar") or record.get("action") or "-")
        act_color = GREEN if any(k in act_ar.lower() for k in ["block", "drop", "discard", "حظر", "إسقاط"]) else RED

        result_ip, intel, related_count = _event_reputation_result(record, intel_results)
        overall, overall_color = _overall_verdict(intel) if intel and "reason" not in intel else ("غير متاح", MUTED)
        reputation_details = [
            _rich_paragraph([
                {"text": "الحكم الموحد للاستخبارات: ", "bold": True, "color": BLUE, "size": 17},
                {"text": overall, "bold": True, "color": overall_color, "size": 17},
            ], after=20),
        ]
        if result_ip and result_ip != str(record.get("src_ip")):
            reputation_details.append(_paragraph(
                f"وفرت الأنظمة نتيجة للعنوان المستخرج {result_ip} ضمن سياق هذا الحدث.",
                color=MUTED, size=16, after=20,
            ))
        reputation_details.extend(_source_reputation_details(intel))

        detail_rows = [
            [_cell(f"الحدث رقم {index}", width=1600, fill=BLUE, bold=True, color=WHITE, align="center"),
             _cell(f"Event ID: {record.get('event_id', '-')}", width=7500, fill=BLUE, bold=True, color=WHITE, align="center", colspan=3)],
            [_cell("وقت الحدوث", width=1600, fill=LIGHT_BLUE, bold=True), _cell(record.get("event_time", "-"), width=2950),
             _cell("مستوى الخطورة", width=1600, fill=LIGHT_BLUE, bold=True), _cell(f"{record.get('severity', '-')} - الدرجة {record.get('risk_score', 0)} من 100", width=2950, bold=True, color=sev_color)],
            [_cell("المصدر / المنفذ", width=1600, fill=LIGHT_BLUE, bold=True), _cell(source_disp, width=2950),
             _cell("الوجهة / المنفذ", width=1600, fill=LIGHT_BLUE, bold=True), _cell(dest_disp, width=2950)],
            [_cell("عائلة التهديد", width=1600, fill=LIGHT_BLUE, bold=True), _cell(record.get("threat_family", "-"), width=2950, bold=True, color=RED),
             _cell("الإجراء المنفذ", width=1600, fill=LIGHT_BLUE, bold=True), _cell(act_ar, width=2950, bold=True, color=act_color)],
            [_cell("التفاصيل والتحليل الجنائي", width=1600, fill=LIGHT_BLUE, bold=True), _cell(_forensic_analysis_paragraphs(record), width=7500, align="right", colspan=3)],
            [_cell("السياق والمؤشرات الفنية", width=1600, fill=LIGHT_BLUE, bold=True), _cell(_technical_context_paragraphs(record), width=7500, align="right", colspan=3)],
            [_cell("نتائج السمعة للمستخرجات", width=1600, fill=LIGHT_BLUE, bold=True), _cell(reputation_details, width=7500, align="right", colspan=3)],
        ]
        parts.extend([_table(detail_rows, [1600, 2950, 1600, 2950]), _paragraph("", after=30)])
    return "".join(parts)


def _recommendations_section(analysis: dict[str, Any]) -> str:
    metadata, summary = analysis.get("metadata", {}), analysis.get("summary", {})
    _, intel_counts, _ = _intel_rows(analysis)
    recommendations = []
    if intel_counts.get("مرتفع الخطورة", 0):
        recommendations.append("عزل أو تقييد المصادر المصنفة مرتفعة الخطورة مؤقتاً بعد التحقق من أثر الإجراء، ثم جمع الأدلة وحفظ السجلات ذات العلاقة.")
    if intel_counts.get("يحتاج مراجعة", 0):
        recommendations.append("مراجعة المصادر المشبوهة وربطها بسجلات الجدار الناري وDNS وProxy والتحقق من الملكية والغرض التشغيلي.")
    if metadata.get("data_type") == "siem_logs":
        recommendations.extend(["البدء بالأحداث الأعلى درجة، والتحقق من حساب المستخدم، وعنوان الـ IP المرتبط.",
                                "إنشاء تنبيهات مخصصة لرصد أي محاولات متتالية للدخول الفاشل كإجراء احترازي من الهجمات.",
                                "التأكد من تحديث سياسات الحماية على أنظمة Active Directory وإلزامية المصادقة الثنائية (MFA).",
                                "تجميع الأحداث المتكررة للعنوان أو الحساب نفسه في قضية تحقيق واحدة لتقليل الضوضاء."])
    else:
        recommendations.extend(["مراجعة أعلى المصادر من حيث السجلات الأمنية والتحقق منها.",
                                "التحقق من التنبيهات المكررة وعزل العناوين المتورطة في هجمات مستمرة.",
                                "مقارنة السجلات الحالية مع فترات طبيعية للكشف عن الانحراف."])
    recommendations.append("توثيق قرار الإغلاق أو التصعيد لكل نتيجة مع إرفاق السجل الأمني ومبرر الإغلاق.")
    items = [_rich_paragraph([{"text": f"{index}. ", "bold": True, "color": BLUE, "size": 23},
                              {"text": recommendation, "color": DARK, "size": 22}], after=95)
             for index, recommendation in enumerate(recommendations, 1)]
    conclusion = (f"بناءً على مراجعة {summary.get('records', 0)} سجل، فإن النتائج الحالية تستدعي ترتيب التحقيق وفق درجة الخطورة وسمعة المصدر وحجم النشاط. "
                  "ولا يوصى باتخاذ قرار احتواء اعتماداً على مؤشر منفرد؛ إذ يجب تثبيت الحكم بمراجعة سجلات الشبكة وملكية الأصل والهوية المستخدمة والمبرر التشغيلي للنشاط.")
    return "".join([_section_title("التوصيات"), *items, _section_title("الخلاصة"),
                    _paragraph(conclusion, size=23, line=360), _paragraph("وتقبلوا خالص التحايا،", bold=True, color=BLUE, size=23, before=280),
                    _paragraph("فريق تحليل سجلات الأمان - LogScope", bold=True, size=21)])


def _header_xml() -> str:
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:hdr xmlns:w="{W_NS}" xmlns:r="{R_NS}"><w:p><w:pPr><w:bidi w:val="1"/><w:jc w:val="left"/><w:pBdr>'
            f'<w:bottom w:val="single" w:sz="8" w:space="4" w:color="{BLUE}"/></w:pBdr></w:pPr>'
            f'{_run("تقرير تحليل سجلات الأمان | LogScope", bold=True, color=BLUE, size=18)}</w:p></w:hdr>')


def _footer_xml() -> str:
    page = '<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText>PAGE</w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>'
    total = '<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText>NUMPAGES</w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>'
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<w:ftr xmlns:w="{W_NS}" xmlns:r="{R_NS}"><w:p><w:pPr><w:bidi w:val="1"/><w:jc w:val="center"/><w:pBdr>'
            f'<w:top w:val="single" w:sz="6" w:space="4" w:color="{BLUE}"/></w:pBdr></w:pPr>'
            f'{_run("للاستخدام الداخلي | صفحة ", color=MUTED, size=16)}{page}{_run(" من ", color=MUTED, size=16)}{total}</w:p></w:ftr>')


def _styles_xml() -> str:
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="{W_NS}">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:cs="Arial"/><w:sz w:val="23"/><w:szCs w:val="23"/><w:lang w:val="en-US" w:bidi="ar-SA"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:bidi w:val="1"/><w:jc w:val="left"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:outlineLvl w:val="0"/><w:bidi w:val="1"/><w:jc w:val="left"/></w:pPr><w:rPr><w:b/><w:bCs/><w:color w:val="{BLUE}"/><w:sz w:val="31"/><w:szCs w:val="31"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:outlineLvl w:val="1"/><w:bidi w:val="1"/><w:jc w:val="left"/></w:pPr><w:rPr><w:b/><w:bCs/><w:color w:val="{BLUE}"/><w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr></w:style></w:styles>'''


def _incidents_section(analysis: dict[str, Any]) -> str:
    incidents = analysis.get("incidents", [])
    if not incidents:
        return ""

    parts = [
        _section_title("الحوادث الأمنية المترابطة (Correlated Incidents)", page_break_before=True),
        _paragraph(
            f"تم رصد وربط {len(incidents)} حادثة أمنية متعددة المراحل عبر محرك الترابط الزمني والسياقي، تفصل الجداول التالية تسلسل الهجوم والكيانات المستهدفة وتوصيات الاحتواء.",
            color=MUTED, size=19
        )
    ]

    for index, inc in enumerate(incidents, 1):
        sev_color = RED if inc.get("severity") == "حرج" else ORANGE
        conclusion_map = {
            "confirmed": "مؤكد بالأدلة الجنائية",
            "likely_successful": "يرجح نجاح الهجوم",
            "correlated_suspicious": "نشاط مترابط مشبوه",
            "likely_malicious": "يرجح كونه خبيثاً",
            "observed": "نشاط مرصود",
        }
        conclusion_ar = conclusion_map.get(str(inc.get("conclusion_level", "")).lower(), inc.get("conclusion_level", "-"))

        rows = [
            [_cell(f"حادثة أمنية رقم {index}: {inc.get('incident_id')}", width=9100, fill=BLUE, bold=True, color=WHITE, align="center", colspan=4)],
            [_cell("عنوان الحادثة", width=1600, fill=LIGHT_BLUE, bold=True), _cell(inc.get("title_ar", "-"), width=7500, colspan=3, bold=True)],
            [_cell("مستوى الخطورة", width=1600, fill=LIGHT_BLUE, bold=True), _cell(f"{inc.get('severity', '-')} ({inc.get('risk_score', 0)}/100)", width=2950, bold=True, color=sev_color),
             _cell("نسبة الموثوقية", width=1600, fill=LIGHT_BLUE, bold=True), _cell(f"{inc.get('confidence_score', 0)}%", width=2950, bold=True, color=BLUE)],
            [_cell("الاستنتاج الجنائي", width=1600, fill=LIGHT_BLUE, bold=True), _cell(conclusion_ar, width=2950, bold=True),
             _cell("عدد الأحداث", width=1600, fill=LIGHT_BLUE, bold=True), _cell(str(inc.get("event_count", 0)), width=2950)],
            [_cell("الحسابات المستهدفة", width=1600, fill=LIGHT_BLUE, bold=True), _cell(", ".join(inc.get("usernames", [])) or "—", width=2950),
             _cell("عناوين IP المهاجمة", width=1600, fill=LIGHT_BLUE, bold=True), _cell(", ".join(inc.get("source_ips", [])) or "—", width=2950)],
            [_cell("التوصيف الجنائي", width=1600, fill=LIGHT_BLUE, bold=True), _cell(inc.get("description_ar", "-"), width=7500, colspan=3)],
        ]

        if inc.get("recommendations"):
            recs_text = " • " + "\n • ".join(inc["recommendations"])
            rows.append([_cell("توصيات الاستجابة", width=1600, fill=LIGHT_BLUE, bold=True), _cell(recs_text, width=7500, colspan=3, bold=True, color=RED)])

        parts.extend([_table(rows, [1600, 2950, 1600, 2950]), _paragraph("", after=40)])

    return "".join(parts)


def _mitre_section(analysis: dict[str, Any]) -> str:
    mitre = analysis.get("mitre_matrix", [])
    if not mitre:
        return ""

    parts = [
        _section_title("مصفوفة تكتيكات وتقنيات MITRE ATT&CK", page_break_before=True),
        _paragraph(
            "توثيق التقنيات والتكتيكات المكتشفة طبقاً للمعايير العالمية لمصفوفة MITRE ATT&CK ومعدلات تكرارها:",
            color=MUTED, size=19
        )
    ]

    widths = [2000, 2800, 1500, 2800]
    headers = ["معرف التقنية", "التكتيك المرتبط", "عدد الأحداث", "عائلة التهديد"]
    rows = [[_cell(h, width=w, fill=BLUE, bold=True, color=WHITE, size=17) for h, w in zip(headers, widths)]]

    for item in mitre[:25]:
        rows.append([
            _cell(item.get("technique", "-"), width=2000, bold=True),
            _cell(item.get("tactic", "-"), width=2800),
            _cell(str(item.get("count", 0)), width=1500, bold=True),
            _cell(item.get("threat_family", "-"), width=2800),
        ])

    parts.append(_table(rows, widths, repeat_header=True))
    parts.append(_paragraph("", after=40))
    return "".join(parts)


def build_report_docx(analysis: dict[str, Any], reader: Any, output_path: str) -> None:
    """Generate a polished multi-section Arabic Word report."""
    # We stream the document XML incrementally to the zip
    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/></Types>'''
    package_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'''
    document_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/></Relationships>'''
    settings = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:settings xmlns:w="{W_NS}"><w:zoom w:percent="100"/><w:defaultTabStop w:val="720"/><w:updateFields w:val="true"/><w:themeFontLang w:val="en-US" w:bidi="ar-SA"/><w:compat/></w:settings>'''
    
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in {"[Content_Types].xml": content_types, "_rels/.rels": package_rels,
                           "word/_rels/document.xml.rels": document_rels,
                           "word/styles.xml": _styles_xml(), "word/settings.xml": settings,
                           "word/header1.xml": _header_xml(), "word/footer1.xml": _footer_xml()}.items():
            archive.writestr(name, data)
            
        with archive.open("word/document.xml", "w", force_zip64=True) as doc_file:
            doc_file.write(f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="{W_NS}" xmlns:r="{R_NS}"><w:body>'''.encode("utf-8"))
            doc_file.write(_cover(analysis.get("metadata", {})).encode("utf-8"))
            doc_file.write(_summary_section(analysis).encode("utf-8"))
            doc_file.write(_incidents_section(analysis).encode("utf-8"))
            doc_file.write(_model_analysis_section(analysis).encode("utf-8"))
            doc_file.write(_mitre_section(analysis).encode("utf-8"))
            doc_file.write(_top_events_section(analysis, reader).encode("utf-8"))
            doc_file.write(_intel_section(analysis).encode("utf-8"))
            doc_file.write(_event_details_section(analysis, reader).encode("utf-8"))
            doc_file.write(_recommendations_section(analysis).encode("utf-8"))
            doc_file.write('''<w:sectPr><w:bidi/><w:headerReference w:type="default" r:id="rId1"/><w:footerReference w:type="default" r:id="rId2"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="893" w:right="1008" w:bottom="893" w:left="1008" w:header="461" w:footer="432" w:gutter="0"/><w:cols w:space="708"/><w:docGrid w:linePitch="360"/></w:sectPr></w:body></w:document>'''.encode("utf-8"))

