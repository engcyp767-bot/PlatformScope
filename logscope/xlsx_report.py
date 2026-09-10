"""Minimal dependency-free XLSX report writer."""

from __future__ import annotations

import io
import re
import zipfile
from typing import Any, Iterable
from xml.sax.saxutils import escape


def _column_name(index: int) -> str:
    result = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _safe_sheet_name(name: str) -> str:
    return re.sub(r"[\\/*?:\[\]]", "_", name)[:31] or "Sheet"


def _cell(value: Any, reference: str, style: int = 0) -> str:
    style_attr = f' s="{style}"' if style else ""
    if value is None:
        return f'<c r="{reference}"{style_attr}/>'
    if isinstance(value, bool):
        return f'<c r="{reference}" t="b"{style_attr}><v>{1 if value else 0}</v></c>'
    if isinstance(value, (int, float)):
        return f'<c r="{reference}"{style_attr}><v>{value}</v></c>'
    text = escape(str(value))
    return f'<c r="{reference}" t="inlineStr"{style_attr}><is><t xml:space="preserve">{text}</t></is></c>'


def _write_sheet(f_out, iter_rows: Iterable[list[Any]], widths: list[int] | None, expected_rows: int = 1):
    width = len(widths) if widths else 1
    cols = ""
    if widths:
        cols = "<cols>" + "".join(
            f'<col min="{i}" max="{i}" width="{min(max(value, 8), 55)}" customWidth="1"/>'
            for i, value in enumerate(widths, 1)
        ) + "</cols>"
        
    dimension = f"A1:{_column_name(width)}{max(expected_rows, 1)}"
    
    header_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="{dimension}"/><sheetViews><sheetView workbookViewId="0" rightToLeft="1">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
        f'{cols}<sheetData>'
    ).encode("utf-8")
    f_out.write(header_xml)
    
    for row_index, row in enumerate(iter_rows, 1):
        cells = "".join(_cell(value, f"{_column_name(col_index)}{row_index}", 1 if row_index == 1 else 0) for col_index, value in enumerate(row, 1))
        f_out.write(f'<row r="{row_index}">{cells}</row>'.encode("utf-8"))
        
    footer_xml = f'</sheetData><autoFilter ref="{dimension}"/></worksheet>'.encode("utf-8")
    f_out.write(footer_xml)


def build_report_xlsx(analysis: dict[str, Any], reader: Any, output_path: str) -> None:
    metadata = analysis.get("metadata", {})
    summary = analysis.get("summary", {})
    data_type = metadata.get("data_type", "")
    total_records = summary.get("records", 0)
    
    summary_rows = [
        ["المؤشر", "القيمة"],
        ["وقت التحليل", metadata.get("analyzed_at", "")],
        ["النظام المصدر", metadata.get("source_system_label", "غير محدد — ملف سابق")],
        ["إجمالي السجلات", total_records],
        ["عناوين IP الفريدة", summary.get("unique_ips", 0)],
    ]
    
    if data_type == "siem_logs":
        summary_rows.extend([
            ["سجلات حرجة", summary.get("critical", 0)],
            ["سجلات مرتفعة", summary.get("high", 0)],
        ])
    elif data_type == "network_flows":
        summary_rows.extend([
            ["إجمالي البايتات", summary.get("formatted_bytes", "")],
            ["إجمالي الحزم", summary.get("total_packets", 0)],
        ])

    def summary_generator():
        for r in summary_rows: yield r

    # We use a list of configs: (name, generator_func, widths, expected_rows)
    sheets = [("الملخص", summary_generator, [30, 70], len(summary_rows))]

    if data_type == "siem_logs":
        record_headers = [
            "وقت الحدث", "الخطورة", "الدرجة", "رقم الحدث (Event ID)", "مصدر الحدث (Source)", "الحساب المرتبط (User)", "تفاصيل الحدث (Description)"
        ]
        
        def records_generator():
            yield record_headers
            for record in reader.iter_records(sort_by="risk_score_desc"):
                yield [
                    record.get("event_time"), record.get("severity"), record.get("risk_score"),
                    record.get("event_id"), record.get("device") or record.get("src_ip") or record.get("event_source"),
                    record.get("user_account"), record.get("description")
                ]
                
        sheets.append(("سجلات الأمان", records_generator, [22, 14, 10, 20, 25, 25, 60], total_records + 1))

        source_headers = [str(value) for value in metadata.get("source_headers", []) if str(value).strip()]
        if not source_headers:
            # We must iterate once just to find headers if missing. (MemoryResultReader only, SQLite usually has it in metadata)
            # To avoid iterating all, we just get first page.
            page, _ = reader.get_paginated_records(0, 100)
            for record in page:
                for header in (record.get("raw_fields") or {}):
                    if header not in source_headers:
                        source_headers.append(header)
        if source_headers:
            def raw_generator():
                yield source_headers
                for record in reader.iter_records(sort_by="risk_score_desc"):
                    fields = record.get("raw_fields") or {}
                    yield [fields.get(header, "") for header in source_headers]
            sheets.append(("البيانات الأصلية", raw_generator, [min(max(len(header) + 4, 14), 45) for header in source_headers], total_records + 1))
        
    elif data_type == "network_flows":
        record_headers = [
            "عنوان المصدر", "عنوان الوجهة", "البروتوكول", "منفذ المصدر", "منفذ الوجهة", "البايتات", "الحزم"
        ]
        def flows_generator():
            yield record_headers
            for record in reader.iter_records(sort_by="risk_score_desc"):
                yield [
                    record.get("src_ip"), record.get("dst_ip"), record.get("protocol"),
                    record.get("src_port"), record.get("dst_port"), record.get("bytes"), record.get("packets")
                ]
        sheets.append(("التدفقات الشبكية", flows_generator, [18, 18, 14, 14, 14, 16, 16], total_records + 1))

    if data_type == "siem_logs" and analysis.get("incidents"):
        inc_headers = [
            "معرف الحادثة", "عنوان الحادثة", "المستوى", "الخطورة", "الموثوقية", "الاستنتاج الجنائي", "عدد الأحداث", "وقت البدء", "وقت الانتهاء", "الحسابات المستهدفة", "عناوين IP"
        ]
        def incidents_generator():
            yield inc_headers
            for inc in analysis.get("incidents", []):
                yield [
                    inc.get("incident_id"),
                    inc.get("title_ar"),
                    inc.get("severity"),
                    inc.get("risk_score"),
                    inc.get("confidence_score"),
                    inc.get("conclusion_level"),
                    inc.get("event_count"),
                    inc.get("start_time"),
                    inc.get("end_time"),
                    ", ".join(inc.get("usernames", [])),
                    ", ".join(inc.get("source_ips", [])),
                ]
        sheets.append(("الحوادث الأمنية", incidents_generator, [20, 40, 14, 12, 12, 22, 14, 22, 22, 25, 25], len(analysis.get("incidents", [])) + 1))

    if data_type == "siem_logs" and analysis.get("mitre_matrix"):
        mitre_headers = ["معرف التقنية", "التكتيك", "التكرار", "عائلة التهديد"]
        def mitre_generator():
            yield mitre_headers
            for item in analysis.get("mitre_matrix", []):
                yield [
                    item.get("technique"),
                    item.get("tactic"),
                    item.get("count"),
                    item.get("threat_family", ""),
                ]
        sheets.append(("مصفوفة MITRE", mitre_generator, [20, 25, 14, 30], len(analysis.get("mitre_matrix", [])) + 1))

    # Intel sheet
    def intel_generator():
        yield ["عنوان IP", "المصدر", "الحكم", "حالة المصدر", "تفاصيل"]
        for ip, providers in analysis.get("enrichment", {}).get("results", {}).items():
            if not providers:
                continue
            if "reason" in providers:
                yield [ip, "محلي", "متخطى", providers.get("reason"), ""]
                continue
                
            for provider, result in providers.items():
                if provider == "status": continue
                details = {key: value for key, value in result.items() if key not in {"verdict", "source_status", "cached"}}
                yield [ip, provider, result.get("verdict"), result.get("source_status"), str(details)]
                
    intel_results = analysis.get("enrichment", {}).get("results", {})
    intel_rows = sum(len(p) for p in intel_results.values() if isinstance(p, dict)) + 1
    sheets.append(("استخبارات IP", intel_generator, [20, 20, 18, 20, 70], intel_rows))

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' + "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1, len(sheets) + 1)) + '</Types>')
        archive.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        workbook_sheets = "".join(f'<sheet name="{escape(_safe_sheet_name(name))}" sheetId="{i}" r:id="rId{i}"/>' for i, (name, _, _, _) in enumerate(sheets, 1))
        archive.writestr("xl/workbook.xml", f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><workbookPr/><bookViews><workbookView/></bookViews><sheets>{workbook_sheets}</sheets></workbook>')
        rels = "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(sheets) + 1)) + f'<Relationship Id="rId{len(sheets)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        archive.writestr("xl/_rels/workbook.xml.rels", f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{rels}</Relationships>')
        archive.writestr("xl/styles.xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Arial"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Arial"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF0078D4"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment horizontal="center"/></xf></cellXfs></styleSheet>')
        
        for index, (_, gen_func, widths, expected_rows) in enumerate(sheets, 1):
            with archive.open(f"xl/worksheets/sheet{index}.xml", "w", force_zip64=True) as f_out:
                _write_sheet(f_out, gen_func(), widths, expected_rows)

