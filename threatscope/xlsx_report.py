"""Minimal dependency-free XLSX report writer."""

from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime
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
    metadata = analysis.get("metadata") or {}
    summary = dict(analysis.get("summary") or {})
    total_records = summary.get("records", 0)
    enrichment = analysis.get("enrichment", {})
    summary_rows = [
        ["المؤشر", "القيمة"],
        ["وقت التحليل", metadata.get("analyzed_at", "غير متاح")],
        ["النظام المصدر", metadata.get("source_system_label", "غير محدد — ملف سابق")],
        ["نطاق التحليل", "أحداث الحماية ومؤشرات الاختراق"],
        ["إجمالي السجلات", summary.get("records", 0)],
        ["الهاشات الفريدة", summary.get("unique_hashes", 0)],
        ["السجلات غير المحلولة", summary.get("unresolved", 0)],
        ["التهديدات غير المخففة", summary.get("not_mitigated", 0)],
        ["الإجراءات المعلقة", summary.get("pending_actions", 0)],
        ["سجلات حرجة", summary.get("critical", 0)],
        ["سجلات مرتفعة", summary.get("high", 0)],
        ["صفوف مكررة", summary.get("duplicate_rows", 0)],
        ["حالة التحقق الخارجي", "مكتمل جزئيًا" if enrichment.get("status") == "completed_partial" else enrichment.get("status", "لم يبدأ")],
        ["نتائج تعذر تحديثها", enrichment.get("refresh_failures", 0)],
        ["نتائج محفوظة استُخدمت كبديل", enrichment.get("fallback", 0)],
    ]
    
    def summary_generator():
        for r in summary_rows: yield r

    sheets = [("الملخص", summary_generator, [30, 70], len(summary_rows))]
    
    record_headers = [
        "رقم الصف", "درجة الخطورة", "المستوى", "اسم التهديد", "الهاش", "نوع الهاش", "الجهاز",
        "التصنيف", "الثقة", "حالة الحادث", "حالة التخفيف", "الموقع", "محرك الكشف", "المسار", "أسباب الخطورة",
    ]
    def records_generator():
        yield record_headers
        for record in reader.iter_records(sort_by="risk_score_desc"):
            yield [
                record.get("row_number"), record.get("risk_score"), record.get("risk_level"), record.get("threat_name"),
                record.get("hash"), record.get("hash_type"), record.get("endpoint"), record.get("classification"),
                record.get("confidence"), record.get("incident_status"), record.get("status"), record.get("site"),
                record.get("engine"), record.get("path"), "، ".join(record.get("risk_reasons") or []),
            ]
    sheets.append(("النتائج", records_generator, [10, 14, 12, 35, 30, 12, 20, 20, 12, 16, 16, 20, 16, 50, 45], total_records + 1))
    
    # Intel sheet
    def intel_generator():
        yield ["الهاش", "المحرك الكاشف", "تصنيف المحرك", "نتيجة الفحص", "النسخة", "وقت الفحص"]
        for file_hash, providers in analysis.get("enrichment", {}).get("results", {}).items():
            vt = providers.get("virustotal", {})
            for name, result in vt.get("scans", {}).items():
                if result.get("detected"):
                    yield [file_hash, name, result.get("result"), "مكتشف", result.get("version"), result.get("update")]
                
    intel_results = analysis.get("enrichment", {}).get("results", {})
    intel_rows = sum(sum(1 for r in p.get("virustotal", {}).get("scans", {}).values() if r.get("detected")) for p in intel_results.values() if isinstance(p, dict)) + 1
    sheets.append(("استخبارات الهاش", intel_generator, [30, 25, 35, 15, 20, 20], intel_rows))

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
