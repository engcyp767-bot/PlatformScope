"""Safe, dependency-free reader for CSV and XLSX files.

Supports automatic format detection, security checks, and normalisation.
"""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree as ET


MAIN_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
REL_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
MAX_XLSX_FILES = 2_000
MAX_UNCOMPRESSED_BYTES = 150 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_CSV_SIZE = 50 * 1024 * 1024  # 50 MB


class ParseError(ValueError):
    """Raised when a file is invalid or violates a safety rule."""


@dataclass
class ParsedData:
    filename: str
    headers: list[str]
    rows: Iterable[list[Any]]
    source_format: str
    total_rows: int = 0


HEADER_HINTS = {
    "event", "time", "date", "device", "source", "severity", "priority", "message",
    "description", "user", "account", "status", "action", "category", "count", "duration",
    "incident", "alert", "control", "policy", "compliance", "host", "ip", "application",
    "attack", "signature", "protocol", "port", "sport", "dport", "target", "destination",
    "zone", "src", "dst", "username", "hostname", "role", "type", "rule", "traffic",
    "client", "server", "domain", "logon", "process", "caller", "object", "command",
    "query", "url", "uri", "path", "method", "code", "file", "threat", "identity",
    "operation", "subject", "substatus", "reason", "level", "endpoint", "audit", "auth",
    "session", "agent", "hash", "sha256", "md5", "service", "computer", "machine",
    "الوصف", "المصدر", "الحدث", "الجهاز", "الوجهة", "المستخدم", "البروتوكول", "المنفذ", "الخطورة", "الإجراء",
    "التاريخ", "الوقت", "العملية", "الرابط", "المسار", "الحساب", "النظام", "التهديد", "الخدمة",
}


def _clean_table(rows: list[list[Any]]) -> tuple[list[str], list[list[Any]]]:
    """Locate a likely table header and preserve every subsequent column and row."""
    rows = [list(row) for row in rows if any(value is not None and str(value).strip() for value in row)]
    if not rows:
        raise ParseError("File does not contain tabular data")

    def score(row: list[Any], index: int) -> tuple[int, int]:
        values = [str(value).strip() for value in row if value is not None and str(value).strip()]
        if not values:
            return (-100, -index)
        matching_cells = sum(
            1 for val in values
            if set(re.findall(r"[a-z\u0621-\u064A]+", val.lower())) & HEADER_HINTS
        )
        text_cells = sum(not re.fullmatch(r"[-+]?\d+(?:[.,]\d+)?", value) for value in values)
        next_width = 0
        if index + 1 < len(rows):
            next_width = sum(value is not None and str(value).strip() != "" for value in rows[index + 1])
        compatibility = min(len(values), next_width) if len(values) > 1 else 0
        multi_col_bonus = 50 if len(values) > 2 else (20 if len(values) > 1 else -100)
        return (matching_cells * 25 + text_cells * 2 + compatibility + multi_col_bonus, -index)

    candidate_range = range(min(len(rows), 50))
    header_index = max(candidate_range, key=lambda index: score(rows[index], index))
    
    header_row = rows[header_index]
    width = max(len(header_row), max((len(row) for row in rows[header_index:]), default=len(header_row)))
    
    raw_headers = list(header_row) + [None] * (width - len(header_row))
    headers: list[str] = []
    used: dict[str, int] = {}
    for index, value in enumerate(raw_headers):
        base = str(value).strip() if value is not None and str(value).strip() else f"Column {index + 1}"
        used[base] = used.get(base, 0) + 1
        headers.append(base if used[base] == 1 else f"{base} ({used[base]})")
    
    data_rows = [list(row) + [None] * (width - len(row)) for row in rows[header_index + 1:]]
    return headers, data_rows


def _column_index(cell_reference: str) -> int:
    match = re.match(r"([A-Z]+)", cell_reference.upper())
    if not match:
        raise ParseError(f"Invalid cell reference: {cell_reference}")
    value = 0
    for char in match.group(1):
        value = value * 26 + ord(char) - 64
    return value - 1


def _normalise_target(target: str) -> str:
    if target.startswith("/"):
        return target.lstrip("/")
    parts: list[str] = []
    for part in ("xl/" + target).split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return "/".join(parts)


def _check_archive(archive: zipfile.ZipFile) -> None:
    infos = archive.infolist()
    if len(infos) > MAX_XLSX_FILES:
        raise ParseError("Workbook contains too many embedded files")
    total = sum(item.file_size for item in infos)
    if total > MAX_UNCOMPRESSED_BYTES:
        raise ParseError("Workbook expands beyond the allowed size")
    for item in infos:
        if item.filename.lower().endswith("vbaproject.bin"):
            raise ParseError("Macro-enabled workbooks are not accepted")
        if item.compress_size and item.file_size / item.compress_size > MAX_COMPRESSION_RATIO:
            raise ParseError("Suspicious archive compression ratio detected")
    required = {"xl/workbook.xml", "xl/_rels/workbook.xml.rels"}
    if not required.issubset({item.filename for item in infos}):
        raise ParseError("File is not a valid XLSX workbook")


def _shared_strings(archive: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    return ["".join(node.text or "" for node in item.iter(MAIN_NS + "t")) for item in root.findall(MAIN_NS + "si")]


def _date_style_indexes(archive: zipfile.ZipFile) -> set[int]:
    if "xl/styles.xml" not in archive.namelist():
        return set()
    root = ET.fromstring(archive.read("xl/styles.xml"))
    custom_formats: dict[int, str] = {}
    number_formats = root.find(MAIN_NS + "numFmts")
    if number_formats is not None:
        for item in number_formats:
            custom_formats[int(item.attrib["numFmtId"])] = item.attrib.get("formatCode", "")
    built_in_dates = set(range(14, 23)) | {45, 46, 47}
    result: set[int] = set()
    cell_formats = root.find(MAIN_NS + "cellXfs")
    if cell_formats is None:
        return result
    for index, item in enumerate(cell_formats):
        number_id = int(item.attrib.get("numFmtId", 0))
        code = custom_formats.get(number_id, "").lower()
        stripped = re.sub(r'"[^"]*"|\\.|\[[^]]*\]', "", code)
        if number_id in built_in_dates or re.search(r"[ymdhis]", stripped):
            result.add(index)
    return result


def _cell_value(cell: ET.Element, shared: list[str], date_styles: set[int]) -> Any:
    cell_type = cell.attrib.get("t")
    value_node = cell.find(MAIN_NS + "v")
    inline = cell.find(MAIN_NS + "is")
    if cell_type == "inlineStr" and inline is not None:
        return "".join(node.text or "" for node in inline.iter(MAIN_NS + "t"))
    if value_node is None:
        return None
    raw = value_node.text or ""
    if cell_type == "s":
        try:
            return shared[int(raw)]
        except (IndexError, ValueError):
            return raw
    if cell_type == "b":
        return raw == "1"
    if cell_type in {"str", "e"}:
        return raw
    try:
        number = float(raw)
    except ValueError:
        return raw
    style_index = int(cell.attrib.get("s", 0))
    if style_index in date_styles:
        return datetime(1899, 12, 30) + timedelta(days=number)
    return int(number) if number.is_integer() else number


def _parse_xlsx(source: bytes) -> ParsedData:
    stream = io.BytesIO(source)
    try:
        archive = zipfile.ZipFile(stream)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ParseError("The uploaded file is not a readable XLSX workbook") from exc
    with archive:
        _check_archive(archive)
        shared = _shared_strings(archive)
        date_styles = _date_style_indexes(archive)
        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        relationships = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        targets = {item.attrib["Id"]: item.attrib["Target"] for item in relationships}
        sheets_node = workbook.find(MAIN_NS + "sheets")
        if sheets_node is None:
            raise ParseError("Workbook does not contain worksheets")
        
        tables: list[tuple[list[str], list[list[Any]]]] = []
        for sheet in sheets_node:
            relation_id = sheet.attrib.get(REL_NS + "id")
            if not relation_id or relation_id not in targets:
                continue
            path = _normalise_target(targets[relation_id])
            if path not in archive.namelist():
                continue
            root = ET.fromstring(archive.read(path))
            sheet_data = root.find(MAIN_NS + "sheetData")
            parsed_rows: list[list[Any]] = []
            if sheet_data is not None:
                for row in sheet_data:
                    values: dict[int, Any] = {}
                    for cell in row.findall(MAIN_NS + "c"):
                        reference = cell.attrib.get("r", "A1")
                        values[_column_index(reference)] = _cell_value(cell, shared, date_styles)
                    if values:
                        parsed_rows.append([values.get(index) for index in range(max(values) + 1)])
            if parsed_rows:
                tables.append(_clean_table(parsed_rows))

        if not tables:
            raise ParseError("Workbook does not contain tabular data")
        headers: list[str] = []
        for table_headers, _ in tables:
            for header in table_headers:
                if header not in headers:
                    headers.append(header)
        parsed_rows = []
        for table_headers, table_rows in tables:
            positions = {header: index for index, header in enumerate(table_headers)}
            for row in table_rows:
                parsed_rows.append([row[positions[header]] if header in positions and positions[header] < len(row) else None for header in headers])
        return ParsedData(
            filename="",
            headers=headers,
            rows=parsed_rows,
            source_format="XLSX",
            total_rows=len(parsed_rows),
        )


def _parse_csv(source: bytes) -> ParsedData:
    if len(source) > MAX_CSV_SIZE:
        raise ParseError(f"CSV file is too large (max {MAX_CSV_SIZE // 1024 // 1024} MB)")
        
    best_encoding = None
    for encoding in ["utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be", "windows-1256", "cp1252", "latin-1"]:
        try:
            sample = source[:8192].decode(encoding)
            if sample and any(c.isalnum() for c in sample[:500]):
                best_encoding = encoding
                break
        except (UnicodeDecodeError, ValueError):
            continue
    else:
        raise ParseError("Could not decode CSV file (unsupported encoding)")

    stream = io.TextIOWrapper(io.BytesIO(source), encoding=best_encoding, newline="")
    try:
        first_line = next(stream).replace('\x00', '').strip().lower()
    except StopIteration:
        raise ParseError("CSV file is empty")

    forced_delimiter = None
    if first_line.startswith("sep="):
        sep_char = first_line.split("=", 1)[1].strip()
        if sep_char:
            forced_delimiter = sep_char[0]

    candidate_delimiters = [forced_delimiter] if forced_delimiter else [",", ";", "\t", "|"]
    
    best_rows: list[list[Any]] = []
    best_score = -1
    best_delim = ","
    skip_sep = False

    for delim in candidate_delimiters:
        try:
            stream = io.TextIOWrapper(io.BytesIO(source), encoding=best_encoding, newline="")
            def stripped_stream():
                for line in stream:
                    yield line.replace('\x00', '')
                    
            reader = csv.reader(stripped_stream(), delimiter=delim)
            
            cand_rows = []
            for _ in range(100):
                try:
                    cand_rows.append(next(reader))
                except StopIteration:
                    break
                    
            if not cand_rows:
                continue

            cand_skip_sep = False
            if len(cand_rows[0]) == 1 and str(cand_rows[0][0]).strip().lower().startswith("sep="):
                cand_rows = cand_rows[1:]
                cand_skip_sep = True

            non_empty = [r for r in cand_rows if any(str(c).strip() for c in r)]
            if not non_empty:
                continue
                
            col_counts = [len(r) for r in non_empty]
            mode_cols, mode_freq = Counter(col_counts).most_common(1)[0]
            consistency_ratio = mode_freq / len(non_empty)

            best_header_matches = 0
            for r in non_empty[:30]:
                if len(r) < 2:
                    continue
                matching_cells = sum(1 for c in r if set(re.findall(r"[a-z\u0621-\u064A]+", str(c).lower())) & HEADER_HINTS)
                if matching_cells > best_header_matches:
                    best_header_matches = matching_cells

            score = (best_header_matches * 100) + (mode_cols * 10 * consistency_ratio)
            if score > best_score:
                best_score = score
                best_delim = delim
                best_rows = cand_rows
                skip_sep = cand_skip_sep
        except Exception:
            continue

    if not best_rows:
        stream = io.TextIOWrapper(io.BytesIO(source), encoding=best_encoding, newline="")
        def stripped_stream():
            for line in stream:
                yield line.replace('\x00', '')
        reader = csv.reader(stripped_stream(), csv.excel)
        best_delim = ","
        cand_rows = []
        for _ in range(100):
            try:
                cand_rows.append(next(reader))
            except StopIteration:
                break
        best_rows = cand_rows

    if not best_rows:
        raise ParseError("CSV file is empty")

    headers, sample_data_rows = _clean_table(best_rows)

    if len(headers) == 1 and any(sep in headers[0] for sep in (",", ";", "\t")):
        for alt_sep in (",", ";", "\t"):
            if alt_sep in headers[0]:
                try:
                    stream = io.TextIOWrapper(io.BytesIO(source), encoding=best_encoding, newline="")
                    def stripped_stream():
                        for line in stream:
                            yield line.replace('\x00', '')
                    alt_reader = csv.reader(stripped_stream(), delimiter=alt_sep)
                    alt_rows = []
                    if skip_sep:
                        next(alt_reader, None)
                    for _ in range(100):
                        try:
                            alt_rows.append(next(alt_reader))
                        except StopIteration:
                            break
                    alt_headers, alt_data = _clean_table(alt_rows)
                    if len(alt_headers) > 1:
                        headers, sample_data_rows = alt_headers, alt_data
                        best_delim = alt_sep
                        best_rows = alt_rows
                        break
                except Exception:
                    pass

    rows_for_cleaning = [list(row) for row in best_rows if any(value is not None and str(value).strip() for value in row)]
    def score_row(row: list[Any], index: int) -> tuple[int, int]:
        values = [str(value).strip() for value in row if value is not None and str(value).strip()]
        if not values:
            return (-100, -index)
        matching_cells = sum(
            1 for val in values
            if set(re.findall(r"[a-z\u0621-\u064A]+", val.lower())) & HEADER_HINTS
        )
        text_cells = sum(not re.fullmatch(r"[-+]?\d+(?:[.,]\d+)?", value) for value in values)
        next_width = 0
        if index + 1 < len(rows_for_cleaning):
            next_width = sum(value is not None and str(value).strip() != "" for value in rows_for_cleaning[index + 1])
        compatibility = min(len(values), next_width) if len(values) > 1 else 0
        multi_col_bonus = 50 if len(values) > 2 else (20 if len(values) > 1 else -100)
        return (matching_cells * 25 + text_cells * 2 + compatibility + multi_col_bonus, -index)

    candidate_range = range(min(len(rows_for_cleaning), 50))
    header_index = max(candidate_range, key=lambda index: score_row(rows_for_cleaning[index], index))
    
    header_row = rows_for_cleaning[header_index]
    width = max(len(header_row), max((len(row) for row in rows_for_cleaning[header_index:]), default=len(header_row)))

    raw_headers = list(header_row) + [None] * (width - len(header_row))
    clean_headers: list[str] = []
    used: dict[str, int] = {}
    for index, raw in enumerate(raw_headers):
        label = str(raw).strip() if raw is not None and str(raw).strip() else f"column_{index + 1}"
        count = used.get(label, 0)
        used[label] = count + 1
        clean_headers.append(label if count == 0 else f"{label}_{count + 1}")

    def _csv_row_generator():
        stream = io.TextIOWrapper(io.BytesIO(source), encoding=best_encoding, newline="")
        def stripped_stream():
            for line in stream:
                yield line.replace('\x00', '')
        reader = csv.reader(stripped_stream(), delimiter=best_delim)
        
        if skip_sep:
            try:
                next(reader)
            except StopIteration:
                pass
                
        non_empty_seen = 0
        for row in reader:
            if not any(str(v).strip() for v in row):
                continue
            if non_empty_seen <= header_index:
                non_empty_seen += 1
                continue
            yield list(row) + [None] * max(0, width - len(row))

    total_newlines = source.count(b"\n")
    estimated_data_rows = max(0, total_newlines - header_index)

    return ParsedData(
        filename="",
        headers=clean_headers,
        rows=_csv_row_generator(),
        source_format="CSV",
        total_rows=estimated_data_rows,
    )


def _parse_json(source: bytes) -> ParsedData:
    """Parse JSON array of objects or JSONL (line-delimited JSON)."""
    text = ""
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            text = source.decode(enc)
            break
        except (UnicodeDecodeError, ValueError):
            continue
    if not text:
        raise ParseError("Could not decode JSON file")

    text_stripped = text.strip()
    headers: list[str] = []
    
    # 1. JSON Array of Objects
    if text_stripped.startswith("[") and text_stripped.endswith("]"):
        try:
            items = json.loads(text_stripped)
            if not isinstance(items, list):
                raise ParseError("JSON root must be a list of log objects")
            # Collect keys union
            seen_headers: set[str] = set()
            for obj in items[:100]:
                if isinstance(obj, dict):
                    for k in obj.keys():
                        if k not in seen_headers:
                            seen_headers.add(k)
                            headers.append(k)
            if not headers:
                headers = ["Message"]

            def _json_array_generator():
                for obj in items:
                    if isinstance(obj, dict):
                        yield [obj.get(h) for h in headers]
                    else:
                        yield [str(obj)]

            return ParsedData(
                filename="",
                headers=headers,
                rows=_json_array_generator(),
                source_format="JSON",
                total_rows=len(items),
            )
        except json.JSONDecodeError as exc:
            raise ParseError(f"Malformed JSON: {exc}")

    # 2. JSONL (Line-delimited JSON)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise ParseError("JSON file is empty")

    seen_headers: set[str] = set()
    sample_objs = []
    for line in lines[:100]:
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                sample_objs.append(obj)
                for k in obj.keys():
                    if k not in seen_headers:
                        seen_headers.add(k)
                        headers.append(k)
        except json.JSONDecodeError:
            pass

    if not headers:
        headers = ["Raw Log"]

    def _jsonl_generator():
        for line in lines:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield [obj.get(h) for h in headers]
                else:
                    yield [str(obj)]
            except json.JSONDecodeError:
                yield [line] + [None] * (len(headers) - 1)

    return ParsedData(
        filename="",
        headers=headers,
        rows=_jsonl_generator(),
        source_format="JSONL",
        total_rows=len(lines),
    )


_SYSLOG_LINE_RE = re.compile(
    r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+([^\s:]+)\s+([^:\[]+)(?:\[(\d+)\])?:\s*(.*)$'
)


def _parse_syslog_txt(source: bytes) -> ParsedData:
    """Parse unstructured text logs and Syslog lines."""
    text = ""
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            text = source.decode(enc)
            break
        except (UnicodeDecodeError, ValueError):
            continue
    if not text:
        raise ParseError("Could not decode text log file")

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise ParseError("Log file is empty")

    # Check first 20 lines against Syslog regex
    syslog_matches = 0
    for line in lines[:20]:
        if _SYSLOG_LINE_RE.match(line):
            syslog_matches += 1

    if syslog_matches >= 3 or syslog_matches == len(lines[:20]):
        headers = ["Time", "Host", "Process", "ProcessID", "Message"]

        def _syslog_generator():
            for line in lines:
                m = _SYSLOG_LINE_RE.match(line)
                if m:
                    yield [m.group(1), m.group(2), m.group(3), m.group(4) or "", m.group(5)]
                else:
                    yield ["", "", "", "", line]

        return ParsedData(
            filename="",
            headers=headers,
            rows=_syslog_generator(),
            source_format="Syslog",
            total_rows=len(lines),
        )

    # Generic Unstructured Text Lines
    headers = ["Time", "Message"]

    def _generic_text_generator():
        for line in lines:
            parts = line.split(" ", 2)
            if len(parts) >= 2 and any(c.isdigit() for c in parts[0]):
                yield [f"{parts[0]} {parts[1]}", line]
            else:
                yield ["", line]

    return ParsedData(
        filename="",
        headers=headers,
        rows=_generic_text_generator(),
        source_format="TXT",
        total_rows=len(lines),
    )


def read_file(source: bytes | str | Path, filename: str = "upload") -> ParsedData:
    """Read a file and auto-detect if it's CSV, XLSX, JSON, JSONL, or Syslog TXT."""
    if isinstance(source, (str, Path)):
        with open(source, "rb") as f:
            content = f.read()
    else:
        content = source

    if not content:
        raise ParseError("File is empty")

    lower_name = filename.lower()

    # 1. ZIP / XLSX
    if content.startswith(b"PK\x03\x04"):
        data = _parse_xlsx(content)
        data.filename = filename
        return data

    # 2. JSON / JSONL
    stripped = content.lstrip()[:50]
    if lower_name.endswith((".json", ".jsonl")) or (stripped and stripped[0:1] in (b"{", b"[")):
        try:
            data = _parse_json(content)
            data.filename = filename
            return data
        except ParseError:
            pass

    # 3. CSV with tabular heuristics
    try:
        data = _parse_csv(content)
        # If CSV parsed only 1 column and line count > 1, check if it's raw Syslog
        if len(data.headers) <= 1 and data.total_rows > 1:
            try:
                syslog_data = _parse_syslog_txt(content)
                if len(syslog_data.headers) > 1:
                    syslog_data.filename = filename
                    return syslog_data
            except Exception:
                pass
        data.filename = filename
        return data
    except Exception:
        # Fallback to Syslog / Text parser
        data = _parse_syslog_txt(content)
        data.filename = filename
        return data

