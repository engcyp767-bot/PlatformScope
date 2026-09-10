"""Safe, dependency-free reader for tabular XLSX workbooks.

The parser intentionally reads values only. It never evaluates formulas or macros.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET


MAIN_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
REL_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
MAX_FILES = 2_000
MAX_UNCOMPRESSED_BYTES = 150 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200


class WorkbookError(ValueError):
    """Raised when a workbook is invalid or violates an upload safety rule."""


@dataclass
class SheetData:
    name: str
    rows: list[list[Any]]
    formulas: int = 0


def _column_index(cell_reference: str) -> int:
    match = re.match(r"([A-Z]+)", cell_reference.upper())
    if not match:
        raise WorkbookError(f"Invalid cell reference: {cell_reference}")
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
    if len(infos) > MAX_FILES:
        raise WorkbookError("Workbook contains too many embedded files")
    total = sum(item.file_size for item in infos)
    if total > MAX_UNCOMPRESSED_BYTES:
        raise WorkbookError("Workbook expands beyond the allowed size")
    for item in infos:
        if item.filename.lower().endswith("vbaproject.bin"):
            raise WorkbookError("Macro-enabled workbooks are not accepted")
        if item.compress_size and item.file_size / item.compress_size > MAX_COMPRESSION_RATIO:
            raise WorkbookError("Suspicious archive compression ratio detected")
    required = {"xl/workbook.xml", "xl/_rels/workbook.xml.rels"}
    if not required.issubset({item.filename for item in infos}):
        raise WorkbookError("File is not a valid XLSX workbook")


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


def read_xlsx(source: bytes | str | Path) -> list[SheetData]:
    """Read workbook values and return non-empty sheets."""
    stream: Any = io.BytesIO(source) if isinstance(source, bytes) else source
    try:
        archive = zipfile.ZipFile(stream)
    except (zipfile.BadZipFile, OSError) as exc:
        raise WorkbookError("The uploaded file is not a readable XLSX workbook") from exc
    with archive:
        _check_archive(archive)
        shared = _shared_strings(archive)
        date_styles = _date_style_indexes(archive)
        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        relationships = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        targets = {item.attrib["Id"]: item.attrib["Target"] for item in relationships}
        sheets_node = workbook.find(MAIN_NS + "sheets")
        if sheets_node is None:
            raise WorkbookError("Workbook does not contain worksheets")
        result: list[SheetData] = []
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
            formula_count = 0
            if sheet_data is not None:
                for row in sheet_data:
                    values: dict[int, Any] = {}
                    for cell in row.findall(MAIN_NS + "c"):
                        reference = cell.attrib.get("r", "A1")
                        values[_column_index(reference)] = _cell_value(cell, shared, date_styles)
                        if cell.find(MAIN_NS + "f") is not None:
                            formula_count += 1
                    if values:
                        parsed_rows.append([values.get(index) for index in range(max(values) + 1)])
            if parsed_rows:
                width = max(len(row) for row in parsed_rows)
                parsed_rows = [row + [None] * (width - len(row)) for row in parsed_rows]
                result.append(SheetData(sheet.attrib.get("name", "Sheet"), parsed_rows, formula_count))
        if not result:
            raise WorkbookError("Workbook does not contain tabular data")
        return result
