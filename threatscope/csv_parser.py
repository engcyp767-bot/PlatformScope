"""Safe, dependency-free reader for tabular CSV files."""

from __future__ import annotations

import csv
import io

try:
    from .xlsx_parser import SheetData, WorkbookError
except ImportError:
    from xlsx_parser import SheetData, WorkbookError


SUPPORTED_ENCODINGS = ("utf-8-sig", "utf-8", "utf-16", "cp1256", "cp1252")
SUPPORTED_DELIMITERS = ",;\t|"
MAX_COLUMNS = 500


def _decode(source: bytes) -> str:
    if not source:
        raise WorkbookError("ملف CSV فارغ")
    # NUL bytes are normal in UTF-16, but otherwise strongly indicate a binary file.
    has_utf16_bom = source.startswith((b"\xff\xfe", b"\xfe\xff"))
    if b"\x00" in source and not has_utf16_bom:
        raise WorkbookError("ملف CSV يبدو ملفًا ثنائيًا وليس بيانات نصية")
    for encoding in SUPPORTED_ENCODINGS:
        try:
            return source.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise WorkbookError("تعذر تحديد ترميز ملف CSV")


def _delimiter(text: str) -> str:
    sample = text[:65536]
    try:
        return csv.Sniffer().sniff(sample, delimiters=SUPPORTED_DELIMITERS).delimiter
    except csv.Error:
        first_line = sample.splitlines()[0] if sample.splitlines() else ""
        counts = {item: first_line.count(item) for item in SUPPORTED_DELIMITERS}
        selected, count = max(counts.items(), key=lambda item: item[1])
        return selected if count else ","


def read_csv(source: bytes) -> list[SheetData]:
    """Decode CSV bytes and return the same sheet structure used by XLSX."""
    text = _decode(source)
    try:
        rows = [list(row) for row in csv.reader(io.StringIO(text, newline=""), delimiter=_delimiter(text))]
    except (csv.Error, ValueError) as exc:
        raise WorkbookError(f"تعذر قراءة ملف CSV: {exc}") from exc

    rows = [row for row in rows if any(str(value).strip() for value in row)]
    if not rows:
        raise WorkbookError("ملف CSV لا يحتوي على بيانات جدولية")
    width = max(len(row) for row in rows)
    if width > MAX_COLUMNS:
        raise WorkbookError(f"ملف CSV يحتوي على أكثر من {MAX_COLUMNS} عمود")
    if width < 1 or len(rows) < 2:
        raise WorkbookError("ملف CSV يجب أن يحتوي على صف عناوين وصف بيانات واحد على الأقل")
    normalised = [row + [None] * (width - len(row)) for row in rows]
    return [SheetData("CSV", normalised, formulas=0)]
