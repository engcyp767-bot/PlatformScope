"""Empirical performance and streaming benchmarks measuring Peak RAM, Throughput, and SQLite write time."""

import io
import time
import tracemalloc
import unittest
import zipfile
from pathlib import Path
import tempfile
import shutil

from logscope.file_parser import read_file
from logscope.analyzer import analyze_ads_data
from logscope.result_sink import SQLiteResultSink


def _generate_synthetic_csv(num_rows: int) -> bytes:
    buffer = io.StringIO()
    buffer.write("Time,Source IP,Destination IP,Action,Protocol,Message\n")
    for i in range(num_rows):
        buffer.write(f"2026-09-03 12:{i%60:02d}:00,10.0.0.{i%250 + 1},192.168.1.1,Block,TCP,CID=0x1;An intrusion was detected.\n")
    return buffer.getvalue().encode("utf-8")


def _generate_synthetic_jsonl(num_rows: int) -> bytes:
    lines = []
    for i in range(num_rows):
        lines.append(f'{{"time": "2026-09-03 12:{i%60:02d}:00", "source_ip": "10.0.0.{i%250 + 1}", "event_id": "4625", "user": "user_{i%50}", "action": "block"}}')
    return "\n".join(lines).encode("utf-8")


def _generate_synthetic_syslog(num_rows: int) -> bytes:
    lines = []
    for i in range(num_rows):
        lines.append(f"Sep  3 12:{i%60:02d}:00 host01 sshd[{i+1000}]: Failed password for root from 192.168.1.{i%250 + 1} port 45000 ssh2")
    return "\n".join(lines).encode("utf-8")


def _generate_synthetic_xlsx(num_rows: int) -> bytes:
    """Generate a minimal valid OpenXML XLSX archive in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # [Content_Types].xml
        z.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>""")
        # _rels/.rels
        z.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>""")
        # xl/_rels/workbook.xml.rels
        z.writestr("xl/_rels/workbook.xml.rels", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>""")
        # xl/workbook.xml
        z.writestr("xl/workbook.xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>
</workbook>""")
        # xl/worksheets/sheet1.xml
        sheet_rows = ['<row r="1"><c r="A1" t="inlineStr"><is><t>Time</t></is></c><c r="B1" t="inlineStr"><is><t>Source IP</t></is></c><c r="C1" t="inlineStr"><is><t>Action</t></is></c></row>']
        for i in range(2, num_rows + 2):
            sheet_rows.append(f'<row r="{i}"><c r="A{i}" t="inlineStr"><is><t>2026-09-03 12:00:00</t></is></c><c r="B{i}" t="inlineStr"><is><t>10.0.0.{i%250 + 1}</t></is></c><c r="C{i}" t="inlineStr"><is><t>Block</t></is></c></row>')
        sheet_content = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{"".join(sheet_rows)}</sheetData></worksheet>"""
        z.writestr("xl/worksheets/sheet1.xml", sheet_content)
    return buf.getvalue()


class StreamingBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _benchmark_pipeline(self, raw_bytes: bytes, filename: str, expected_rows: int) -> dict[str, float]:
        db_path = self.tmp_dir / f"{filename}.db"
        sink = SQLiteResultSink(db_path)

        tracemalloc.start()
        t0 = time.perf_counter()

        parsed = read_file(raw_bytes, filename=filename)
        res = analyze_ads_data(parsed, sink=sink)

        t1 = time.perf_counter()
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        elapsed = t1 - t0
        peak_mb = peak_mem / (1024 * 1024)
        throughput = expected_rows / elapsed if elapsed > 0 else 0

        self.assertEqual(res["total_records"], expected_rows)
        # Verify SQLite stored all rows
        import sqlite3
        conn = sqlite3.connect(db_path)
        try:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM records")
            db_count = c.fetchone()[0]
            self.assertEqual(db_count, expected_rows)
        finally:
            conn.close()

        return {
            "elapsed_sec": round(elapsed, 3),
            "peak_mb": round(peak_mb, 2),
            "throughput": round(throughput, 1),
            "db_count": db_count,
        }

    def test_csv_streaming_benchmark_5000_rows(self):
        csv_bytes = _generate_synthetic_csv(5000)
        metrics = self._benchmark_pipeline(csv_bytes, "test_5000.csv", 5000)

        # High performance and low memory assertions
        self.assertLess(metrics["peak_mb"], 30.0, f"Peak memory {metrics['peak_mb']}MB exceeded 30MB")
        self.assertGreater(metrics["throughput"], 100.0, f"Throughput {metrics['throughput']} records/sec was below 100")
        self.assertLess(metrics["elapsed_sec"], 35.0, f"Processing time {metrics['elapsed_sec']}s exceeded 35.0s")
        self.assertLess(metrics["elapsed_sec"], 50.0, f"Processing time {metrics['elapsed_sec']}s exceeded 50.0s")

    def test_jsonl_streaming_benchmark_3000_rows(self):
        jsonl_bytes = _generate_synthetic_jsonl(3000)
        metrics = self._benchmark_pipeline(jsonl_bytes, "test_3000.jsonl", 3000)

        self.assertLess(metrics["peak_mb"], 25.0)
        self.assertGreater(metrics["throughput"], 100.0)

    def test_syslog_streaming_benchmark_3000_rows(self):
        syslog_bytes = _generate_synthetic_syslog(3000)
        metrics = self._benchmark_pipeline(syslog_bytes, "test_3000.log", 3000)

        self.assertLess(metrics["peak_mb"], 25.0)
        self.assertGreater(metrics["throughput"], 100.0)

    def test_xlsx_streaming_benchmark_1000_rows(self):
        xlsx_bytes = _generate_synthetic_xlsx(1000)
        metrics = self._benchmark_pipeline(xlsx_bytes, "test_1000.xlsx", 1000)

        self.assertLess(metrics["peak_mb"], 20.0)
        self.assertGreater(metrics["throughput"], 100.0)


if __name__ == "__main__":
    unittest.main()
