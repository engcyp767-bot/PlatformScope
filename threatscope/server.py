"""ThreatScope local web server (standard-library only)."""

from __future__ import annotations

import json
import mimetypes
import os
import re
import socket
import threading
import traceback
import uuid
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

try:
    from .analyzer import analyze_workbook, apply_enrichment
    from .csv_parser import read_csv
    from .docx_report import build_report_docx
    from .enrichment import enrich_hashes, provider_configuration
    from .report_builder import build_report_html
    from .xlsx_parser import WorkbookError, read_xlsx
    from .xlsx_report import build_report_xlsx
    from . import result_sink
except ImportError:  # Preserve direct execution: python server.py
    from analyzer import analyze_workbook, apply_enrichment
    from csv_parser import read_csv
    from docx_report import build_report_docx
    from report_builder import build_report_html
    from xlsx_parser import WorkbookError, read_xlsx
    from xlsx_report import build_report_xlsx
    import result_sink

try:
    from platform_core import learning_engine, ollama_advisor, report_preview, audit_engine
except ImportError:  # Direct execution from the ThreatScope directory.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from platform_core import learning_engine, ollama_advisor, report_preview, audit_engine


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
STORAGE = ROOT / "storage"
JOBS = STORAGE / "jobs"
CACHE = STORAGE / "intel_cache.sqlite3"
WORD_TEMPLATE = ROOT.parent / "data" / "XDR_VirusTotal_Hash_Report_AR.docx"
MAX_UPLOAD = 20 * 1024 * 1024
MODEL_ANALYSIS_ENABLED = True
AUTO_ENRICH = False
LEARNING_ENABLED = True
WRITE_LOCK = threading.Lock()
SOURCE_SYSTEMS = {
    "xdr_1": "C-IN",
    "xdr_2": "DCS",
    "xdr_3": "C-OUT",
}


def _export_filename(analysis: dict, extension: str) -> str:
    source = str(analysis.get("metadata", {}).get("source_system_label") or "UNSPECIFIED")
    source = re.sub(r"[^A-Za-z0-9_-]+", "-", source).strip("-_") or "UNSPECIFIED"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"ThreatScope_{source}_XDR_Report_{stamp}.{extension.lstrip('.')}"


def _job_dir(job_id: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise ValueError("Invalid job identifier")
    return JOBS / job_id


def _read_analysis(job_id: str) -> dict:
    path = _job_dir(job_id) / "analysis.json"
    if not path.exists():
        raise FileNotFoundError(job_id)
    analysis = json.loads(path.read_text(encoding="utf-8"))
    model_analysis = ollama_advisor.read_sidecar(_job_dir(job_id) / "model_analysis.json")
    if model_analysis:
        analysis["model_analysis"] = model_analysis
    return analysis


def _write_analysis(job_id: str, analysis: dict) -> None:
    folder = _job_dir(job_id)
    folder.mkdir(parents=True, exist_ok=True)
    temporary = folder / "analysis.tmp"
    with WRITE_LOCK:
        temporary.write_text(json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(folder / "analysis.json")


def _schedule_model_analysis(job_id: str, analysis: dict) -> None:
    if MODEL_ANALYSIS_ENABLED:
        ollama_advisor.schedule(
            "threatscope", job_id, analysis, _job_dir(job_id) / "model_analysis.json"
        )


def _background_enrichment(job_id: str, force_refresh: bool = False) -> None:
    audit_engine.record_engine_event(
        application="threatscope", action="enrichment_worker_start",
        message="بدء فحص سمعة البصمات الرقمية", job_id=job_id, category="enrichment",
        details={"force_refresh": force_refresh},
    )
    try:
        analysis = _read_analysis(job_id)
        analysis["enrichment"]["status"] = "running"
        _write_analysis(job_id, analysis)
        enrichment = enrich_hashes(analysis["hashes"], CACHE, force_refresh=force_refresh)
        latest = _read_analysis(job_id)
        apply_enrichment(latest, enrichment)
        _write_analysis(job_id, latest)
        _schedule_model_analysis(job_id, latest)
        audit_engine.record_engine_event(
            application="threatscope", action="enrichment_worker_complete",
            message="اكتمل فحص سمعة البصمات الرقمية", job_id=job_id, category="enrichment",
            details={key: enrichment.get(key, 0) for key in ("status", "checked", "total", "cached", "new")},
        )
    except Exception as exc:
        try:
            analysis = _read_analysis(job_id)
            analysis["enrichment"] = {"status": "failed", "error": str(exc)[:500], "providers": {}, "results": {}}
            _write_analysis(job_id, analysis)
        except Exception:
            traceback.print_exc()
        audit_engine.record_engine_event(
            application="threatscope", action="enrichment_worker_failed",
            message="فشل فحص سمعة البصمات الرقمية", job_id=job_id, category="enrichment",
            level="error", outcome="failure", details={"error_type": type(exc).__name__, "error": str(exc)[:500]},
        )


class ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
    """Bind exclusively so stale local instances cannot share the same port."""

    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def _build_preview_docx(analysis: dict, job_id: str) -> bytes:
    """Build a DOCX report into a temporary file and return raw bytes for preview."""
    import tempfile as _tf
    storage_type = analysis.get("result_storage", {}).get("type")
    if storage_type == "sqlite" and (JOBS / job_id / "results.db").is_file():
        reader = result_sink.SQLiteResultReader(JOBS / job_id / "results.db")
    else:
        reader = result_sink.MemoryResultReader(analysis.get("records") or analysis.get("events") or analysis.get("hashes") or [])
    fd, tmp = _tf.mkstemp(suffix=".docx")
    os.close(fd)
    try:
        build_report_docx(analysis, reader, Path(tmp))
        with open(tmp, "rb") as f:
            return f.read()
    finally:
        reader.close()
        try:
            os.unlink(tmp)
        except OSError:
            pass


class Handler(BaseHTTPRequestHandler):
    server_version = "ThreatScope/1.0"

    def log_message(self, fmt: str, *args) -> None:
        try:
            print(f"[{self.log_date_time_string()}] {fmt % args}", flush=True)
        except (BrokenPipeError, OSError):
            # Logging must never prevent an HTTP response when the server is
            # launched without an attached console.
            pass

    def _headers(self, status: int, content_type: str, length: int | None = None, disposition: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store" if content_type.startswith("application/json") else "private, max-age=60")
        if length is not None:
            self.send_header("Content-Length", str(length))
        if disposition:
            self.send_header("Content-Disposition", disposition)
        self.end_headers()

    def _json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(data))
        self.wfile.write(data)

    def _bytes(self, status: int, data: bytes, content_type: str, disposition: str | None = None) -> None:
        self._headers(status, content_type, len(data), disposition)
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/health":
                self._json(200, {"status": "ok", "version": "1.0"})
                return
            if path == "/api/config":
                providers = provider_configuration()
                self._json(200, {"max_upload_mb": MAX_UPLOAD // 1024 // 1024, "providers": {name: {"enabled": value["enabled"]} for name, value in providers.items()}})
                return
            match = re.fullmatch(r"/api/jobs/([0-9a-f]{32})(?:/(records))?", path)
            if match:
                job_id = match.group(1)
                sub_route = match.group(2)
                
                if sub_route == "records":
                    query_params = parse_qs(parsed.query)
                    cursor = int(query_params.get("cursor", [0])[0])
                    limit = int(query_params.get("limit", [100])[0])
                    limit = min(max(1, limit), 1000)
                    q = query_params.get("q", [""])[0].strip() or None
                    
                    analysis = _read_analysis(job_id)
                    storage_type = analysis.get("result_storage", {}).get("type")
                    if storage_type == "sqlite":
                        db_path = JOBS / job_id / "results.db"
                        reader = result_sink.SQLiteResultReader(db_path)
                    else:
                        records_list = analysis.get("records") or analysis.get("events") or analysis.get("hashes") or []
                        reader = result_sink.MemoryResultReader(records_list)
                    
                    try:
                        records, next_cursor = reader.get_paginated_records(cursor, limit, query=q)
                    finally:
                        reader.close()
                    
                    self._json(200, {
                        "records": records,
                        "pagination": {
                            "limit": limit,
                            "next_cursor": next_cursor,
                            "has_more": next_cursor is not None
                        }
                    })
                    return
                else:
                    analysis = _read_analysis(job_id)
                    # Strip records from metadata response to prevent UI memory blowup
                    analysis.pop("records", None)
                    analysis.pop("events", None)
                    analysis.pop("hashes", None)
                    self._json(200, {"job_id": job_id, "analysis": analysis})
                    return
            match = re.fullmatch(r"/api/(?:report|preview)/([0-9a-f]{32})(?:\.pdf)?", path)
            if match:
                job_id = match.group(1)
                query_params = parse_qs(parsed.query)
                snapshot = query_params.get("snapshot", [None])[0]
                wants_json = query_params.get("format", [""])[0].lower() == "json"
                analysis = _read_analysis(job_id)
                try:
                    report, _ = report_preview.pdf_artifact(
                        "threatscope", job_id, analysis,
                        lambda: _build_preview_docx(analysis, job_id), snapshot=snapshot,
                    )
                    if wants_json:
                        import base64
                        b64 = base64.b64encode(report).decode("ascii")
                        self._json(200, {
                            "status": "ok",
                            "job_id": job_id,
                            "size": len(report),
                            "pdf_base64": b64,
                            "mime": "application/pdf"
                        })
                        return
                    self._bytes(200, report, "application/pdf")
                    return
                except report_preview.PreviewUnavailable as exc:
                    self._json(503, {"error": str(exc)})
                    return
                except Exception as exc:
                    self._json(500, {"error": f"Preview generation failed: {str(exc)[:300]}"})
                    return
            match = re.fullmatch(r"/api/export/([0-9a-f]{32})\.xlsx", path)
            if match:
                job_id = match.group(1)
                analysis = _read_analysis(job_id)
                storage_type = analysis.get("result_storage", {}).get("type")
                if storage_type == "sqlite" and (JOBS / job_id / "results.db").is_file():
                    reader = result_sink.SQLiteResultReader(JOBS / job_id / "results.db")
                else:
                    reader = result_sink.MemoryResultReader(analysis.get("records") or analysis.get("events") or analysis.get("hashes") or [])
                import tempfile
                import shutil
                fd, tmp_path = tempfile.mkstemp(suffix=".xlsx")
                os.close(fd)
                try:
                    build_report_xlsx(analysis, reader, Path(tmp_path))
                    filename = _export_filename(analysis, "xlsx")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                    self.send_header("Content-Length", str(os.path.getsize(tmp_path)))
                    self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                    self.end_headers()
                    with open(tmp_path, "rb") as f:
                        shutil.copyfileobj(f, self.wfile)
                finally:
                    reader.close()
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                return
            match = re.fullmatch(r"/api/export/([0-9a-f]{32})\.docx", path)
            if match:
                job_id = match.group(1)
                analysis = _read_analysis(job_id)
                storage_type = analysis.get("result_storage", {}).get("type")
                if storage_type == "sqlite" and (JOBS / job_id / "results.db").is_file():
                    reader = result_sink.SQLiteResultReader(JOBS / job_id / "results.db")
                else:
                    reader = result_sink.MemoryResultReader(analysis.get("records") or analysis.get("events") or analysis.get("hashes") or [])
                import tempfile
                import shutil
                fd, tmp_path = tempfile.mkstemp(suffix=".docx")
                os.close(fd)
                try:
                    build_report_docx(analysis, reader, Path(tmp_path))
                    filename = _export_filename(analysis, "docx")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
                    self.send_header("Content-Length", str(os.path.getsize(tmp_path)))
                    self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                    self.end_headers()
                    with open(tmp_path, "rb") as f:
                        shutil.copyfileobj(f, self.wfile)
                finally:
                    reader.close()
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                return
            self._serve_static(path)
        except FileNotFoundError:
            self._json(404, {"error": "المهمة غير موجودة"})
        except Exception as exc:
            self._json(500, {"error": str(exc)[:500]})

    def _serve_static(self, path: str) -> None:
        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        target = (STATIC / relative).resolve()
        if STATIC.resolve() not in target.parents and target != STATIC.resolve():
            self._json(403, {"error": "Forbidden"})
            return
        if not target.is_file():
            target = STATIC / "index.html"
        data = target.read_bytes()
        media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if media_type.startswith("text/") or media_type in {"application/javascript"}:
            media_type += "; charset=utf-8"
        self._bytes(200, data, media_type)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/analyze":
            self._analyze()
            return
        match = re.fullmatch(r"/api/enrich/([0-9a-f]{32})", path)
        if match:
            force_refresh = parse_qs(parsed.query).get("force", ["0"])[0].lower() in {"1", "true", "yes"}
            self._start_enrichment(match.group(1), force_refresh=force_refresh)
            return
        self._json(404, {"error": "Not found"})

    def _analyze(self) -> None:
        job_id = None
        try:
            length = int(self.headers.get("Content-Length", "0"))
            filename = os.path.basename(unquote(self.headers.get("X-Filename", "upload.xlsx")))
            source_system = self.headers.get("X-Source-System", "").strip().lower()
            if source_system not in SOURCE_SYSTEMS:
                self._json(400, {"error": "يجب تحديد نظام XDR المصدر"})
                return
            if length <= 0 or length > MAX_UPLOAD:
                self._json(413, {"error": f"حجم الملف يجب أن يكون بين 1 بايت و{MAX_UPLOAD // 1024 // 1024} ميجابايت"})
                return
            extension = Path(filename).suffix.lower()
            if extension not in {".xlsx", ".csv"}:
                self._json(415, {"error": "الصيغ المدعومة هي XLSX وCSV فقط"})
                return
            source = self.rfile.read(length)
            if extension == ".xlsx":
                if not source.startswith(b"PK"):
                    self._json(415, {"error": "الملف لا يحمل بنية XLSX صحيحة"})
                    return
                sheets = read_xlsx(source)
            else:
                sheets = read_csv(source)
            job_id = uuid.uuid4().hex
            audit_engine.record_engine_event(
                application="threatscope", action="analysis_worker_start",
                message="بدء تحليل ملف XDR", job_id=job_id,
                details={"filename": filename, "source_system": source_system, "payload_bytes": length, "sheets": len(sheets)},
            )
            analysis = analyze_workbook(sheets, source, filename)
            analysis["metadata"]["source_system"] = source_system
            analysis["metadata"]["source_system_label"] = SOURCE_SYSTEMS[source_system]
            if LEARNING_ENABLED:
                learning_engine.annotate_analysis("threatscope", job_id, analysis)
            folder = _job_dir(job_id)
            folder.mkdir(parents=True, exist_ok=False)
            (folder / f"source{extension}").write_bytes(source)
            _write_analysis(job_id, analysis)
            _schedule_model_analysis(job_id, analysis)
            model_analysis = ollama_advisor.read_sidecar(_job_dir(job_id) / "model_analysis.json")
            if model_analysis:
                analysis["model_analysis"] = model_analysis
            audit_engine.record_engine_event(
                application="threatscope", action="analysis_worker_complete",
                message="اكتمل تحليل ملف XDR بنجاح", job_id=job_id,
                details={"records": analysis.get("summary", {}).get("records", 0), "unique_hashes": analysis.get("summary", {}).get("unique_hashes", 0)},
            )
            self._json(201, {"job_id": job_id, "analysis": analysis})
            if AUTO_ENRICH:
                threading.Thread(target=_background_enrichment, args=(job_id, False), daemon=True).start()
        except (WorkbookError, ValueError) as exc:
            audit_engine.record_engine_event(
                application="threatscope", action="analysis_worker_rejected",
                message="رُفض ملف XDR لعدم صلاحية البيانات", job_id=job_id,
                level="warning", outcome="failure", details={"error": str(exc)[:500]},
            )
            self._json(422, {"error": str(exc)})
        except Exception as exc:
            traceback.print_exc()
            audit_engine.record_engine_event(
                application="threatscope", action="analysis_worker_failed",
                message="فشل تحليل ملف XDR", job_id=job_id,
                level="error", outcome="failure", details={"error_type": type(exc).__name__, "error": str(exc)[:500]},
            )
            self._json(500, {"error": str(exc)[:500]})

    def _start_enrichment(self, job_id: str, force_refresh: bool = False) -> None:
        try:
            analysis = _read_analysis(job_id)
            status = analysis.get("enrichment", {}).get("status")
            if status == "running":
                self._json(202, {"job_id": job_id, "status": "running"})
                return
            analysis["enrichment"] = {
                "status": "running", "checked": 0, "total": len(analysis.get("hashes", [])),
                "cached": 0, "new": len(analysis.get("hashes", [])),
                "force_refresh": force_refresh, "providers": {}, "results": {},
            }
            _write_analysis(job_id, analysis)
            thread = threading.Thread(
                target=_background_enrichment, args=(job_id, force_refresh), daemon=True
            )
            thread.start()
            self._json(202, {"job_id": job_id, "status": "started"})
        except FileNotFoundError:
            self._json(404, {"error": "المهمة غير موجودة"})

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        match = re.fullmatch(r"/api/jobs/([0-9a-f]{32})", path)
        if not match:
            self._json(404, {"error": "Not found"})
            return
        try:
            folder = _job_dir(match.group(1))
            if not folder.exists():
                raise FileNotFoundError
            for child in folder.iterdir():
                if child.is_file():
                    child.unlink()
            folder.rmdir()
            report_preview.remove_artifacts("threatscope", match.group(1))
            self._json(200, {"deleted": True})
        except FileNotFoundError:
            self._json(404, {"error": "المهمة غير موجودة"})


def main() -> None:
    JOBS.mkdir(parents=True, exist_ok=True)
    host = os.environ.get("THREATSCOPE_HOST", "127.0.0.1")
    port = int(os.environ.get("THREATSCOPE_PORT", "8080"))
    server = ExclusiveThreadingHTTPServer((host, port), Handler)
    print(f"ThreatScope running on http://{host}:{port}")
    print("Only hashes are sent to configured intelligence providers.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
