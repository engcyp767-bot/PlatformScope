"""Local HTTP Server for FlowScope."""

from __future__ import annotations

import json
import re
import os
import shutil
import socket
import threading
import traceback
import uuid
import sys
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

try:
    from . import analyzer, enrichment, file_parser, flow_analyzer, result_sink
    from .docx_report import build_report_docx
    from .xlsx_report import build_report_xlsx
except ImportError:  # Preserve direct execution: python server.py
    import analyzer
    import enrichment
    import file_parser
    import flow_analyzer
    from docx_report import build_report_docx
    from xlsx_report import build_report_xlsx

try:
    from platform_core import learning_engine, ollama_advisor, report_preview, audit_engine
except ImportError:  # Direct execution from the FlowScope directory.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from platform_core import learning_engine, ollama_advisor, report_preview, audit_engine

HOST = os.environ.get("FLOWSCOPE_HOST", "127.0.0.1")
PORT = int(os.environ.get("FLOWSCOPE_PORT", 8080))
STORAGE_DIR = Path(__file__).resolve().parent / "storage"
JOBS_DIR = STORAGE_DIR / "jobs"
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_ENRICH_IPS = max(int(os.environ.get("FLOWSCOPE_MAX_ENRICH_IPS", "0")), 0)
MODEL_ANALYSIS_ENABLED = True
AUTO_ENRICH = False
LEARNING_ENABLED = True
APP_VERSION = "1.2.0"
RESULT_STORAGE_MODE = os.environ.get("FLOWSCOPE_RESULT_STORAGE", "sqlite").lower()
ENRICHMENT_SCOPE = "all_public_addresses_v2"
SOURCE_SYSTEMS = {
    "flow_1": "C-IN",
    "flow_2": "DCS",
    "flow_3": "C-OUT",
}


def _export_filename(analysis: dict, extension: str) -> str:
    source = str(analysis.get("metadata", {}).get("source_system_label") or "UNSPECIFIED")
    source = re.sub(r"[^A-Za-z0-9_-]+", "-", source).strip("-_") or "UNSPECIFIED"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"FlowScope_{source}_Flow_Report_{stamp}{extension}"


def _build_preview_docx(data: dict) -> bytes:
    """Build a DOCX report into a temp file and return raw bytes for preview."""
    import tempfile as _tf
    storage_type = data.get("result_storage", {}).get("type")
    if storage_type == "sqlite":
        job_id = data.get("metadata", {}).get("job_id", "")
        db_path = JOBS_DIR / job_id / "results.db"
        if db_path.is_file():
            reader = result_sink.SQLiteResultReader(db_path)
        else:
            reader = result_sink.MemoryResultReader(data.get("records") or [])
    else:
        reader = result_sink.MemoryResultReader(data.get("records") or [])
    fd, tmp = _tf.mkstemp(suffix=".docx")
    os.close(fd)
    try:
        build_report_docx(data, reader, Path(tmp))
        return Path(tmp).read_bytes()
    finally:
        reader.close()
        Path(tmp).unlink(missing_ok=True)

WRITE_LOCK = threading.Lock()
ACTIVE_ENRICHMENTS: dict[str, threading.Event] = {}
ACTIVE_ENRICHMENTS_LOCK = threading.Lock()


class ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
    """Prevent multiple FlowScope processes from sharing the same port.

    ``HTTPServer`` enables ``SO_REUSEADDR``. On Windows that can allow several
    live Python processes to bind to 127.0.0.1:8080, causing requests to be
    served unpredictably by an outdated process.
    """

    allow_reuse_address = False

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def _read_json(path: Path) -> dict:
    with WRITE_LOCK:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)


def _write_json_atomic(path: Path, data: dict) -> None:
    """Write job state without exposing a partially written JSON document."""
    import time as _time
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with WRITE_LOCK:
        try:
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(data, stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            for attempt in range(5):
                try:
                    os.replace(temporary, path)
                    return
                except PermissionError:
                    if attempt == 4:
                        raise
                    _time.sleep(0.1 * (attempt + 1))
        finally:
            temporary.unlink(missing_ok=True)


def _model_analysis_path(job_id: str) -> Path:
    return JOBS_DIR / job_id / "model_analysis.json"


def _attach_model_analysis(job_id: str, data: dict) -> dict:
    model_analysis = ollama_advisor.read_sidecar(_model_analysis_path(job_id))
    if model_analysis:
        data["model_analysis"] = model_analysis
    return data


def _schedule_model_analysis(job_id: str, data: dict) -> None:
    if MODEL_ANALYSIS_ENABLED:
        ollama_advisor.schedule("flowscope", job_id, data, _model_analysis_path(job_id))


def _severity(score: int) -> str:
    if score >= 85:
        return "حرج"
    if score >= 70:
        return "مرتفع"
    if score >= 40:
        return "متوسط"
    return "منخفض"


def _analysis_complete(data: dict) -> bool:
    analysis_state = data.get("analysis")
    return not analysis_state or analysis_state.get("status") == "completed"


def _select_enrichment_ips(data: dict) -> tuple[set[str], int]:
    """Collect every public IP represented in the uploaded data."""
    ranked: dict[str, tuple[int, int]] = {}
    is_ads = data.get("metadata", {}).get("data_type") == "ads_events"
    for record in data.get("records", []):
        weight = int(record.get("risk_score", 0) if is_ads else record.get("bytes", 0) or 0)
        if is_ads:
            candidates = [
                record.get("event_source", ""),
                *record.get("event_targets", []),
                *record.get("extracted_ips", []),
            ]
        else:
            candidates = [
                record.get("src_ip", ""), record.get("dst_ip", ""),
                *record.get("extracted_ips", []),
            ]
        for ip in candidates:
            ip = str(ip).strip()
            if not ip or enrichment.is_private_ip(ip):
                continue
            previous_weight, count = ranked.get(ip, (0, 0))
            ranked[ip] = (max(previous_weight, weight), count + 1)
    ordered = sorted(ranked, key=lambda ip: (ranked[ip][0], ranked[ip][1]), reverse=True)
    selected = ordered[:MAX_ENRICH_IPS] if MAX_ENRICH_IPS else ordered
    return set(selected), len(ordered)


def _recover_interrupted_jobs() -> None:
    """Make jobs left running by an earlier process retryable after restart."""
    for job_file in JOBS_DIR.glob("*/analysis.json"):
        try:
            with open(job_file, "rb") as raw_file:
                raw = raw_file.read()
            if b'"running"' not in raw and b'"queued"' not in raw:
                continue
            data = json.loads(raw.decode("utf-8"))
            changed = False
            if data.get("analysis", {}).get("status") in {"queued", "running"}:
                data["analysis"].update({
                    "status": "error", "stage": "توقف التحليل عند إغلاق الخادم",
                    "error": "أعد رفع الملف لبدء التحليل من جديد",
                })
                changed = True
            if data.get("enrichment", {}).get("status") == "running":
                data["enrichment"].update({
                    "status": "interrupted", "error": "يمكن إعادة تشغيل الفحص الآن"
                })
                changed = True
            if changed:
                _write_json_atomic(job_file, data)
        except (OSError, json.JSONDecodeError):
            continue


def _safe_json_response(handler: SimpleHTTPRequestHandler, data: dict, status: int = 200) -> None:
    try:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)
    except Exception as exc:
        handler.send_error(500, f"Error encoding response: {exc}")


class RequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs) -> None:
        self.static_dir = Path(__file__).resolve().parent / "static"
        super().__init__(*args, directory=str(self.static_dir), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def _handle_get_records(self, job_id: str, job_file: Path, query_str: str) -> None:
        try:
            query_params = parse_qs(query_str)
            cursor = int(query_params.get("cursor", [0])[0])
            limit = int(query_params.get("limit", [100])[0])
            limit = min(max(1, limit), 1000)
            q = query_params.get("q", [""])[0].strip() or None
            
            data = _read_json(job_file)
            
            storage_type = data.get("result_storage", {}).get("type")
            if storage_type == "sqlite":
                db_path = JOBS_DIR / job_id / "results.db"
                reader = result_sink.SQLiteResultReader(db_path)
            else:
                records_list = data.get("records") or data.get("events") or []
                reader = result_sink.MemoryResultReader(records_list)
                
            try:
                records, next_cursor = reader.get_paginated_records(cursor, limit, query=q)
                for r in records:
                    if not r.get("src_ip"):
                        r["src_ip"] = r.get("event_source") or r.get("source_ip") or (r.get("extracted_ips")[0] if r.get("extracted_ips") else None)
                    if not r.get("dst_ip"):
                        targets = r.get("event_targets")
                        if isinstance(targets, list) and targets:
                            r["dst_ip"] = targets[0]
                        elif isinstance(targets, str) and targets.strip():
                            r["dst_ip"] = targets.strip()
                        elif r.get("extracted_ips") and len(r.get("extracted_ips")) > 1:
                            r["dst_ip"] = r.get("extracted_ips")[1]
            finally:
                reader.close()
            
            return _safe_json_response(self, {
                "records": records,
                "pagination": {
                    "limit": limit,
                    "next_cursor": next_cursor,
                    "has_more": next_cursor is not None
                }
            })
        except ValueError:
            return _safe_json_response(self, {"error": "Invalid cursor or limit"}, 400)
        except Exception as exc:
            traceback.print_exc()
            return _safe_json_response(self, {"error": "Failed to retrieve records"}, 500)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            return _safe_json_response(self, {"status": "ok", "version": APP_VERSION})

        if path == "/api/config":
            return _safe_json_response(self, {
                "max_upload_bytes": MAX_UPLOAD_SIZE,
                "max_enrichment_ips": MAX_ENRICH_IPS or None,
                "enrichment_unlimited": MAX_ENRICH_IPS == 0,
                "enrichment_scope": ENRICHMENT_SCOPE,
                "providers": enrichment.public_provider_configuration(),
            })

        jobs_match = re.fullmatch(r"/api/jobs/([^/]+)(?:/(records))?", path)
        if jobs_match:
            job_id = jobs_match.group(1)
            sub_route = jobs_match.group(2)
            
            if not re.match(r"^[0-9a-f]{32}$", job_id):
                return _safe_json_response(self, {"error": "Invalid Job ID"}, 400)
                
            job_file = JOBS_DIR / job_id / "analysis.json"
            if not job_file.is_file():
                return _safe_json_response(self, {"error": "Job not found"}, 404)

            if sub_route == "records":
                return self._handle_get_records(job_id, job_file, parsed.query)
                
            try:
                data = _read_json(job_file)
                # Strip records/events from the main status payload to prevent UI memory blowup
                data.pop("records", None)
                data.pop("events", None)
                return _safe_json_response(self, _attach_model_analysis(job_id, data))
            except (OSError, json.JSONDecodeError):
                return _safe_json_response(self, {"error": "Job data is unavailable or corrupted"}, 500)

        preview_match = re.fullmatch(r"/api/preview/([0-9a-f]{32})(?:\.pdf)?", path)
        if preview_match:
            job_id = preview_match.group(1)
            snapshot = parse_qs(parsed.query).get("snapshot", [None])[0]
            format_param = parse_qs(parsed.query).get("format", [None])[0]
            accept_hdr = self.headers.get("Accept", "")
            wants_json = format_param == "json" or "application/json" in accept_hdr
            job_file = JOBS_DIR / job_id / "analysis.json"
            if not job_file.is_file():
                return self.send_error(404, "Job not found")
            try:
                data = _attach_model_analysis(job_id, _read_json(job_file))
                if not _analysis_complete(data):
                    return _safe_json_response(self, {"error": "Analysis is not complete"}, 409)
                body, _ = report_preview.pdf_artifact("flowscope", job_id, data, lambda: _build_preview_docx(data), snapshot=snapshot)
                if wants_json:
                    import base64
                    b64 = base64.b64encode(body).decode("ascii")
                    return _safe_json_response(self, {
                        "status": "ok",
                        "job_id": job_id,
                        "size": len(body),
                        "pdf_base64": b64,
                        "mime": "application/pdf"
                    })
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", 'inline; filename="preview.pdf"')
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except report_preview.PreviewUnavailable as exc:
                return _safe_json_response(self, {"error": str(exc)}, 503)
            except Exception as exc:
                traceback.print_exc()
                return _safe_json_response(self, {"error": f"Preview generation failed: {str(exc)[:300]}"}, 500)
            return

        if path.startswith("/api/export/"):
            filename = path.split("/")[-1]
            job_id, ext = os.path.splitext(filename)
            snapshot = parse_qs(parsed.query).get("snapshot", [None])[0]
            if ext not in {".docx", ".xlsx"} or not re.match(r"^[0-9a-f]{32}$", job_id):
                return self.send_error(400, "Invalid export request")
                
            job_file = JOBS_DIR / job_id / "analysis.json"
            if not job_file.is_file():
                return self.send_error(404, "Job not found")
                
            try:
                data = _attach_model_analysis(job_id, _read_json(job_file))
            except (OSError, json.JSONDecodeError):
                return _safe_json_response(self, {"error": "Job data is unavailable or corrupted"}, 500)

            if not _analysis_complete(data):
                return _safe_json_response(self, {"error": "Analysis is not complete"}, 409)

            try:
                import tempfile
                import shutil
                fd, tmp_path = tempfile.mkstemp(suffix=ext)
                os.close(fd)
                
                if ext == ".docx":
                    job_id_param = job_id
                    if RESULT_STORAGE_MODE == "sqlite" and (JOBS_DIR / job_id / "results.db").is_file():
                        reader = result_sink.SQLiteResultReader(JOBS_DIR / job_id / "results.db")
                    else:
                        reader = result_sink.MemoryResultReader(data.get("records") or [])
                        
                    build_report_docx(data, reader, Path(tmp_path))
                    reader.close()
                    mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                else:
                    if RESULT_STORAGE_MODE == "sqlite" and (JOBS_DIR / job_id / "results.db").is_file():
                        reader = result_sink.SQLiteResultReader(JOBS_DIR / job_id / "results.db")
                    else:
                        reader = result_sink.MemoryResultReader(data.get("records") or [])
                    build_report_xlsx(data, reader, Path(tmp_path))
                    reader.close()
                    mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(os.path.getsize(tmp_path)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("X-FlowScope-Report-Version", "2-ar")
                report_filename = _export_filename(data, ext)
                self.send_header(
                    "Content-Disposition",
                    f'attachment; filename="{report_filename}"',
                )
                self.end_headers()
                
                with open(tmp_path, "rb") as f:
                    shutil.copyfileobj(f, self.wfile)
                    
            except Exception as exc:
                traceback.print_exc()
                self.send_error(500, f"Export generation failed: {exc}")
            finally:
                if 'tmp_path' in locals() and os.path.exists(tmp_path):
                    os.remove(tmp_path)
            return

        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/analyze":
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return _safe_json_response(self, {"error": "Invalid Content-Length"}, 400)
            if content_length <= 0:
                return _safe_json_response(self, {"error": "File is empty"}, 400)
            if content_length > MAX_UPLOAD_SIZE:
                return _safe_json_response(self, {"error": "File too large"}, 413)

            body = self.rfile.read(content_length)
            job_id = uuid.uuid4().hex
            job_dir = JOBS_DIR / job_id
            job_file = job_dir / "analysis.json"
            input_file = job_dir / "input.bin"
            filename = Path(unquote(self.headers.get("X-Filename", "upload"))).name or "upload"
            source_system = self.headers.get("X-Source-System", "").strip().lower()
            if source_system not in SOURCE_SYSTEMS:
                return _safe_json_response(self, {"error": "يجب تحديد نظام Flow المصدر"}, 400)

            try:
                job_dir.mkdir(parents=True, exist_ok=True)
                input_file.write_bytes(body)
                initial_state = {
                    "metadata": {"job_id": job_id, "filename": filename, "data_type": "pending", "row_count": 0,
                                 "source_system": source_system, "source_system_label": SOURCE_SYSTEMS[source_system]},
                    "summary": {"records": 0, "unique_ips": 0},
                    "records": [],
                    "enrichment": {"status": "not_started"},
                    "analysis": {
                        "status": "queued", "progress": 5, "stage": "تم استلام الملف",
                        "processed": 0, "total": 0, "error": None,
                    },
                }
                _write_json_atomic(job_file, initial_state)
                threading.Thread(
                    target=self._run_analysis,
                    args=(job_id, filename, input_file, job_file, source_system),
                    daemon=True,
                ).start()
                return _safe_json_response(self, {"job_id": job_id})
            except Exception as exc:
                traceback.print_exc()
                shutil.rmtree(job_dir, ignore_errors=True)
                return _safe_json_response(self, {"error": str(exc)}, 400)

        if path.startswith("/api/enrich/"):
            force_refresh = parse_qs(parsed.query).get("force", ["0"])[0].lower() in {"1", "true", "yes"}
            job_id = path.split("/")[-1]
            if not re.match(r"^[0-9a-f]{32}$", job_id):
                return self.send_error(400, "Invalid Job ID")
                
            job_file = JOBS_DIR / job_id / "analysis.json"
            if not job_file.is_file():
                return self.send_error(404, "Job not found")

            try:
                current = _read_json(job_file)
            except (OSError, json.JSONDecodeError):
                return _safe_json_response(self, {"error": "Job data is unavailable or corrupted"}, 500)
            if not _analysis_complete(current):
                return _safe_json_response(self, {"error": "Analysis is not complete"}, 409)
            if (
                not force_refresh
                and
                current.get("enrichment", {}).get("status") == "completed"
                and current.get("enrichment", {}).get("scope") == ENRICHMENT_SCOPE
            ):
                return _safe_json_response(self, {"status": "already_completed"})
            with ACTIVE_ENRICHMENTS_LOCK:
                if job_id in ACTIVE_ENRICHMENTS:
                    return _safe_json_response(self, {"status": "already_running"})
                cancel_event = threading.Event()
                ACTIVE_ENRICHMENTS[job_id] = cancel_event

            current["enrichment"] = {
                "status": "running", "checked": 0, "total": 0,
                "cached": 0, "new": 0,
                "force_refresh": force_refresh,
                "providers": {}, "results": {}, "stage": "preparing",
            }
            try:
                _write_json_atomic(job_file, current)
                threading.Thread(
                    target=self._run_enrichment,
                    args=(job_id, job_file, cancel_event, force_refresh), daemon=True
                ).start()
            except Exception:
                with ACTIVE_ENRICHMENTS_LOCK:
                    ACTIVE_ENRICHMENTS.pop(job_id, None)
                raise
            return _safe_json_response(self, {"status": "started"})

        self.send_error(404)

    def do_DELETE(self) -> None:
        if self.path.startswith("/api/enrich/"):
            job_id = self.path.split("/")[-1]
            if not re.match(r"^[0-9a-f]{32}$", job_id):
                return self.send_error(400, "Invalid Job ID")
            with ACTIVE_ENRICHMENTS_LOCK:
                cancel_event = ACTIVE_ENRICHMENTS.get(job_id)
                if cancel_event:
                    cancel_event.set()
            job_file = JOBS_DIR / job_id / "analysis.json"
            if job_file.is_file():
                data = _read_json(job_file)
                data.setdefault("enrichment", {})["status"] = "cancelling"
                _write_json_atomic(job_file, data)
            return _safe_json_response(self, {"status": "cancelling" if cancel_event else "not_running"})

        if self.path.startswith("/api/jobs/"):
            job_id = self.path.split("/")[-1]
            if re.match(r"^[0-9a-f]{32}$", job_id):
                job_dir = JOBS_DIR / job_id
                with WRITE_LOCK:
                    if job_dir.is_dir():
                        shutil.rmtree(job_dir, ignore_errors=True)
                        report_preview.remove_artifacts("flowscope", job_id)
                        return _safe_json_response(self, {"status": "deleted"})
            return self.send_error(404, "Job not found")
        self.send_error(404)

    def _run_analysis(
        self, job_id: str, filename: str, input_file: Path, job_file: Path,
        source_system: str = "flow_1",
    ) -> None:
        started_at = datetime.now()
        last_audit = {"stage": None, "bucket": -1}

        def save_progress(progress: int, stage: str, processed: int = 0, total: int = 0) -> None:
            if not job_file.is_file():
                return
            current = _read_json(job_file)
            current["analysis"].update({
                "status": "running",
                "progress": min(max(int(progress), 0), 99),
                "stage": stage,
                "processed": processed,
                "total": total,
            })
            _write_json_atomic(job_file, current)
            bucket = int(progress) // 5
            if stage != last_audit["stage"] or bucket > last_audit["bucket"]:
                audit_engine.record_engine_event(
                    application="flowscope", action="analysis_progress",
                    message=f"تقدم تحليل FlowScope: {stage}", job_id=job_id,
                    details={"progress": int(progress), "stage": stage, "processed": processed, "total": total},
                )
                last_audit.update(stage=stage, bucket=bucket)

        try:
            audit_engine.record_engine_event(
                application="flowscope", action="analysis_worker_start",
                message="بدء عامل تحليل FlowScope", job_id=job_id,
                details={"filename": filename, "source_system": source_system},
            )
            save_progress(10, "قراءة الملف")
            parsed_data = file_parser.read_file(input_file, filename=filename)
            save_progress(20, "تمت قراءة الملف", 0, len(parsed_data.rows))

            headers_lower = [str(header).strip().lower() for header in parsed_data.headers]
            if any(name in headers_lower for name in {"event type", "type", "نوع الحدث"}):
                result = analyzer.analyze_ads_data(parsed_data, progress_callback=save_progress)
            else:
                result = flow_analyzer.analyze_flow_data(parsed_data, progress_callback=save_progress)

            result["metadata"]["job_id"] = job_id
            result["metadata"]["source_system"] = source_system
            result["metadata"]["source_system_label"] = SOURCE_SYSTEMS.get(source_system, "نظام Flow غير محدد")
            result["analysis"] = {
                "status": "completed", "progress": 100, "stage": "اكتمل التحليل",
                "processed": result["metadata"]["row_count"],
                "total": result["metadata"]["row_count"], "error": None,
            }
            if LEARNING_ENABLED:
                learning_engine.annotate_analysis("flowscope", job_id, result)
            _write_json_atomic(job_file, result)
            _schedule_model_analysis(job_id, result)
            audit_engine.record_engine_event(
                application="flowscope", action="analysis_worker_complete",
                message="اكتمل تحليل FlowScope بنجاح", job_id=job_id,
                details={
                    "records": result["metadata"]["row_count"],
                    "data_type": result["metadata"].get("data_type"),
                    "duration_ms": round((datetime.now() - started_at).total_seconds() * 1000, 2),
                },
            )
            if AUTO_ENRICH:
                cancel_event = threading.Event()
                with ACTIVE_ENRICHMENTS_LOCK:
                    ACTIVE_ENRICHMENTS[job_id] = cancel_event
                self._run_enrichment(job_id, job_file, cancel_event, False)
        except Exception as exc:
            traceback.print_exc()
            if job_file.is_file():
                try:
                    error_data = _read_json(job_file)
                    error_data["analysis"].update({
                        "status": "error", "stage": "فشل التحليل", "error": str(exc)[:500]
                    })
                    _write_json_atomic(job_file, error_data)
                except Exception:
                    pass
            audit_engine.record_engine_event(
                application="flowscope", action="analysis_worker_failed",
                message="فشل عامل تحليل FlowScope", job_id=job_id, level="error", outcome="failure",
                details={"error_type": type(exc).__name__, "error": str(exc)[:500]},
            )
        finally:
            input_file.unlink(missing_ok=True)

    def _run_enrichment(
        self, job_id: str, job_file: Path, cancel_event=None, force_refresh: bool = False
    ) -> None:
        if not job_file.is_file():
            return
        data = _read_json(job_file)
        audit_engine.record_engine_event(
            application="flowscope", action="enrichment_worker_start",
            message="بدء فحص سمعة عناوين IP", job_id=job_id, category="enrichment",
            details={"force_refresh": force_refresh},
        )
                
        # Set running state
        data["enrichment"]["status"] = "running"
        _write_json_atomic(job_file, data)
                
        try:
            ips, candidate_count = _select_enrichment_ips(data)
                
            cache_path = STORAGE_DIR / "intel_cache.sqlite3"
            
            last_logged = {"bucket": -1, "status": None}

            def save_progress(enrich_output):
                """Save enrichment progress to disk after each IP."""
                try:
                    current = _read_json(job_file)
                    current["enrichment"] = enrich_output
                    _write_json_atomic(job_file, current)
                    checked = int(enrich_output.get("checked") or 0)
                    total = int(enrich_output.get("total") or 0)
                    bucket = int((checked / max(total, 1)) * 20)
                    status = str(enrich_output.get("status") or "running")
                    if bucket > last_logged["bucket"] or status != last_logged["status"]:
                        audit_engine.record_engine_event(
                            application="flowscope", action="enrichment_progress",
                            message="تقدم فحص سمعة عناوين IP", job_id=job_id, category="enrichment",
                            details={"checked": checked, "total": total, "cached": enrich_output.get("cached", 0), "new": enrich_output.get("new", 0), "status": status},
                        )
                        last_logged.update(bucket=bucket, status=status)
                except Exception:
                    pass
            
            intel_results = enrichment.enrich_ips(
                ips, cache_path, progress_callback=save_progress,
                cancel_event=cancel_event, force_refresh=force_refresh,
            )
            intel_results["scope"] = ENRICHMENT_SCOPE
            intel_results["candidates"] = candidate_count
            intel_results["selected"] = len(ips)
            intel_results["truncated"] = candidate_count > len(ips)
             
            latest_data = _read_json(job_file)

            latest_data["enrichment"] = intel_results

            # Re-calculate risk for ADS events if enriched.
            if intel_results["status"] == "completed" and latest_data["metadata"]["data_type"] == "ads_events":
                for record in latest_data["records"]:
                    results = intel_results.get("results", {})
                    source = str(record.get("event_source", "")).strip()
                    base_score = record.get("base_risk_score")
                    if base_score is None:
                        base_score = analyzer.score_event_risk(
                            record.get("event_type", ""), record.get("priority", ""),
                            record.get("detail", ""), record.get("attributes", ""),
                        )
                        record["base_risk_score"] = base_score
                    base_score = int(base_score)
                    if source in results and results[source] and "reason" not in results[source]:
                        related = [results[source]]
                    else:
                        related = [
                            results[ip] for ip in record.get("event_targets", [])
                            if ip in results and results[ip] and "reason" not in results[ip]
                        ]
                    if not related:
                        record["risk_score"] = base_score
                        record["severity"] = _severity(base_score)
                        continue

                    candidate_scores = []
                    for provs in related:
                        score = base_score
                        abuse = provs.get("abuseipdb", {})
                        if abuse.get("score", 0) >= 75:
                            score = max(70, score + 15)
                        elif abuse.get("score", 0) >= 50:
                            score = max(40, score + 10)
                        elif abuse.get("score", 0) >= 25:
                            score += 5

                        vt = provs.get("virustotal", {})
                        if vt.get("malicious", 0) >= 3:
                            score = max(70, score + 15)
                        elif vt.get("malicious", 0) >= 1:
                            score += 8
                        elif vt.get("suspicious", 0) >= 1:
                            score += 4

                        shodan = provs.get("shodan", {})
                        if shodan.get("verdict") == "exposed":
                            score = max(40, score + 10)
                        elif shodan.get("verdict") == "notable":
                            score += 5
                        candidate_scores.append(score)

                    score = max(candidate_scores, default=base_score)

                    record["risk_score"] = min(max(score, 0), 100)
                    record["severity"] = _severity(record["risk_score"])

                latest_data["summary"]["critical"] = sum(
                    record.get("severity") == "حرج" for record in latest_data["records"]
                )
                latest_data["summary"]["high"] = sum(
                    record.get("severity") == "مرتفع" for record in latest_data["records"]
                )

            _write_json_atomic(job_file, latest_data)
            _schedule_model_analysis(job_id, latest_data)
            audit_engine.record_engine_event(
                application="flowscope", action="enrichment_worker_complete",
                message="اكتمل فحص سمعة عناوين IP", job_id=job_id, category="enrichment",
                outcome="success" if intel_results.get("status") == "completed" else "failure",
                level="info" if intel_results.get("status") == "completed" else "warning",
                details={key: intel_results.get(key, 0) for key in ("status", "checked", "total", "cached", "new", "selected", "candidates")},
            )
                    
        except Exception as exc:
            traceback.print_exc()
            try:
                error_data = _read_json(job_file)
                error_data["enrichment"]["status"] = "error"
                error_data["enrichment"]["error"] = str(exc)
                _write_json_atomic(job_file, error_data)
            except Exception:
                pass
            audit_engine.record_engine_event(
                application="flowscope", action="enrichment_worker_failed",
                message="فشل فحص سمعة عناوين IP", job_id=job_id, category="enrichment",
                level="error", outcome="failure", details={"error_type": type(exc).__name__, "error": str(exc)[:500]},
            )
        finally:
            with ACTIVE_ENRICHMENTS_LOCK:
                ACTIVE_ENRICHMENTS.pop(job_id, None)


def run_server() -> None:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    _recover_interrupted_jobs()
    server = ExclusiveThreadingHTTPServer((HOST, PORT), RequestHandler)
    
    print(f"FlowScope Server running on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()

if __name__ == "__main__":
    run_server()
