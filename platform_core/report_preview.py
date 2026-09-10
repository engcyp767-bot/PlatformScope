"""Build one DOCX artifact and render that exact artifact for in-app preview."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parent.parent
CACHE_ROOT = ROOT / "tmp" / "report-previews"
ARTIFACT_VERSION = "word-preview-4-rtl-layout"
_LOCK = threading.RLock()


class PreviewUnavailable(RuntimeError):
    pass


def _soffice_path() -> Path:
    candidates = [
        os.environ.get("LIBREOFFICE_PATH", ""),
        shutil.which("libreoffice") or "",
        shutil.which("soffice") or "",
    ]
    if os.name == "nt":
        candidates.extend([
            ROOT / ".tools" / "libreoffice" / "LibreOffice" / "program" / "soffice.com",
            Path(r"C:\Program Files\LibreOffice\program\soffice.com"),
            Path(r"C:\Program Files (x86)\LibreOffice\program\soffice.com"),
        ])
    else:
        portable_root = ROOT / ".tools" / "offline"
        portable_candidates = list(portable_root.glob("linux-*/libreoffice/**/program/soffice"))
        candidates.extend(portable_candidates)
        candidates.extend([
            Path("/usr/bin/libreoffice"), Path("/usr/bin/soffice"), Path("/snap/bin/libreoffice"),
        ])
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).resolve()
    raise PreviewUnavailable("محرك معاينة Word غير متاح على الخادم.")


def _word_installed() -> bool:
    if os.name != "nt":
        return False
    candidates = [
        os.environ.get("MICROSOFT_WORD_PATH", ""),
        Path(r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
        Path(r"C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE"),
    ]
    return any(candidate and Path(candidate).is_file() for candidate in candidates)


def _convert_with_word(document: Path, preview: Path) -> tuple[bool, str]:
    """Export through Microsoft Word without allowing an Office dialog."""
    if not _word_installed():
        return False, "Microsoft Word is not installed"
    helper = ROOT / "scripts" / "word_export.ps1"
    temporary = preview.with_name(f"{preview.stem}.word.tmp.pdf")
    temporary.unlink(missing_ok=True)
    command = [
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-File", str(helper),
        "-InputPath", str(document.resolve()), "-OutputPath", str(temporary.resolve()),
    ]
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, creationflags=creation_flags)
    except (OSError, subprocess.TimeoutExpired) as error:
        temporary.unlink(missing_ok=True)
        return False, str(error)
    if result.returncode != 0 or not temporary.is_file() or temporary.stat().st_size < 100:
        temporary.unlink(missing_ok=True)
        return False, (result.stderr or result.stdout or "Word conversion failed").strip()[:500]
    if not temporary.read_bytes().startswith(b"%PDF-"):
        temporary.unlink(missing_ok=True)
        return False, "Microsoft Word returned an invalid PDF"
    os.replace(temporary, preview)
    return True, ""


def _convert_with_libreoffice(document: Path, preview: Path) -> None:
    converter = _soffice_path()
    # LibreOffice creates deeply nested registry paths below its profile.
    # Keep this path short to stay below Windows MAX_PATH.
    profile = ROOT / "tmp" / "lo-profile"
    profile.mkdir(parents=True, exist_ok=True)
    profile_uri = profile.resolve().as_uri()
    command = [
        str(converter), f"-env:UserInstallation={profile_uri}", "--headless", "--nologo", "--nodefault",
        "--nolockcheck", "--nofirststartwizard", "--convert-to", "pdf:writer_pdf_Export",
        "--outdir", str(document.parent), str(document),
    ]
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=180, creationflags=creation_flags)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PreviewUnavailable("تعذر تشغيل محرك معاينة Word.") from error
    if result.returncode != 0 or not preview.is_file() or preview.stat().st_size < 100:
        detail = (result.stderr or result.stdout or "conversion failed").strip()[:300]
        raise PreviewUnavailable(f"تعذر تحويل تقرير Word للمعاينة: {detail}")


def _artifact_directory(application: str, job_id: str) -> Path:
    if application not in {"flowscope", "threatscope", "logscope"} or not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise ValueError("Invalid report artifact identifier")
    target = (CACHE_ROOT / application / job_id).resolve()
    root = CACHE_ROOT.resolve()
    if root not in target.parents:
        raise ValueError("Invalid report artifact path")
    target.mkdir(parents=True, exist_ok=True)
    return target


def _analysis_fingerprint(analysis: dict) -> str:
    serialized = json.dumps(analysis, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((ARTIFACT_VERSION + serialized).encode("utf-8")).hexdigest()


def _snapshot_name(snapshot: str | None) -> str | None:
    if snapshot is None:
        return None
    if not re.fullmatch(r"[0-9a-f]{16,32}", str(snapshot)):
        raise ValueError("Invalid report snapshot")
    return str(snapshot)


def docx_artifact(application: str, job_id: str, analysis: dict, builder: Callable[[], bytes], snapshot: str | None = None) -> tuple[Path, str]:
    fingerprint = _analysis_fingerprint(analysis)
    snapshot = _snapshot_name(snapshot)
    directory = _artifact_directory(application, job_id)
    document = directory / (f"snapshot-{snapshot}.docx" if snapshot else f"report-{fingerprint}.docx")
    with _LOCK:
        if not document.is_file():
            payload = builder()
            if not isinstance(payload, bytes) or not payload.startswith(b"PK"):
                raise RuntimeError("تعذر إنشاء ملف Word صالح للمعاينة.")
            temporary = document.with_suffix(".docx.tmp")
            temporary.write_bytes(payload)
            os.replace(temporary, document)
        if snapshot:
            _remove_old_snapshots(directory, snapshot)
        else:
            _remove_stale(directory, fingerprint)
    return document, fingerprint


def pdf_artifact(application: str, job_id: str, analysis: dict, builder: Callable[[], bytes], snapshot: str | None = None) -> tuple[bytes, bytes]:
    """Return PDF preview bytes and the exact DOCX bytes used to create it."""
    document, fingerprint = docx_artifact(application, job_id, analysis, builder, snapshot=snapshot)
    preview = document.with_suffix(".pdf")
    engine_marker = preview.with_suffix(".engine")
    if preview.is_file() and engine_marker.is_file() and document.is_file():
        try:
            return preview.read_bytes(), document.read_bytes()
        except OSError:
            pass
    with _LOCK:
        # Old cached PDFs did not record their renderer. Rebuild them once so
        # Word can replace the previous LibreOffice approximation.
        if preview.is_file() and not engine_marker.is_file():
            preview.unlink(missing_ok=True)
        if not preview.is_file():
            mode = os.environ.get("WORD_PREVIEW_ENGINE", "auto").strip().lower()
            # A project copied from Windows may retain "word" in its saved
            # settings. Linux must transparently use its native LibreOffice.
            if mode == "word" and not _word_installed():
                mode = "libreoffice"
            converted = False
            word_error = ""
            if mode in {"auto", "word"}:
                converted, word_error = _convert_with_word(document, preview)
            if converted:
                engine_marker.write_text("microsoft-word", encoding="ascii")
            else:
                if mode == "word":
                    raise PreviewUnavailable(f"تعذر إنشاء المعاينة بواسطة Microsoft Word: {word_error}")
                _convert_with_libreoffice(document, preview)
                engine_marker.write_text("libreoffice", encoding="ascii")
        return preview.read_bytes(), document.read_bytes()


def _remove_stale(directory: Path, current_fingerprint: str) -> None:
    """Keep only the current immutable report artifact for a job."""
    current_prefix = f"report-{current_fingerprint}"
    for candidate in directory.iterdir():
        if candidate.is_file() and candidate.name.startswith("report-") and not candidate.name.startswith(current_prefix):
            candidate.unlink(missing_ok=True)


def _remove_old_snapshots(directory: Path, current: str) -> None:
    snapshots = sorted(directory.glob("snapshot-*.docx"), key=lambda path: path.stat().st_mtime, reverse=True)
    for document in snapshots[5:]:
        token = document.stem.removeprefix("snapshot-")
        if token != current:
            document.unlink(missing_ok=True)
            document.with_suffix(".pdf").unlink(missing_ok=True)
            document.with_suffix(".engine").unlink(missing_ok=True)


def remove_artifacts(application: str, job_id: str) -> None:
    """Remove cached previews when the owning analysis job is deleted."""
    if application not in {"flowscope", "threatscope", "logscope"} or not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise ValueError("Invalid report artifact identifier")
    target = (CACHE_ROOT / application / job_id).resolve()
    root = CACHE_ROOT.resolve()
    if root not in target.parents:
        raise ValueError("Invalid report artifact path")
    if target.is_dir():
        try:
            shutil.rmtree(target)
        except OSError:
            pass
