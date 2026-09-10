from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = ROOT_DIR / "storage"
ARCHIVE_DIR = STORAGE_DIR / "archives"


@dataclass
class RetentionPolicies:
    jobs_days: int = 90
    audit_days: int = 365
    incidents_days: int = 730


class StorageGovernanceManager:
    """Manages disk consumption, cold data archival, and data retention compliance."""

    @classmethod
    def get_storage_breakdown(cls, storage_dir: Path | str | None = None) -> dict[str, Any]:
        """Calculates precise disk usage across all platform storage directories."""
        root = Path(storage_dir) if storage_dir else STORAGE_DIR
        breakdown = {}
        total_bytes = 0

        # Sub-directories
        for subdir_name in ["analyses", "evidence", "threat_intel", "archives"]:
            path = root / subdir_name
            size = sum(f.stat().st_size for f in path.glob("**/*") if f.is_file()) if path.exists() else 0
            breakdown[subdir_name] = {
                "size_bytes": size,
                "size_mb": round(size / (1024 * 1024), 2),
            }
            total_bytes += size

        # SQLite databases
        # SQLite databases (match *.sqlite3* and *.db*)
        sqlite_size = 0
        db_files = list(root.glob("*.sqlite3*"))
        for db in db_files:
            if db.is_file():
                s = db.stat().st_size
                sqlite_size += s
                total_bytes += s
        raw_db_files = list(root.glob("*.sqlite3*")) + list(root.glob("*.db*"))
        unique_db_files = list({p.resolve(): p for p in raw_db_files if p.is_file()}.values())
        for db in unique_db_files:
            s = db.stat().st_size
            sqlite_size += s
            total_bytes += s
        breakdown["sqlite_databases"] = {
            "size_bytes": sqlite_size,
            "size_mb": round(sqlite_size / (1024 * 1024), 2),
            "file_count": len(db_files),
            "file_count": len(unique_db_files),
        }

        # Audit file
        audit_file = root / "audit.jsonl"
        audit_size = audit_file.stat().st_size if audit_file.exists() else 0
        breakdown["audit_trail"] = {
            "size_bytes": audit_size,
            "size_mb": round(audit_size / (1024 * 1024), 2),
        }
        total_bytes += audit_size

        return {
            "total_bytes": total_bytes,
            "total_mb": round(total_bytes / (1024 * 1024), 2),
            "breakdown": breakdown,
            "storage_path": str(root),
        }

    @classmethod
    def archive_cold_jobs(
        cls,
        days_threshold: int = 90,
        dry_run: bool = True,
        storage_dir: Path | str | None = None,
    ) -> dict[str, Any]:
        """Identifies completed jobs older than threshold and packages them into a sealed archive."""
        root = Path(storage_dir) if storage_dir else STORAGE_DIR
        analyses_dir = root / "analyses"
        archive_dir = root / "archives"

        if not analyses_dir.exists():
            return {
                "dry_run": dry_run,
                "candidate_jobs_count": 0,
                "estimated_reclaimed_bytes": 0,
                "job_ids": [],
            }

        cutoff_epoch = time.time() - (days_threshold * 86400)
        jobs_to_archive = []

        for job_folder in analyses_dir.iterdir():
            if job_folder.is_dir():
                mtime = job_folder.stat().st_mtime
                if mtime < cutoff_epoch:
                    size = sum(f.stat().st_size for f in job_folder.glob("**/*") if f.is_file())
                    jobs_to_archive.append({"path": job_folder, "id": job_folder.name, "size": size})

        if dry_run or not jobs_to_archive:
            return {
                "dry_run": dry_run,
                "candidate_jobs_count": len(jobs_to_archive),
                "estimated_reclaimed_bytes": sum(j["size"] for j in jobs_to_archive),
                "job_ids": [j["id"] for j in jobs_to_archive[:20]],
            }

        archive_dir.mkdir(parents=True, exist_ok=True)
        archive_name = f"archive_{time.strftime('%Y%m%d_%H%M%S')}.zip"
        archive_path = archive_dir / archive_name

        total_reclaimed = 0
        manifest_lines = []

        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for job in jobs_to_archive:
                for file_p in job["path"].glob("**/*"):
                    if file_p.is_file():
                        rel = file_p.relative_to(root)
                        zf.write(file_p, arcname=str(rel))
                        h = hashlib.sha256(file_p.read_bytes()).hexdigest()
                        manifest_lines.append(f"{h}  {rel}")
                total_reclaimed += job["size"]
                shutil.rmtree(job["path"], ignore_errors=True)
            manifest_content = "\n".join(manifest_lines) + "\n"
            zf.writestr("manifest.sha256", manifest_content)

        return {
            "dry_run": False,
            "archived_jobs_count": len(jobs_to_archive),
            "reclaimed_bytes": total_reclaimed,
            "reclaimed_mb": round(total_reclaimed / (1024 * 1024), 2),
            "archive_path": str(archive_path),
            "manifest_records": len(manifest_lines),
        }

    @classmethod
    def vacuum_databases(cls, storage_dir: Path | str | None = None) -> dict[str, Any]:
        """Runs SQLite VACUUM on all platform databases to defragment and reclaim disk space."""
        root = Path(storage_dir) if storage_dir else STORAGE_DIR
        db_patterns = ["*.sqlite3", "*.db"]
        reclaimed_total = 0
        details = []

        seen = set()
        for pat in db_patterns:
            for db_path in root.glob(pat):
                if not db_path.is_file() or db_path in seen or "-wal" in db_path.name or "-shm" in db_path.name:
                    continue
                seen.add(db_path)
                size_before = db_path.stat().st_size
                try:
                    conn = sqlite3.connect(str(db_path), timeout=10.0)
                    conn.execute("PRAGMA busy_timeout=5000;")
                    conn.execute("VACUUM;")
                    conn.close()
                    size_after = db_path.stat().st_size
                    reclaimed = max(0, size_before - size_after)
                    reclaimed_total += reclaimed
                    details.append({
                        "database": db_path.name,
                        "size_before_bytes": size_before,
                        "size_after_bytes": size_after,
                        "reclaimed_bytes": reclaimed,
                        "status": "success",
                    })
                except Exception as exc:
                    details.append({
                        "database": db_path.name,
                        "error": str(exc),
                        "status": "failed",
                    })

        return {
            "success": True,
            "reclaimed_total_bytes": reclaimed_total,
            "reclaimed_total_mb": round(reclaimed_total / (1024 * 1024), 2),
            "databases_processed": len(details),
            "details": details,
        }

    @classmethod
    def cleanup_storage(
        cls,
        jobs_days: int = 30,
        audit_days: int = 90,
        dry_run: bool = False,
        storage_dir: Path | str | None = None,
    ) -> dict[str, Any]:
        """Applies data retention policy across completed jobs, archives cold data, and runs vacuum."""
        root = Path(storage_dir) if storage_dir else STORAGE_DIR
        archive_res = cls.archive_cold_jobs(days_threshold=jobs_days, dry_run=dry_run, storage_dir=root)

        vacuum_res = {}
        if not dry_run:
            vacuum_res = cls.vacuum_databases(storage_dir=root)

        return {
            "dry_run": dry_run,
            "jobs_days_threshold": jobs_days,
            "audit_days_threshold": audit_days,
            "archive": archive_res,
            "vacuum": vacuum_res,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
