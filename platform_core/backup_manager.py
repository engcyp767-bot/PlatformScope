"""Enterprise Backup and Disaster Recovery Manager.

Handles full platform state archives (SQLite databases, configuration, detection rules),
verifying cryptographic SHA-256 manifests, tamper detection, and automated restoration snapshots.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import shutil
import sqlite3
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from platform_core import audit_engine

logger = logging.getLogger("platform.backup_manager")

ROOT = Path(__file__).resolve().parent.parent
STORAGE_DIR = ROOT / "storage"
BACKUP_DIR = STORAGE_DIR / "backups"
DETECTIONS_DIR = ROOT / "detections"

_LOCK = threading.RLock()


class BackupManager:
    _instance: BackupManager | None = None

    def __init__(self, backup_dir: Path | None = None, storage_dir: Path | None = None, detections_dir: Path | None = None):
        self.storage_dir = storage_dir or STORAGE_DIR
        self.backup_dir = backup_dir or (self.storage_dir / "backups")
        self.detections_dir = detections_dir or DETECTIONS_DIR
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_instance(cls) -> BackupManager:
        if cls._instance is None:
            with _LOCK:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _compute_sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _compute_file_sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def sanitize_filename(self, filename: str) -> str:
        base = os.path.basename(filename).strip()
        if not base.endswith(".zip"):
            base += ".zip"
        clean = "".join(c for c in base if c.isalnum() or c in ("-", "_", "."))
        return clean

    def get_backup_path(self, filename: str) -> Path:
        clean = self.sanitize_filename(filename)
        target = (self.backup_dir / clean).resolve()
        if not str(target).startswith(str(self.backup_dir.resolve())):
            raise ValueError("Invalid backup path traversal attempted.")
        return target

    def _get_sqlite_consistent_bytes(self, db_path: Path) -> bytes:
        """Read SQLite file safely, passively checkpointing WAL first if accessible."""
        try:
            try:
                with sqlite3.connect(str(db_path), timeout=1.0) as con:
                    con.execute("PRAGMA wal_checkpoint(PASSIVE);")
            except Exception:
                pass
        except Exception:
            pass

        with open(db_path, "rb") as f:
            return f.read()

    def create_backup(
        self,
        actor: str = "system",
        note: str = "",
        include_detections: bool = True,
        include_databases: bool = True,
        include_configs: bool = True,
    ) -> dict[str, Any]:
        with _LOCK:
            now_dt = datetime.now(timezone.utc)
            timestamp_str = now_dt.strftime("%Y%m%d_%H%M%S")
            short_id = uuid.uuid4().hex[:8]
            filename = f"platform_backup_{timestamp_str}_{short_id}.zip"
            archive_path = self.backup_dir / filename

            manifest_files: dict[str, dict[str, Any]] = {}
            total_uncompressed_bytes = 0

            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                # 1. Databases
                if include_databases and self.storage_dir.exists():
                    db_patterns = ["*.sqlite3", "*.db"]
                    for pattern in db_patterns:
                        for db_file in self.storage_dir.glob(pattern):
                            if db_file.is_file() and not db_file.name.endswith(("-wal", "-shm")):
                                try:
                                    data = self._get_sqlite_consistent_bytes(db_file)
                                    sha256 = self._compute_sha256(data)
                                    arcname = f"storage/{db_file.name}"
                                    zf.writestr(arcname, data)
                                    manifest_files[arcname] = {
                                        "sha256": sha256,
                                        "size_bytes": len(data),
                                        "category": "database",
                                    }
                                    total_uncompressed_bytes += len(data)
                                except Exception as e:
                                    logger.error("Failed to archive db %s: %s", db_file.name, e)

                # 2. Config files
                if include_configs and self.storage_dir.exists():
                    config_names = ["platform_config.json", "security_auth.json"]
                    for cfg_name in config_names:
                        cfg_file = self.storage_dir / cfg_name
                        if cfg_file.is_file():
                            try:
                                data = cfg_file.read_bytes()
                                sha256 = self._compute_sha256(data)
                                arcname = f"storage/{cfg_name}"
                                zf.writestr(arcname, data)
                                manifest_files[arcname] = {
                                    "sha256": sha256,
                                    "size_bytes": len(data),
                                    "category": "config",
                                }
                                total_uncompressed_bytes += len(data)
                            except Exception as e:
                                logger.error("Failed to archive config %s: %s", cfg_name, e)

                # 3. Detection rules
                if include_detections and self.detections_dir.exists():
                    for root_dir, _, files in os.walk(self.detections_dir):
                        for f in files:
                            if f.endswith((".json", ".yml", ".yaml")):
                                full_p = Path(root_dir) / f
                                try:
                                    rel_p = full_p.relative_to(self.detections_dir)
                                    data = full_p.read_bytes()
                                    sha256 = self._compute_sha256(data)
                                    arcname = f"detections/{rel_p.as_posix()}"
                                    zf.writestr(arcname, data)
                                    manifest_files[arcname] = {
                                        "sha256": sha256,
                                        "size_bytes": len(data),
                                        "category": "detection_rule",
                                    }
                                    total_uncompressed_bytes += len(data)
                                except Exception as e:
                                    logger.error("Failed to archive detection rule %s: %s", full_p, e)

                # Build manifest
                manifest = {
                    "manifest_version": "1.0",
                    "backup_id": filename,
                    "created_at": now_dt.isoformat(),
                    "actor": actor,
                    "note": note,
                    "platform": "Unified Security Platform",
                    "total_files": len(manifest_files),
                    "total_uncompressed_bytes": total_uncompressed_bytes,
                    "files": manifest_files,
                }
                manifest_json_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
                manifest_sha256 = self._compute_sha256(manifest_json_bytes)

                zf.writestr("manifest.json", manifest_json_bytes)
                zf.writestr("manifest.sha256", manifest_sha256.encode("utf-8"))

            archive_size = archive_path.stat().st_size
            archive_sha256 = self._compute_file_sha256(archive_path)

            result = {
                "backup_id": filename,
                "filename": filename,
                "size_bytes": archive_size,
                "size_mb": round(archive_size / (1024 * 1024), 2),
                "uncompressed_bytes": total_uncompressed_bytes,
                "file_count": len(manifest_files),
                "created_at": now_dt.isoformat(),
                "sha256": archive_sha256,
                "note": note,
                "actor": actor,
            }

            audit_engine.record_engine_event(
                application="platform",
                action="backup_created",
                message=f"تم إنشاء نسخة احتياطية جديدة بنجاح: {filename} ({len(manifest_files)} ملفات)",
                category="administration",
                details=result,
            )

            return result

    def list_backups(self) -> list[dict[str, Any]]:
        backups: list[dict[str, Any]] = []
        if not self.backup_dir.exists():
            return backups

        for zf_path in self.backup_dir.glob("*.zip"):
            if not zf_path.is_file():
                continue
            try:
                stat = zf_path.stat()
                created_iso = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
                item = {
                    "backup_id": zf_path.name,
                    "filename": zf_path.name,
                    "size_bytes": stat.st_size,
                    "size_mb": round(stat.st_size / (1024 * 1024), 2),
                    "created_at": created_iso,
                    "valid": True,
                    "file_count": 0,
                    "note": "",
                    "actor": "system",
                }

                # Try reading manifest
                try:
                    with zipfile.ZipFile(zf_path, "r") as zf:
                        if "manifest.json" in zf.namelist():
                            manifest_bytes = zf.read("manifest.json")
                            m = json.loads(manifest_bytes.decode("utf-8"))
                            item["created_at"] = m.get("created_at", created_iso)
                            item["file_count"] = m.get("total_files", 0)
                            item["note"] = m.get("note", "")
                            item["actor"] = m.get("actor", "system")
                except Exception:
                    item["valid"] = False

                backups.append(item)
            except Exception as e:
                logger.error("Error reading backup info for %s: %s", zf_path.name, e)

        backups.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return backups

    def validate_backup(self, filename_or_path: str) -> dict[str, Any]:
        path = self.get_backup_path(filename_or_path)
        if not path.exists():
            return {"valid": False, "errors": [f"Backup file does not exist: {path.name}"]}

        errors: list[str] = []
        manifest: dict[str, Any] = {}

        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = set(zf.namelist())
                if "manifest.json" not in names:
                    return {"valid": False, "errors": ["Missing manifest.json in archive"]}
                if "manifest.sha256" not in names:
                    return {"valid": False, "errors": ["Missing manifest.sha256 in archive"]}

                manifest_raw = zf.read("manifest.json")
                expected_manifest_hash = zf.read("manifest.sha256").decode("utf-8").strip()
                actual_manifest_hash = self._compute_sha256(manifest_raw)

                if actual_manifest_hash != expected_manifest_hash:
                    errors.append(
                        f"Manifest SHA-256 hash mismatch. Expected: {expected_manifest_hash}, got: {actual_manifest_hash}"
                    )

                try:
                    manifest = json.loads(manifest_raw.decode("utf-8"))
                except Exception as e:
                    errors.append(f"Failed to parse manifest.json: {e}")
                    return {"valid": False, "errors": errors}

                # Verify each file in manifest
                files_dict = manifest.get("files", {})
                for arcname, meta in files_dict.items():
                    if arcname not in names:
                        errors.append(f"File declared in manifest missing from archive: {arcname}")
                        continue

                    file_data = zf.read(arcname)
                    actual_file_hash = self._compute_sha256(file_data)
                    expected_file_hash = meta.get("sha256")
                    if actual_file_hash != expected_file_hash:
                        errors.append(
                            f"File integrity violation in {arcname}: hash mismatch. Expected {expected_file_hash}, got {actual_file_hash}"
                        )

        except zipfile.BadZipFile:
            return {"valid": False, "errors": ["Corrupt or invalid ZIP archive"]}
        except Exception as e:
            return {"valid": False, "errors": [str(e)]}

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "manifest": manifest,
            "verified_files_count": len(manifest.get("files", {})),
        }

    def restore_backup(
        self,
        filename_or_path: str,
        actor: str = "system",
        create_safety_snapshot: bool = True,
    ) -> dict[str, Any]:
        with _LOCK:
            path = self.get_backup_path(filename_or_path)
            validation = self.validate_backup(path.name)
            if not validation["valid"]:
                err_msg = "; ".join(validation["errors"])
                raise ValueError(f"فشل التحقق من سلامة النسخة الاحتياطية: {err_msg}")

            safety_snapshot_id = None
            if create_safety_snapshot:
                try:
                    safety_result = self.create_backup(
                        actor=actor,
                        note="Automatic pre-restore safety snapshot",
                    )
                    safety_snapshot_id = safety_result["backup_id"]
                except Exception as e:
                    logger.warning("Could not create pre-restore safety snapshot: %s", e)

            manifest = validation["manifest"]
            files_dict = manifest.get("files", {})
            restored_count = 0

            with zipfile.ZipFile(path, "r") as zf:
                for arcname, meta in files_dict.items():
                    data = zf.read(arcname)

                    if arcname.startswith("storage/"):
                        rel_file = arcname[len("storage/"):]
                        target_file = self.storage_dir / rel_file
                        target_file.parent.mkdir(parents=True, exist_ok=True)

                        tmp_file = target_file.with_suffix(target_file.suffix + ".restoring")
                        tmp_file.write_bytes(data)
                        if target_file.exists():
                            try:
                                target_file.unlink()
                            except Exception:
                                pass
                        try:
                            shutil.move(str(tmp_file), str(target_file))
                        except Exception:
                            target_file.write_bytes(data)
                        restored_count += 1

                    elif arcname.startswith("detections/"):
                        rel_file = arcname[len("detections/"):]
                        target_file = self.detections_dir / rel_file
                        target_file.parent.mkdir(parents=True, exist_ok=True)
                        target_file.write_bytes(data)
                        restored_count += 1

            audit_engine.record_engine_event(
                application="platform",
                action="backup_restored",
                message=f"تمت استعادة المنصة من النسخة الاحتياطية: {path.name} ({restored_count} ملفات)",
                category="administration",
                details={
                    "backup_id": path.name,
                    "actor": actor,
                    "restored_files_count": restored_count,
                    "safety_snapshot_id": safety_snapshot_id,
                },
            )

            return {
                "restored": True,
                "backup_id": path.name,
                "restored_files_count": restored_count,
                "safety_snapshot_id": safety_snapshot_id,
                "restored_at": datetime.now(timezone.utc).isoformat(),
            }

    def delete_backup(self, filename: str, actor: str = "system") -> bool:
        with _LOCK:
            path = self.get_backup_path(filename)
            if not path.exists():
                return False
            path.unlink()

            audit_engine.record_engine_event(
                application="platform",
                action="backup_deleted",
                message=f"تم حذف ملف النسخة الاحتياطية: {path.name}",
                category="administration",
                details={"filename": path.name, "actor": actor},
            )
            return True
