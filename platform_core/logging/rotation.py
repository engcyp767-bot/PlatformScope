"""Log rotation, compression, and retention policy manager."""

from __future__ import annotations

import gzip
import os
from pathlib import Path
import shutil
import threading
import time
from typing import IO


class RotatingLogWriter:
    """Thread-safe rotating file writer supporting size rotation, gzip compression, and retention."""

    def __init__(
        self,
        file_path: Path | str,
        *,
        max_size_mb: int = 100,
        max_files: int = 10,
        retention_days: int = 30,
        compression: bool = True,
    ) -> None:
        self.file_path = Path(file_path)
        self.max_bytes = max(1, max_size_mb) * 1024 * 1024
        self.max_files = max(1, max_files)
        self.retention_seconds = max(1, retention_days) * 86400
        self.compression = compression
        self._lock = threading.RLock()
        self._stream: IO[str] | None = None
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def write_line(self, line: str) -> None:
        """Write single line to log file, rotating if limit exceeded."""
        with self._lock:
            if not self._stream or self._stream.closed:
                self._stream = open(self.file_path, "a", encoding="utf-8", newline="\n")

            if self.file_path.exists() and self.file_path.stat().st_size >= self.max_bytes:
                self._rotate()

            self._stream.write(line if line.endswith("\n") else line + "\n")
            self._stream.flush()

    def _rotate(self) -> None:
        """Perform log rotation and schedule background compression."""
        if self._stream and not self._stream.closed:
            self._stream.close()
            self._stream = None

        # Shift existing rotated files
        for i in range(self.max_files - 1, 0, -1):
            src_gz = self.file_path.with_name(f"{self.file_path.name}.{i}.gz")
            dst_gz = self.file_path.with_name(f"{self.file_path.name}.{i + 1}.gz")
            if src_gz.exists():
                if i + 1 >= self.max_files:
                    try:
                        src_gz.unlink()
                    except OSError:
                        pass
                else:
                    try:
                        src_gz.rename(dst_gz)
                    except OSError:
                        pass

            src_plain = self.file_path.with_name(f"{self.file_path.name}.{i}")
            dst_plain = self.file_path.with_name(f"{self.file_path.name}.{i + 1}")
            if src_plain.exists():
                if i + 1 >= self.max_files:
                    try:
                        src_plain.unlink()
                    except OSError:
                        pass
                else:
                    try:
                        src_plain.rename(dst_plain)
                    except OSError:
                        pass

        # Move current file to .1
        target_1 = self.file_path.with_name(f"{self.file_path.name}.1")
        if self.file_path.exists():
            try:
                self.file_path.rename(target_1)
            except OSError:
                pass

        # Compress target_1 if compression enabled
        if self.compression and target_1.exists():
            try:
                gz_target = self.file_path.with_name(f"{self.file_path.name}.1.gz")
                with open(target_1, "rb") as f_in, gzip.open(gz_target, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
                target_1.unlink()
            except Exception:
                pass

        # Clean retention expired files
        self._clean_retention()

        # Reopen main log file
        self._stream = open(self.file_path, "a", encoding="utf-8", newline="\n")

    def _clean_retention(self) -> None:
        """Delete files older than retention policy."""
        now = time.time()
        parent = self.file_path.parent
        prefix = self.file_path.name
        try:
            for item in parent.iterdir():
                if item.name.startswith(prefix) and item != self.file_path:
                    try:
                        if now - item.stat().st_mtime > self.retention_seconds:
                            item.unlink()
                    except OSError:
                        pass
        except OSError:
            pass

    def flush(self) -> None:
        with self._lock:
            if self._stream and not self._stream.closed:
                self._stream.flush()

    def close(self) -> None:
        with self._lock:
            if self._stream and not self._stream.closed:
                self._stream.flush()
                self._stream.close()
                self._stream = None

