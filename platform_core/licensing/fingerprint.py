"""
Platform Scope - Machine Fingerprinting & Anti-Tamper Watermark Engine
Generates immutable Hardware Installation ID and manages DPAPI-protected system watermarks.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

IS_WINDOWS = os.name == "nt"


def _get_windows_machine_guid() -> str:
    if not IS_WINDOWS:
        return "NON_WINDOWS_GUID"
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(guid).strip()
    except Exception:
        return "UNKNOWN_MACHINE_GUID"


def _get_volume_serial() -> str:
    if not IS_WINDOWS:
        return "NON_WINDOWS_VOL"
    try:
        serial = ctypes.c_ulong()
        if ctypes.windll.kernel32.GetVolumeInformationW("C:\\", None, 0, ctypes.byref(serial), None, None, None, 0):
            return hex(serial.value)
    except Exception:
        pass
    return "UNKNOWN_VOL_SERIAL"


def _get_cpu_and_os_fingerprint() -> str:
    parts = [
        sys.platform,
        os.environ.get("PROCESSOR_IDENTIFIER", ""),
        os.environ.get("COMPUTERNAME", ""),
        os.environ.get("PROCESSOR_ARCHITECTURE", ""),
    ]
    return "|".join(parts)


def get_installation_id() -> str:
    """
    Computes a deterministic, hardware-bound Installation ID for this physical or virtual machine.
    Format: PS-INST-XXXX-XXXX-XXXX-XXXX
    """
    elements = [
        "PlatformScope_HardwareBinding_V1",
        _get_windows_machine_guid(),
        _get_volume_serial(),
        _get_cpu_and_os_fingerprint(),
    ]
    combined = ":::".join(elements).encode("utf-8")
    digest = hashlib.sha256(combined).hexdigest().upper()
    return f"PS-INST-{digest[:4]}-{digest[4:8]}-{digest[8:12]}-{digest[12:16]}"


def get_instance_id(storage_path: Path, installation_id: str | None = None) -> str:
    """
    Generates an Instance ID combining the installation ID and the specific storage directory path.
    Format: PS-INST-YYYY-YYYY
    """
    inst_id = installation_id or get_installation_id()
    combined = f"{inst_id}:::{storage_path.resolve()}".encode("utf-8")
    digest = hashlib.sha256(combined).hexdigest().upper()
    return f"PS-INST-{digest[:4]}-{digest[4:8]}"


# ==============================================================================
# Windows DPAPI Watermark Storage
# ==============================================================================

class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_ulong),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _dpapi_protect(data: bytes) -> bytes | None:
    if not IS_WINDOWS:
        return data  # Fallback for non-windows testing
    try:
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        blob_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        # CRYPTPROTECT_LOCAL_MACHINE = 0x4
        flags = 0x4
        if crypt32.CryptProtectData(ctypes.byref(blob_in), "PlatformScopeWatermark", None, None, None, flags, ctypes.byref(blob_out)):
            result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            kernel32.LocalFree(blob_out.pbData)
            return result
    except Exception:
        pass
    return None


def _dpapi_unprotect(encrypted_data: bytes) -> bytes | None:
    if not IS_WINDOWS:
        return encrypted_data
    try:
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        blob_in = DATA_BLOB(len(encrypted_data), ctypes.cast(ctypes.create_string_buffer(encrypted_data), ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        flags = 0x4
        if crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, flags, ctypes.byref(blob_out)):
            result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            kernel32.LocalFree(blob_out.pbData)
            return result
    except Exception:
        pass
    return None


def _get_watermark_paths(custom_storage_dir: Path | None = None) -> list[Path]:
    """Returns candidate watermark paths ordered by system resilience."""
    if custom_storage_dir:
        return [custom_storage_dir / ".license_watermark"]
    candidates: list[Path] = []
    if IS_WINDOWS:
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        candidates.append(Path(program_data) / "Platform Scope" / "security" / ".license_watermark")
        app_data = os.environ.get("LOCALAPPDATA")
        if app_data:
            candidates.append(Path(app_data) / "Platform Scope" / ".license_watermark")
    return candidates


def save_system_watermark(payload: dict[str, Any], custom_storage_dir: Path | None = None) -> bool:
    """Saves DPAPI-encrypted watermark across candidate system locations."""
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    encrypted = _dpapi_protect(data)
    if not encrypted:
        encrypted = data

    success = False
    for path in _get_watermark_paths(custom_storage_dir):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(encrypted)
            success = True
        except Exception:
            continue
    return success


def load_system_watermark(custom_storage_dir: Path | None = None) -> dict[str, Any] | None:
    """Loads and decrypts watermark from the first available system location."""
    for path in _get_watermark_paths(custom_storage_dir):
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()
            decrypted = _dpapi_unprotect(raw) or raw
            return json.loads(decrypted.decode("utf-8"))
        except Exception:
            continue
    return None

