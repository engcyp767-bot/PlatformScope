"""Cross-platform lifecycle manager for the unified security platform.

The launcher deliberately uses only the Python standard library so the same
project directory can bootstrap itself on Windows and Linux/Ubuntu.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import webbrowser
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
STORAGE = ROOT / "storage"
_STORAGE_ENV = os.environ.get("PLATFORM_STORAGE_DIR") or os.environ.get("PLATFORM_SCOPE_DATA_DIR")
STORAGE = Path(_STORAGE_ENV).resolve() if _STORAGE_ENV else (ROOT / "storage")
RUNTIME_DIR = STORAGE / "runtime"
LOG_DIR = STORAGE / "logs"
STATE_FILE = RUNTIME_DIR / "platform-pids.json"
RUNTIME_FILE = RUNTIME_DIR / "platform-runtime.json"
SETTINGS_FILE = STORAGE / "platform_config.json"
LEGACY_STATE_FILES = (ROOT / ".security-nextjs-pids.json", ROOT / ".security-portal-pids.json")
IS_WINDOWS = os.name == "nt"
SYSTEM_NAME = "windows" if IS_WINDOWS else platform.system().lower()
MACHINE_NAME = platform.machine().lower()
MACHINE_ALIASES = {"amd64": "x64", "x86_64": "x64", "aarch64": "arm64"}
PLATFORM_KEY = f"{SYSTEM_NAME}-{MACHINE_ALIASES.get(MACHINE_NAME, MACHINE_NAME)}"
OFFLINE_ROOT = ROOT / ".tools" / "offline"
OFFLINE_PLATFORM = OFFLINE_ROOT / PLATFORM_KEY
OFFLINE_NPM_CACHE = OFFLINE_ROOT / "npm-cache"

# A moved Windows installation may inherit a legacy cp1252 console.  Keep the
# launcher deterministic when its output is redirected by CMD, SSH or VS Code.
for _stream in (sys.stdout, sys.stderr):
    _reconfigure = getattr(_stream, "reconfigure", None)
    if _reconfigure:
        try:
            _reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


class LaunchError(RuntimeError):
    """A user-actionable startup failure."""


def _message(text: str, level: str = "INFO") -> None:
    print(f"[{level}] {text}", flush=True)


def _load_dotenv(path: Path) -> None:
    """Load a small, predictable .env subset without adding a dependency."""
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if name.replace("_", "a").isalnum() and not name[0].isdigit():
            os.environ.setdefault(name, value)


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, TypeError):
        return default


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def _command(name: str, windows_name: str | None = None) -> str | None:
    return shutil.which(windows_name or name) if IS_WINDOWS else shutil.which(name)


def _offline_mode() -> str:
    value = os.environ.get("SECURITY_OFFLINE_MODE", "auto").strip().lower()
    aliases = {"1": "true", "yes": "true", "on": "true", "0": "false", "no": "false", "off": "false"}
    value = aliases.get(value, value)
    if value not in {"auto", "true", "false"}:
        raise LaunchError("SECURITY_OFFLINE_MODE must be auto, true or false.")
    return value


def _safe_unpack(archive: Path, destination: Path) -> None:
    """Extract an offline payload while rejecting paths outside destination."""
    destination.mkdir(parents=True, exist_ok=True)
    target_root = destination.resolve()

    def validate(name: str) -> None:
        member = (destination / name).resolve()
        if member != target_root and target_root not in member.parents:
            raise LaunchError(f"Unsafe path inside offline archive: {name}")

    if archive.suffix.lower() == ".zip":
        with zipfile.ZipFile(archive) as package:
            for member in package.infolist():
                validate(member.filename)
            package.extractall(destination)
        return
    with tarfile.open(archive, mode="r:*") as package:
        for member in package.getmembers():
            validate(member.name)
            if member.issym() or member.islnk():
                link_target = ((destination / member.name).parent / member.linkname).resolve()
                if link_target != target_root and target_root not in link_target.parents:
                    raise LaunchError(f"Unsafe link inside offline archive: {member.name}")
        package.extractall(destination)


def _materialize_offline_runtime(name: str) -> Path | None:
    destination = OFFLINE_PLATFORM / name
    if destination.is_dir():
        return destination
    archive = next((item for item in (
        OFFLINE_PLATFORM / f"{name}.tar.xz",
        OFFLINE_PLATFORM / f"{name}.tar.gz",
        OFFLINE_PLATFORM / f"{name}.zip",
    ) if item.is_file()), None)
    if archive is None:
        return None
    _message(f"Extracting offline {name} runtime for {PLATFORM_KEY}...", "SETUP")
    temporary = destination.with_name(f".{destination.name}-extracting")
    if temporary.exists():
        shutil.rmtree(temporary)
    _safe_unpack(archive, temporary)
    children = list(temporary.iterdir())
    source = children[0] if len(children) == 1 and children[0].is_dir() else temporary
    if source == temporary:
        temporary.replace(destination)
    else:
        source.replace(destination)
        shutil.rmtree(temporary, ignore_errors=True)
    return destination


def _bundled_node_commands() -> tuple[str, str] | None:
    directory = _materialize_offline_runtime("node")
    if directory is None:
        return None
    if IS_WINDOWS:
        node = directory / "node.exe"
        npm = directory / "npm.cmd"
    else:
        node = directory / "bin" / "node"
        npm = directory / "bin" / "npm"
        npm_cli = directory / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"
        if node.is_file():
            node.chmod(node.stat().st_mode | 0o700)
        if npm_cli.is_file():
            npm.write_text(
                '#!/usr/bin/env sh\nHERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"\nexec "$HERE/node" "$HERE/../lib/node_modules/npm/bin/npm-cli.js" "$@"\n',
                encoding="utf-8",
            )
            npm.chmod(npm.stat().st_mode | 0o700)
    if not node.is_file() or not npm.is_file():
        return None
    os.environ["PATH"] = str(node.parent.resolve()) + os.pathsep + os.environ.get("PATH", "")
    return str(node.resolve()), str(npm.resolve())


def _python_executable() -> str:
    current = Path(sys.executable)
    if current.is_file():
        return str(current.resolve())
    candidates = []
    if IS_WINDOWS:
        candidates.extend([
            OFFLINE_PLATFORM / "python" / "python.exe",
            ROOT / ".tools" / "libreoffice" / "LibreOffice" / "program" / "python.exe",
        ])
    else:
        candidates.extend([
            OFFLINE_PLATFORM / "python" / "bin" / "python3",
            OFFLINE_PLATFORM / "python" / "bin" / "python",
        ])
    selected = next((item for item in candidates if item.is_file()), None)
    if selected is None:
        raise LaunchError("تعذر تحديد ملف Python التنفيذي المستخدم لتشغيل الخدمات.")
    return str(selected.resolve())


def _version(command: str, *args: str) -> str:
    result = subprocess.run([command, *args], capture_output=True, text=True, timeout=15, check=False)
    if result.returncode:
        raise LaunchError((result.stderr or result.stdout or f"تعذر تشغيل {command}").strip())
    return result.stdout.strip()


def _version_tuple(value: str) -> tuple[int, int, int]:
    parts = value.strip().lstrip("v").split(".")
    try:
        numbers = [int(part.split("-", 1)[0]) for part in parts[:3]]
    except ValueError as error:
        raise LaunchError(f"تعذر قراءة رقم الإصدار: {value}") from error
    return tuple((numbers + [0, 0, 0])[:3])


def _runtime_commands() -> tuple[str, str, str]:
    python_command = _python_executable()
    node_command = _command("node", "node.exe")
    npm_command = _command("npm", "npm.cmd")
    if not node_command or not npm_command:
        bundled = _bundled_node_commands()
        if bundled:
            node_command, npm_command = bundled
    if not node_command or not npm_command:
        raise LaunchError(
            f"Node.js 20.9+ وnpm غير متوفرين. ضع runtime المحلي في {OFFLINE_PLATFORM / 'node'} "
            "أو ثبّت Node.js في PATH."
        )
    if sys.version_info < (3, 10):
        raise LaunchError(f"Python 3.10+ مطلوب؛ الإصدار الحالي {platform.python_version()}.")
    node_version = _version(node_command, "--version")
    if _version_tuple(node_version) < (20, 9, 0):
        raise LaunchError(f"Node.js 20.9+ مطلوب؛ الإصدار الحالي {node_version}.")
    return python_command, node_command, npm_command


def _platform_signature(node_command: str) -> dict[str, str]:
    return {
        "system": SYSTEM_NAME,
        "machine": platform.machine().lower(),
        "node": _version(node_command, "--version"),
    }


def _ensure_node_dependencies(directory: Path, required: Path, npm_command: str, signature: dict[str, str]) -> None:
    marker = directory / "node_modules" / ".security-platform-runtime.json"
    lockfile = directory / "package-lock.json"
    effective_signature = dict(signature)
    if lockfile.is_file():
        effective_signature["lock_sha256"] = hashlib.sha256(lockfile.read_bytes()).hexdigest()
    installed_for = _read_json(marker, {})
    signature_matches = all(installed_for.get(key) == value for key, value in effective_signature.items())
    if required.is_file() and signature_matches:
        return
    reason = "اعتماديات Node غير موجودة" if not required.is_file() else "تم اكتشاف نقل الاعتماديات من نظام أو معمارية أخرى"
    mode = _offline_mode()
    command = [npm_command, "ci", "--no-audit", "--no-fund"]
    cache_available = (OFFLINE_NPM_CACHE / "_cacache").is_dir()
    use_offline_cache = cache_available and mode != "false"
    if use_offline_cache:
        command.extend(["--offline", "--cache", str(OFFLINE_NPM_CACHE.resolve())])
        _message(f"{reason} داخل {directory.name}؛ التثبيت من ذاكرة npm المحلية دون إنترنت...", "SETUP")
    elif mode == "true":
        raise LaunchError(
            f"اعتماديات {directory.name} غير موجودة ووضع Offline الصارم مفعل. "
            f"جهز {OFFLINE_NPM_CACHE} على جهاز متصل أولاً."
        )
    else:
        _message(f"{reason} داخل {directory.name}؛ تشغيل npm ci...", "SETUP")
    result = subprocess.run(command, cwd=directory, check=False)
    if result.returncode:
        if required.is_file():
            _message(
                f"تعذر تحديث الاعتماديات من ذاكرة npm ({result.returncode})؛ استخدام الاعتماديات المتوفرة مسبقاً داخل {directory.name}.",
                "WARN",
            )
            if not IS_WINDOWS:
                bin_dir = directory / "node_modules" / ".bin"
                if bin_dir.is_dir():
                    for item in bin_dir.iterdir():
                        try:
                            item.chmod(item.stat().st_mode | 0o755)
                        except OSError:
                            pass
                try:
                    required.chmod(required.stat().st_mode | 0o755)
                except OSError:
                    pass
            _atomic_json(marker, effective_signature)
            return
        source = "ذاكرة npm المحلية" if use_offline_cache else "npm registry"
        raise LaunchError(f"فشل تثبيت اعتماديات Node داخل {directory} من {source}.")
    _atomic_json(marker, effective_signature)


def _run_build(directory: Path, npm_command: str, label: str) -> None:
    _message(f"بناء {label}...", "BUILD")
    if not IS_WINDOWS:
        bin_dir = directory / "node_modules" / ".bin"
        if bin_dir.is_dir():
            for item in bin_dir.iterdir():
                try:
                    item.chmod(item.stat().st_mode | 0o755)
                except OSError:
                    pass
        for extra in (
            directory / "node_modules" / "typescript" / "bin" / "tsc",
            directory / "node_modules" / "next" / "dist" / "bin" / "next",
        ):
            if extra.is_file():
                try:
                    extra.chmod(extra.stat().st_mode | 0o755)
                except OSError:
                    pass
    result = subprocess.run([npm_command, "run", "build"], cwd=directory, check=False)
    if result.returncode:
        raise LaunchError(f"فشل بناء {label}.")


def _bounded_port(value: Any, name: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as error:
        raise LaunchError(f"{name} يجب أن يكون رقم منفذ صحيحًا.") from error
    if not 1 <= port <= 65535:
        raise LaunchError(f"{name} يجب أن يكون بين 1 و65535.")
    return port


def _env_or_default(name: str, default: Any) -> str:
    value = os.environ.get(name)
    return str(default if value is None or not value.strip() else value.strip())


def _network_addresses() -> list[str]:
    candidates: set[str] = set()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            candidates.add(item[4][0])
    except OSError:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("192.0.2.1", 9))
        candidates.add(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass
    output: list[str] = []
    for value in candidates:
        try:
            address = ipaddress.ip_address(value)
            if address.version == 4 and not address.is_loopback and not address.is_link_local:
                output.append(value)
        except ValueError:
            continue
    return sorted(set(output), key=lambda item: tuple(int(part) for part in item.split(".")))


def _configure_environment() -> dict[str, Any]:
    _load_dotenv(ROOT / ".env")
    stored = _read_json(SETTINGS_FILE, {})
    network = stored.get("network") if isinstance(stored.get("network"), dict) else {}
    security = stored.get("security") if isinstance(stored.get("security"), dict) else {}

    frontend_port = _bounded_port(_env_or_default("SECURITY_FRONTEND_PORT", network.get("frontend_port", 3000)), "SECURITY_FRONTEND_PORT")
    gateway_port = _bounded_port(_env_or_default("SECURITY_GATEWAY_PORT", network.get("gateway_port", 8081)), "SECURITY_GATEWAY_PORT")
    analysis_port = _bounded_port(_env_or_default("ANALYSIS_ENGINE_PORT", network.get("analysis_port", 8082)), "ANALYSIS_ENGINE_PORT")
    if len({frontend_port, gateway_port, analysis_port}) != 3:
        raise LaunchError("يجب أن تكون منافذ الواجهة وGateway ومحرك التحليل مختلفة.")

    frontend_host = _env_or_default("SECURITY_FRONTEND_HOST", network.get("bind_address", "0.0.0.0"))
    gateway_host = _env_or_default("SECURITY_GATEWAY_HOST", "127.0.0.1")
    analysis_host = _env_or_default("ANALYSIS_ENGINE_HOST", "127.0.0.1")
    addresses = _network_addresses()
    automatic_origins = [f"http://127.0.0.1:{frontend_port}", f"http://localhost:{frontend_port}"]
    automatic_origins.extend(f"http://{address}:{frontend_port}" for address in addresses)
    configured_origins = [item.strip() for item in os.environ.get("SECURITY_ALLOWED_ORIGINS", "").split(",") if item.strip()]
    saved_origins = [str(item).strip() for item in network.get("trusted_origins", []) if str(item).strip()]

    values = {
        "SECURITY_FRONTEND_HOST": frontend_host,
        "SECURITY_FRONTEND_PORT": str(frontend_port),
        "SECURITY_GATEWAY_HOST": gateway_host,
        "SECURITY_GATEWAY_PORT": str(gateway_port),
        "ANALYSIS_ENGINE_HOST": analysis_host,
        "ANALYSIS_ENGINE_PORT": str(analysis_port),
        "PYTHON_BACKEND_URL": f"http://127.0.0.1:{analysis_port}",
        "GATEWAY_INTERNAL_URL": f"http://127.0.0.1:{gateway_port}",
        "SECURITY_ALLOWED_ORIGINS": ",".join(dict.fromkeys(automatic_origins + configured_origins + saved_origins)),
    }
    inherited_security = {
        "SECURITY_SESSION_HOURS": security.get("session_hours"),
        "SECURITY_LOGIN_MAX_ATTEMPTS": security.get("login_max_attempts"),
        "SECURITY_LOGIN_WINDOW_MINUTES": security.get("login_window_minutes"),
        "SECURITY_SECURE_COOKIE": str(bool(security.get("secure_cookie", False))).lower(),
        "SECURITY_PROXY_TIMEOUT_SECONDS": network.get("proxy_timeout_seconds"),
    }
    for name, value in {**values, **inherited_security}.items():
        if value is not None:
            os.environ.setdefault(name, str(value))
    # Network values must reflect the validated result even when saved settings were used.
    os.environ.update(values)
    return {
        "frontend_host": frontend_host, "frontend_port": frontend_port,
        "gateway_host": gateway_host, "gateway_port": gateway_port,
        "analysis_host": analysis_host, "analysis_port": analysis_port,
        "addresses": addresses,
    }


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _terminate_process(pid: int, quiet: bool = False) -> None:
    if pid <= 0:
        return
    if IS_WINDOWS:
        # os.kill(pid, 0) is not a reliable existence probe on every Windows
        # Python build. taskkill is idempotent and also releases child workers.
        result = subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)
        if result.returncode == 0 and not quiet:
            _message(f"تم إيقاف العملية PID {pid}.", "STOP")
        return
    if not _pid_alive(pid):
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            return
    deadline = time.time() + 5
    while time.time() < deadline and _pid_alive(pid):
        time.sleep(0.1)
    if _pid_alive(pid):
        try:
            os.killpg(pid, signal.SIGKILL)
        except OSError:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    if not quiet:
        _message(f"تم إيقاف العملية PID {pid}.", "STOP")


def _state_processes(payload: Any) -> dict[str, int]:
    if not isinstance(payload, dict):
        return {}
    source = payload.get("processes", payload)
    if not isinstance(source, dict):
        return {}
    output: dict[str, int] = {}
    for name, value in source.items():
        try:
            output[str(name)] = int(value.get("pid") if isinstance(value, dict) else value)
        except (TypeError, ValueError):
            continue
    return output


def _pids_on_ports(ports: tuple[int, ...]) -> set[int]:
    pids: set[int] = set()
    current_pid = os.getpid()
    if IS_WINDOWS:
        try:
            output = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, check=False).stdout
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[3].upper() == "LISTENING":
                    local_address = parts[1]
                    try:
                        port = int(local_address.rsplit(":", 1)[-1])
                        pid = int(parts[4])
                        if port in ports and pid > 0 and pid != current_pid:
                            pids.add(pid)
                    except (ValueError, IndexError):
                        continue
        except Exception:
            pass
    else:
        for port in ports:
            for tool in ("lsof", "fuser"):
                if shutil.which(tool):
                    cmd = ["lsof", "-t", f"-i:{port}"] if tool == "lsof" else ["fuser", f"{port}/tcp"]
                    try:
                        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                        for token in res.stdout.split():
                            if token.isdigit():
                                pid = int(token)
                                if pid > 0 and pid != current_pid:
                                    pids.add(pid)
                    except Exception:
                        pass
    return pids


def stop_services(quiet: bool = False) -> bool:
    found = False
    stopped_pids: set[int] = set()
    for state_path in (STATE_FILE, *LEGACY_STATE_FILES):
        if not state_path.is_file():
            continue
        for _, pid in _state_processes(_read_json(state_path, {})).items():
            if pid not in stopped_pids:
                _terminate_process(pid, quiet=quiet)
                stopped_pids.add(pid)
                found = True
        try:
            state_path.unlink()
        except OSError:
            pass

    configured_ports = (3000, 8081, 8082)
    try:
        saved_network = _read_json(SETTINGS_FILE, {}).get("network", {})
        if isinstance(saved_network, dict):
            configured_ports = tuple(filter(None, (
                _bounded_port(saved_network.get("frontend_port"), "frontend_port") if saved_network.get("frontend_port") else 3000,
                _bounded_port(saved_network.get("gateway_port"), "gateway_port") if saved_network.get("gateway_port") else 8081,
                _bounded_port(saved_network.get("analysis_port"), "analysis_port") if saved_network.get("analysis_port") else 8082,
            )))
    except Exception:
        pass

    for pid in _pids_on_ports(configured_ports):
        if pid not in stopped_pids:
            _terminate_process(pid, quiet=quiet)
            stopped_pids.add(pid)
            found = True

    if not quiet:
        _message("تم إيقاف منصة التحليل الأمني." if found else "لا توجد عمليات مسجلة للمنصة.", "OK")
    return found


def is_platform_running() -> bool:
    """Check whether the platform services or ports are currently active."""
    for state_path in (STATE_FILE, *LEGACY_STATE_FILES):
        if state_path.is_file():
            processes = _state_processes(_read_json(state_path, {}))
            if processes and any(_pid_alive(pid) for pid in processes.values()):
                return True

    configured_ports = (3000, 8081, 8082)
    try:
        saved_network = _read_json(SETTINGS_FILE, {}).get("network", {})
        if isinstance(saved_network, dict):
            configured_ports = tuple(filter(None, (
                _bounded_port(saved_network.get("frontend_port"), "frontend_port") if saved_network.get("frontend_port") else 3000,
                _bounded_port(saved_network.get("gateway_port"), "gateway_port") if saved_network.get("gateway_port") else 8081,
                _bounded_port(saved_network.get("analysis_port"), "analysis_port") if saved_network.get("analysis_port") else 8082,
            )))
    except Exception:
        pass

    if _pids_on_ports(configured_ports):
        return True

    if any(not _port_available(port) for port in configured_ports):
        return True

    return False


def restart_services(skip_build: bool = False, no_browser: bool = False, configure_firewall: bool = False, wait_forever: bool = False) -> int:
    """Restart all services if already running, or start if stopped."""
    if is_platform_running():
        _message("تم اكتشاف تشغيل مسبق للمنصة؛ جاري إيقاف الخدمات لإعادة التشغيل...", "INFO")
        stop_services(quiet=False)
        time.sleep(1)
    else:
        _message("المنصة متوقفة؛ جاري بدء تشغيل المنصة...", "INFO")
    if wait_forever:
        return start_services(skip_build, no_browser, configure_firewall, wait_forever=True)
    return start_services(skip_build, no_browser, configure_firewall)


def _port_available(port: int) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _start_process(name: str, command: list[str], cwd: Path, log_stem: str, environment: dict[str, str]) -> subprocess.Popen[bytes]:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stdout_path = LOG_DIR / f"{log_stem}.out.log"
    stderr_path = LOG_DIR / f"{log_stem}.error.log"
    stdout = stdout_path.open("ab")
    stderr = stderr_path.open("ab")
    options: dict[str, Any] = {"cwd": cwd, "env": environment, "stdout": stdout, "stderr": stderr, "stdin": subprocess.DEVNULL}
    try:
        if IS_WINDOWS:
            detached = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            create_new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
            breakaway = 0x01000000  # CREATE_BREAKAWAY_FROM_JOB
            flags = detached | create_new_group
            try:
                options["creationflags"] = flags | breakaway
                process = subprocess.Popen(command, **options)
            except OSError:
                options["creationflags"] = flags
                process = subprocess.Popen(command, **options)
        else:
            options["start_new_session"] = True
            process = subprocess.Popen(command, **options)
    finally:
        stdout.close()
        stderr.close()
    _message(f"تشغيل {name} (PID {process.pid}).", "START")
    return process


def _http_ready(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return 200 <= response.status < 400
    except (OSError, urllib.error.URLError, ValueError):
        return False


def _wait_for_services(config: dict[str, Any], processes: dict[str, subprocess.Popen[bytes]], timeout: int = 75) -> None:
    urls = (
        f"http://127.0.0.1:{config['analysis_port']}/api/system/health",
        f"http://127.0.0.1:{config['gateway_port']}/api/system/health",
        f"http://127.0.0.1:{config['frontend_port']}",
        f"http://127.0.0.1:{config['frontend_port']}/api/system/health",
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        failed_process = next((name for name, process in processes.items() if process.poll() is not None), None)
        if failed_process:
            raise LaunchError(f"توقفت خدمة {failed_process} أثناء الإقلاع؛ راجع storage/logs.")
        if all(_http_ready(url) for url in urls):
            return
        time.sleep(0.5)
    raise LaunchError("لم تصبح جميع الخدمات جاهزة خلال المهلة؛ راجع storage/logs.")


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _configure_firewall(port: int) -> None:
    if IS_WINDOWS:
        powershell = _command("powershell", "powershell.exe")
        if not powershell:
            _message(f"تعذر العثور على PowerShell؛ اسمح يدويًا بمنفذ TCP {port}.", "WARN")
            return
        rule = f"Security Analysis Platform Frontend TCP {port}"
        script = (
            f"if (-not (Get-NetFirewallRule -DisplayName '{rule}' -ErrorAction SilentlyContinue)) "
            f"{{ New-NetFirewallRule -DisplayName '{rule}' -Direction Inbound -Action Allow "
            f"-Protocol TCP -LocalPort {port} -Profile Domain,Private | Out-Null }}"
        )
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, check=False)
        if result.returncode:
            _message(f"تعذر تعديل Windows Firewall؛ شغّل كمسؤول أو اسمح يدويًا بمنفذ TCP {port}.", "WARN")
        else:
            _message(f"Windows Firewall يسمح بمنفذ الواجهة TCP {port}.", "OK")
        return

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        _message(f"إعداد firewall يحتاج root. على Ubuntu نفذ: sudo ufw allow {port}/tcp", "WARN")
        return
    ufw = shutil.which("ufw")
    firewall_cmd = shutil.which("firewall-cmd")
    if ufw:
        result = subprocess.run([ufw, "allow", f"{port}/tcp"], check=False)
    elif firewall_cmd:
        result = subprocess.run([firewall_cmd, "--permanent", f"--add-port={port}/tcp"], check=False)
        if result.returncode == 0:
            result = subprocess.run([firewall_cmd, "--reload"], check=False)
    else:
        _message(f"لم يُكتشف ufw أوfirewalld؛ اسمح يدويًا بمنفذ TCP {port}.", "WARN")
        return
    if result.returncode:
        _message(f"تعذر إعداد firewall لمنفذ TCP {port}.", "WARN")
    else:
        _message(f"Firewall يسمح بمنفذ الواجهة TCP {port}.", "OK")


def _libreoffice_path() -> str | None:
    configured = os.environ.get("LIBREOFFICE_PATH", "").strip()
    candidates = [configured, shutil.which("libreoffice") or "", shutil.which("soffice") or ""]
    if IS_WINDOWS:
        candidates.extend([
            str(ROOT / ".tools" / "libreoffice" / "LibreOffice" / "program" / "soffice.com"),
            r"C:\Program Files\LibreOffice\program\soffice.com",
            r"C:\Program Files (x86)\LibreOffice\program\soffice.com",
        ])
    else:
        portable = _materialize_offline_runtime("libreoffice")
        if portable:
            candidates.extend([
                str(portable / "program" / "soffice"),
                str(portable / "LibreOffice" / "program" / "soffice"),
            ])
            candidates.extend(str(item) for item in portable.rglob("program/soffice"))
        candidates.extend(["/usr/bin/libreoffice", "/usr/bin/soffice", "/snap/bin/libreoffice"])
    selected = next((Path(item).resolve() for item in candidates if item and Path(item).is_file()), None)
    if selected and not IS_WINDOWS and OFFLINE_PLATFORM in selected.parents:
        marker = OFFLINE_PLATFORM / "libreoffice" / ".permissions-ready"
        if not marker.is_file():
            # Archives created on Windows may lose POSIX executable bits. This
            # payload is trusted and platform-specific, so restore them once.
            for item in (OFFLINE_PLATFORM / "libreoffice").rglob("*"):
                if item.is_file():
                    item.chmod(item.stat().st_mode | 0o700)
            marker.touch()
    return str(selected) if selected else None


def _install_offline_linux_debs() -> bool:
    """Install a staged Ubuntu package set without contacting apt repositories."""
    if IS_WINDOWS or SYSTEM_NAME != "linux":
        return False
    package_dir = OFFLINE_PLATFORM / "debs"
    packages = sorted(package_dir.glob("*.deb")) if package_dir.is_dir() else []
    dpkg = shutil.which("dpkg")
    if not packages or not dpkg:
        return False
    prefix: list[str] = []
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo or subprocess.run([sudo, "-n", "true"], check=False, capture_output=True).returncode:
            _message(
                f"حزم Ubuntu المحلية موجودة في {package_dir} لكنها تحتاج root؛ شغّل sudo bash start.sh مرة واحدة.",
                "WARN",
            )
            return False
        prefix = [sudo, "-n"]
    _message(f"تثبيت {len(packages)} حزمة Ubuntu محلية دون اتصال...", "SETUP")
    result = subprocess.run([*prefix, dpkg, "-i", *map(str, packages)], check=False)
    if result.returncode:
        raise LaunchError(
            f"فشل تثبيت حزم Ubuntu المحلية في {package_dir}. تأكد أن الحزمة تضم جميع ملفات deb التابعة للإصدار الهدف."
        )
    return True


def _microsoft_word_path() -> str | None:
    if not IS_WINDOWS:
        return None
    candidates = [
        os.environ.get("MICROSOFT_WORD_PATH", "").strip(),
        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        r"C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE",
    ]
    return next((str(Path(item).resolve()) for item in candidates if item and Path(item).is_file()), None)


def doctor(running: bool = False) -> int:
    _load_dotenv(ROOT / ".env")
    failures: list[str] = []
    warnings: list[str] = []

    def check(condition: bool, success: str, failure: str) -> None:
        _message(success if condition else failure, "PASS" if condition else "FAIL")
        if not condition:
            failures.append(failure)

    _message(f"النظام: {platform.platform()} | Python {platform.python_version()}", "SYSTEM")
    for relative in ("backend_server.py", "frontend/package-lock.json", "gateway/package-lock.json", "platform_launcher.py"):
        check((ROOT / relative).is_file(), f"{relative} موجود.", f"{relative} مفقود.")
    try:
        _, node_command, npm_command = _runtime_commands()
        check(True, f"Node {_version(node_command, '--version')} وnpm {_version(npm_command, '--version')} جاهزان.", "Node/npm غير جاهزين.")
    except LaunchError as error:
        check(False, "Node/npm جاهزان.", str(error))
    preview = _libreoffice_path()
    word = _microsoft_word_path()
    if word:
        _message(f"Microsoft Word متاح: {word}", "PASS")
    if preview:
        _message(f"LibreOffice متاح: {preview}", "PASS")
    if not preview and not word:
        failures.append(
            "محرك معاينة التقارير غير متاح. على Ubuntu: sudo apt install libreoffice fonts-noto-core fonts-noto-extra"
            if not IS_WINDOWS else "ثبّت Microsoft Word أوLibreOffice لتشغيل معاينة التقارير."
        )
    if not IS_WINDOWS:
        font_catalog = shutil.which("fc-list")
        if font_catalog:
            result = subprocess.run([font_catalog], capture_output=True, text=True, timeout=20, check=False)
            if "Noto" not in result.stdout:
                warnings.append("خطوط Noto غير مكتشفة؛ ثبّت fonts-noto-core وfonts-noto-extra لثبات تخطيط العربية.")
    try:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        probe = RUNTIME_DIR / f"doctor-{os.getpid()}.tmp"
        probe.write_text("ok", encoding="ascii")
        probe.unlink()
        check(True, "مسارات التخزين قابلة للكتابة.", "مسارات التخزين غير قابلة للكتابة.")
    except OSError:
        check(False, "مسارات التخزين قابلة للكتابة.", "مسارات التخزين غير قابلة للكتابة.")
    if running:
        config = _configure_environment()
        check(config["frontend_host"] in {"0.0.0.0", "::", "[::]"}, "الواجهة مربوطة بكل واجهات الشبكة.", "الواجهة ليست مربوطة بالشبكة العامة.")
        check(config["gateway_host"] in {"127.0.0.1", "::1", "localhost"}, "Gateway خاص على loopback.", "Gateway مكشوف خارج loopback.")
        check(config["analysis_host"] in {"127.0.0.1", "::1", "localhost"}, "محرك التحليل خاص على loopback.", "محرك التحليل مكشوف خارج loopback.")
        urls = [
            f"http://127.0.0.1:{config['frontend_port']}",
            f"http://127.0.0.1:{config['frontend_port']}/api/system/health",
            f"http://127.0.0.1:{config['gateway_port']}/api/system/health",
            f"http://127.0.0.1:{config['analysis_port']}/api/system/health",
        ]
        if "192.168.88.66" in config.get("addresses", []):
            urls.append(f"http://192.168.88.66:{config['frontend_port']}")
            urls.append(f"http://192.168.88.66:{config['frontend_port']}/api/system/health")
        for url in urls:
            check(_http_ready(url), f"الاتصال ناجح: {url}", f"الاتصال فشل: {url}")
    for warning in warnings:
        _message(warning, "WARN")
    _message("فحص الجاهزية ناجح." if not failures else f"فشل فحص الجاهزية في {len(failures)} بند.", "OK" if not failures else "FAIL")
    return 0 if not failures else 1


def start_services(skip_build: bool = False, no_browser: bool = False, configure_firewall: bool = False, wait_forever: bool = False) -> int:
    config = _configure_environment()
    python_command, node_command, npm_command = _runtime_commands()
    preview_engine = _libreoffice_path()
    if not preview_engine and not _microsoft_word_path():
        _install_offline_linux_debs()
        preview_engine = _libreoffice_path()
    if not preview_engine and not _microsoft_word_path():
        raise LaunchError(
            f"لا يوجد محرك لمعاينة التقارير. أضف LibreOffice المحمول أوحزم deb المحلية تحت {OFFLINE_PLATFORM}، "
            "أو ثبّت LibreOffice/Word على النظام."
        )
    if preview_engine:
        os.environ["LIBREOFFICE_PATH"] = preview_engine
    signature = _platform_signature(node_command)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    _message(f"تهيئة المنصة على {SYSTEM_NAME}/{platform.machine()}.", "SYSTEM")
    lockfile = ROOT / "frontend" / "package-lock.json"
    if lockfile.is_file():
        # Native Node binaries can be locked by the previous frontend on Windows.
        # Stop tracked services before npm replaces dependencies after a move.
        stop_services(quiet=True)
        _ensure_node_dependencies(ROOT / "gateway", ROOT / "gateway" / "node_modules" / "typescript" / "bin" / "tsc", npm_command, signature)
        _ensure_node_dependencies(ROOT / "frontend", ROOT / "frontend" / "node_modules" / "next" / "dist" / "bin" / "next", npm_command, signature)
    if not skip_build:
        _run_build(ROOT / "gateway", npm_command, "API Gateway")
        _run_build(ROOT / "frontend", npm_command, "واجهة Next.js")

    for port, label in ((config["analysis_port"], "محرك التحليل"), (config["gateway_port"], "Gateway"), (config["frontend_port"], "الواجهة")):
        if not _port_available(port):
            raise LaunchError(f"المنفذ {port} مستخدم ولا يمكن تشغيل {label}.")

    environment = os.environ.copy()
    environment["PYTHONUNBUFFERED"] = "1"
    specs: dict[str, tuple[str, list[str], Path, str]] = {
        "AnalysisEngine": (
            "Python Analysis Engine",
            [python_command, "-B", str(ROOT / "backend_server.py")],
            ROOT,
            "python-analysis-engine",
        ),
        "Gateway": (
            "Node API Gateway",
            [node_command, str(ROOT / "gateway" / "dist" / "index.js")],
            ROOT / "gateway",
            "node-api-gateway",
        ),
        "Frontend": (
            "Next.js Frontend",
            [
                node_command,
                str(ROOT / "frontend" / "node_modules" / "next" / "dist" / "bin" / "next"),
                "start",
                "-H",
                config["frontend_host"],
                "-p",
                str(config["frontend_port"]),
            ],
            ROOT / "frontend",
            "next.js-frontend",
        ),
    }
    processes: dict[str, subprocess.Popen[bytes]] = {}
    try:
        for name, (label, cmd, cwd, log_stem) in specs.items():
            processes[name] = _start_process(label, cmd, cwd, log_stem, environment)
        _atomic_json(STATE_FILE, {
            "version": 2, "system": SYSTEM_NAME, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "processes": {name: {"pid": process.pid} for name, process in processes.items()},
        })
        _wait_for_services(config, processes)
    except Exception:
        for process in processes.values():
            _terminate_process(process.pid, quiet=True)
        STATE_FILE.unlink(missing_ok=True)
        raise

    network_urls = [f"http://{address}:{config['frontend_port']}" for address in config["addresses"]]
    local_url = f"http://127.0.0.1:{config['frontend_port']}"
    preferred_ip = "192.168.88.66"
    primary_url = next((url for url in network_urls if preferred_ip in url), None) or (network_urls[0] if network_urls else local_url)

    _atomic_json(RUNTIME_FILE, {
        "version": 2, "system": SYSTEM_NAME, "workspace": str(ROOT),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "frontend": {"bind": config["frontend_host"], "port": config["frontend_port"], "primary_url": primary_url, "local_url": local_url, "network_urls": network_urls},
        "gateway": {"bind": config["gateway_host"], "port": config["gateway_port"], "internal_url": os.environ["GATEWAY_INTERNAL_URL"]},
        "analysis_engine": {"bind": config["analysis_host"], "port": config["analysis_port"], "internal_url": os.environ["PYTHON_BACKEND_URL"]},
    })
    if configure_firewall or _truthy(os.environ.get("SECURITY_CONFIGURE_FIREWALL")):
        _configure_firewall(config["frontend_port"])

    _message("منصة التحليل الأمني الموحدة جاهزة.", "READY")
    _message(f"الرابط الرئيسي (الشبكة): {primary_url}", "URL")
    _message(f"Local: {local_url}", "URL")
    for url in network_urls:
        if url != primary_url:
            _message(f"Network: {url}", "URL")
    if not configure_firewall:
        hint = "start.cmd --configure-firewall" if IS_WINDOWS else "sudo bash start.sh --configure-firewall"
        _message(f"إذا تعذر الوصول من الشبكة شغّل: {hint}", "TIP")
    if not no_browser and (IS_WINDOWS or os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        try:
            webbrowser.open(primary_url)
        except webbrowser.Error:
            pass
    if wait_forever:
        try:
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            stop_services()
        _supervise_processes(processes, specs, config, environment)
    return 0


def _supervise_processes(
    processes: dict[str, subprocess.Popen[bytes]],
    specs: dict[str, tuple[str, list[str], Path, str]],
    config: dict[str, Any],
    environment: dict[str, str],
) -> None:
    """Active process supervision loop with auto-restart on unexpected exit."""
    _message("وضع الإشراف المباشر على العمليات (Process Supervisor) نشط.", "SUPERVISOR")
    crash_counts: dict[str, int] = {name: 0 for name in processes}
    last_restart: dict[str, float] = {name: 0.0 for name in processes}
    try:
        while True:
            time.sleep(2)
            for name, proc in list(processes.items()):
                code = proc.poll()
                if code is not None:
                    now = time.time()
                    if now - last_restart[name] > 60:
                        crash_counts[name] = 0
                    crash_counts[name] += 1
                    last_restart[name] = now
                    _message(f"العملية {name} توقفت بشكل غير متوقع (رمز الخروج {code}). جاري إعادة التشغيل #{crash_counts[name]}...", "WARN")
                    backoff = min(10, crash_counts[name] * 2)
                    if backoff > 0:
                        time.sleep(backoff)
                    label, cmd, cwd, log_stem = specs[name]
                    new_proc = _start_process(label, cmd, cwd, log_stem, environment)
                    processes[name] = new_proc
                    _atomic_json(STATE_FILE, {
                        "version": 2, "system": SYSTEM_NAME,
                        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "processes": {k: {"pid": p.pid} for k, p in processes.items()},
                    })
                    _message(f"تمت إعادة تشغيل {name} بنجاح (PID {new_proc.pid}).", "OK")
    except (KeyboardInterrupt, SystemExit):
        _message("إيقاف المنصة وجميع العمليات التابعة...", "STOP")
        stop_services()


def _manage_autostart_windows(action: str) -> int:
    task_name = "SecurityPlatformAutoStart"
    schtasks = shutil.which("schtasks.exe") or "schtasks"
    appdata = os.environ.get("APPDATA")
    startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" if appdata else None
    startup_cmd = startup_dir / f"{task_name}.cmd" if startup_dir else None

    if action == "status":
        has_task = False
        res = subprocess.run([schtasks, "/Query", "/TN", task_name], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            has_task = True
        has_startup = bool(startup_cmd and startup_cmd.is_file())
        if has_task or has_startup:
            method = "مجدول المهام (Task Scheduler)" if has_task else "مجلد بدء التشغيل (Windows Startup)"
            _message(f"التشغيل التلقائي مفعل على Windows عبر {method}.", "PASS")
            return 0
        _message("التشغيل التلقائي غير مفعل على Windows.", "INFO")
        return 1
    if action == "disable":
        deleted_any = False
        res = subprocess.run([schtasks, "/Delete", "/TN", task_name, "/F"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            deleted_any = True
        if startup_cmd and startup_cmd.is_file():
            startup_cmd.unlink(missing_ok=True)
            deleted_any = True
        if deleted_any:
            _message("تم إلغاء التشغيل التلقائي على Windows بنجاح.", "OK")
        else:
            _message("التشغيل التلقائي لم يكن مفعلًا أو تم حذفه مسبقاً.", "INFO")
        return 0
    if action == "enable":
        python_exe, _, _ = _runtime_commands()
        launcher_path = str((ROOT / "platform_launcher.py").resolve())
        tr_command = f'"{python_exe}" "{launcher_path}" start --skip-build --no-browser'
        res = subprocess.run([
            schtasks, "/Create", "/TN", task_name, "/TR", tr_command,
            "/SC", "ONSTART", "/RL", "HIGHEST", "/F",
        ], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            _message(f"تم تفعيل التشغيل التلقائي بنجاح عند إقلاع Windows (مجدول المهام: {task_name}).", "OK")
            return 0
        res_logon = subprocess.run([
            schtasks, "/Create", "/TN", task_name, "/TR", tr_command,
            "/SC", "ONLOGON", "/F",
        ], capture_output=True, text=True, check=False)
        if res_logon.returncode == 0:
            _message(f"تم تفعيل التشغيل التلقائي بنجاح عند تسجيل الدخول (مجدول المهام: {task_name}).", "OK")
            return 0
        if startup_dir:
            startup_dir.mkdir(parents=True, exist_ok=True)
            cmd_content = f'@echo off\r\ncd /d "{ROOT}"\r\nstart "" "{python_exe}" "{launcher_path}" start --skip-build --no-browser\r\n'
            startup_cmd.write_text(cmd_content, encoding="utf-8")
            _message(f"تم تفعيل التشغيل التلقائي بنجاح عبر مجلد بدء التشغيل: {startup_cmd}", "OK")
            return 0
        raise LaunchError(f"فشل تفعيل التشغيل التلقائي على Windows: {res.stderr.strip()}")
    return 0


def _manage_autostart_linux(action: str) -> int:
    service_name = "security-platform.service"
    systemctl = shutil.which("systemctl")
    if not systemctl:
        raise LaunchError("أمر systemctl غير متوفر على هذا النظام لإدارة الخدمات التلقائية.")
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    user_flag = [] if is_root else ["--user"]
    service_dir = Path("/etc/systemd/system") if is_root else (Path.home() / ".config" / "systemd" / "user")
    service_path = service_dir / service_name

    if action == "status":
        res = subprocess.run([systemctl, *user_flag, "is-enabled", service_name], capture_output=True, text=True, check=False)
        enabled = res.stdout.strip() == "enabled"
        res_active = subprocess.run([systemctl, *user_flag, "is-active", service_name], capture_output=True, text=True, check=False)
        active = res_active.stdout.strip() == "active"
        if enabled or active:
            _message(f"خدمة التشغيل التلقائي مفعلة على Linux ({service_name}) [enabled: {enabled}, active: {active}].", "PASS")
            return 0
        _message(f"خدمة التشغيل التلقائي غير مفعلة على Linux ({service_name}).", "INFO")
        return 1
    if action == "disable":
        subprocess.run([systemctl, *user_flag, "stop", service_name], capture_output=True, text=True, check=False)
        subprocess.run([systemctl, *user_flag, "disable", service_name], capture_output=True, text=True, check=False)
        service_path.unlink(missing_ok=True)
        subprocess.run([systemctl, *user_flag, "daemon-reload"], capture_output=True, text=True, check=False)
        _message(f"تم إلغاء التشغيل التلقائي وحذف خدمة {service_name} على Linux.", "OK")
        return 0
    if action == "enable":
        python_exe, _, _ = _runtime_commands()
        launcher_path = str((ROOT / "platform_launcher.py").resolve())
        service_dir.mkdir(parents=True, exist_ok=True)
        user_line = f"User={os.environ.get('SUDO_USER') or os.environ.get('USER') or 'root'}\n" if is_root else ""
        service_content = f"""[Unit]
Description=Unified Security Platform Auto-Start
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
{user_line}WorkingDirectory={ROOT}
ExecStart={python_exe} {launcher_path} start --skip-build --no-browser
ExecStop={python_exe} {launcher_path} stop
TimeoutStartSec=180
TimeoutStopSec=30
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target default.target
"""
        service_path.write_text(service_content, encoding="utf-8")
        subprocess.run([systemctl, *user_flag, "daemon-reload"], check=True)
        subprocess.run([systemctl, *user_flag, "enable", service_name], check=True)
        if not is_root:
            loginctl = shutil.which("loginctl")
            if loginctl:
                subprocess.run([loginctl, "enable-linger", os.environ.get("USER", "")], capture_output=True, check=False)
        _message(f"تم تفعيل خدمة التشغيل التلقائي بنجاح على Linux ({service_path}).", "OK")
        return 0
    return 0


def autostart(action: str = "status") -> int:
    if IS_WINDOWS:
        return _manage_autostart_windows(action)
    return _manage_autostart_linux(action)


def _sync_service_xml(xml_path: Path, python_exe: str, launcher_path: str) -> None:
    """Ensure service XML has valid paths matching current installation."""
    xml_content = f"""<service>
  <id>PlatformScopeService</id>
  <name>Platform Scope Analysis Service</name>
  <description>Platform Scope - Unified Security Analysis Platform Background Service</description>
  <executable>{python_exe}</executable>
  <arguments>"{launcher_path}" start --skip-build --no-browser --wait</arguments>
  <workingdirectory>{ROOT}</workingdirectory>
  <logpath>{LOG_DIR}</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>5</keepFiles>
  </log>
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="20 sec"/>
  <resetfailure>1 hour</resetfailure>
  <stopexecutable>{python_exe}</stopexecutable>
  <stoparguments>"{launcher_path}" stop</stoparguments>
  <stoptimeout>30 sec</stoptimeout>
  <startmode>Automatic</startmode>
  <delayedAutoStart>true</delayedAutoStart>
</service>
"""
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    xml_path.write_text(xml_content, encoding="utf-8")


def _manage_service_windows(action: str) -> int:
    service_wrapper = ROOT / "service" / "PlatformScopeService.exe"
    service_xml = ROOT / "service" / "PlatformScopeService.xml"

    if not service_wrapper.is_file():
        # Fallback to Task Scheduler autostart if wrapper is not present
        return _manage_autostart_windows(action)

    python_exe, _, _ = _runtime_commands()
    launcher_path = str((ROOT / "platform_launcher.py").resolve())

    if action == "status":
        res = subprocess.run([str(service_wrapper), "status"], capture_output=True, text=True, check=False)
        status_text = res.stdout.strip() or res.stderr.strip()
        if "Started" in status_text or "Running" in status_text:
            _message(f"خدمة Windows (PlatformScopeService) قيد التشغيل [Status: {status_text}].", "PASS")
            return 0
        elif "Stopped" in status_text:
            _message(f"خدمة Windows (PlatformScopeService) متوقفة [Status: {status_text}].", "INFO")
            return 0
        elif "NonExistent" in status_text:
            _message("خدمة Windows (PlatformScopeService) غير مثبتة.", "INFO")
            return 1
        _message(f"حالة خدمة Windows: {status_text}", "INFO")
        return 0

    if action == "install":
        _sync_service_xml(service_xml, python_exe, launcher_path)
        res = subprocess.run([str(service_wrapper), "install"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            _message("تم تثبيت خدمة Platform Scope بنجاح كخدمة Windows (PlatformScopeService).", "OK")
            return 0
        if "already exists" in (res.stderr + res.stdout).lower():
            _message("خدمة Platform Scope مثبتة مسبقاً في Windows.", "INFO")
            return 0
        _message(f"فشل تثبيت خدمة Windows: {(res.stderr or res.stdout).strip()}", "ERROR")
        return res.returncode

    if action == "uninstall":
        subprocess.run([str(service_wrapper), "stop"], capture_output=True, check=False)
        stop_services(quiet=True)
        res = subprocess.run([str(service_wrapper), "uninstall"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            _message("تم إلغاء تثبيت وحذف خدمة Platform Scope من Windows.", "OK")
            return 0
        _message(f"إلغاء تثبيت الخدمة: {(res.stderr or res.stdout).strip()}", "INFO")
        return 0

    if action == "start":
        res = subprocess.run([str(service_wrapper), "start"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            _message("تم إرسال أمر بدء التشغيل إلى خدمة Platform Scope.", "OK")
            return 0
        _message(f"فشل بدء تشغيل خدمة Windows: {(res.stderr or res.stdout).strip()}", "ERROR")
        return res.returncode

    if action == "stop":
        res = subprocess.run([str(service_wrapper), "stop"], capture_output=True, text=True, check=False)
        stop_services(quiet=True)
        _message("تم إيقاف خدمة Platform Scope بنجاح.", "OK")
        return 0

    if action == "restart":
        res = subprocess.run([str(service_wrapper), "restart"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            _message("تمت إعادة تشغيل خدمة Platform Scope بنجاح.", "OK")
            return 0
        _message(f"فشلت إعادة تشغيل الخدمة: {(res.stderr or res.stdout).strip()}", "ERROR")
        return res.returncode

    return 0


def manage_service(action: str = "status") -> int:
    if IS_WINDOWS:
        return _manage_service_windows(action)
    return _manage_autostart_linux(action)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unified Security Platform cross-platform launcher")
    subparsers = parser.add_subparsers(dest="command")
    start_parser = subparsers.add_parser("start", help="build and start all services")
    start_parser.add_argument("--skip-build", "-SkipBuild", action="store_true")
    start_parser.add_argument("--no-browser", "-NoBrowser", action="store_true")
    start_parser.add_argument("--configure-firewall", "-ConfigureFirewall", action="store_true")
    start_parser.add_argument("--wait", "-w", action="store_true", help="keep launcher running in foreground")
    restart_parser = subparsers.add_parser("restart", help="restart services if running, or start if stopped")
    restart_parser.add_argument("--skip-build", "-SkipBuild", action="store_true")
    restart_parser.add_argument("--no-browser", "-NoBrowser", action="store_true")
    restart_parser.add_argument("--configure-firewall", "-ConfigureFirewall", action="store_true")
    restart_parser.add_argument("--wait", "-w", action="store_true", help="keep launcher running in foreground")
    subparsers.add_parser("stop", help="stop tracked services")
    doctor_parser = subparsers.add_parser("doctor", help="verify this machine and optionally the running chain")
    doctor_parser.add_argument("--running", action="store_true")
    autostart_parser = subparsers.add_parser("autostart", help="manage automatic startup on host boot")
    autostart_group = autostart_parser.add_mutually_exclusive_group()
    autostart_group.add_argument("--enable", action="store_true", help="enable automatic startup on host boot")
    autostart_group.add_argument("--disable", action="store_true", help="disable automatic startup on host boot")
    autostart_group.add_argument("--status", action="store_true", help="check automatic startup status")
    service_parser = subparsers.add_parser("service", help="manage platform background Windows service")
    service_parser.add_argument("action", choices=["install", "uninstall", "start", "stop", "restart", "status"], help="service action")
    arguments = sys.argv[1:] if argv is None else list(argv)
    args = parser.parse_args(arguments or ["start"])
    try:
        if args.command == "service":
            return manage_service(args.action)
        if args.command == "stop":
            stop_services()
            return 0
        if args.command == "doctor":
            return doctor(args.running)
        if args.command == "autostart":
            action = "enable" if args.enable else ("disable" if args.disable else "status")
            return autostart(action)
        if args.command == "restart":
            if getattr(args, "wait", False):
                return restart_services(args.skip_build, args.no_browser, args.configure_firewall, wait_forever=True)
            return restart_services(args.skip_build, args.no_browser, args.configure_firewall)
        if getattr(args, "wait", False):
            return start_services(args.skip_build, args.no_browser, args.configure_firewall, wait_forever=True)
        return start_services(args.skip_build, args.no_browser, args.configure_firewall)
    except (LaunchError, OSError, subprocess.SubprocessError) as error:
        _message(str(error), "ERROR")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
