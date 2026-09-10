import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import platform_launcher


class PlatformLauncherTests(unittest.TestCase):
    def test_dotenv_preserves_existing_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            dotenv = Path(directory) / ".env"
            dotenv.write_text("EXISTING=new\nQUOTED='hello world'\n# ignored\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"EXISTING": "old"}, clear=True):
                platform_launcher._load_dotenv(dotenv)
                self.assertEqual(os.environ["EXISTING"], "old")
                self.assertEqual(os.environ["QUOTED"], "hello world")

    def test_state_reader_accepts_new_and_legacy_formats(self):
        self.assertEqual(
            platform_launcher._state_processes({"processes": {"Frontend": {"pid": 12}}}),
            {"Frontend": 12},
        )
        self.assertEqual(platform_launcher._state_processes({"Gateway": 34}), {"Gateway": 34})

    def test_embedded_python_directory_falls_back_to_bundled_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "python" / "python.exe"
            executable.parent.mkdir()
            executable.write_text("binary", encoding="ascii")
            with mock.patch.object(platform_launcher.sys, "executable", str(root / "python-core")), \
                 mock.patch.object(platform_launcher, "IS_WINDOWS", True), \
                 mock.patch.object(platform_launcher, "OFFLINE_PLATFORM", root):
                self.assertEqual(platform_launcher._python_executable(), str(executable.resolve()))

    def test_environment_uses_env_then_saved_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = root / "storage" / "platform_config.json"
            settings.parent.mkdir(parents=True)
            settings.write_text(json.dumps({
                "network": {
                    "frontend_port": 3001, "gateway_port": 8083, "analysis_port": 8084,
                    "bind_address": "0.0.0.0", "trusted_origins": ["http://trusted.local"],
                    "proxy_timeout_seconds": 444,
                },
                "security": {"session_hours": 8, "secure_cookie": False},
            }), encoding="utf-8")
            environment = {"SECURITY_FRONTEND_PORT": "3100"}
            with mock.patch.object(platform_launcher, "ROOT", root), \
                 mock.patch.object(platform_launcher, "SETTINGS_FILE", settings), \
                 mock.patch.object(platform_launcher, "_network_addresses", return_value=["10.0.0.5"]), \
                 mock.patch.dict(os.environ, environment, clear=True):
                config = platform_launcher._configure_environment()
                self.assertEqual(config["frontend_port"], 3100)
                self.assertEqual(config["gateway_port"], 8083)
                self.assertIn("http://10.0.0.5:3100", os.environ["SECURITY_ALLOWED_ORIGINS"])
                self.assertIn("http://trusted.local", os.environ["SECURITY_ALLOWED_ORIGINS"])
                self.assertEqual(os.environ["SECURITY_PROXY_TIMEOUT_SECONDS"], "444")

    def test_linux_libreoffice_override_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "libreoffice"
            executable.write_text("binary", encoding="ascii")
            with mock.patch.dict(os.environ, {"LIBREOFFICE_PATH": str(executable)}, clear=False):
                self.assertEqual(platform_launcher._libreoffice_path(), str(executable.resolve()))

    def test_linux_does_not_select_bundled_windows_libreoffice(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundled = root / ".tools" / "libreoffice" / "LibreOffice" / "program" / "soffice.com"
            bundled.parent.mkdir(parents=True)
            bundled.write_text("windows binary", encoding="ascii")
            with mock.patch.object(platform_launcher, "ROOT", root), \
                 mock.patch.object(platform_launcher, "IS_WINDOWS", False), \
                 mock.patch.object(platform_launcher.shutil, "which", return_value=None), \
                 mock.patch.dict(os.environ, {}, clear=True):
                self.assertIsNone(platform_launcher._libreoffice_path())

    def test_dependency_marker_includes_lockfile_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory)
            required = package / "node_modules" / "tool"
            required.parent.mkdir(parents=True)
            required.write_text("ok", encoding="ascii")
            (package / "package-lock.json").write_text('{"lockfileVersion": 3}', encoding="utf-8")
            completed = SimpleNamespace(returncode=0)
            with mock.patch.object(platform_launcher.subprocess, "run", return_value=completed) as run:
                platform_launcher._ensure_node_dependencies(package, required, "npm", {"system": "linux"})
            run.assert_called_once()
            marker = json.loads((package / "node_modules" / ".security-platform-runtime.json").read_text(encoding="utf-8"))
            self.assertEqual(marker["system"], "linux")
            self.assertEqual(len(marker["lock_sha256"]), 64)

    def test_dependency_install_uses_bundled_cache_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "frontend"
            cache = root / "cache"
            package.mkdir()
            (package / "package-lock.json").write_text('{"lockfileVersion": 3}', encoding="utf-8")
            (cache / "_cacache").mkdir(parents=True)
            completed = SimpleNamespace(returncode=0)
            with mock.patch.object(platform_launcher, "OFFLINE_NPM_CACHE", cache), \
                 mock.patch.object(platform_launcher.subprocess, "run", return_value=completed) as run, \
                 mock.patch.dict(os.environ, {"SECURITY_OFFLINE_MODE": "true"}, clear=False):
                platform_launcher._ensure_node_dependencies(
                    package, package / "node_modules" / "next", "npm", {"system": "windows"},
                )
            command = run.call_args.args[0]
            self.assertIn("--offline", command)
            self.assertIn(str(cache.resolve()), command)

    def test_strict_offline_mode_never_falls_back_to_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "gateway"
            package.mkdir()
            with mock.patch.object(platform_launcher, "OFFLINE_NPM_CACHE", root / "missing-cache"), \
                 mock.patch.object(platform_launcher.subprocess, "run") as run, \
                 mock.patch.dict(os.environ, {"SECURITY_OFFLINE_MODE": "true"}, clear=False):
                with self.assertRaises(platform_launcher.LaunchError):
                    platform_launcher._ensure_node_dependencies(
                        package, package / "node_modules" / "typescript", "npm", {"system": "linux"},
                    )
            run.assert_not_called()

    def test_windows_stop_uses_taskkill_without_unreliable_signal_probe(self):
        completed = SimpleNamespace(returncode=0)
        with mock.patch.object(platform_launcher, "IS_WINDOWS", True), \
             mock.patch.object(platform_launcher.subprocess, "run", return_value=completed) as run, \
             mock.patch.object(platform_launcher, "_pid_alive", return_value=False) as alive:
            platform_launcher._terminate_process(1234, quiet=True)
        run.assert_called_once_with(["taskkill", "/PID", "1234", "/T", "/F"], capture_output=True, check=False)
        alive.assert_not_called()

    def test_main_supports_legacy_powershell_switches(self):
        with mock.patch.object(platform_launcher, "start_services", return_value=0) as start:
            result = platform_launcher.main(["start", "-SkipBuild", "-NoBrowser", "-ConfigureFirewall"])
        self.assertEqual(result, 0)
        start.assert_called_once_with(True, True, True)


    def test_windows_autostart_uses_startup_fallback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.object(platform_launcher, "IS_WINDOWS", True), \
                 mock.patch.object(platform_launcher, "_runtime_commands", return_value=("python", "node", "npm")), \
                 mock.patch.dict(os.environ, {"APPDATA": tmpdir}, clear=False), \
                 mock.patch.object(platform_launcher.subprocess, "run", return_value=SimpleNamespace(returncode=1, stderr="Access denied")):
                code = platform_launcher.autostart("enable")
            self.assertEqual(code, 0)
            expected = Path(tmpdir) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "SecurityPlatformAutoStart.cmd"
            self.assertTrue(expected.is_file())

    def test_linux_autostart_writes_systemd_unit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            service_dir = Path(tmpdir) / ".config" / "systemd" / "user"
            with mock.patch.object(platform_launcher, "IS_WINDOWS", False), \
                 mock.patch.object(platform_launcher, "_runtime_commands", return_value=("python3", "node", "npm")), \
                 mock.patch.object(platform_launcher.shutil, "which", return_value="/bin/systemctl"), \
                 mock.patch.object(Path, "home", return_value=Path(tmpdir)), \
                 mock.patch.object(platform_launcher.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")):
                code = platform_launcher.autostart("enable")
            self.assertEqual(code, 0)
            service_file = service_dir / "security-platform.service"
            self.assertTrue(service_file.is_file())
            content = service_file.read_text(encoding="utf-8")
            self.assertIn("ExecStart=", content)
            self.assertIn("ExecStop=", content)

    def test_restart_when_running_stops_and_starts(self):
        with mock.patch.object(platform_launcher, "is_platform_running", return_value=True), \
             mock.patch.object(platform_launcher, "stop_services") as mock_stop, \
             mock.patch.object(platform_launcher.time, "sleep"), \
             mock.patch.object(platform_launcher, "start_services", return_value=0) as mock_start:
            res = platform_launcher.restart_services(skip_build=True, no_browser=True, configure_firewall=False)
            self.assertEqual(res, 0)
            mock_stop.assert_called_once_with(quiet=False)
            mock_start.assert_called_once_with(True, True, False)

    def test_restart_when_stopped_starts_directly(self):
        with mock.patch.object(platform_launcher, "is_platform_running", return_value=False), \
             mock.patch.object(platform_launcher, "stop_services") as mock_stop, \
             mock.patch.object(platform_launcher, "start_services", return_value=0) as mock_start:
            res = platform_launcher.restart_services(skip_build=True, no_browser=False, configure_firewall=True)
            self.assertEqual(res, 0)
            mock_stop.assert_not_called()
            mock_start.assert_called_once_with(True, False, True)

    def test_main_restart_command_dispatch(self):
        with mock.patch.object(platform_launcher, "restart_services", return_value=0) as mock_restart:
            res = platform_launcher.main(["restart", "-SkipBuild", "-NoBrowser"])
            self.assertEqual(res, 0)
            mock_restart.assert_called_once_with(True, True, False)


if __name__ == "__main__":
    unittest.main()
