"""#344 the boot pass: `hv doctor --boot` waits (bounded) for the sync daemon, checks, fixes, rechecks and records
one `boot` fact per boot; the boot unit and the WSL logon task are written by the installer's unit library."""

import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
UNITS = PROJECT / "scripts" / "platform" / "linux" / "_units.sh"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _boot(home, port, wait, *extra):
    (home / ".peers.json").write_text(json.dumps({"port": port, "peers": []}))
    env = dict(os.environ, HIVE_HOME=str(home), HIVE_IDENTITY_STASH=str(home / "stash"),
               HIVE_BOOT_SYNC_WAIT=str(wait), PATH=os.environ["PATH"])
    return subprocess.run([sys.executable, str(PROJECT / "hv"), "doctor", "--boot", *extra], env=env,
                          capture_output=True, text=True, timeout=120)


def _facts(home):
    env = dict(os.environ, HIVE_HOME=str(home), HIVE_IDENTITY_STASH=str(home / "stash"))
    r = subprocess.run([sys.executable, str(PROJECT / "hv"), "search", "booted", "--format", "json"], env=env,
                       capture_output=True, text=True)
    return r.stdout


class _Ok(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def test_boot_with_sync_down_reports_it_after_the_bound_and_records_one_fact(tmp_path):
    t0 = time.monotonic()
    r = _boot(tmp_path, _free_port(), 2)
    assert 2 <= time.monotonic() - t0 < 60
    assert "--boot: node " in r.stdout and "sync DOWN" in r.stdout        # mutant: no wait/report
    assert "needs operator: " in r.stdout and "sync-daemon" in r.stdout.split("needs operator:")[1]
    assert "booted" in _facts(tmp_path)


def test_boot_waits_for_a_daemon_that_comes_up_late(tmp_path):
    port = _free_port()
    srv = HTTPServer(("127.0.0.1", port), _Ok)
    threading.Timer(2.0, lambda: threading.Thread(target=srv.serve_forever, daemon=True).start()).start()
    try:
        t0 = time.monotonic()
        r = _boot(tmp_path, port, 30)
        assert time.monotonic() - t0 < 25                                  # not the whole bound
        assert "sync ok (answered after" in r.stdout and "sync DOWN" not in r.stdout   # mutant: no wait
    finally:
        srv.shutdown()


def test_boot_reports_once_per_boot(tmp_path):
    if not Path("/proc/sys/kernel/random/boot_id").exists():
        pytest.skip("no boot id on this platform")
    _boot(tmp_path, _free_port(), 0)
    r = _boot(tmp_path, _free_port(), 0)
    assert "already reported for this boot" in r.stdout
    assert _facts(tmp_path).count('"content"') == 1


def test_boot_dry_run_records_nothing(tmp_path):
    r = _boot(tmp_path, _free_port(), 0, "--dry-run")
    assert "not recorded" in r.stdout and "booted" not in _facts(tmp_path)


def test_boot_mode_reaches_the_module_doctor_environment(tmp_path):
    import hive_module_doctor
    old = os.environ.get("HIVE_DOCTOR_MODE")
    os.environ["HIVE_DOCTOR_MODE"] = "boot"
    try:
        assert hive_module_doctor.doctor_mode() == "boot"
    finally:
        os.environ.pop("HIVE_DOCTOR_MODE") if old is None else os.environ.update(HIVE_DOCTOR_MODE=old)


def _bash(script, env=None):
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=dict(os.environ, **(env or {})))


def _fake_schtasks(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "schtasks.exe").write_text(f'#!/bin/sh\necho "$@" >> "{tmp_path}/calls"\n')
    (bindir / "schtasks.exe").chmod(0o755)
    (tmp_path / "ver").write_text("Linux version 5.15 microsoft-standard-WSL2\n")
    return {"PATH": f"{bindir}:{os.environ['PATH']}", "HIVE_PROC_VERSION": str(tmp_path / "ver")}


def test_wsl_logon_task_is_created_for_a_plain_distro_name(tmp_path):
    env = _fake_schtasks(tmp_path) | {"WSL_DISTRO_NAME": "Ubuntu-24.04"}
    assert _bash(f'. "{UNITS}"; write_wsl_logon_task', env).returncode == 0
    call = (tmp_path / "calls").read_text()
    assert "/SC ONLOGON" in call and "HiveMind-WSL-Ubuntu-24.04" in call and "--exec /usr/bin/sleep infinity" in call


@pytest.mark.parametrize("distro", ['U" & calc & "', "a b", "x;y", ""])
def test_wsl_logon_task_refuses_a_name_that_needs_quoting(tmp_path, distro):
    env = _fake_schtasks(tmp_path) | {"WSL_DISTRO_NAME": distro}
    assert _bash(f'. "{UNITS}"; write_wsl_logon_task', env).returncode == 0
    assert not (tmp_path / "calls").exists()


def test_wsl_logon_task_is_a_noop_off_wsl(tmp_path):
    env = _fake_schtasks(tmp_path) | {"WSL_DISTRO_NAME": "Ubuntu"}
    (tmp_path / "ver").write_text("Linux version 6.1 generic\n")
    _bash(f'. "{UNITS}"; write_wsl_logon_task', env)
    assert not (tmp_path / "calls").exists()


def test_boot_unit_runs_the_doctor_after_sync_without_requiring_it(tmp_path):
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "systemctl").write_text("#!/bin/sh\nexit 0\n")
    (fake / "systemctl").chmod(0o755)
    hive, unitdir = tmp_path / "hive", tmp_path / "home" / ".config" / "systemd" / "user"
    hive.mkdir()
    (hive / "hive_sync_daemon.py").write_text("")
    r = _bash(f'. "{UNITS}"; write_systemd_units "{hive}"',
              {"PATH": f"{fake}:{os.environ['PATH']}", "HOME": str(tmp_path / "home")})
    assert r.returncode == 0, r.stderr
    text = (unitdir / "hive-doctor-boot.service").read_text()
    assert "ExecStart=/usr/bin/python3 " + str(hive) + "/hv doctor --boot" in text
    assert "After=network.target hive-sync.service" in text and "Wants=hive-sync.service" in text
    assert "Requires=" not in text and "WantedBy=default.target" in text


def _uninstall(tmp_path, extra_env):
    home = tmp_path / "home"
    unit_dir = home / ".config/systemd/user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "hive-doctor-boot.service").write_text("[Unit]\n")
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "systemctl").write_text(f'#!/bin/sh\necho "$*" >> "{tmp_path}/sysctl"\n')
    (shim / "systemctl").chmod(0o755)
    hive = tmp_path / "hivedir"
    hive.mkdir()
    env = dict(os.environ, HOME=str(home), HIVE_DIR=str(hive), BIN_DIR=str(tmp_path / "ubin"),
               SETTINGS=str(tmp_path / "s.json"), HIVE_UNINSTALL_TEST="1", **extra_env)
    env["PATH"] = f"{shim}:{extra_env.get('PATH', os.environ['PATH'])}"
    r = subprocess.run(["bash", str(UNITS.parent.parent.parent / "installer/_uninstall.sh"), "--yes"], env=env,
                       capture_output=True, text=True, input="")
    assert r.returncode == 0, r.stderr
    return unit_dir


def test_uninstall_removes_the_boot_unit(tmp_path):
    unit_dir = _uninstall(tmp_path, {})
    assert not (unit_dir / "hive-doctor-boot.service").exists()
    assert "disable --now hive-doctor-boot.service" in (tmp_path / "sysctl").read_text()


def test_uninstall_deletes_the_wsl_logon_task(tmp_path):
    env = _fake_schtasks(tmp_path) | {"WSL_DISTRO_NAME": "Ubuntu-24.04"}
    _uninstall(tmp_path, env)
    assert "/Delete /F /TN HiveMind-WSL-Ubuntu-24.04" in (tmp_path / "calls").read_text()


@pytest.mark.parametrize("distro", ['U" & calc & "', "a b", ""])
def test_uninstall_leaves_the_logon_task_alone_for_an_odd_name(tmp_path, distro):
    _uninstall(tmp_path, _fake_schtasks(tmp_path) | {"WSL_DISTRO_NAME": distro})
    assert not (tmp_path / "calls").exists()
