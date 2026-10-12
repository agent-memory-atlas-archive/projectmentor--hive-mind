"""`hv wire`: a credential reaches a cell's shell only through the environment, never the command text, and
credential names are validated. Also `module config` takes a secret value from stdin, not argv."""

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
HV = PROJECT / "hv"
sys.path.insert(0, str(PROJECT))
import _planes  # noqa: E402


def run(home, *args, env_extra=None, check=True):
    env = dict(os.environ, HIVE_HOME=str(home), **(env_extra or {}))
    r = subprocess.run([sys.executable, str(HV), *args], env=env, capture_output=True, text=True)
    if check:
        assert r.returncode == 0, r.stderr
    return r


def _loadhv(home, mp):
    mp.setenv("HIVE_HOME", str(home))
    loader = importlib.machinery.SourceFileLoader("hvmod_wiresec", str(HV))
    spec = importlib.util.spec_from_loader("hvmod_wiresec", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    _planes.install_control_plane(m)
    return m


def _cell(tmp_path, name, requires, steps, verify, home):
    f = tmp_path / f"{name}.json"
    f.write_text(json.dumps({"name": name, "kind": "tool", "version": 1, "requires": requires,
                             "spec": {"platforms": {p: {"steps": steps} for p in ("linux", "wsl", "darwin")}},
                             "verify": verify}))
    return run(home, "wire", "--add", str(f), check=False)


def _envf(tmp_path, **kv):
    f = tmp_path / "dot.env"
    f.write_text("".join(f"{k}={v}\n" for k, v in kv.items()))
    return str(f)


LINUX_ONLY = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc and relies on Linux E2BIG limits")


@LINUX_ONLY
def test_secret_is_in_environ_not_in_the_command_line(tmp_path):
    home, out = tmp_path / "h", tmp_path / "out"
    out.mkdir()
    secret = "s3cr3t-value-ABC"
    r = _cell(tmp_path, "t1", ["MYTOK"],
              [f"cat /proc/self/environ | tr '\\0' '\\n' > {out}/environ"],
              {"cmd": f"cat /proc/$$/cmdline | tr '\\0' ' ' > {out}/cmdline; test -f {out}/environ && echo OK # \"{{MYTOK}}\"",
               "expect": "OK"}, home)
    assert r.returncode == 0, r.stderr
    run(home, "wire", "t1", "--env-file", _envf(tmp_path, MYTOK=secret))
    assert f"MYTOK={secret}" in (out / "environ").read_text()
    cmdline = (out / "cmdline").read_text()
    assert secret not in cmdline and "${MYTOK}" in cmdline


def test_secret_with_shell_syntax_is_inert(tmp_path):
    home, marker = tmp_path / "h", tmp_path / "marker"
    _cell(tmp_path, "t2", ["MYTOK"], [], {"cmd": 'echo "{MYTOK}" >/dev/null', "expect": None}, home)
    r = run(home, "wire", "t2", "--env-file", _envf(tmp_path, MYTOK=f"x$(touch {marker})"))
    assert not marker.exists(), r.stdout


def test_spaces_and_glob_arrive_as_one_argument(tmp_path):
    home, out = tmp_path / "h", tmp_path / "argc"
    _cell(tmp_path, "t3", ["MYTOK"], [],
          {"cmd": f'set -- "Bearer {{MYTOK}}"; echo $# > {out}; test $# = 1 && echo OK', "expect": "OK"}, home)
    r = run(home, "wire", "t3", "--env-file", _envf(tmp_path, MYTOK="a b * c"))
    assert "already provisioned" in r.stdout and out.read_text().strip() == "1"


@pytest.mark.parametrize("name", ["BASH_ENV", "PATH", "BASH_FUNC_curl%%", "LD_PRELOAD", "HTTPS_PROXY",
                                  "HIVE_HOME", "lower", "GIT_SSH_COMMAND", "1ABC"])
def test_bad_credential_names_refused_at_add_and_at_wire(tmp_path, monkeypatch, name):
    home = tmp_path / "h"
    r = _cell(tmp_path, "bad", [name], [], {}, home)
    assert "not allowed" in r.stdout and "bad" not in run(home, "wire", "--list").stdout.split("claude")[-1]
    hv = _loadhv(home, monkeypatch)                    # a journaled cell that predates the rule
    cell = {"name": "old", "kind": "tool", "requires": [name], "verify": {}}
    assert hv._wire_tool(cell, _envf(tmp_path, **{name: "v"})) == 1


def test_capsule_put_refuses_a_bad_name(tmp_path):
    home = tmp_path / "h"
    r = run(home, "capsule", "put", "BASH_ENV", "--stdin", check=False)
    assert r.returncode != 0 or "not allowed" in r.stdout
    assert "not allowed" in r.stdout


def test_passphrase_is_not_passed_to_steps(tmp_path):
    home, out = tmp_path / "h", tmp_path / "pp"
    _cell(tmp_path, "t5", ["MYTOK"], [f"echo \"[$HIVE_OWNER_KEY_PASSPHRASE]\" > {out}"],
          {"cmd": f"test -f {out} && echo OK", "expect": "OK"}, home)
    run(home, "wire", "t5", "--env-file", _envf(tmp_path, MYTOK="v"),
        env_extra={"HIVE_OWNER_KEY_PASSPHRASE": "hunter2-pass"})
    assert out.read_text().strip() == "[]"


def test_failing_step_output_is_redacted_and_odd_values_do_not_crash(tmp_path):
    home = tmp_path / "h"
    _cell(tmp_path, "t6", ["MYTOK"], ['echo "leak $MYTOK" >&2; exit 3'], {"cmd": "false"}, home)
    r = run(home, "wire", "t6", "--env-file", _envf(tmp_path, MYTOK="topsecretvalue"))
    assert "step failed" in r.stdout and "topsecretvalue" not in r.stdout + r.stderr and "***" in r.stdout


@LINUX_ONLY
def test_oversize_credential_is_reported_not_a_traceback(tmp_path):
    home = tmp_path / "h"
    _cell(tmp_path, "t7", ["MYTOK"], ["true"], {"cmd": "false"}, home)
    r = run(home, "wire", "t7", "--env-file", _envf(tmp_path, MYTOK="v" * 200000))
    assert "Traceback" not in r.stderr and "could not run" in r.stdout


def test_nul_in_a_credential_is_reported_not_a_traceback(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path / "h", monkeypatch)
    cell = {"name": "n", "kind": "tool", "requires": ["MYTOK"], "verify": {},
            "spec": {"platforms": {p: {"steps": ["true"]} for p in ("linux", "wsl", "darwin")}}}
    assert hv._wire_tool(cell, _envf(tmp_path, MYTOK="a\0b")) in (0, 1)
    assert hv._run_verify({"verify": {"cmd": "true"}}, {"MYTOK": "a\0b"}) is False


def test_env_name_ok():
    sys.path.insert(0, str(PROJECT))
    loader = importlib.machinery.SourceFileLoader("hvmod_names", str(HV))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader("hvmod_names", loader))
    loader.exec_module(m)
    for ok in ("GITHUB_TOKEN", "EXAMPLE_API_TOKEN", "A", "CLOUDFLARE_API_TOKEN"):
        assert m._env_name_ok(ok), ok
    for bad in ("PATH", "BASH_ENV", "BASH_FUNC_x%%", "LD_PRELOAD", "NODE_OPTIONS", "http_proxy", "ALL_PROXY",
                "PYTHONPATH", "SSH_AUTH_SOCK", "X" * 65, "", None, 7):
        assert not m._env_name_ok(bad), bad
