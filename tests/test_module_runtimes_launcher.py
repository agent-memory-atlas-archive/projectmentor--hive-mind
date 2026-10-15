"""3.1 runtimes, unit PATH, the CLI launcher, `module run` and `module status` (#294 PR 3, design
`module_contract_3_1.md` §3, §8, §13). The PATH rules (an unsafe directory is skipped, a slash is refused, a missing
runtime warns), the launcher's collision rules and its hostile-argv quoting, removal on `remove`, `module run` and
`module status`, and a manifest without `contract` getting none of it."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
import hive_modules  # noqa: E402
from hive_modules import ModuleError  # noqa: E402
from test_module_lifecycle import LINUX_ONLY, _add, _publish, _state, hive, units  # noqa: E402,F401
from test_succession import _run  # noqa: E402

V31 = dict(min_core="3.1", contract=1, config=None)
SERVICE = {"command": ["run.sh"], "restart": "always"}
FILES = {"run.sh": "#!/bin/sh\nexit 0\n", "hooks/stop": "#!/bin/sh\nexit 0\n",
         "cli.sh": "#!/bin/sh\nprintf '%s|' \"$HIVE_MODULE_NAME\" \"$@\"; echo\nexit 3\n",
         "status.sh": "#!/bin/sh\necho '{\"schema\":1,\"state\":\"ok\",\"version\":\"1.0.0\",\"problems\":[]}'\n"}


def tool_dir(tmp_path, name="bin", mode=0o755, **programs):
    d = tmp_path / name
    d.mkdir(exist_ok=True)
    d.chmod(mode)
    for p in programs:
        (d / p).write_text("#!/bin/sh\nexit 0\n")
        (d / p).chmod(0o755)
    return d


@pytest.fixture
def bindir(tmp_path, monkeypatch):
    d = tool_dir(tmp_path, "launchers")
    monkeypatch.setenv("HIVE_BIN_DIR", str(d))
    return d


def publish(tmp_path, files=None, **kw):
    return _publish(tmp_path / "repo", files={**FILES, **(files or {})}, **{**V31, **kw})


def unit_text(units):
    return (units[0] / "hive-module-demo.service").read_text()


# ── resolving runtimes ────────────────────────────────────────────────────────────────────────────

def test_a_runtime_is_found_on_the_invoking_path_and_an_unsafe_directory_is_skipped(tmp_path, monkeypatch):
    bad = tool_dir(tmp_path, "bad", 0o777, claude=1)
    good = tool_dir(tmp_path, "good", claude=1)
    grp = tool_dir(tmp_path, "grp", 0o775, grok=1)
    monkeypatch.setenv("PATH", f"{bad}:{grp}:{good}:relative/dir")
    found, missing = hive_modules.resolve_runtimes(["claude", "grok"])
    assert found == {"claude": str(good)} and missing == ["grok"]       # the 0777 and 0775 directories never count


def test_a_directory_must_be_absolute_owned_by_the_operator_and_free_of_a_colon(tmp_path):
    assert hive_modules.safe_dir(tool_dir(tmp_path))
    assert not hive_modules.safe_dir("relative") and not hive_modules.safe_dir(tmp_path / "missing")
    assert not hive_modules.safe_dir(tool_dir(tmp_path, "w", 0o722))
    colon = tmp_path / "a:b"
    colon.mkdir()
    assert not hive_modules.safe_dir(colon)                             # it would split a PATH


def test_the_per_module_override_is_the_last_resort(tmp_path, monkeypatch):
    elsewhere = tool_dir(tmp_path, "else", claude=1)
    monkeypatch.setenv("PATH", "/nonexistent")
    assert hive_modules.resolve_runtimes(["claude"], {"claude": str(elsewhere)})[0] == {"claude": str(elsewhere)}
    assert hive_modules.resolve_runtimes(["claude"], {"claude": "/tmp"})[1] == ["claude"]     # /tmp is world-writable


def test_the_unit_path_lists_runtimes_then_bin_then_the_system():
    assert hive_modules.unit_path(["/r/a", "/r/b"], "/b") == "/r/a:/r/b:/b:/usr/local/bin:/usr/bin:/bin"
    assert hive_modules.unit_path([], "") == "/usr/local/bin:/usr/bin:/bin"
    assert hive_modules.unit_path(["/usr/bin"], "/b") == "/usr/bin:/b:/usr/local/bin:/bin"          # no duplicates


@pytest.mark.parametrize("bad", ["/usr/bin/claude", "../claude", "a/b", "", ".", ".."])
def test_a_runtime_with_a_slash_or_dots_is_refused(bad):
    m = {"name": "demo", "version": "1", "min_core": "3.1", "contract": 1, "publisher": "A" * 43 + "=", "files": {},
         "runtimes": [bad]}
    with pytest.raises(ModuleError):
        hive_modules._validate_contract(m)


@pytest.mark.parametrize("cmd", [["-x"], ["A=b", "x"]])
def test_a_bare_first_word_that_env_would_misread_is_refused(cmd):
    with pytest.raises(ModuleError, match="not a program name"):
        hive_modules._check_argv("cli command", cmd)
    hive_modules._check_argv("cli command", ["./-x"])              # a path is fine


# ── the unit PATH ─────────────────────────────────────────────────────────────────────────────────

@LINUX_ONLY
def test_a_contract_unit_gets_the_resolved_path_and_a_missing_runtime_warns_but_installs(hive, tmp_path, units, bindir, monkeypatch):
    rt = tool_dir(tmp_path, "rt", claude=1)
    monkeypatch.setenv("PATH", f"{rt}:{os.environ['PATH']}")
    pub = publish(tmp_path, service=SERVICE, runtimes=["claude", "nosuchprog"])
    r = _add(hive, tmp_path / "repo", pub)
    assert f'Environment="PATH={rt}:{bindir}:/usr/local/bin:/usr/bin:/bin"' in unit_text(units)
    assert "nosuchprog" in r.stderr and "hive-mind module runtime demo nosuchprog" in r.stderr
    rec = _state(hive)["demo"]
    assert rec["runtime_dirs"] == [str(rt)] and rec["bin_dir"] == str(bindir)


@LINUX_ONLY
def test_a_manifest_without_contract_gets_no_path_no_launcher_and_no_new_state(hive, tmp_path, units, bindir):
    pub = _publish(tmp_path / "repo", service=SERVICE)
    _add(hive, tmp_path / "repo", pub)
    assert "PATH=" not in unit_text(units)
    assert not list(bindir.iterdir())
    assert not {"runtime_dirs", "bin_dir", "launcher"} & set(_state(hive)["demo"])


@LINUX_ONLY
def test_the_operator_override_reaches_the_unit_and_survives_reapply(hive, tmp_path, units, bindir, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    pub = publish(tmp_path, service=SERVICE, runtimes=["zzzprog"])
    _add(hive, tmp_path / "repo", pub)
    where = tool_dir(tmp_path, "zz", zzzprog=1)
    _run(hive, "module", "runtime", "demo", "zzzprog", str(where))
    assert str(where) in unit_text(units).split("PATH=")[1].split(":")[0]
    _run(hive, "module", "reapply")
    assert _state(hive)["demo"]["runtime_overrides"] == {"zzzprog": str(where)}
    assert _run(hive, "module", "runtime", "demo", "zzzprog", "/tmp", check=False).returncode == 1       # world-writable
    assert _run(hive, "module", "runtime", "demo", "other", str(where), check=False).returncode == 1      # not declared
    _run(hive, "module", "runtime", "demo", "zzzprog", "--unset")
    assert "runtime_overrides" not in _state(hive)["demo"]


@LINUX_ONLY
def test_reapply_re_resolves_a_runtime_that_moved(hive, tmp_path, units, bindir, monkeypatch):
    first = tool_dir(tmp_path, "first", claude=1)
    monkeypatch.setenv("PATH", f"{first}:/usr/bin:/bin")
    pub = publish(tmp_path, service=SERVICE, runtimes=["claude"])
    _add(hive, tmp_path / "repo", pub)
    second = tool_dir(tmp_path, "second", claude=1)
    (first / "claude").unlink()
    monkeypatch.setenv("PATH", f"{second}:/usr/bin:/bin")
    _run(hive, "module", "reapply")
    assert f"PATH={second}:" in unit_text(units) and _state(hive)["demo"]["runtime_dirs"] == [str(second)]


# ── the launcher ──────────────────────────────────────────────────────────────────────────────────

CLI = {"name": "democtl", "command": ["cli.sh", "x"]}


@LINUX_ONLY
def test_the_launcher_is_written_runs_the_cli_with_the_module_environment_and_goes_on_remove(hive, tmp_path, bindir):
    pub = publish(tmp_path, cli=CLI)
    _add(hive, tmp_path / "repo", pub)
    launcher = bindir / "democtl"
    assert launcher.stat().st_mode & 0o777 == 0o755 and _state(hive)["demo"]["launcher"] == "democtl"
    r = subprocess.run([str(launcher), "a b", "$(touch pwned)"], capture_output=True, text=True,
                       env=dict(os.environ, HIVE_OWNER_PASSPHRASE="secret"))
    assert r.stdout == "demo|x|a b|$(touch pwned)|\n" and r.returncode == 3
    assert not Path("pwned").exists()
    _run(hive, "module", "remove", "demo")
    assert not launcher.exists()


@LINUX_ONLY
def test_the_launcher_unsets_the_owners_secrets_and_quotes_a_hostile_argv(hive, tmp_path, bindir):
    hostile = {"name": "democtl", "command": ["cli.sh", "'; touch /tmp/pwned-x #", "$(id)", "`id`", "a\"b"]}
    pub = publish(tmp_path, cli=hostile, files={"cli.sh": "#!/bin/sh\nenv | grep -c HIVE_OWNER_PASSPHRASE\nprintf '%s\\n' \"$@\"\n"})
    _add(hive, tmp_path / "repo", pub)
    r = subprocess.run([str(bindir / "democtl")], capture_output=True, text=True,
                       env=dict(os.environ, HIVE_OWNER_PASSPHRASE="secret", HIVE_KEY_DIR="/k"))
    lines = r.stdout.splitlines()
    assert lines[0] == "0" and lines[1:] == hostile["command"][1:]       # the secret is gone, every word arrived intact
    assert not Path("/tmp/pwned-x").exists()
    text = (bindir / "democtl").read_text()
    assert text.startswith("#!/bin/sh\n# hive-mind module launcher v1 module=demo sha256=")


@LINUX_ONLY
def test_the_launcher_runs_the_command_from_the_module_tree_so_a_relative_script_works_anywhere(hive, tmp_path, bindir):
    # #518: hdash's `cli.command` was `python3 -I hdash`, a script name relative to the module tree; run from any other
    # directory the launcher failed with "can't open file". The launcher now enters HIVE_MODULE_DIR before the exec.
    cli = {"name": "democwd", "command": ["python3", "-I", "tool.py"]}
    pub = publish(tmp_path, cli=cli, files={"tool.py": "import os, sys\nprint(os.getcwd())\nprint('|'.join(sys.argv[1:]))\n"})
    _add(hive, tmp_path / "repo", pub)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    r = subprocess.run([str(bindir / "democwd"), "x", "y z"], capture_output=True, text=True, cwd=elsewhere)
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    assert lines[0].endswith("/modules/demo") and lines[1] == "x|y z"
    assert 'cd "$HIVE_MODULE_DIR" || exit 1' in (bindir / "democwd").read_text()


@LINUX_ONLY
def test_a_launcher_name_that_is_a_foreign_file_refuses_before_anything_is_written(hive, tmp_path, bindir):
    (bindir / "democtl").write_text("#!/bin/sh\necho mine\n")
    pub = publish(tmp_path, cli=CLI)
    r = _add(hive, tmp_path / "repo", pub, check=False)
    assert r.returncode == 1 and "not this module's launcher" in r.stderr
    assert (bindir / "democtl").read_text() == "#!/bin/sh\necho mine\n"
    assert not (tmp_path / "modules" / "demo").exists() and "demo" not in (_state(hive) if (hive / ".modules.json").exists() else {})


@LINUX_ONLY
def test_a_core_name_is_never_a_launcher_name(hive, tmp_path, bindir):
    pub = publish(tmp_path, cli={"name": "hv", "command": ["cli.sh"]})
    assert _add(hive, tmp_path / "repo", pub, check=False).returncode == 1
    assert not list(bindir.iterdir())


@LINUX_ONLY
def test_two_modules_cannot_claim_one_cli_name(hive, tmp_path, bindir):
    pub = publish(tmp_path, cli=CLI)
    _add(hive, tmp_path / "repo", pub)
    pub2 = _publish(tmp_path / "repo2", name="other", files=FILES, **V31, cli=CLI)
    r = _add(hive, tmp_path / "repo2", pub2, "other", False)
    assert r.returncode == 1 and "already taken by module 'demo'" in r.stderr
    assert "other" not in _state(hive)


@LINUX_ONLY
def test_an_edited_launcher_is_not_overwritten_or_removed(hive, tmp_path, bindir):
    pub = publish(tmp_path, cli=CLI)
    _add(hive, tmp_path / "repo", pub)
    (bindir / "democtl").write_text((bindir / "democtl").read_text() + "# edited\n")
    _run(hive, "module", "remove", "demo")
    assert (bindir / "democtl").exists()                                 # not ours any more: left alone


@LINUX_ONLY
def test_a_bin_directory_others_can_write_cannot_hold_a_launcher(hive, tmp_path, monkeypatch):
    open_dir = tool_dir(tmp_path, "open", 0o777)
    monkeypatch.setenv("HIVE_BIN_DIR", str(open_dir))
    pub = publish(tmp_path, cli=CLI)
    r = _add(hive, tmp_path / "repo", pub, check=False)
    assert r.returncode == 1 and "only you (or root) can write" in r.stderr
    assert not list(open_dir.iterdir())


@LINUX_ONLY
def test_update_renames_the_launcher_and_a_failed_update_keeps_the_old_one(hive, tmp_path, bindir):
    pub = publish(tmp_path, cli=CLI)
    _add(hive, tmp_path / "repo", pub)
    publish(tmp_path, cli={"name": "democtl2", "command": ["cli.sh"]}, version="1.1.0")
    _run(hive, "module", "update", "demo")
    assert (bindir / "democtl2").exists() and not (bindir / "democtl").exists()
    assert _state(hive)["demo"]["launcher"] == "democtl2"
    (bindir / "democtl3").write_text("foreign")
    publish(tmp_path, cli={"name": "democtl3", "command": ["cli.sh"]}, version="1.2.0")
    assert _run(hive, "module", "update", "demo", check=False).returncode == 1
    assert (bindir / "democtl2").exists() and (bindir / "democtl3").read_text() == "foreign"


# ── module run / module status ────────────────────────────────────────────────────────────────────

@LINUX_ONLY
def test_module_run_is_the_launcher_without_the_launcher(hive, tmp_path, bindir):
    pub = publish(tmp_path, cli=CLI)
    _add(hive, tmp_path / "repo", pub)
    r = _run(hive, "module", "run", "demo", "--", "--flag", "v", check=False)
    assert r.stdout == "demo|x|--flag|v|\n" and r.returncode == 3         # the module's own exit status
    r = _run(hive, "module", "run", "demo", "--help", check=False)
    assert r.stdout == "demo|x|--help|\n"                                 # flags after the name belong to the module
    assert _run(hive, "module", "run", "missing", check=False).returncode == 1


@LINUX_ONLY
def test_module_run_needs_a_cli(hive, tmp_path, bindir):
    pub = publish(tmp_path)
    _add(hive, tmp_path / "repo", pub)
    r = _run(hive, "module", "run", "demo", check=False)
    assert r.returncode == 1 and "declares no cli" in r.stderr


@LINUX_ONLY
def test_module_status_proxies_the_envelope(hive, tmp_path, bindir):
    pub = publish(tmp_path, status=["status.sh"])
    _add(hive, tmp_path / "repo", pub)
    r = _run(hive, "module", "status", "demo", "--json")
    assert json.loads(r.stdout)["state"] == "ok"
    assert _run(hive, "module", "status", "demo").stdout.startswith("demo: ok (1.0.0)")


@LINUX_ONLY
@pytest.mark.parametrize("script", ["#!/bin/sh\necho not json\n", "#!/bin/sh\necho '{\"schema\":2}'\n", "#!/bin/sh\nexit 1\n",
                                    "#!/bin/sh\nhead -c 200000 /dev/zero | tr '\\0' x\n"])
def test_a_broken_status_is_unknown_with_the_reason_never_a_crash(hive, tmp_path, bindir, script):
    pub = publish(tmp_path, status=["status.sh"], files={"status.sh": script})
    _add(hive, tmp_path / "repo", pub)
    r = _run(hive, "module", "status", "demo", "--json", check=False)
    env = json.loads(r.stdout)
    assert r.returncode == 1 and env["state"] == "unknown" and env["problems"]


@LINUX_ONLY
def test_module_status_gets_a_narrow_environment(hive, tmp_path, bindir):
    script = "#!/bin/sh\necho \"{\\\"schema\\\":1,\\\"state\\\":\\\"ok\\\",\\\"version\\\":\\\"${HIVE_OWNER_PASSPHRASE:-none}-${HIVE_HOME:-nohome}\\\",\\\"problems\\\":[]}\"\n"
    pub = publish(tmp_path, status=["status.sh"], files={"status.sh": script})
    _add(hive, tmp_path / "repo", pub)
    env = dict(os.environ, HIVE_HOME=str(hive), HIVE_IDENTITY_STASH=str(hive / "stash"), HIVE_OWNER_PASSPHRASE="secret")
    r = subprocess.run([sys.executable, str(__import__("_planes").entry_for(("module",))), "module", "status", "demo", "--json"],
                       env=env, capture_output=True, text=True)
    assert json.loads(r.stdout)["version"] == "none-nohome"
