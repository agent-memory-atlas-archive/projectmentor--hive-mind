"""3.1 `config_schema` (#294 PR 2, design `module_contract_3_1.md` §6, §13): typed, scoped module config from the CLI.
Layer order and source reporting, secret masking in every output, `set` to the current value signing nothing, a
missing required key refusing before anything is staged, `--set` at install, and a module without `contract`
behaving exactly as before. Drives the real `hive-mind` CLI against a module repository in a temp git repo."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
import _keys  # noqa: E402
import _planes  # noqa: E402
import hive_modules  # noqa: E402
from hive_modules import ModuleError  # noqa: E402
from test_module_lifecycle import LINUX_ONLY, _add, _publish, _state, hive  # noqa: E402,F401
from test_succession import _gov, _run  # noqa: E402

SCHEMA = {
    "operator.name": {"type": "string", "max": 20, "scope": "fleet", "required_at_install": True, "identifying": True,
                      "description": "Name shown for the operator"},
    "poll": {"type": "int", "min": 1, "max": 600, "default": "30", "description": "Seconds between polls"},
    "runtime": {"type": "enum", "values": ["claude", "grok"], "required_at_install": True, "description": "Runtime"},
    "token": {"type": "string", "secret": True, "description": "API token"},
    "seat.{role}.enabled": {"type": "bool", "default": "false", "scope": "fleet-node", "description": "Seat on"},
    "board": {"type": "string", "scope": "fleet", "default": "main", "description": "Board"},
}
REQUIRED = ("--set", "runtime=claude", "--set-fleet", "operator.name=Dana")
V31 = dict(min_core="3.1", contract=1, config=None)


def publish(repo, schema=None, **kw):
    return _publish(repo, config_schema=SCHEMA if schema is None else schema, **{**V31, **kw})


def cfg(home, *args, check=True, stdin=None, env=None):
    e = dict(os.environ, HIVE_HOME=str(home), HIVE_IDENTITY_STASH=str(Path(home) / "stash"), **(env or {}))
    argv = [sys.executable, str(_planes.entry_for(("module",))), "module", "config", "demo", *args]
    r = subprocess.run(argv, env=e, capture_output=True, text=True, input=stdin)
    if check:
        assert r.returncode == 0, r.stderr
    return r


def installed(hive, tmp_path, *extra):
    pub = publish(tmp_path / "repo")
    _add(hive, tmp_path / "repo", pub, "demo", True, *REQUIRED, *extra)
    return tmp_path / "modules" / "demo"


def fleet_values(home):
    return {k: v for k, v in _gov(home)[1]["module_config"].items() if k.startswith("x-demo:")}


def node_file(d):
    return json.loads((d / "config").read_text())


# ── install ───────────────────────────────────────────────────────────────────────────────────────────

@LINUX_ONLY
def test_install_stores_node_values_in_the_node_file_and_fleet_values_in_the_journal(hive, tmp_path):
    d = installed(hive, tmp_path)
    assert node_file(d) == {"runtime": "claude"}                 # defaults stay in the schema, not copied into the file
    assert fleet_values(hive) == {"x-demo:operator.name": "Dana"}
    assert (d / "config").stat().st_mode & 0o777 == 0o600


@LINUX_ONLY
def test_a_missing_required_key_refuses_before_anything_is_staged(hive, tmp_path):
    pub = publish(tmp_path / "repo")
    r = _add(hive, tmp_path / "repo", pub, "demo", False, "--non-interactive")
    assert r.returncode == 1
    assert "operator.name" in r.stderr and "runtime" in r.stderr and "--set" in r.stderr
    assert not (tmp_path / "modules" / "demo").exists() and not (tmp_path / "modules" / ".demo.staging").exists()
    assert not _key_dir(hive).exists() and not (hive / ".modules.json").exists()
    _, gov = _gov(hive)
    assert not gov["modules"] and not fleet_values(hive)


def _key_dir(home):
    return _keys.key_dir(home) / "modules" / "demo"


@LINUX_ONLY
def test_required_keys_are_refused_without_a_terminal_even_without_the_flag(hive, tmp_path):
    pub = publish(tmp_path / "repo")
    assert _add(hive, tmp_path / "repo", pub, "demo", False).returncode == 1          # pytest has no tty


@LINUX_ONLY
@pytest.mark.parametrize("flags,needle", [
    (("--set", "runtime=gemini", "--set-fleet", "operator.name=D"), "not one of"),
    (("--set", "nope=1", "--set-fleet", "operator.name=D"), "not a key"),
    (("--set", "operator.name=D", "--set", "runtime=claude"), "scope fleet"),
    (("--set", "runtime=claude", "--set-fleet", "runtime=claude"), "scope node"),
    (("--set", "runtime=claude", "--set", "runtime=grok"), "twice"),
    (("--set", "runtime=claude", "--set-fleet", "operator.name=" + "x" * 21), "longer than"),
    (("--set", "seat.coder.enabled=true", "--set-fleet", "operator.name=D"), "scope fleet-node"),
    (("--set", "token=abc", "--set", "runtime=claude", "--set-fleet", "operator.name=D"), "secret"),
    (("--set", "bare",), "key=value"),
])
def test_a_bad_install_value_refuses_and_installs_nothing(hive, tmp_path, flags, needle):
    pub = publish(tmp_path / "repo")
    r = _add(hive, tmp_path / "repo", pub, "demo", False, *flags)
    assert r.returncode == 1 and needle in r.stderr, r.stderr
    assert not (tmp_path / "modules" / "demo").exists() and not _key_dir(hive).exists()


@LINUX_ONLY
def test_a_secret_comes_from_the_environment_never_the_command_line(hive, tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_TOKEN", "s3cret-value")
    d = installed(hive, tmp_path, "--set-env", "token=DEMO_TOKEN")
    assert node_file(d)["token"] == "s3cret-value" and (d / "config").stat().st_mode & 0o777 == 0o600
    r = _add(hive, tmp_path / "repo", "x", "other", False, "--set-env", "token=UNSET_VARIABLE")
    assert r.returncode == 1


@LINUX_ONLY
def test_set_flags_on_a_module_without_a_schema_are_refused(hive, tmp_path):
    pub = _publish(tmp_path / "repo")
    r = _add(hive, tmp_path / "repo", pub, "demo", False, "--set", "poll=5")
    assert r.returncode == 1 and "no config_schema" in r.stderr


# ── set / get / list / layers ─────────────────────────────────────────────────────────────────────────

@LINUX_ONLY
def test_layers_scope_and_source_are_reported(hive, tmp_path):
    d = installed(hive, tmp_path)
    rows = {r["key"]: r for r in json.loads(cfg(hive, "list", "--json").stdout)}
    assert rows["poll"]["source"] == "default" and rows["poll"]["value"] == "30"
    assert rows["runtime"]["source"] == "node" and rows["operator.name"]["source"] == "fleet"
    assert rows["board"]["source"] == "default" and rows["token"]["set"] is False
    cfg(hive, "set", "poll", "45")
    assert cfg(hive, "get", "poll").stdout == "45\n"
    assert {r["key"]: r for r in json.loads(cfg(hive, "list", "--json").stdout)}["poll"]["source"] == "node"
    # a fleet-scope key is read only from the fleet layer: a stray node-file value does not shadow it
    f = node_file(d)
    f["board"] = "shadow"
    (d / "config").write_text(json.dumps(f))
    assert cfg(hive, "get", "board").stdout == "main\n"
    assert "ignored, its scope is fleet" in cfg(hive, "validate").stdout
    cfg(hive, "set", "board", "ops", "--fleet")
    assert cfg(hive, "get", "board").stdout == "ops\n" and fleet_values(hive)["x-demo:board"] == "ops"


@LINUX_ONLY
def test_set_checks_key_type_bounds_enum_and_scope(hive, tmp_path):
    installed(hive, tmp_path)
    for args, needle in ((("set", "poll", "0"), "outside"), (("set", "poll", "x"), "not an integer"),
                         (("set", "runtime", "gemini"), "not one of"), (("set", "nope", "1"), "no config key"),
                         (("set", "board", "x"), "scope fleet: set it with --fleet"),
                         (("set", "operator.name", "x", "--fleet-node", "k1:0123456789abcdef"), "scope fleet"),
                         (("set", "seat.coder.enabled", "true"), "--fleet-node"),
                         (("set", "poll", "5", "--fleet"), "scope node"),
                         (("set", "seat.coder.enabled", "maybe", "--fleet-node", "k1:0123456789abcdef"), "not true or false"),
                         (("set", "seat.coder.enabled", "true", "--fleet-node", "not-a-device"), "not a device id"),
                         (("get", "nope"), "no config key"), (("get", "token"), "no value"),
                         (("unset", "poll"), "no config key"), (("unset", "operator.name", "--fleet"), "cannot be removed")):
        r = cfg(hive, *args, check=False)
        assert r.returncode == 1 and needle in r.stderr, (args, r.stderr)


@LINUX_ONLY
def test_set_to_the_current_value_signs_nothing(hive, tmp_path):
    installed(hive, tmp_path)
    before = (hive / "journal").stat().st_mtime_ns, sorted(p.name for p in (hive / "journal").iterdir())
    assert "nothing signed" in cfg(hive, "set", "operator.name", "Dana", "--fleet").stdout
    assert "nothing changed" in cfg(hive, "set", "poll", "30").stdout                 # the default is already the value
    assert before == ((hive / "journal").stat().st_mtime_ns, sorted(p.name for p in (hive / "journal").iterdir()))
    cfg(hive, "set", "operator.name", "Sam", "--fleet")
    assert fleet_values(hive)["x-demo:operator.name"] == "Sam"


@LINUX_ONLY
def test_a_fleet_node_value_is_keyed_by_device_and_read_only_on_that_device(hive, tmp_path):
    installed(hive, tmp_path)
    here = _run(hive, "config", "identity", "show").stdout
    me = re.search(r"k1:[0-9a-f]{16}", here).group(0)
    other = "k1:" + "ab" * 8
    cfg(hive, "set", "seat.coder.enabled", "true", "--fleet-node", me)
    cfg(hive, "set", "seat.coder.enabled", "false", "--fleet-node", other)
    vals = fleet_values(hive)
    assert vals[f"x-demo:node.{me[3:]}.seat.coder.enabled"] == "true"
    assert vals[f"x-demo:node.{'ab' * 8}.seat.coder.enabled"] == "false"
    assert cfg(hive, "get", "seat.coder.enabled").stdout == "true\n"          # this device's value, not the other's
    assert cfg(hive, "get", "seat.coder.enabled", "--json").stdout.count('"fleet-node"') == 1
    assert cfg(hive, "set", "seat.coder.enabled", "true", "--fleet-node", me[3:]).stdout.count("nothing signed") == 1


@LINUX_ONLY
def test_a_secret_is_masked_everywhere_and_never_taken_from_argv(hive, tmp_path):
    d = installed(hive, tmp_path)
    r = cfg(hive, "set", "token", "hunter2", check=False)
    assert r.returncode == 1 and "never taken from the command line" in r.stderr and "hunter2" not in r.stdout + r.stderr
    assert "token" not in node_file(d)
    out = cfg(hive, "set", "token", "--stdin", stdin="hunter2\n")
    assert "hunter2" not in out.stdout + out.stderr and node_file(d)["token"] == "hunter2"
    assert (d / "config").stat().st_mode & 0o777 == 0o600
    shown = [cfg(hive, "list").stdout, cfg(hive, "list", "--json").stdout, cfg(hive, "get", "token").stdout,
             cfg(hive, "get", "token", "--json").stdout, cfg(hive, "validate").stdout, cfg(hive, "validate", "--json").stdout,
             cfg(hive, "set", "token", "--stdin", stdin="hunter2\n").stdout]
    assert all("hunter2" not in text for text in shown) and "********" in shown[2]
    assert cfg(hive, "set", "token", "--fleet", "--stdin", stdin="x\n", check=False).returncode == 1       # never fleet
    assert all("hunter2" not in v for v in fleet_values(hive).values())
    assert cfg(hive, "set", "token", "arg", "--stdin", stdin="x\n", check=False).returncode == 1
    assert cfg(hive, "set", "token", check=False).returncode == 1                                      # no terminal to ask on
    cfg(hive, "unset", "token")
    assert "token" not in node_file(d)


@LINUX_ONLY
def test_validate_reports_bad_values_missing_required_keys_and_unknown_keys(hive, tmp_path):
    d = installed(hive, tmp_path)
    assert cfg(hive, "validate").stdout.strip() == "config ok"
    f = node_file(d)
    f.update(poll="9999", stale="1")
    del f["runtime"]
    (d / "config").write_text(json.dumps(f))
    r = cfg(hive, "validate", check=False)
    assert r.returncode == 1
    assert "node config poll: outside 1..600" in r.stdout and "runtime: required and has no value" in r.stdout
    assert "node config stale: not in the schema" in r.stdout
    assert "stale=********  (node, not in schema)" in cfg(hive, "list").stdout and "stale=1" not in cfg(hive, "list").stdout
    j = json.loads(cfg(hive, "validate", "--json", check=False).stdout)
    assert j["ok"] is False and len(j["errors"]) == 2 and len(j["warnings"]) == 1


@LINUX_ONLY
def test_the_module_doctor_warns_on_config_that_breaks_the_schema_without_naming_values(hive, tmp_path):
    d = installed(hive, tmp_path)
    f = node_file(d)
    f.update(poll="9999", token="hunter2")
    (d / "config").write_text(json.dumps(f))
    r = _run(hive, "doctor", "--format", "json", check=False)
    c = {x["name"]: x for x in json.loads(r.stdout)["checks"]}["modules:demo"]
    assert "config: node config poll: outside 1..600" in c["detail"] and "hunter2" not in c["detail"] + r.stdout


# ── update, and manifests without `contract` ─────────────────────────────────────────────────────────

@LINUX_ONLY
def test_update_asks_only_for_keys_the_new_schema_added(hive, tmp_path):
    d = installed(hive, tmp_path)
    new = {**SCHEMA, "region": {"type": "string", "required_at_install": True, "identifying": True, "description": "Region"}}
    publish(tmp_path / "repo", schema=new, version="1.1.0", files={"run.sh": "#!/bin/sh\necho v2\n", "hooks/stop": "#!/bin/sh\n"})
    r = _run(hive, "module", "update", "demo", check=False)
    assert r.returncode == 1 and "region" in r.stderr and "runtime" not in r.stderr and "operator.name" not in r.stderr
    assert hive_modules.load_state is not None and _state(hive)["demo"]["version"] == "1.0.0"
    _run(hive, "module", "update", "demo", "--set", "region=north")
    assert node_file(d) == {"runtime": "claude", "region": "north"} and _state(hive)["demo"]["version"] == "1.1.0"


@LINUX_ONLY
def test_a_module_without_contract_keeps_free_form_config(hive, tmp_path):
    pub = _publish(tmp_path / "repo")
    _add(hive, tmp_path / "repo", pub)
    d = tmp_path / "modules" / "demo"
    assert cfg(hive, "list").stdout == "poll=30\n"
    cfg(hive, "set", "anything.goes", "x")
    assert node_file(d) == {"anything.goes": "x", "poll": "30"}
    assert "poll=30  (node)" in cfg(hive, "list", "--merged").stdout
    assert "validate" and "no config_schema" in cfg(hive, "validate").stdout
    assert cfg(hive, "set", "poll", "--stdin", stdin="7\n").returncode == 0 and node_file(d)["poll"] == "7"


# ── prompts (in process: a terminal is needed) ────────────────────────────────────────────────────────

class FakeLib:
    NODE_ID = "k1:0123456789abcdef"

    def _owner_key_exists(self):
        return True

    def _owner_seed(self):
        return b"x"


def _args(**kw):
    import argparse
    return argparse.Namespace(**{"set": [], "set_fleet": [], "set_env": [], "non_interactive": False, **kw})


def manifest_of(schema):
    return {"name": "demo", "config_schema": schema}


def tty(monkeypatch, answers):
    monkeypatch.setattr(sys, "stdin", type("T", (), {"isatty": lambda s: True, "readline": lambda s, n=0: ""})())
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(it))
    monkeypatch.setattr(hive_modules.getpass, "getpass", lambda prompt="": next(it))
    monkeypatch.setattr(hive_modules, "_gov", lambda lib: {"module_config": {}})


def test_prompts_ask_for_each_missing_required_key_and_reask_on_a_bad_answer(monkeypatch, capsys):
    schema = {"runtime": SCHEMA["runtime"], "operator.name": SCHEMA["operator.name"],
              "api.key": {"type": "string", "secret": True, "required_at_install": True, "description": "Key"}}
    tty(monkeypatch, ["topsecret", "Dana", "gemini", "claude"])
    node, fleet = hive_modules.install_config(FakeLib(), _args(), manifest_of(schema), owner=True)
    assert node == {"runtime": "claude", "api.key": "topsecret"} and fleet == {"operator.name": "Dana"}
    assert "not one of" in capsys.readouterr().err


def test_a_prompt_that_never_gets_a_valid_answer_refuses(monkeypatch):
    tty(monkeypatch, ["", "", ""])
    with pytest.raises(ModuleError, match="no valid value for runtime"):
        hive_modules.install_config(FakeLib(), _args(), manifest_of({"runtime": SCHEMA["runtime"]}), owner=True)


def test_non_interactive_never_prompts(monkeypatch):
    tty(monkeypatch, [])
    with pytest.raises(ModuleError, match="no terminal is available"):
        hive_modules.install_config(FakeLib(), _args(non_interactive=True), manifest_of({"runtime": SCHEMA["runtime"]}), owner=True)


def test_a_required_fleet_key_is_not_demanded_of_a_device_that_cannot_sign_it(monkeypatch):
    tty(monkeypatch, [])
    node, fleet = hive_modules.install_config(FakeLib(), _args(non_interactive=True), manifest_of({"operator.name": SCHEMA["operator.name"]}),
                                               owner=False)
    assert node == {} and fleet == {}
    with pytest.raises(ModuleError, match="owner key"):
        hive_modules.install_config(FakeLib(), _args(set_fleet=["operator.name=D"]), manifest_of(SCHEMA), owner=False)


def test_templates_match_one_segment_and_exact_names_win():
    s = {"seat.{role}.enabled": {}, "seat.lead.enabled": {"x": 1}}
    assert hive_modules.schema_entry(s, "seat.lead.enabled") == ("seat.lead.enabled", {"x": 1})
    assert hive_modules.schema_entry(s, "seat.coder.enabled")[0] == "seat.{role}.enabled"
    for bad in ("seat.a.b.enabled", "seat..enabled", "seat.Bad.enabled", "seat.coder"):
        assert hive_modules.schema_entry(s, bad) is None
