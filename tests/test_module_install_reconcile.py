"""3.1 `module install`, the idempotent reconcile with fixed exit codes and `--json` (#294 PR 5, design
`module_contract_3_1.md` §8, §13). Running it twice leaves the state byte-identical and signs nothing the second
time; a new commit takes the update path; a member node stages and exits 3; a sealed owner key that would need a
prompt exits 5 with nothing written; `--require-healthy` exits 4; `add` keeps its 3.0 behaviour."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))
import _keys  # noqa: E402
import hive_modules  # noqa: E402
from test_module_lifecycle import LINUX_ONLY, _publish, _state, hive, units  # noqa: E402,F401
from test_module_nonowner import Nodes, nodes  # noqa: E402,F401
from test_succession import _run  # noqa: E402

V31 = dict(min_core="3.1", contract=1, config=None)
SCHEMA = {"poll": {"type": "int", "min": 1, "max": 600, "default": "30", "description": "Seconds between polls"},
          "mode": {"type": "string", "max": 20, "description": "A mode"}}


def install(home, repo, pub, *extra, name="demo", check=True):
    return _run(home, "module", "install", name, "--from", str(repo), "--publisher", pub, *extra, check=check)


def journal_bytes(home):
    d = home / "journal"
    return sorted((p.name, p.read_bytes()) for p in d.glob("*.jsonl")) if d.exists() else []


@LINUX_ONLY
def test_install_converges_and_a_second_run_changes_and_signs_nothing(hive, tmp_path, units):
    pub = _publish(tmp_path / "repo")
    r = install(hive, tmp_path / "repo", pub)
    assert "installed module demo 1.0.0" in r.stdout and "doctor: modules:demo" in r.stdout
    state, journal = (hive / ".modules.json").read_bytes(), journal_bytes(hive)
    tree = sorted((p.name, p.read_bytes()) for p in (tmp_path / "modules" / "demo").rglob("*") if p.is_file())
    again = install(hive, tmp_path / "repo", pub)
    assert again.returncode == 0 and "nothing to do" in again.stdout
    assert (hive / ".modules.json").read_bytes() == state and journal_bytes(hive) == journal       # nothing signed
    assert sorted((p.name, p.read_bytes()) for p in (tmp_path / "modules" / "demo").rglob("*") if p.is_file()) == tree
    assert install(hive, tmp_path / "repo", pub).returncode == 0                                    # and again


@LINUX_ONLY
def test_the_source_is_remembered_so_a_bare_install_converges(hive, tmp_path, units):
    pub = _publish(tmp_path / "repo")
    install(hive, tmp_path / "repo", pub)
    r = _run(hive, "module", "install", "demo")
    assert r.returncode == 0 and "nothing to do" in r.stdout


@LINUX_ONLY
def test_a_new_commit_takes_the_update_path_and_keeps_the_key(hive, tmp_path, units):
    pub = _publish(tmp_path / "repo")
    install(hive, tmp_path / "repo", pub)
    dev = _state(hive)["demo"]["device_id"]
    _publish(tmp_path / "repo", version="1.1.0")
    r = install(hive, tmp_path / "repo", pub)
    assert "updated module demo to 1.1.0" in r.stdout
    assert _state(hive)["demo"]["version"] == "1.1.0" and _state(hive)["demo"]["device_id"] == dev


@LINUX_ONLY
def test_json_is_one_object_with_the_outcome(hive, tmp_path, units):
    pub = _publish(tmp_path / "repo")
    o = json.loads(install(hive, tmp_path / "repo", pub, "--json").stdout)
    assert o["ok"] and o["exit"] == 0 and o["result"] == "installed" and o["version"] == "1.0.0"
    assert o["doctor"]["name"] == "modules:demo" and o["error"] is None and o["admit_line"] is None
    assert any("installed module demo" in m for m in o["messages"])
    o = json.loads(install(hive, tmp_path / "repo", pub, "--json").stdout)
    assert o["ok"] and o["result"] == "unchanged"


@LINUX_ONLY
def test_a_refusal_exits_1_with_nothing_changed(hive, tmp_path, units):
    pub = _publish(tmp_path / "repo")
    r = _run(hive, "module", "install", "demo", check=False)                                        # not installed, no source
    assert r.returncode == 1 and "--from" in r.stderr
    r = install(hive, tmp_path / "missing", pub, check=False)
    assert r.returncode == 1 and not (hive / ".modules.json").exists() and not (tmp_path / "modules" / "demo").exists()
    o = json.loads(install(hive, tmp_path / "repo", "wrongkey", "--json", check=False).stdout)
    assert o["exit"] == 1 and o["result"] == "refused" and not o["ok"] and o["error"]
    assert not (hive / ".modules.json").exists()
    assert not (_keys.key_dir(hive) / "modules" / "demo").exists()


@LINUX_ONLY
def test_usage_errors_exit_2(hive, tmp_path):
    assert _run(hive, "module", "install", check=False).returncode == 2
    assert _run(hive, "module", "install", "demo", "--no-such-flag", check=False).returncode == 2


@LINUX_ONLY
def test_a_sealed_owner_key_that_would_prompt_exits_5_and_writes_nothing(hive, tmp_path, units, monkeypatch):
    pub = _publish(tmp_path / "repo")
    monkeypatch.delenv("HIVE_OWNER_KEY_PASSPHRASE")
    before = journal_bytes(hive)
    r = install(hive, tmp_path / "repo", pub, "--non-interactive", check=False)
    assert r.returncode == 5 and "owner unlock" in r.stderr
    o = json.loads(install(hive, tmp_path / "repo", pub, "--json", check=False).stdout)              # --json never prompts
    assert o["exit"] == 5 and o["result"] == "locked" and not o["ok"]
    assert not (hive / ".modules.json").exists() and journal_bytes(hive) == before
    assert not (_keys.key_dir(hive) / "modules" / "demo").exists() and not (tmp_path / "modules" / "demo").exists()


@LINUX_ONLY
def test_a_trust_raise_on_the_update_path_never_prompts_under_json(hive, tmp_path, units, monkeypatch):
    pub = _publish(tmp_path / "repo", trust="confined", **V31)
    install(hive, tmp_path / "repo", pub)
    _publish(tmp_path / "repo", version="1.1.0", **V31)                    # no `trust`: the raise confined -> trusted
    monkeypatch.delenv("HIVE_OWNER_KEY_PASSPHRASE")
    before = _state(hive)
    o = json.loads(install(hive, tmp_path / "repo", pub, "--json", check=False).stdout)
    assert o["exit"] == 5 and o["result"] == "locked" and not o["ok"] and "owner unlock" in o["error"]
    assert _state(hive) == before and before["demo"]["version"] == "1.0.0" and before["demo"]["trust"] == "confined"


@LINUX_ONLY
def test_require_healthy_exits_4_only_when_asked(hive, tmp_path, units):
    pub = _publish(tmp_path / "repo")
    install(hive, tmp_path / "repo", pub)
    st = _state(hive)
    del st["demo"]["device_id"]                                                  # the doctor row for it becomes `fail`
    (hive / ".modules.json").write_text(json.dumps(st))
    assert install(hive, tmp_path / "repo", pub).returncode == 0
    r = install(hive, tmp_path / "repo", pub, "--require-healthy", check=False)
    assert r.returncode == 4 and "modules:demo fail" in r.stdout
    o = json.loads(install(hive, tmp_path / "repo", pub, "--require-healthy", "--json", check=False).stdout)
    assert o["exit"] == 4 and o["result"] == "unhealthy" and o["doctor"]["status"] == "fail"


@LINUX_ONLY
def test_a_member_node_stages_and_exits_3_until_the_admit_arrives(nodes, tmp_path, units):
    pub = _publish(tmp_path / "repo")

    def on_b(*extra, check=False):
        return nodes.run_b("module", "install", "demo", "--from", str(tmp_path / "repo"), "--publisher", pub,
                           "--principal", "op", *extra, check=check)
    r = on_b()
    assert r.returncode == 3 and "NOT installed" in r.stdout and not nodes.b_modules().exists()
    o = json.loads(on_b("--json").stdout)
    assert o["exit"] == 3 and o["result"] == "waiting" and o["admit_line"].startswith("hive-mind group admit ")
    nodes.run_a(*o["admit_line"].split()[1:])
    assert on_b().returncode == 3                                                # the admit has not reached B yet
    nodes.sync_to_b()
    r = on_b()
    assert r.returncode == 0 and "installed module demo" in r.stdout and nodes.b_modules().exists()
    assert on_b().returncode == 0                                                # and the rerun is a no-op


@LINUX_ONLY
def test_config_given_on_a_rerun_is_applied_once(hive, tmp_path, units):
    pub = _publish(tmp_path / "repo", config_schema=SCHEMA, **V31)
    install(hive, tmp_path / "repo", pub, "--set", "mode=a")
    node = lambda: json.loads((tmp_path / "modules" / "demo" / "config").read_text())      # noqa: E731
    assert node()["mode"] == "a"
    assert "nothing to do" in install(hive, tmp_path / "repo", pub, "--set", "mode=a").stdout
    assert "configuration updated" in install(hive, tmp_path / "repo", pub, "--set", "mode=b").stdout
    assert node()["mode"] == "b"
    r = install(hive, tmp_path / "repo", pub, "--set", "nope=1", check=False)
    assert r.returncode == 1 and node()["mode"] == "b"


@LINUX_ONLY
def test_add_keeps_its_exit_codes(hive, tmp_path, units):
    pub = _publish(tmp_path / "repo")
    assert _run(hive, "module", "add", "demo", "--from", str(tmp_path / "repo"), "--publisher", pub).returncode == 0
    r = _run(hive, "module", "add", "demo", "--from", str(tmp_path / "repo"), "--publisher", pub, check=False)
    assert r.returncode == 1 and "already installed" in r.stderr                  # add is not idempotent; install is


def test_install_is_a_module_verb_and_the_exit_codes_are_named():
    assert "install" in hive_modules.VERBS
    assert (hive_modules.EXIT_REFUSED, hive_modules.EXIT_WAITING, hive_modules.EXIT_UNHEALTHY,
            hive_modules.EXIT_LOCKED) == (1, 3, 4, 5)
