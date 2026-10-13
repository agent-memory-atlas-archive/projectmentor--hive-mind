"""Owner approval slice A0: `--plan --json` on the owner verbs a ticket can carry prints the exact canonical
governance bodies the verb would sign, and signs and writes nothing. For every verb the plan's bytes must equal the
bytes the real run signs (and the signature must verify over them); `_assert_plan_signed` is the check, and the mutant
tests show it fails when the real run drifts from the plan."""

import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
import ed25519  # noqa: E402
import merkle  # noqa: E402
from test_module_lifecycle import LINUX_ONLY, _add, _publish  # noqa: E402,F401
from test_succession import _device_id, _run  # noqa: E402

OTHER = "k1:" + "ab" * 8


@pytest.fixture
def hive(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_MODULES_DIR", str(tmp_path / "modules"))
    monkeypatch.delenv("TERMUX_VERSION", raising=False)
    home = tmp_path / "A"
    _run(home, "config", "identity", "init")
    _run(home, "owner", "init")
    _run(home, "group", "admit", _device_id(home), "--principal", "op")
    return home


def _gov_entries(home):
    return [e for e in merkle.read_all_entries(str(home / "journal")) if e.get("type") == "governance"]


def _signed_since(home, before):
    """The (canonical bytes, sha256) of every governance body signed after `before` entries, with the signature checked."""
    out = []
    for e in _gov_entries(home)[before:]:
        p = dict(e["payload"])
        sig = base64.b64decode(p.pop("owner_sig"))
        body = merkle._canonical(p)
        assert ed25519.verify(body, sig, base64.b64decode(p["owner_pub"])), "the owner signature does not cover the bytes"
        out.append((body.decode(), hashlib.sha256(body).hexdigest()))
    return out


def _plan(home, *argv, check=True):
    r = _run(home, *argv, "--plan", "--json", check=check)
    return r, (json.loads(r.stdout) if r.returncode == 0 else None)


def _assert_plan_signed(home, plan, before):
    planned = [(b["canonical"], b["sha256"]) for b in plan["bodies"]]
    assert planned, "the plan holds no body"
    assert [p[0].encode() for p in planned] and all(hashlib.sha256(c.encode()).hexdigest() == h for c, h in planned)
    assert _signed_since(home, before) == planned, "the real run signed other bytes than the plan printed"


def _verb(home, argv, replay=()):
    """Plan `argv`, check the plan signs nothing, run it for real (plus the plan's replay argv), and compare."""
    before = len(_gov_entries(home))
    _r, plan = _plan(home, *argv)
    assert len(_gov_entries(home)) == before, "the plan wrote a journal entry"
    _run(home, *argv, *plan["replay"]["extra_argv"], *replay)
    _assert_plan_signed(home, plan, before)
    return plan


@pytest.mark.parametrize("argv", [
    ("config", "set", "cap_self", "0.55"),
    ("config", "confidence", "set", "cap_self", "0.45"),
    ("config", "quorum", "set", "quorum_m", "2"),
    ("config", "set", "x-demo:poll", "45"),
    ("group", "admit", OTHER, "--principal", "bob"),
    ("admit", OTHER, "--principal", "bob"),
    ("group", "admit", OTHER, "--principal", "bob", "--module", "demo"),
])
def test_plan_bytes_equal_signed_bytes(hive, argv):
    plan = _verb(hive, list(argv))
    assert plan["schema"] == 1 and plan["replay"]["extra_argv"] == []
    for b in plan["bodies"]:
        assert b["body"]["owner_pub"] and "owner_sig" not in b["body"]


def test_revoke_plan_bytes_equal_signed_bytes(hive):
    _run(hive, "group", "admit", OTHER, "--principal", "bob")
    plan = _verb(hive, ["group", "revoke", OTHER])
    assert plan["bodies"][0]["body"]["action"] == "revoke"


def test_a_plan_signs_and_writes_nothing(hive):
    before = len(_gov_entries(hive))
    for argv in (("group", "admit", OTHER, "--principal", "bob"), ("config", "set", "cap_self", "0.5")):
        r, plan = _plan(hive, *argv)
        assert r.stdout.strip().startswith("{") and plan["bodies"]
    assert len(_gov_entries(hive)) == before
    assert not (hive / ".peers.json").exists()


def test_a_plan_needs_json_and_a_refusal_prints_no_plan(hive):
    r = _run(hive, "config", "set", "cap_self", "0.5", "--plan", check=False)
    assert r.returncode == 2 and not r.stdout
    r = _run(hive, "config", "set", "no_such_key", "1", "--plan", "--json", check=False)
    assert r.returncode == 1 and not r.stdout.strip().startswith("{")


def test_a_hive_without_an_owner_cannot_plan(tmp_path):
    home = tmp_path / "B"
    _run(home, "config", "identity", "init")
    r = _run(home, "group", "admit", OTHER, "--principal", "bob", "--plan", "--json", check=False)
    assert r.returncode == 1 and not r.stdout


# ---- the mutants: a real run that drifts from its plan must fail the equality check ----------------------

def test_mutant_a_run_with_another_principal_fails_the_check(hive):
    before = len(_gov_entries(hive))
    _r, plan = _plan(hive, "group", "admit", OTHER, "--principal", "bob")
    _run(hive, "group", "admit", OTHER, "--principal", "mallory")          # the drift
    with pytest.raises(AssertionError, match="other bytes"):
        _assert_plan_signed(hive, plan, before)


def test_mutant_a_run_with_another_value_fails_the_check(hive):
    before = len(_gov_entries(hive))
    _r, plan = _plan(hive, "config", "set", "cap_self", "0.5")
    _run(hive, "config", "set", "cap_self", "0.6")
    with pytest.raises(AssertionError, match="other bytes"):
        _assert_plan_signed(hive, plan, before)


# ---- module verbs ----------------------------------------------------------------------------------------

from test_module_config_schema import REQUIRED, publish  # noqa: E402


@LINUX_ONLY
def test_module_add_plan_fixes_the_minted_device_id_and_matches_the_run(hive, tmp_path):
    pub = publish(tmp_path / "repo")
    argv = ["module", "add", "demo", "--from", str(tmp_path / "repo"), "--publisher", pub, *REQUIRED]
    before = len(_gov_entries(hive))
    _r, plan = _plan(hive, *argv)
    assert [b["act"] for b in plan["bodies"]] == ["admit", "set-config"]
    assert len(_gov_entries(hive)) == before and not (hive / ".modules.json").exists()
    extra = plan["replay"]["extra_argv"]
    assert extra[0] == "--device-id" and extra[2:] == ["--principal", "op"]      # the derived principal is fixed too
    assert _plan(hive, *argv)[1]["bodies"] == plan["bodies"]        # a second plan reuses the key the first minted
    _run(hive, *argv, *extra)
    _assert_plan_signed(hive, plan, before)


@LINUX_ONLY
def test_module_add_with_a_device_id_no_plan_minted_is_refused(hive, tmp_path):
    pub = publish(tmp_path / "repo")
    r = _run(hive, "module", "add", "demo", "--from", str(tmp_path / "repo"), "--publisher", pub, *REQUIRED,
             "--device-id", OTHER, check=False)
    assert r.returncode == 1 and "no module key of that id" in r.stderr
    assert not (hive / ".modules.json").exists()


@LINUX_ONLY
def test_module_remove_and_fleet_config_plans_match_the_run(hive, tmp_path):
    pub = publish(tmp_path / "repo")
    _add(hive, tmp_path / "repo", pub, "demo", True, *REQUIRED)
    _verb(hive, ["module", "config", "demo", "set", "board", "side", "--fleet"])
    _verb(hive, ["module", "config", "demo", "set", "seat.dev.enabled", "true", "--fleet-node", _device_id(hive)])
    plan = _verb(hive, ["module", "remove", "demo"])
    assert plan["bodies"][0]["body"]["action"] == "revoke"


@LINUX_ONLY
def test_module_plan_refuses_a_node_value_a_secret_and_a_missing_json(hive, tmp_path):
    pub = publish(tmp_path / "repo")
    _add(hive, tmp_path / "repo", pub, "demo", True, *REQUIRED)
    assert _run(hive, "module", "config", "demo", "set", "poll", "9", "--plan", "--json", check=False).returncode == 2
    assert _run(hive, "module", "remove", "demo", "--plan", check=False).returncode == 2
    r = _run(hive, "module", "config", "demo", "set", "token", "--stdin", "--fleet", "--plan", "--json", check=False)
    assert r.returncode == 1 and not r.stdout.strip()
