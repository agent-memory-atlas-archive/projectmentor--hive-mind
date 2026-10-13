"""4.0 C2 (hconfig design §6): `config node list|get|set`, `module list --json`, `module config <name> schema`, and
`--non-interactive` on `config set` and `module config set` (exit 5, no prompt, no read of stdin, nothing signed).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))
import _planes  # noqa: E402
import merkle  # noqa: E402
from test_module_config_schema import REQUIRED, SCHEMA, publish  # noqa: E402
from test_module_lifecycle import LINUX_ONLY, _add  # noqa: E402
from test_owner_agent import PASS, hive, unlock  # noqa: E402,F401  (the agent fixture: a sealed owner key, an XDG dir)
from test_succession import _run  # noqa: E402

PEERS = {"self": "n1", "bind": "100.64.0.1", "port": 9876, "peers": [{"url": "http://100.64.0.2:9876", "id": "p2"}],
         "future_key": {"keep": True}}


def hv(home, *args, env=None, check=True):
    e = dict(os.environ, HIVE_HOME=str(home), HIVE_IDENTITY_STASH=str(Path(home) / "stash"), **(env or {}))
    r = subprocess.run([sys.executable, str(_planes.entry_for(args)), *args], env=e, capture_output=True, text=True)
    if check:
        assert r.returncode == 0, r.stdout + r.stderr
    return r


def peers_home(tmp_path, name, peers=PEERS):
    home = tmp_path / name
    home.mkdir()
    (home / ".peers.json").write_text(json.dumps(peers, indent=2) + "\n")
    return home


# ── config node ─────────────────────────────────────────────────────────────────────────────────────

def test_sync_auth_and_config_node_set_write_byte_identical_files_and_keep_the_peers(tmp_path):
    a, b, c = (peers_home(tmp_path, n) for n in "abc")
    hv(a, "sync", "auth", "enforce", "--outbound", "permissive")
    hv(b, "config", "node", "set", "sync_auth", "enforce")
    hv(b, "config", "node", "set", "sync_auth_outbound", "permissive")
    hv(c, "sync", "auth", "enforce")
    hv(c, "sync", "auth", "--outbound", "permissive")
    assert (a / ".peers.json").read_bytes() == (b / ".peers.json").read_bytes() == (c / ".peers.json").read_bytes()
    cfg = json.loads((b / ".peers.json").read_text())
    assert cfg["peers"] == PEERS["peers"] and cfg["future_key"] == PEERS["future_key"] and cfg["bind"] == "100.64.0.1"
    assert cfg["sync_auth"] == "enforce" and cfg["sync_auth_outbound"] == "permissive"


def test_node_set_into_an_absent_file_matches_sync_auth_too(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    hv(a, "sync", "auth", "off")
    hv(b, "config", "node", "set", "sync_auth", "off")
    assert (a / ".peers.json").read_bytes() == (b / ".peers.json").read_bytes()


def test_node_list_and_get_report_value_source_and_default(tmp_path):
    home = peers_home(tmp_path, "h")
    doc = json.loads(hv(home, "config", "node", "list", "--json").stdout)
    rows = {r["id"]: r for r in doc["keys"]}
    assert doc["schema"] == 1 and list(rows) == ["port", "bind", "sync_auth", "sync_auth_outbound",
                                                 "dashboard_share", "dashboard_viewers", "dashboard_viewer_port"]
    assert rows["bind"]["value"] == "100.64.0.1" and rows["bind"]["source"] == "node" and rows["bind"]["set"]
    assert rows["sync_auth"] == {**rows["sync_auth"], "value": "permissive", "source": "default", "set": False}
    assert rows["dashboard_viewers"]["value"] == []
    assert rows["dashboard_share"]["value"] is False and rows["dashboard_share"]["type"] == "bool"
    got = json.loads(hv(home, "config", "node", "get", "port", "--json").stdout)
    assert got["key"]["value"] == 9876 and got["key"]["source"] == "node"
    assert hv(home, "config", "node", "get", "bind").stdout.strip() == "100.64.0.1"
    assert hv(home, "config", "node", "list").returncode == 0


def test_node_set_validates_and_a_refusal_changes_nothing(tmp_path):
    home = peers_home(tmp_path, "h")
    before = (home / ".peers.json").read_bytes()
    for key, bad in (("port", "0"), ("port", "70000"), ("port", "abc"), ("port", "1.5"), ("bind", "not an ip"),
                     ("bind", ""), ("sync_auth", "sometimes"), ("sync_auth_outbound", "yes"),
                     ("dashboard_share", "maybe"), ("dashboard_share", ""), ("dashboard_viewers", "[1]"), ("dashboard_viewers", "a b"), ("dashboard_viewer_port", "99999"),
                     ("peers", "[]"), ("self", "x"), ("nonsense", "1")):
        r = hv(home, "config", "node", "set", key, bad, check=False)
        assert r.returncode == 1, (key, bad, r.stdout)
        assert (home / ".peers.json").read_bytes() == before
    j = json.loads(hv(home, "config", "node", "set", "port", "0", "--json", check=False).stdout)
    assert j["ok"] is False and "port must be between" in j["error"]


def test_node_set_accepts_each_type_and_keeps_the_rest(tmp_path):
    home = peers_home(tmp_path, "h")
    hv(home, "config", "node", "set", "port", "9999")
    hv(home, "config", "node", "set", "bind", "127.0.0.1")
    hv(home, "config", "node", "set", "dashboard_viewers", "b@x.org, a@x.org")
    hv(home, "config", "node", "set", "dashboard_viewer_port", "8081")
    hv(home, "config", "node", "set", "dashboard_share", "ON")
    cfg = json.loads((home / ".peers.json").read_text())
    assert (cfg["port"], cfg["bind"], cfg["dashboard_viewers"], cfg["dashboard_viewer_port"], cfg["dashboard_share"]) == \
        (9999, "127.0.0.1", ["a@x.org", "b@x.org"], 8081, True)
    hv(home, "config", "node", "set", "dashboard_share", "false")
    assert json.loads((home / ".peers.json").read_text())["dashboard_share"] is False
    assert cfg["peers"] == PEERS["peers"] and cfg["future_key"] == PEERS["future_key"]
    out = json.loads(hv(home, "config", "node", "set", "sync_auth", "ENFORCE", "--json").stdout)
    assert out["ok"] and out["value"] == "enforce" and "restart the daemon" in out["note"]


def test_an_env_override_is_source_env_and_its_value_is_masked(tmp_path):
    home = peers_home(tmp_path, "h")
    env = {"HIVE_SYNC_AUTH": "enforce", "HIVE_BIND": "10.9.8.7"}
    rows = {r["id"]: r for r in json.loads(hv(home, "config", "node", "list", "--json", env=env).stdout)["keys"]}
    for k in ("sync_auth", "bind"):
        assert rows[k]["source"] == "env" and rows[k]["value"] == "********" and rows[k]["env"]
    out = hv(home, "config", "node", "list", env=env).stdout
    assert "10.9.8.7" not in out and "enforce" not in out.replace("sync_auth=********", "")
    assert rows["port"]["source"] == "node"
    note = hv(home, "config", "node", "set", "sync_auth", "off", env=env).stdout
    assert "OVERRIDES" in note
    bad = {r["id"]: r for r in json.loads(hv(home, "config", "node", "list", "--json",
                                             env={"HIVE_SYNC_AUTH": "bogus"}).stdout)["keys"]}
    assert bad["sync_auth"]["source"] == "node"                     # an invalid mode is ignored, as the daemon does


# ── module list --json, module config schema ────────────────────────────────────────────────────────

@LINUX_ONLY
def test_module_list_json_rows_equal_the_text_columns_and_schema_equals_the_manifest(hive, tmp_path):
    pub = publish(tmp_path / "repo")
    _add(hive.home, tmp_path / "repo", pub, "demo", True, *REQUIRED)
    text = hv(hive.home, "module", "list").stdout.splitlines()
    doc = json.loads(hv(hive.home, "module", "list", "--json").stdout)
    assert doc["schema"] == 1 and len(doc["modules"]) == 1
    row, cols = doc["modules"][0], text[1].split(None, 7)
    assert [row[k] for k in ("name", "version", "publisher", "signature", "service", "device", "trust")] == cols[:7]
    assert row["quota_use"] == cols[7] and row["problem"] is None and row["config_schema"] is True
    manifest = json.loads((tmp_path / "modules" / "demo" / "module.json").read_text())
    shown = json.loads(hv(hive.home, "module", "config", "demo", "schema", "--json").stdout)
    assert shown == manifest["config_schema"] == SCHEMA
    assert hv(hive.home, "module", "config", "demo", "schema", "x", check=False).returncode == 2


def test_module_list_json_with_no_modules(tmp_path):
    out = hv(tmp_path / "h", "module", "list", "--json").stdout
    assert json.loads(out) == {"schema": 1, "modules": []}
    assert "No modules installed." in hv(tmp_path / "h", "module", "list").stdout


# ── --non-interactive ───────────────────────────────────────────────────────────────────────────────

def _ctl(h, args, stdin_bytes=b"never-read\n", passphrase=False):   # stdin_bytes=None: DEVNULL
    """Run `hive-mind` with a pipe on stdin that holds `stdin_bytes`; returns (result, bytes still unread)."""
    env = dict(h.env)
    if not passphrase:
        env.pop("HIVE_OWNER_KEY_PASSPHRASE", None)
    if stdin_bytes is None:                       # a control that may prompt: nothing to read
        r = subprocess.run([sys.executable, str(PROJECT / "hivemind_ctl.py"), *args], env=env, capture_output=True,
                           text=True, stdin=subprocess.DEVNULL, start_new_session=True, timeout=60)
        return r, b""
    rfd, wfd = os.pipe()
    os.write(wfd, stdin_bytes)
    try:
        r = subprocess.run([sys.executable, str(PROJECT / "hivemind_ctl.py"), *args], env=env, capture_output=True,
                           text=True, stdin=rfd, start_new_session=True, timeout=60)
        os.set_blocking(rfd, False)
        try:
            left = os.read(rfd, 4096)
        except BlockingIOError:
            left = b""
    finally:
        os.close(rfd)
        os.close(wfd)
    return r, left


def _set_configs(h):
    return [e["payload"] for e in merkle.read_all_entries(str(h.home / "journal"))
            if e.get("type") == "governance" and (e.get("payload") or {}).get("action") == "set-config"]


def _install(h, tmp_path):
    pub = publish(tmp_path / "repo")
    _add(h.home, tmp_path / "repo", pub, "demo", True, *REQUIRED)


@LINUX_ONLY
@pytest.mark.parametrize("stdin_flag", [False, True])
def test_a_locked_agent_exits_5_signs_nothing_and_reads_no_stdin(hive, tmp_path, stdin_flag):
    _install(hive, tmp_path)
    before = _set_configs(hive)
    args = ["module", "config", "demo", "set", "board", "dev", "--fleet", "--non-interactive"]
    if stdin_flag:
        args = ["module", "config", "demo", "set", "board", "--stdin", "--fleet", "--non-interactive"]
    r, left = _ctl(hive, args)
    assert r.returncode == 5 and "owner key is locked" in r.stderr, (r.stdout, r.stderr)
    assert left == b"never-read\n" and _set_configs(hive) == before


@LINUX_ONLY
def test_without_the_flag_the_same_command_still_prompts_and_cancels_with_exit_1(hive, tmp_path):
    _install(hive, tmp_path)
    r, _left = _ctl(hive, ["module", "config", "demo", "set", "board", "dev", "--fleet"], None)
    assert r.returncode == 1 and "Cancelled" in r.stderr


@LINUX_ONLY
def test_an_agent_unlocked_for_another_module_exits_5_journal_unchanged_stdin_untouched(hive, tmp_path):
    _install(hive, tmp_path)
    before = _set_configs(hive)
    unlock(hive, "--module", "other")
    for extra in ([], ["--stdin"]):
        args = ["module", "config", "demo", "set", "board", *([] if extra else ["dev"]), *extra, "--fleet",
                "--non-interactive"]
        r, left = _ctl(hive, args, b"x-m-value\n")
        assert r.returncode == 5, (r.stdout, r.stderr)
        assert left == b"x-m-value\n" and _set_configs(hive) == before
    fn = _ctl(hive, ["module", "config", "demo", "set", "seat.reviewer.enabled", "true", "--fleet-node",
                     "k1:" + "ab" * 8, "--non-interactive"])
    assert fn[0].returncode == 5 and _set_configs(hive) == before


@LINUX_ONLY
def test_an_agent_unlocked_for_the_module_signs_with_the_flag_and_no_prompt(hive, tmp_path):
    _install(hive, tmp_path)
    unlock(hive, "--module", "demo")
    r, left = _ctl(hive, ["module", "config", "demo", "set", "board", "dev", "--fleet", "--non-interactive"])
    assert r.returncode == 0 and "signed by agent: set-config" in r.stderr, (r.stdout, r.stderr)
    assert left == b"never-read\n" and _set_configs(hive)[-1]["key"] == "x-demo:board"
    again, _ = _ctl(hive, ["module", "config", "demo", "set", "board", "dev", "--fleet", "--non-interactive"])
    assert again.returncode == 0 and "nothing signed" in again.stdout
    node, _ = _ctl(hive, ["module", "config", "demo", "set", "poll", "50", "--non-interactive"])    # node layer: no key at all
    assert node.returncode == 0


@LINUX_ONLY
def test_a_node_value_and_a_secret_never_prompt_under_the_flag(hive, tmp_path):
    _install(hive, tmp_path)
    r, left = _ctl(hive, ["module", "config", "demo", "set", "token", "--non-interactive"])
    assert r.returncode == 1 and "no terminal to ask on" in r.stderr and left == b"never-read\n"


@LINUX_ONLY
def test_core_config_set_exits_5_when_the_agent_is_absent_locked_or_refuses(hive):
    before = _set_configs(hive)
    r, left = _ctl(hive, ["config", "set", "cap_self", "0.5", "--non-interactive"])           # no agent
    assert r.returncode == 5 and "--non-interactive" in r.stderr and left == b"never-read\n"
    unlock(hive)                                                                                 # up, but cap_self is not on its list
    r2, left2 = _ctl(hive, ["config", "set", "cap_self", "0.5", "--non-interactive"])
    assert r2.returncode == 5 and left2 == b"never-read\n" and _set_configs(hive) == before
    unlock(hive, "--module", "demo", check=False)
    r3, left3 = _ctl(hive, ["config", "set", "quorum_m", "2", "--non-interactive"])
    assert r3.returncode == 5 and left3 == b"never-read\n" and _set_configs(hive) == before
    r4, _ = _ctl(hive, ["config", "set", "cap_self", "0.5"], None)                                    # without the flag: a prompt, cancelled
    assert r4.returncode == 1 and "Cancelled" in r4.stderr


@LINUX_ONLY
def test_core_config_set_refusals_before_the_key_keep_exit_1_under_the_flag(hive):
    r, _ = _ctl(hive, ["config", "set", "cap_self", "abc", "--non-interactive"])
    assert r.returncode == 1 and "bad value for cap_self" in r.stdout
    r, _ = _ctl(hive, ["config", "set", "no_such", "1", "--non-interactive"])
    assert r.returncode == 1 and "unknown config key" in r.stdout


@LINUX_ONLY
def test_a_passphrase_in_the_environment_is_not_a_prompt(hive):
    r, left = _ctl(hive, ["config", "set", "cap_self", "0.5", "--non-interactive"], passphrase=True)
    assert r.returncode == 0 and "set cap_self = 0.5" in r.stdout and left == b"never-read\n"
