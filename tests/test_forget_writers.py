"""#122 step 2 (contract 1.25), after 3.0 removed the grandfather arm.

Through 2.4 the governed `forget_writers` policy switched the pre-genesis grandfather: `legacy` (the default) honoured an
owner-source forget positioned before the genesis owner without a signature, `owner` closed it. 3.0 deletes the arm, so
the projection ignores such a forget whatever the key says (frozen-oracle differential: test_forget_oracle.py). The
key stays a recognised governed key whose value the projection no longer reads: it is still applied only when the
owner current at that position signed it, the latest such act wins, and an unknown value is ignored, because a 2.x
peer reads it. `hv config set forget_writers owner` stays accepted (it records the close for 2.x peers) and refuses while
a 2.x peer would still keep a fact forgotten only by an unsigned pre-genesis forget; `legacy` is refused with a sentence.
"""

import base64
import glob
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "tests"))
from test_links import _loadhv, _owner_key, _device, _gov, _entry, _fact, _project, T0  # noqa: E402
from test_unforget import _act, _hive, _transfer, _row, FORGET_FLOOR, PRE  # noqa: E402
import _planes  # noqa: E402  (which plane runs a command, 2.0)


def _policy(hv, owner, value, ts, seq):
    return _gov(hv, {"action": "set-config", "key": "forget_writers", "value": value}, owner[0], owner[1], ts, seq)


def test_a_pre_genesis_unsigned_forget_is_ignored_whatever_the_key_says(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, _), base = _hive(hv)
    f = _fact(hv, d0, "the backup runs at 02:00", "2026-01-02T00:00:00Z")
    forged = _act(hv, d1, f, PRE)                                          # the #122 attack: backdated, unsigned
    for tail in ([], [_policy(hv, a, "legacy", "2026-01-05T00:00:00Z", 20)],
                 [_policy(hv, a, "owner", "2026-01-05T00:00:00Z", 21)]):
        assert _row(_project(hv, tmp_path, base + [f, forged, *tail]), "the backup runs at 02:00")[0] != FORGET_FLOOR


def test_a_forget_backdated_after_the_close_erases_nothing(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, _), base = _hive(hv)
    f = _fact(hv, d0, "port 443 is open", "2026-01-02T00:00:00Z")
    close = _policy(hv, a, "owner", "2026-01-03T00:00:00Z", 20)
    late = _act(hv, d1, f, PRE)                                            # appended after the close, dated before
    assert _row(_project(hv, tmp_path, base + [f, close, late]), "port 443 is open")[0] != FORGET_FLOOR


def test_signed_forgets_and_unforgets_are_unaffected(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, _), base = _hive(hv)
    f = _fact(hv, d0, "vendor X is approved", "2026-01-02T00:00:00Z")
    g = _fact(hv, d0, "vendor Y is approved", "2026-01-02T00:00:01Z")
    close = _policy(hv, a, "owner", "2026-01-03T00:00:00Z", 20)
    entries = base + [f, g, close,
                      _act(hv, d1, f, "2026-01-04T00:00:00Z", owner=a[:2]),                 # signed forget
                      _act(hv, d1, g, "2026-01-04T00:00:00Z", owner=a[:2]),
                      _act(hv, d1, g, "2026-01-05T00:00:00Z", owner=a[:2], unforget=True)]  # then lifted
    conn = _project(hv, tmp_path, entries)
    assert _row(conn, "vendor X is approved")[0] == FORGET_FLOOR
    assert _row(conn, "vendor Y is approved")[0] != FORGET_FLOOR


def _key(hv, entries):
    return hv._governance_state(entries)["config"].get("forget_writers", "legacy")


def test_only_the_owner_at_that_position_sets_the_policy(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, _), base = _hive(hv)
    b = _owner_key(hv)
    stranger = _owner_key(hv)
    for i, bad in enumerate((_policy(hv, stranger, "owner", "2026-01-03T00:00:00Z", 20),     # not an owner
                             _policy(hv, b, "owner", "2026-01-03T00:00:00Z", 20))):           # B, before B's term
        entries = base + [bad, _transfer(hv, a, b[1], "2026-01-04T00:00:00Z", 21)]
        assert _key(hv, entries) == "legacy", i
    # after the transfer, retired owner A's act is ignored and B's counts
    xfer = _transfer(hv, a, b[1], "2026-01-04T00:00:00Z", 21)
    late_a = _policy(hv, a, "owner", "2026-01-05T00:00:00Z", 22)
    assert _key(hv, base + [xfer, late_a]) == "legacy"
    ok_b = _policy(hv, b, "owner", "2026-01-05T00:00:00Z", 22)
    assert _key(hv, base + [xfer, ok_b]) == "owner"


def test_latest_act_wins_and_an_unknown_value_is_ignored(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, _), base = _hive(hv)
    close = _policy(hv, a, "owner", "2026-01-03T00:00:00Z", 20)
    reopen = _policy(hv, a, "legacy", "2026-01-04T00:00:00Z", 21)
    assert _key(hv, base + [close, reopen]) == "legacy"
    bogus = _policy(hv, a, "nobody", "2026-01-05T00:00:00Z", 22)          # fails closed: the owner setting stands
    assert _key(hv, base + [close, bogus]) == "owner"
    assert _key(hv, base + [bogus]) == "legacy"


def test_two_nodes_project_identically(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, _), base = _hive(hv)
    fs = [_fact(hv, d0, f"fact {i}", f"2026-01-02T00:00:0{i}Z") for i in range(3)]
    entries = base + fs + [_act(hv, d1, fs[0], PRE), _act(hv, d1, fs[1], PRE),
                           _act(hv, d1, fs[1], "2026-01-03T00:00:00Z", owner=a[:2]),
                           _policy(hv, a, "owner", "2026-01-04T00:00:00Z", 20)]
    rows = []
    for home, order in ((tmp_path / "n1", entries), (tmp_path / "n2", list(reversed(entries)))):
        conn = _project(_loadhv(home, monkeypatch), home, order)
        rows.append([tuple(r) for r in conn.execute("SELECT content, confidence, last_evidence_at FROM facts ORDER BY content")])
    assert rows[0] == rows[1]
    assert [r[1] == FORGET_FLOOR for r in rows[0]] == [False, True, False]   # only the signed forget holds


def test_a_pre_1_25_node_ignores_the_policy(tmp_path, monkeypatch):
    """A 1.24 node lands the set-config (owner-signed) and ignores the unknown key: projection skew only."""
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, _), base = _hive(hv)
    f = _fact(hv, d0, "the disk is 2TB", "2026-01-02T00:00:00Z")
    entries = base + [f, _act(hv, d1, f, PRE), _policy(hv, a, "owner", "2026-01-03T00:00:00Z", 20)]
    src = subprocess.run(["git", "-C", str(PROJECT), "show", "v1.24.0:hv"], capture_output=True, text=True)
    if src.returncode != 0:
        pytest.skip("v1.24.0 is not in this checkout (shallow clone)")
    old_hv = tmp_path / "hv_1_24"
    old_hv.write_text(src.stdout)
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("hv_1_24", str(old_hv))
    spec = importlib.util.spec_from_loader("hv_1_24", loader)
    old = importlib.util.module_from_spec(spec)
    loader.exec_module(old)
    assert old._content_evidence(entries, old._governance_state(entries))["the disk is 2TB"]["forget"] is True
    assert hv._content_evidence(entries, hv._governance_state(entries))["the disk is 2TB"]["forget"] is False
    (tmp_path / "journal").mkdir(exist_ok=True)
    accepted, _dups = old.append_foreign_entries(entries)
    assert accepted == len(entries)


# ── the CLI guard: closing never silently brings a fact back ──────────────────────────────────────

def _cli(tmp_path):
    def run(*args, check=True):
        env = dict(os.environ, HIVE_HOME=str(tmp_path), HIVE_IDENTITY_STASH=str(tmp_path / "stash"))
        r = subprocess.run([sys.executable, str(_planes.entry_for(args)), *args], env=env, capture_output=True, text=True)
        if check:
            assert r.returncode == 0, r.stderr
        return r
    return run


def _backdate_forget(tmp_path, run, text):
    """An owner hive with a fact, then an unsigned owner-source forget of it dated before genesis (#122's shape)."""
    out = run("remember", text).stdout
    sid = out.split()[2]
    ref = [x for x in json.loads(run("search", text.split()[1], "--format", "json").stdout)
           if x.get("kind") == "fact"][0]["ref"]
    node, seq = ref.rsplit(":", 1)
    f = sorted(glob.glob(f"{tmp_path}/journal/*.jsonl"))[0]
    with open(f, "a") as fh:
        fh.write(json.dumps({"node_id": "legacy-dev", "seq": 1, "type": "retract", "timestamp": "2020-01-01T00:00:00Z",
                             "payload": {"retracts_ref": [node, int(seq)], "reason": "", "source": "owner:owner/owner"}}) + "\n")
    run("doctor", "rebuild")
    return sid


def _journal(tmp_path):
    out = []
    for f in sorted(glob.glob(f"{tmp_path}/journal/*.jsonl")):
        out += [json.loads(l) for l in open(f).read().splitlines() if l.strip()]
    return out


def _policy_acts(tmp_path):
    return [e for e in _journal(tmp_path) if e["type"] == "governance"
            and e["payload"].get("action") == "set-config" and e["payload"].get("key") == "forget_writers"]


def _forget_authz_status(tmp_path, run):
    doc = json.loads(run("doctor", "--format", "json", check=False).stdout)
    return {c["name"]: c for c in doc["checks"]}["forget-authz"]["status"]


def _legacy_hive(tmp_path, run):
    """Since 1.28 (#135) `hv owner init` leaves a hive CLOSED, so a test of the #122 guard must first put
    it back in the state every pre-1.28 hive is in: grandfather open, `forget_writers=legacy`. Returns the
    number of policy acts that baseline costs, so a test can assert nothing NEW was written."""
    run("owner", "init")
    reopen_as_2x(tmp_path)
    return len(_policy_acts(tmp_path))                                     # init's close, then this reopen


def reopen_as_2x(home, env=None, root=PROJECT):
    """3.0 refuses `config set forget_writers legacy`, so a 2.x hive's open policy is planted the way 2.x wrote it:
    an owner-signed `set-config forget_writers legacy` governance act, through the same append path. `root` is
    the checkout whose code signs it (the update tests run a sandbox clone)."""
    code = ("import sys, importlib.machinery as m, importlib.util as u; sys.path.insert(0, %r); "
            "l = m.SourceFileLoader('hv_plant', %r); hv = u.module_from_spec(u.spec_from_loader('hv_plant', l)); "
            "l.exec_module(hv); import hivemind_ctl; hivemind_ctl.install(hv); "
            "assert hv._append_governance({'action': 'set-config', 'key': 'forget_writers', 'value': 'legacy'})"
            % (str(root), str(Path(root) / "hv")))
    env = env or dict(os.environ, HIVE_HOME=str(home), HIVE_IDENTITY_STASH=str(Path(home) / "stash"))
    r = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, cwd=str(home))
    assert r.returncode == 0, r.stderr


def test_config_set_refuses_while_a_fact_would_come_back_and_names_it(tmp_path):
    run = _cli(tmp_path)
    base = _legacy_hive(tmp_path, run)
    sid = _backdate_forget(tmp_path, run, "the backup runs at 02:00")
    r = run("config", "set", "forget_writers", "owner")
    assert "Not set" in r.stdout and sid in r.stdout and "hive-mind retract" in r.stdout and "hive-mind unforget" in r.stdout
    assert len(_policy_acts(tmp_path)) == base                             # nothing written
    doc = json.loads(run("doctor", "--format", "json", check=False).stdout)
    fa = {c["name"]: c for c in doc["checks"]}["forget-authz"]
    # 3.0: `fail` while the migration set is not empty, and the one command that settles it is `hive-mind migrate forget`.
    assert fa["status"] == "fail" and sid in fa["detail"] and "hive-mind migrate forget" in fa["detail"]


@pytest.mark.parametrize("decision", ["keep", "release"])
def test_after_the_owner_decides_each_fact_the_close_is_written(tmp_path, decision):
    run = _cli(tmp_path)
    base = _legacy_hive(tmp_path, run)
    sid = _backdate_forget(tmp_path, run, "the backup runs at 02:00")
    if decision == "keep":
        run("retract", sid, "--owner", "--reason", "keep it")
    else:
        run("unforget", sid, "--reason", "it was right")
    r = run("config", "set", "forget_writers", "owner")
    assert "set forget_writers = owner" in r.stdout
    acts = _policy_acts(tmp_path)
    assert len(acts) == base + 1 and acts[-1]["payload"]["value"] == "owner" and "owner_sig" in acts[-1]["payload"]
    import sqlite3
    conf = sqlite3.connect(tmp_path / "store.db").execute("SELECT confidence FROM facts").fetchone()[0]
    assert (conf == FORGET_FLOOR) == (decision == "keep")
    assert _forget_authz_status(tmp_path, run) == "ok"          # decided, so nothing is owed any more


def test_config_set_refuses_an_unknown_value_and_needs_no_decision_when_nothing_is_hidden(tmp_path):
    run = _cli(tmp_path)
    base = _legacy_hive(tmp_path, run)
    run("remember", "a fact nobody forgot")
    assert "must be 'owner'" in run("config", "set", "forget_writers", "sometimes").stdout
    assert "no longer honoured" in run("config", "set", "forget_writers", "legacy").stdout      # 3.0: refused with a sentence
    assert len(_policy_acts(tmp_path)) == base
    assert "set forget_writers = owner" in run("config", "set", "forget_writers", "owner").stdout
