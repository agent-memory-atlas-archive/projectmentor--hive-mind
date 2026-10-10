"""2.0 4c, re-specified by 3.0 PR 4: the pre-genesis forget grandfather is settled by the owner, never by a default flip
(public #136, #135 part 2; decisions h:af137f9421 and h:696638b9b7).

- 3.0 deleted the grandfather arm: an unsigned pre-genesis owner forget hides nothing, whatever `forget_writers` says. The
  facts the last 2.x hid by it (the MIGRATION SET) show until the owner re-signs those forgets.
- `hv doctor`'s `forget-authz` FAILS on an owned hive while the migration set is not empty, naming each fact by its `h:` id,
  and PASSES on an empty set with the key unset, `legacy` or `owner` (the old check failed an open policy).
- `hive-mind doctor --fix` and `hive-mind migrate forget` settle it. Nothing depends: nothing to do. Facts depend: it lists
  them and asks y/N at a terminal, default N, BEFORE unlocking the owner key; `y` re-signs each dependent forget and
  records the close. No terminal, a piped answer or N: nothing is written.
- `hv doctor --fix` (the 15-minute timer) never settles it: it cannot owner-sign, so it points.
"""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "tests"))
from test_links import _loadhv, _fact  # noqa: E402
from test_unforget import _act, _hive, FORGET_FLOOR, PRE  # noqa: E402
from test_forget_writers import (_policy, _cli, _backdate_forget, _legacy_hive, _policy_acts,  # noqa: E402
                                 _journal)
import _keys  # noqa: E402
import _planes  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent / "oracles"))
import content_evidence_2_4 as oracle_mod  # noqa: E402

CTL = PROJECT / "hivemind_ctl.py"
HV = PROJECT / "hv"


def _env(home, **extra):
    e = dict(os.environ, HIVE_HOME=str(home), HIVE_IDENTITY_STASH=str(Path(home) / "stash"))
    e.update(extra)
    return e


def _ctl(home, *argv, stdin=subprocess.DEVNULL, input=None, env=None):
    return subprocess.run([sys.executable, str(CTL), *argv], env=env or _env(home), capture_output=True,
                          text=True, stdin=None if input is not None else stdin, input=input, timeout=120)


def _ctl_at_a_terminal(home, answer, *argv, env=None):
    """Run the control plane with a real pseudo-terminal on stdin, typing `answer` then Enter."""
    pty = pytest.importorskip("pty")
    master, slave = pty.openpty()
    try:
        p = subprocess.Popen([sys.executable, str(CTL), *argv], env=env or _env(home), stdin=slave,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        os.close(slave)
        os.write(master, (answer + "\n").encode())
        out, _ = p.communicate(timeout=120)
    finally:
        os.close(master)
    return p.returncode, out


def _backdate(home, run, text, seq):
    """`_backdate_forget` with its own entry seq, so two forged forgets in one hive stay two entries (the
    journal is a G-Set on (node_id, seq))."""
    sid = run("remember", text).stdout.split()[2]
    ref = [x for x in json.loads(run("search", text.split()[1], "--format", "json").stdout)
           if x.get("kind") == "fact"][0]["ref"]
    node, fseq = ref.rsplit(":", 1)
    jf = sorted(Path(home, "journal").glob("*.jsonl"))[0]
    with open(jf, "a") as fh:
        fh.write(json.dumps({"node_id": "legacy-dev", "seq": seq, "type": "retract", "timestamp": "2020-01-01T00:00:00Z",
                             "payload": {"retracts_ref": [node, int(fseq)], "reason": "", "source": "owner:owner/owner"}})
                 + "\n")
    run("doctor", "rebuild")
    return sid


def _forget_authz(home):
    doc = json.loads(subprocess.run([sys.executable, str(HV), "doctor", "--format", "json"], env=_env(home),
                                    capture_output=True, text=True).stdout)
    return {c["name"]: c for c in doc["checks"]}.get("forget-authz")


def _retracts(home):
    return [e for e in _journal(home) if e["type"] == "retract"]


def _confidences(home):
    with sqlite3.connect(Path(home) / "store.db") as c:
        return dict(c.execute("SELECT content, confidence FROM facts").fetchall())


# ── the projection does not change ─────────────────────────────────────────────────────────────────

def test_an_unset_policy_projects_exactly_like_an_explicit_legacy_one(tmp_path, monkeypatch):
    """Every shape of owner forget at once, fact by fact. 3.0 does not read the key, so an unset and an explicit
    `legacy` policy project identically, and the facts 2.4 hid by the grandfather (the migration set) show."""
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, d2), base = _hive(hv)
    dep, signed, lifted, late, plain = (_fact(hv, d0, c, f"2026-01-02T00:00:0{i}Z") for i, c in
                                        enumerate(("dependent", "signed", "lifted", "backdated late", "plain")))
    ghost = {"node_id": "DESKTOP-OLD", "seq": 5}
    acts = [_act(hv, d1, dep, PRE),                                                   # hidden only by the grandfather
            _act(hv, d1, ghost, PRE),                                                 # dangling
            _act(hv, d1, signed, "2026-01-03T00:00:00Z", owner=a[:2]),                # owner-signed
            _act(hv, d1, lifted, PRE),
            _act(hv, d1, lifted, "2026-01-04T00:00:00Z", owner=a[:2], unforget=True),  # lifted by the owner
            _act(hv, d2, late, PRE)]                                                  # appended last, dated before genesis
    entries = base + [dep, signed, lifted, late, plain] + acts
    unset = hv._content_evidence(entries, hv._governance_state(entries))
    legacy_entries = entries + [_policy(hv, a, "legacy", "2026-01-06T00:00:00Z", 30)]
    legacy = hv._content_evidence(legacy_entries, hv._governance_state(legacy_entries))
    assert unset == legacy
    assert {c: v["forget"] for c, v in unset.items()} == {
        "dependent": False, "signed": True, "lifted": False, "backdated late": False, "plain": False}
    old = oracle_mod.bind(hv)(entries, hv._governance_state(entries))                  # what 2.4 projected
    assert {c: v["forget"] for c, v in old.items()} == {
        "dependent": True, "signed": True, "lifted": False, "backdated late": True, "plain": False}
    m = hv._forget_migration(entries, hv._governance_state(entries))
    assert {f["content"] for f in m["facts"]} == {"dependent", "backdated late"} and len(m["dangling"]) == 1


# ── hv doctor: an open owned hive fails ────────────────────────────────────────────────────────────

def test_an_open_hive_with_a_dependent_fact_fails_and_names_it_by_h_id(tmp_path):
    run = _cli(tmp_path)
    _legacy_hive(tmp_path, run)
    sid = _backdate_forget(tmp_path, run, "the backup runs at 02:00")
    fa = _forget_authz(tmp_path)
    assert fa["status"] == "fail" and fa["facts"] == [
        {"sid": sid, "ref": fa["facts"][0]["ref"], "content": "the backup runs at 02:00"}]
    assert sid in fa["detail"] and "hive-mind migrate forget` here (this device keeps an owner key)" in fa["detail"]


def test_a_legacy_hive_with_nothing_depending_passes(tmp_path):
    """3.0 (plan 3.4): the check is the migration set, not the key. `legacy` and nothing dependent passes, and the
    detail states the empty list; the 2.4 check failed this hive."""
    run = _cli(tmp_path)
    _legacy_hive(tmp_path, run)
    run("remember", "a fact nobody forgot")
    fa = _forget_authz(tmp_path)
    assert fa["status"] == "ok" and "closed: 0 facts depend on a pre-genesis unsigned forget" in fa["detail"]


def test_a_closed_hive_passes_and_an_unowned_one_says_nothing(tmp_path):
    run = _cli(tmp_path / "closed")
    run("owner", "init")                                                   # 1.28: born closed
    assert _forget_authz(tmp_path / "closed")["status"] == "ok"
    _cli(tmp_path / "unowned")("remember", "a fact in a hive with no owner")
    assert _forget_authz(tmp_path / "unowned") is None


@pytest.mark.parametrize("closed", [False, True])
def test_doctor_exits_non_zero_while_a_migration_is_owed_because_of_this_check(tmp_path, monkeypatch, closed):
    """The exit code, asserted, not just the status (Fable's ask 2). `authenticity` fails on any unsigned
    working tree, so the check under test is the only one run here: the exit is attributable to it."""
    run = _cli(tmp_path)
    _legacy_hive(tmp_path, run)
    _backdate_forget(tmp_path, run, "the backup runs at 02:00")
    if closed:
        rc, _ = _ctl_at_a_terminal(tmp_path, "y", "migrate", "forget")
        assert rc == 0
    hv = _planes.load_hv(tmp_path, "hv_forget_exit", control_plane=False)
    real = hv._doctor_status
    monkeypatch.setattr(hv, "_doctor_status", lambda: [c for c in real() if c["name"] == "forget-authz"])
    with pytest.raises(SystemExit) as e:
        hv.doctor_cmd(argparse.Namespace(doctor_action=None, format="text", fix=False, dry_run=False))
    assert e.value.code == (0 if closed else 1)


def test_the_printed_remedies_run_as_printed(tmp_path):
    """Fable's ask 3: the id in the detail is accepted by both remedies (2.0 refuses local ids)."""
    run = _cli(tmp_path)
    _legacy_hive(tmp_path, run)
    run("remember", "a second fact")
    for i, text in enumerate(("the backup runs at 02:00", "the vpn uses wireguard"), 1):
        _backdate(tmp_path, run, text, i)
    sids = [f["sid"] for f in _forget_authz(tmp_path)["facts"]]
    assert len(sids) == 2 and all(s in _forget_authz(tmp_path)["detail"] for s in sids)
    keep = _ctl(tmp_path, "retract", sids[0], "--owner", "--reason", "keep it")
    back = _ctl(tmp_path, "unforget", sids[1], "--reason", "it was right")
    assert keep.returncode == 0 and back.returncode == 0, keep.stdout + keep.stderr + back.stdout + back.stderr
    assert _forget_authz(tmp_path)["status"] == "ok"                      # both settled


# ── hive-mind doctor --fix: the close ──────────────────────────────────────────────────────────────

def test_fix_with_nothing_depending_writes_nothing_and_the_check_passes(tmp_path):
    run = _cli(tmp_path)
    base = _legacy_hive(tmp_path, run)
    run("remember", "a fact nobody forgot")
    before = _bytes_of(tmp_path)
    r = _ctl(tmp_path, "doctor", "--fix")
    assert "[y/N]" not in r.stdout
    assert len(_policy_acts(tmp_path)) == base and _bytes_of(tmp_path) == before
    assert _forget_authz(tmp_path)["status"] == "ok"


def _bytes_of(home):
    return {str(p.relative_to(home)): p.read_bytes() for p in sorted(Path(home, "journal").glob("*.jsonl"))}


@pytest.mark.parametrize("how", ["closed stdin", "y piped, no terminal", "N at a terminal", "Enter at a terminal"])
def test_fix_writes_nothing_without_a_yes_at_a_terminal(tmp_path, how):
    """Fable's ask 8: no terminal is a no, even with `y` on a pipe; N is a no; and the default is N, so Enter
    alone is a no too (Fable's mutant 11 on #180 found that case unguarded). Nothing is re-signed or set."""
    run = _cli(tmp_path)
    base = _legacy_hive(tmp_path, run)
    sid = _backdate_forget(tmp_path, run, "the backup runs at 02:00")
    before = (len(_retracts(tmp_path)), _confidences(tmp_path))
    if how == "closed stdin":
        out = _ctl(tmp_path, "doctor", "--fix").stdout
    elif how == "y piped, no terminal":
        out = _ctl(tmp_path, "doctor", "--fix", input="y\n").stdout
    elif how == "N at a terminal":
        _rc, out = _ctl_at_a_terminal(tmp_path, "n", "doctor", "--fix")
    else:
        _rc, out = _ctl_at_a_terminal(tmp_path, "", "doctor", "--fix")
    assert sid in out and "the backup runs at 02:00" in out and "Nothing was written" in out, out
    assert len(_policy_acts(tmp_path)) == base and (len(_retracts(tmp_path)), _confidences(tmp_path)) == before


def test_a_no_never_asks_for_the_owner_key_passphrase(tmp_path):
    """Grok's tightening: confirm, then unlock. With no passphrase available, a no still completes cleanly,
    because the sealed key is never opened before the answer."""
    run = _cli(tmp_path)
    _legacy_hive(tmp_path, run)
    _backdate_forget(tmp_path, run, "the backup runs at 02:00")
    env = _env(tmp_path)
    env.pop("HIVE_OWNER_KEY_PASSPHRASE", None)
    r = _ctl(tmp_path, "doctor", "--fix", env=env)
    assert "Nothing was written" in r.stdout and "passphrase" not in (r.stdout + r.stderr).lower()


def test_yes_at_a_terminal_re_signs_every_dependent_forget_then_closes_and_nothing_comes_back(tmp_path):
    """The re-issue brings the 3.0 projection to what 2.4 projected: the facts show before it and are hidden after, and
    the frozen 2.4 oracle over the journal as a peer that never saw the close would read it agrees."""
    run = _cli(tmp_path)
    base = _legacy_hive(tmp_path, run)
    run("remember", "a fact nobody forgot")
    sids = [_backdate(tmp_path, run, t, i) for i, t in enumerate(("the backup runs at 02:00", "the vpn uses wireguard"), 1)]
    before, n_retracts = _confidences(tmp_path), len(_retracts(tmp_path))
    rc, out = _ctl_at_a_terminal(tmp_path, "y", "doctor", "--fix")
    assert all(s in out for s in sids) and "re-issued 2 pre-genesis forget(s)" in out, out
    new = _retracts(tmp_path)[n_retracts:]
    assert len(new) == 2 and all("owner_sig" in e["payload"] and "doctor --fix" in e["payload"]["reason"] for e in new)
    acts = _policy_acts(tmp_path)
    assert len(acts) == base + 1 and acts[-1]["payload"]["value"] == "owner"
    journal = _journal(tmp_path)
    assert journal.index(new[-1]) < journal.index(acts[-1])               # re-issues first, the close last
    after = _confidences(tmp_path)
    hidden = ("the backup runs at 02:00", "the vpn uses wireguard")
    assert all(before[t] != FORGET_FLOOR for t in hidden) and all(after[t] == FORGET_FLOOR for t in hidden)
    assert after["a fact nobody forgot"] == before["a fact nobody forgot"]
    hv = _planes.load_hv(tmp_path, "hv_forget_legacy", control_plane=False)
    as_1x = [e for e in journal if e not in acts[base:]]                  # a peer that never saw the close
    ev = oracle_mod.bind(hv)(as_1x, hv._governance_state(as_1x))
    assert {c: v["forget"] for c, v in ev.items()} == {c: v == FORGET_FLOOR for c, v in after.items()}
    assert _forget_authz(tmp_path)["status"] == "ok"
    assert rc == 0 or "forget-authz now: closed" in out


def test_fix_on_a_device_without_the_owner_key_writes_nothing(tmp_path):
    run = _cli(tmp_path)
    base = _legacy_hive(tmp_path, run)
    _backdate_forget(tmp_path, run, "the backup runs at 02:00")
    kd = _keys.key_dir(tmp_path)
    for name in ("owner-key.sealed", "owner-key"):
        if (kd / name).exists():
            shutil.move(str(kd / name), str(tmp_path / name))
    before = len(_retracts(tmp_path))
    r = _ctl(tmp_path, "doctor", "--fix")
    assert "does not hold the owner key" in r.stdout and "on the owner machine" in r.stdout
    assert len(_policy_acts(tmp_path)) == base and len(_retracts(tmp_path)) == before


def test_fix_dry_run_only_says_what_it_would_do(tmp_path):
    run = _cli(tmp_path)
    base = _legacy_hive(tmp_path, run)
    _backdate_forget(tmp_path, run, "the backup runs at 02:00")
    r = _ctl(tmp_path, "doctor", "--fix", "--dry-run")
    assert "would ask to re-sign 1 pre-genesis forget(s), then record forget_writers=owner" in r.stdout
    assert len(_policy_acts(tmp_path)) == base


# ── hv doctor --fix: the timer never closes ────────────────────────────────────────────────────────

def test_hv_doctor_fix_points_and_never_closes_but_still_repairs(tmp_path):
    """Fable's ask 11: the 15-minute timer runs `hv doctor --fix`. On an open hive it must not touch the
    policy, must keep failing, and must still make its own repairs (here: the device key's permissions)."""
    run = _cli(tmp_path)
    run("config", "identity", "init")                                     # a device key for the repair to fix
    base = _legacy_hive(tmp_path, run)
    _backdate_forget(tmp_path, run, "the backup runs at 02:00")
    dk = _keys.key_path(tmp_path, "device-key")
    os.chmod(dk, 0o644)
    r = subprocess.run([sys.executable, str(HV), "doctor", "--fix"], env=_env(tmp_path), capture_output=True,
                       text=True, stdin=subprocess.DEVNULL)
    assert r.returncode != 0 and "run `hive-mind migrate forget` on the owner machine" in r.stdout
    assert "[y/N]" not in r.stdout and "heal error" not in r.stdout and "hive-mind " + "config set" not in r.stderr
    assert len(_policy_acts(tmp_path)) == base and _forget_authz(tmp_path)["status"] == "fail"
    assert (dk.stat().st_mode & 0o777) == 0o600
