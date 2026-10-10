"""#122 step 1: `_forgets_grandfathered`, and (3.0) the `forget-authz` doctor check it feeds.

Through 2.4 an owner forget positioned before the genesis owner was honoured without a signature (the
grandfather in `_content_evidence`), and ingest does not check timestamps, so an admitted device could erase a
fact with a backdated unsigned owner forget. 3.0 removed the arm: the projection ignores such a forget. The
function still lists them in two groups: `hides` (what the last 2.x kept forgotten by it: the migration set's
source) and `dangling` (its target is not in the journal). It is read by the migration and the check only.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "tests"))
from test_links import _loadhv, _owner_key, _device, _gov, _entry, _fact, _project, T0  # noqa: E402
from test_unforget import _act, _hive, PRE  # noqa: E402
sys.path.insert(0, str(PROJECT / "tests" / "oracles"))
import content_evidence_2_4 as oracle_mod  # noqa: E402


def _check(hv, entries):
    gov = hv._governance_state(entries)
    return hv._forgets_grandfathered(entries, gov), hv._content_evidence(entries, gov)


def test_no_owner_means_nothing_to_report(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    d = _device(hv)
    f = _fact(hv, d, "a fact", "2026-01-02T00:00:00Z")
    (hides, dangling), _ = _check(hv, [f, _act(hv, d, f, PRE)])
    assert hides == [] and dangling == []


def test_a_backdated_unsigned_forget_is_reported_as_hiding_the_fact(tmp_path, monkeypatch):
    """The #122 attack: an admitted device appends an unsigned owner-source forget dated before genesis."""
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, _), base = _hive(hv)
    f = _fact(hv, d0, "the backup runs at 02:00", "2026-01-02T00:00:00Z")
    forged = _act(hv, d1, f, PRE)
    (hides, dangling), ev = _check(hv, base + [f, forged])
    assert ev["the backup runs at 02:00"]["forget"] is False          # 3.0: the projection no longer honours it
    assert hides == [f"forget {d1['id']}:{forged['seq']}→{f['node_id']}:{f['seq']}"] and dangling == []


def test_a_forget_whose_target_is_missing_is_dangling(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, _), base = _hive(hv)
    ghost = {"node_id": "DESKTOP-OLD", "seq": 5}                      # a pre-device-identity ref, not in the journal
    (hides, dangling), _ = _check(hv, base + [_fact(hv, d0, "x", "2026-01-02T00:00:00Z"), _act(hv, d1, ghost, PRE)])
    assert hides == [] and dangling == [f"forget {d1['id']}:1→DESKTOP-OLD:5"]


def test_signed_forgets_and_lifted_or_superseded_grandfathered_forgets_are_not_reported(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, _), base = _hive(hv)
    f = _fact(hv, d0, "signed", "2026-01-02T00:00:00Z")
    g = _fact(hv, d0, "lifted", "2026-01-02T00:00:01Z")
    h = _fact(hv, d0, "then signed", "2026-01-02T00:00:02Z")
    entries = base + [f, g, h,
                      _act(hv, d1, f, "2026-01-03T00:00:00Z", owner=a[:2]),              # properly authorised
                      _act(hv, d1, g, PRE),
                      _act(hv, d1, g, "2026-01-04T00:00:00Z", owner=a[:2], unforget=True),  # owner lifted it
                      _act(hv, d1, h, PRE),
                      _act(hv, d1, h, "2026-01-05T00:00:00Z", owner=a[:2])]              # owner forgot it too
    (hides, dangling), ev = _check(hv, entries)
    assert hides == [] and dangling == []
    assert [ev[c]["forget"] for c in ("signed", "lifted", "then signed")] == [True, False, True]


def test_every_reported_fact_is_shown_by_the_projection_and_hidden_by_the_oracle(tmp_path, monkeypatch):
    """The check names what the 2.4 rule hid: the frozen oracle forgets each fact it names, 3.0's projection does not."""
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, d2), base = _hive(hv)
    fs = [_fact(hv, d0, f"fact {i}", f"2026-01-02T00:00:0{i}Z") for i in range(4)]
    entries = base + fs + [_act(hv, d1, fs[0], PRE), _act(hv, d2, fs[1], PRE),
                           _act(hv, d1, fs[2], "2026-01-03T00:00:00Z")]                  # unsigned, post-genesis: ignored
    (hides, _), ev = _check(hv, entries)
    by_label = {f"{f['node_id']}:{f['seq']}": f["payload"]["content"] for f in fs}
    named = {by_label[l.split("→")[1]] for l in hides}
    assert named == {"fact 0", "fact 1"}
    old = oracle_mod.bind(hv)(entries, hv._governance_state(entries))
    assert all(old[c]["forget"] and not ev[c]["forget"] for c in named)
    assert not old["fact 2"]["forget"] and not old["fact 3"]["forget"]


def test_doctor_reports_forget_authz(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    a, (d0, d1, _), base = _hive(hv)
    f = _fact(hv, d0, "the vpn uses wireguard", "2026-01-02T00:00:00Z")
    _project(hv, tmp_path, base + [f, _act(hv, d1, f, PRE)])
    env = dict(os.environ, HIVE_HOME=str(tmp_path))
    r = subprocess.run([sys.executable, str(PROJECT / "hv"), "doctor", "--format", "json"], env=env,
                       capture_output=True, text=True)
    checks = {c["name"]: c for c in json.loads(r.stdout)["checks"]}
    # 3.0 (plan 3.4): an owned hive FAILS while the migration set is not empty, and names the fact by its `h:` id
    # and `hive-mind migrate forget`.
    fa = checks["forget-authz"]
    assert fa["status"] == "fail" and r.returncode != 0
    assert hv._short_id(f["node_id"], f["seq"]) in fa["detail"]
    assert "hive-mind unforget" in fa["detail"] and "hive-mind migrate forget" in fa["detail"] and "#122" in fa["detail"]


# ── 3.0 PR 4: the check is the migration set, not the key (plan 3.4) ──────────────────────────────

sys.path.insert(0, str(PROJECT / "tests"))
import forget_corpus as fc  # noqa: E402


def _verdict(hv, name, policy):
    scn = fc.CORPUS[name](hv)
    entries = fc.journal(hv, scn, policy)
    return hv._forget_authz_check(entries, hv._governance_state(entries))


def test_key_absent_or_legacy_with_a_dependent_fact_fails(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    for policy in ("absent", "legacy"):
        c = _verdict(hv, "pre_genesis_unsigned_latest", policy)
        assert c["status"] == "fail" and c["open"] and len(c["facts"]) == 1 and "migrate forget" in c["detail"]


def test_key_legacy_or_absent_with_nothing_dependent_passes_with_an_explicit_empty_list(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    for name in ("pre_genesis_forget_then_signed_unforget", "pre_genesis_forget_reforgotten_post_genesis"):
        for policy in ("absent", "legacy"):
            c = _verdict(hv, name, policy)
            assert c["status"] == "ok" and "closed: 0 facts depend on a pre-genesis unsigned forget" in c["detail"]


def test_key_owner_with_an_unsigned_pre_genesis_forget_on_the_journal_passes_and_appends_nothing(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    scn = fc.CORPUS["pre_genesis_unsigned_latest"](hv)
    entries = fc.journal(hv, scn, "owner")
    before = list(entries)
    c = hv._forget_authz_check(entries, hv._governance_state(entries))
    assert c["status"] == "ok" and "0 facts depend" in c["detail"] and "open" not in c and entries == before


def test_a_dangling_forget_is_informational_and_does_not_fail(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    c = _verdict(hv, "dangling_pre_genesis_forget", "absent")
    assert c["status"] == "ok" and "dangling: 1" in c["detail"]


def test_no_owner_yet_says_nothing(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    assert _verdict(hv, "pre_owner_hive", "absent") is None
