"""Release 3.0 PR 1 and PR 4 (plan 3.6): the frozen 2.4 `_content_evidence` oracle, and the forget corpus it is
checked against.

PR 1's gate was oracle == live on every corpus journal. PR 4 deleted the grandfather arm, so the gate is now the
differential (plan 3.4, 3.6): on every corpus journal, under each `forget_writers` setting,
  * MIGRATED: after the owner re-issues the migration set, the live projection equals the oracle (the forget set
    and every other field), and the oracle itself is unchanged by the re-issues;
  * UNMIGRATED: the live projection differs from the oracle on exactly the migration set `--check` prints, in the
    forget flag only: no more and no fewer;
  * the pre-owner source-tag path is pinned: no owner, nothing differs;
  * an arm-restored mutant of `_content_evidence` fails the differential.
The corpus is also pinned by hand-written expectations, so "oracle equals live" cannot pass by both being wrong
the same way.
"""

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "tests"))
sys.path.insert(0, str(PROJECT / "tests" / "oracles"))
from test_links import _loadhv, _project  # noqa: E402
from test_unforget import FORGET_FLOOR, _row  # noqa: E402
import forget_corpus as fc  # noqa: E402
import content_evidence_2_4 as oracle_mod  # noqa: E402

ORACLE_FILE = PROJECT / "tests" / "oracles" / "content_evidence_2_4.py"
ORACLE_SHA256 = "d468fb88d4035c44aae240aca679a0e6082d624f6220a8f907ceb6f50035b90d"
FROZEN_AT = "53a3eeb"
CASES = [(name, policy) for name in fc.CORPUS for policy in fc.POLICIES]


def _frozen_text():
    src = ORACLE_FILE.read_text()
    return src.split("# --- begin frozen 2.4 text ---\n", 1)[1].split("# --- end frozen 2.4 text ---\n", 1)[0]


def _forgotten(result):
    return {c for c, ev in result.items() if ev["forget"]}


def _build(tmp_path, monkeypatch, name, policy):
    hv = _loadhv(tmp_path, monkeypatch)
    scn = fc.CORPUS[name](hv)
    return hv, scn, fc.journal(hv, scn, policy)


# ── the oracle is the 2.4 text ─────────────────────────────────────────────────────────────────────

def test_the_frozen_text_is_pinned():
    assert hashlib.sha256(_frozen_text().encode()).hexdigest() == ORACLE_SHA256, \
        "tests/oracles/content_evidence_2_4.py is frozen; it is never edited"


def test_the_frozen_text_is_what_2_4_shipped():
    shown = subprocess.run(["git", "-C", str(PROJECT), "show", f"{FROZEN_AT}:hv"], capture_output=True, text=True)
    if shown.returncode != 0:
        pytest.skip(f"{FROZEN_AT} is not in this checkout (shallow clone)")
    import ast
    tree = ast.parse(shown.stdout)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_content_evidence")
    shipped = "\n".join(shown.stdout.splitlines()[node.lineno - 1:node.end_lineno]) + "\n"
    assert _frozen_text() == shipped


def test_the_oracle_is_a_separate_function_from_the_live_one(tmp_path, monkeypatch):
    hv = _loadhv(tmp_path, monkeypatch)
    bound = oracle_mod.bind(hv)
    assert bound is not hv._content_evidence and bound.__code__ is not hv._content_evidence.__code__


# ── the gate: the differential, on every corpus journal ────────────────────────────────────────────

REISSUE_TS = "2027-01-01T00:00:00Z"


def _migrate(hv, scn, entries, m):
    """What `migrate forget` appends: an owner-signed retract of each fact in the set, by the CURRENT owner,
    positioned after everything in the corpus (the real routine signs with the key it holds, at now)."""
    cur = scn.current or scn.owner
    return [*entries, *(fc._forget_at(hv, scn.devs[1], {"node_id": f["ref"][0], "seq": f["ref"][1]}, REISSUE_TS,
                                      owner=cur[:2]) for f in m["facts"])]


def _rest(ev):
    return {k: v for k, v in ev.items() if k not in ("forget", "acts")}


def _differential(hv, scn, entries, evidence):
    """Unmigrated, `evidence` (a `_content_evidence`) differs from the oracle by exactly the migration set;
    migrated, it equals the oracle. Raises AssertionError otherwise."""
    gov = hv._governance_state(entries)
    oracle = oracle_mod.bind(hv)
    m = hv._forget_migration(entries, gov)
    old, new = oracle(entries, gov, False), evidence(entries, gov, False)
    assert set(old) == set(new)
    assert all(_rest(old[c]) == _rest(new[c]) for c in old)              # nothing but the forget flag can differ
    assert {c for c in old if old[c]["forget"] != new[c]["forget"]} == {f["content"] for f in m["facts"]}
    assert _forgotten(new) <= _forgotten(old)                             # closing never forgets more
    migrated = _migrate(hv, scn, entries, m) if m["facts"] else entries
    gov2 = hv._governance_state(migrated)
    after = evidence(migrated, gov2, False)
    assert _forgotten(after) == _forgotten(old) == _forgotten(oracle(migrated, gov2, False))
    assert all(_rest(oracle(migrated, gov2, False)[c]) == _rest(after[c]) for c in after)
    assert hv._forget_migration(migrated, gov2)["facts"] == []            # and the check says so


@pytest.mark.parametrize("name,policy", CASES)
def test_the_differential(tmp_path, monkeypatch, name, policy):
    hv, scn, entries = _build(tmp_path, monkeypatch, name, policy)
    _differential(hv, scn, entries, hv._content_evidence)


@pytest.mark.parametrize("name,policy", CASES)
def test_where_the_set_is_empty_the_live_projection_equals_the_oracle(tmp_path, monkeypatch, name, policy):
    """Empty set: same forget set and same evidence. `acts` (the per-act honoured flags `hv feed` reads) still
    differs by the unsigned pre-genesis acts the oracle honoured and 3.0 does not, so it is compared on the pre-owner
    path only (test_the_pre_owner_source_tag_path_is_pinned)."""
    hv, scn, entries = _build(tmp_path, monkeypatch, name, policy)
    gov = hv._governance_state(entries)
    if hv._forget_migration(entries, gov)["facts"]:
        pytest.skip("a non-empty set is the differential's case")
    oracle = oracle_mod.bind(hv)
    for links in (True, False):
        old, new = oracle(entries, gov, links), hv._content_evidence(entries, gov, links)
        assert set(old) == set(new)
        assert all(_rest(old[c]) == _rest(new[c]) and old[c]["forget"] == new[c]["forget"] for c in old)


def test_the_set_is_non_empty_somewhere_in_the_corpus(tmp_path, monkeypatch):
    """The differential is not vacuous: some journals have a non-empty set, some an empty one."""
    sizes = {}
    for name in fc.CORPUS:
        hv, scn, entries = _build(tmp_path, monkeypatch, name, "absent")
        sizes[name] = len(hv._forget_migration(entries, hv._governance_state(entries))["facts"])
    assert sizes["pre_genesis_unsigned_latest"] == 1 and sizes["member_device_backdated"] == 2
    assert sizes["owner_transfer_between"] == 1 and sizes["closed_at_genesis"] == 0 and sizes["pre_owner_hive"] == 0


def test_the_pre_owner_source_tag_path_is_pinned(tmp_path, monkeypatch):
    """No owner yet: a source-tag forget is honoured, an unforget is not, a peer retract is evidence; the 3.0 projection
    equals the oracle exactly and the migration set is empty."""
    for policy in fc.POLICIES:
        hv, scn, entries = _build(tmp_path, monkeypatch, "pre_owner_hive", policy)
        gov = hv._governance_state(entries)
        assert not gov["owner_id"]
        live = hv._content_evidence(entries, gov)
        assert live == oracle_mod.bind(hv)(entries, gov)
        assert _forgotten(live) == {"pre-owner: fact 0", "pre-owner: fact 1"}
        assert hv._forget_migration(entries, gov)["facts"] == []


def _arm_restored(hv):
    """`hv._content_evidence` with the 2.4 grandfather arm put back (the text 3.0 deleted)."""
    import ast
    import inspect
    src = inspect.getsource(hv._content_evidence)
    assert "or (at is None and not unforget and grandfather)" not in src
    mutated = src.replace(
        "                honored = _owner_signed_at(signer, pos, gov)\n",
        "                at = _owner_at(timeline, pos)\n"
        "                honored = _owner_signed_at(signer, pos, gov) or (at is None and not unforget and grandfather)\n"
    ).replace(
        "    owner_acts = {}  ",
        "    timeline = gov.get('owner_timeline') or []\n"
        "    grandfather = (gov.get('config') or {}).get('forget_writers', 'legacy') != 'owner'\n    owner_acts = {}  ", 1)
    assert mutated != src and "grandfather" in mutated
    ast.parse(mutated)
    ns = dict(vars(hv))
    exec(compile(mutated, "<arm-restored mutant>", "exec"), ns)
    return ns["_content_evidence"]


def test_a_mutant_with_the_arm_restored_fails_the_differential(tmp_path, monkeypatch):
    hv, scn, entries = _build(tmp_path, monkeypatch, "pre_genesis_unsigned_latest", "absent")
    mutant = _arm_restored(hv)
    gov = hv._governance_state(entries)
    assert _forgotten(mutant(entries, gov, False)) == _forgotten(oracle_mod.bind(hv)(entries, gov, False))   # it IS the old rule
    with pytest.raises(AssertionError):
        _differential(hv, scn, entries, mutant)
    failed = []
    for name in fc.CORPUS:
        h, sc, es = _build(tmp_path, monkeypatch, name, "absent")
        try:
            _differential(h, sc, es, _arm_restored(h))
        except AssertionError:
            failed.append(name)
    assert {"pre_genesis_unsigned_latest", "member_device_backdated", "owner_transfer_between"} <= set(failed)


# ── the corpus says what the 2.4 rule says ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,policy", CASES)
def test_corpus_expectations(tmp_path, monkeypatch, name, policy):
    hv, scn, entries = _build(tmp_path, monkeypatch, name, policy)
    gov = hv._governance_state(entries)
    if scn.owner is not None:
        assert gov["config"].get("forget_writers", "legacy") == fc.effective(scn, policy)
    column = 1 if fc.effective(scn, policy) == "owner" else 0
    want = {c for c, flags in scn.expect.items() if flags[column]}
    assert _forgotten(oracle_mod.bind(hv)(entries, gov)) == want


@pytest.mark.parametrize("name", list(fc.CORPUS))
def test_the_grandfather_arm_is_what_the_policy_switches(tmp_path, monkeypatch, name):
    """`legacy` and `owner` differ on exactly the contents whose expectation differs; nothing else moves."""
    hv, scn, _ = _build(tmp_path, monkeypatch, name, "absent")
    oracle = oracle_mod.bind(hv)
    legacy, owner = (_forgotten(oracle(es, hv._governance_state(es)))
                     for es in (fc.journal(hv, scn, "legacy"), fc.journal(hv, scn, "owner")))
    assert legacy - owner == {c for c, (lg, ow) in scn.expect.items() if lg and not ow}
    assert owner - legacy == set()                                   # closing never forgets more


def test_the_corpus_covers_what_the_plan_names():
    assert set(fc.CORPUS) >= {
        "pre_genesis_unsigned_latest", "pre_genesis_forget_then_signed_unforget",
        "pre_genesis_forget_reforgotten_post_genesis", "member_device_backdated", "owner_transfer_between",
        "owner_succession_between", "owner_election_between", "dangling_pre_genesis_forget",
        "shared_content_one_forgotten", "pre_owner_hive", "closed_at_genesis"}
    assert set(fc.POLICIES) == {"absent", "legacy", "owner"}


# ── the corpus is real: the live projection hides what the oracle says is forgotten ────────────────

@pytest.mark.parametrize("name,policy", CASES)
def test_projection_hides_exactly_the_forgotten_contents(tmp_path, monkeypatch, name, policy):
    hv, scn, entries = _build(tmp_path, monkeypatch, name, policy)
    conn = _project(hv, tmp_path, entries)
    hidden = {r["content"] for r in conn.execute("SELECT content, confidence FROM facts") if r["confidence"] == FORGET_FLOOR}
    assert hidden == _forgotten(hv._content_evidence(entries, hv._governance_state(entries)))
