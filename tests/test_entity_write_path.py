"""3.0 PR 8 (plan 4.2, 4.5): an `entity` entry says which entity it writes.

  * `new_identity: true` creates one (a second entity of a taken name is the two-Davids case);
  * `identity_ref` updates the entity whose creating entry that ref names, by the identity's creator, or the owner;
  * neither (every entry a 2.x node wrote) is read by name, exactly as before: PR 7's corpus test still holds.

The journals here are built by hand, so they hold what the gate would refuse and what a peer could have synced.
The last section runs the new fields through the FROZEN 2.4 validator and projection (`tests/oracles`), so that
"a 2.4 node accepts them and shows one entity per name" is asserted against 2.4's text.
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))
sys.path.insert(0, str(PROJECT / "tests" / "oracles"))
import test_links as TL  # noqa: E402
from test_entity_authority import T, device_sorted, ent, link, mod_ent, ref  # noqa: E402
from test_entity_rekey import _frozen_text, project_oracle, project_live, dump  # noqa: E402,F401
from test_module_api import Hive, hive  # noqa: E402,F401
from test_module_write import SRC, journal, post  # noqa: E402

VALIDATOR_FILE = PROJECT / "tests" / "oracles" / "validator_2_4.py"
VALIDATOR_SHA256 = "6b05f9c3c634bec682afe25c08c172b36c55750f3a917c814165394c50bf65eb"
VERDICTS_SHA256 = "2271a271703beb998df2d04c4aec939e20cfed66efcdf86e001c3112ede4d108"


def _entity(hv, dev, name, ts, type_="person", attrs=None, source="manual", owner=None, **fields):
    return TL._entry(hv, dev, "entity", dict({"name": name, "type": type_, "attributes": attrs or {}, "source": source},
                                              **fields), ts, owner=owner)


def new(hv, dev, name, ts, **kw):
    return _entity(hv, dev, name, ts, new_identity=True, **kw)


def upd(hv, dev, target, name, ts, **kw):
    return _entity(hv, dev, name, ts, identity_ref=target if isinstance(target, list) else ref(target), **kw)


def project(h, entries):
    return TL._project(h.hv, h.home, entries)


def ents(conn):
    return [(r["name"], r["type"], r["attributes"], r["ref_node"], r["ref_seq"])
            for r in conn.execute("SELECT * FROM entities ORDER BY ref_node, ref_seq")]


def sid(e):
    return "h:" + hashlib.sha256(f"{e['node_id']}:{e['seq']}".encode()).hexdigest()[:10]


def indexed(conn, e):
    r = conn.execute("SELECT kind, local_id FROM journal_index WHERE node_id = ? AND seq = ?",
                     (e["node_id"], e["seq"])).fetchone()
    return None if r is None else (r["kind"], r["local_id"])


# ── the two-Davids case ───────────────────────────────────────────────────────────────────────────────────────

def test_two_creates_of_one_name_are_two_entities_each_with_its_own_identity(hive):
    hv = hive.hv
    d1 = new(hv, hive.plain, "david", T % 1, attrs={"who": "one"})
    d2 = new(hv, device_sorted(hive), "david", T % 2, attrs={"who": "two"})
    conn = project(hive, hive.entries + [d1, d2])
    got = ents(conn)
    assert len(got) == 2 and {(g[3], g[4]) for g in got} == {tuple(ref(d1)), tuple(ref(d2))}
    assert sorted(json.loads(g[2])["who"] for g in got) == ["one", "two"]
    for e in (d1, d2):
        assert hv._index_lookup(conn, "entity", indexed(conn, e)[1]) == ref(e)


def test_a_link_by_ref_lands_on_the_entity_it_names(hive):
    hv = hive.hv
    d1, d2 = new(hv, hive.plain, "david", T % 1), new(hv, device_sorted(hive), "david", T % 2)
    f1 = TL._fact(hv, hive.plain, "the first david likes tea", T % 3)
    f2 = TL._fact(hv, hive.plain, "the second david likes coffee", T % 4)
    l1, l2 = link(hv, hive.plain, "entity", d1, f1, T % 5), link(hv, hive.plain, "entity", d2, f2, T % 6)
    conn = project(hive, hive.entries + [d1, d2, f1, f2, l1, l2])
    by_entity = {}
    for r in conn.execute("SELECT e.ref_node, e.ref_seq, f.content FROM entity_facts ef JOIN entities e ON e.id = ef.entity_id "
                          "JOIN facts f ON f.id = ef.fact_id"):
        by_entity[(r["ref_node"], r["ref_seq"])] = r["content"]
    assert by_entity == {tuple(ref(d1)): "the first david likes tea", tuple(ref(d2)): "the second david likes coffee"}


def test_a_module_same_as_to_either_david_by_ref_works(hive):
    hv = hive.hv
    d1, d2 = new(hv, hive.plain, "david", T % 1), new(hv, device_sorted(hive), "david", T % 2)
    mine = mod_ent(hv, hive.mod, "x-hwatch:david", T % 3)
    join = link(hv, hive.plain, "same-as", mine, d2, T % 4)
    conn = project(hive, hive.entries + [d1, d2, mine, join])
    rows = {(r["ref_node"], r["ref_seq"]): r["id"] for r in conn.execute("SELECT * FROM entities")}
    one, two = (hv.entity_view(conn, "david", entity_id=rows[tuple(ref(d))]) for d in (d1, d2))
    assert [j["name"] for j in two["joined"]] == ["x-hwatch:david"] and one["joined"] == []


# ── the reading rule ──────────────────────────────────────────────────────────────────────────────────────────

def test_an_update_by_the_creator_applies_and_leaves_the_identity_where_it_was(hive):
    hv = hive.hv
    d1 = new(hv, hive.plain, "david", T % 1, attrs={"v": 1})
    u = upd(hv, hive.plain, d1, "david", T % 2, type_="boss", attrs={"v": 2})
    conn = project(hive, hive.entries + [d1, u])
    assert ents(conn) == [("david", "boss", '{"v": 2}', d1["node_id"], d1["seq"])]
    assert indexed(conn, u) == indexed(conn, d1)


def test_a_non_creators_identity_ref_update_is_weigh_only(hive):
    hv = hive.hv
    early = device_sorted(hive, before=hive.plain)
    d1 = new(hv, early, "david", T % 1, attrs={"v": 1})
    foreign = upd(hv, hive.plain, d1, "david", T % 2, type_="hacked", attrs={"v": 2})
    conn = project(hive, hive.entries + [d1, foreign])
    assert ents(conn) == [("david", "person", '{"v": 1}', d1["node_id"], d1["seq"])]
    assert indexed(conn, foreign) is None
    gov = hv._governance_state(journal(hive))
    assert hv._entity_verdicts(journal(hive), gov) == (set(), {(foreign["node_id"], foreign["seq"])})


def test_an_owner_signed_update_applies_whoever_carries_it(hive):
    hv = hive.hv
    oseed, opub, _ = hive.owner
    d1 = new(hv, hive.plain, "david", T % 1, attrs={"v": 1})
    owned = upd(hv, device_sorted(hive, after=hive.plain), d1, "david", T % 2, type_="ruled", attrs={"v": 3}, owner=(oseed, opub))
    conn = project(hive, hive.entries + [d1, owned])
    assert ents(conn) == [("david", "ruled", '{"v": 3}', d1["node_id"], d1["seq"])]
    assert indexed(conn, owned) == indexed(conn, d1)


def test_an_owner_update_from_a_lower_node_id_than_the_creator_neither_forks_nor_moves_the_identity(hive):
    """Replay is by (node_id, seq): the update is read first, so it finds no entity yet. The projection holds it as
    the entity's row and the create, replayed after, lands on that row. One entity, the create's ref, its time."""
    hv = hive.hv
    oseed, opub, _ = hive.owner
    low = device_sorted(hive, before=hive.plain)
    d1 = new(hv, hive.plain, "david", T % 5, attrs={"v": 1})
    owned = upd(hv, low, d1, "david", T % 2, type_="ruled", attrs={"v": 2}, owner=(oseed, opub))
    conn = project(hive, hive.entries + [owned, d1])
    got = ents(conn)
    assert len(got) == 1 and (got[0][3], got[0][4]) == (d1["node_id"], d1["seq"])
    assert hv._index_lookup(conn, "entity", indexed(conn, owned)[1]) == ref(d1)
    assert conn.execute("SELECT first_seen FROM entities").fetchone()[0] == T % 5
    again = project(hive, hive.entries + [owned, d1])
    assert ents(again) == got


def test_an_update_naming_a_legacy_member_resolves_to_the_names_identity(hive):
    hv = hive.hv
    legacy = ent(hv, hive.plain, "david", T % 1, attrs={"v": 1})
    member = ent(hv, hive.plain, "david", T % 2, attrs={"v": 2})
    u = upd(hv, hive.plain, member, "david", T % 3, attrs={"v": 3})
    conn = project(hive, hive.entries + [legacy, member, u])
    assert ents(conn) == [("david", "person", '{"v": 3}', legacy["node_id"], legacy["seq"])]
    assert indexed(conn, u) == indexed(conn, legacy)


@pytest.mark.parametrize("case", ["dangling", "other-name", "names-an-update", "both-fields"])
def test_an_entry_that_names_no_entity_it_could_write_is_not_applied(hive, case):
    hv = hive.hv
    d1 = new(hv, hive.plain, "david", T % 1, attrs={"v": 1})
    u1 = upd(hv, hive.plain, d1, "david", T % 2, attrs={"v": 2})
    bad = {
        "dangling": upd(hv, hive.plain, ["nobody", 7], "david", T % 3, attrs={"v": 9}),
        "other-name": upd(hv, hive.plain, d1, "grace", T % 3, attrs={"v": 9}),
        "names-an-update": upd(hv, hive.plain, u1, "david", T % 3, attrs={"v": 9}),
        "both-fields": _entity(hv, hive.plain, "david", T % 3, attrs={"v": 9}, new_identity=True, identity_ref=ref(d1)),
    }[case]
    conn = project(hive, hive.entries + [d1, u1, bad])
    assert ents(conn) == [("david", "person", '{"v": 2}', d1["node_id"], d1["seq"])]
    assert indexed(conn, bad) is None
    declined, weigh = hv._entity_verdicts(journal(hive), hv._governance_state(journal(hive)))
    assert (bad["node_id"], bad["seq"]) in declined and not weigh


def test_a_legacy_entry_for_a_name_a_3_0_node_created_updates_that_entity(hive):
    """A 2.x node never writes a second identity: its `add David` is an update of the one David it sees."""
    hv = hive.hv
    d1 = new(hv, hive.plain, "david", T % 1, attrs={"v": 1})
    old = ent(hv, hive.plain, "david", T % 2, "human", {"v": 2})
    conn = project(hive, hive.entries + [d1, old])
    assert ents(conn) == [("david", "human", '{"v": 2}', d1["node_id"], d1["seq"])]
    assert indexed(conn, old) == indexed(conn, d1)


def test_a_later_create_leaves_the_legacy_group_with_the_first_identity(hive):
    """Mixed-journal rule (4.4): the legacy members stay with the first; the create is a second entity."""
    hv = hive.hv
    legacy = ent(hv, hive.plain, "david", T % 1, attrs={"v": 1})
    second = new(hv, hive.plain, "david", T % 2, attrs={"v": 2})
    more = ent(hv, hive.plain, "david", T % 3, "human", {"v": 3})
    conn = project(hive, hive.entries + [legacy, second, more])
    assert ents(conn) == [("david", "human", '{"v": 3}', legacy["node_id"], legacy["seq"]),
                          ("david", "person", '{"v": 2}', second["node_id"], second["seq"])]
    assert indexed(conn, more) == indexed(conn, legacy)


def test_a_create_needs_no_authority_and_replaces_nothing(hive):
    hv = hive.hv
    early = device_sorted(hive, before=hive.plain)
    mine = new(hv, early, "david", T % 1, attrs={"v": 1})
    theirs = new(hv, hive.plain, "david", T % 2, attrs={"v": 2})
    conn = project(hive, hive.entries + [mine, theirs])
    assert sorted(json.loads(g[2])["v"] for g in ents(conn)) == [1, 2]


def test_the_projection_does_not_depend_on_where_the_store_started(hive):
    hv = hive.hv
    low = device_sorted(hive, before=hive.plain)
    entries = [new(hv, hive.plain, "david", T % 1), upd(hv, hive.plain, ["x", 0], "david", T % 9)]
    d2 = new(hv, low, "david", T % 2)
    entries += [d2, upd(hv, low, d2, "david", T % 3, attrs={"late": True}), ent(hv, hive.plain, "grace", T % 4)]
    first = ents(project(hive, hive.entries + entries))
    assert ents(project(hive, hive.entries + list(reversed(entries)))) == first       # the journal is read in (node_id, seq)
    hv.rebuild_db()
    assert ents(hv.get_conn()) == first


# ── a module ──────────────────────────────────────────────────────────────────────────────────────────────────

def test_a_modules_second_create_of_a_name_it_holds_is_declined(hive):
    hv = hive.hv
    one = _entity(hv, hive.mod, "x-hwatch:host", T % 1, source=SRC, new_identity=True)
    two = _entity(hv, hive.mod, "x-hwatch:host", T % 2, source=SRC, new_identity=True, attrs={"dup": 1})
    conn = project(hive, hive.entries + [one, two])
    assert [(g[0], g[3], g[4]) for g in ents(conn)] == [("x-hwatch:host", one["node_id"], one["seq"])]
    assert indexed(conn, two) is None
    declined, _w = hv._entity_verdicts(journal(hive), hv._governance_state(journal(hive)))
    assert declined == {(two["node_id"], two["seq"])}


def test_a_module_updates_its_own_entity_by_ref_and_not_another_writers(hive):
    hv = hive.hv
    mine = _entity(hv, hive.mod, "x-hwatch:host", T % 1, source=SRC, new_identity=True)
    own = _entity(hv, hive.mod, "x-hwatch:host", T % 2, source=SRC, type_="server", identity_ref=ref(mine))
    seeded = ent(hv, hive.plain, "x-hwatch:seed", T % 3, "seed")
    theirs = _entity(hv, hive.mod, "x-hwatch:seed", T % 4, source=SRC, type_="mine", identity_ref=ref(seeded))
    conn = project(hive, hive.entries + [mine, own, seeded, theirs])
    assert {g[0]: g[1] for g in ents(conn)} == {"x-hwatch:host": "server", "x-hwatch:seed": "seed"}
    assert indexed(conn, theirs) is None


def test_the_gate_accepts_the_three_forms_and_refuses_what_the_projection_would_decline(hive):
    first, entry = post(hive, "mod", "entity", {"name": "x-hwatch:host", "type": "host", "source": SRC, "new_identity": True})
    assert first[0] == 200
    ref_ = [entry["node_id"], entry["seq"]]
    assert post(hive, "mod", "entity", {"name": "x-hwatch:host", "type": "server", "source": SRC, "identity_ref": ref_})[0][0] == 200
    assert post(hive, "mod", "entity", {"name": "x-hwatch:host", "type": "legacy", "source": SRC})[0][0] == 200
    before = journal(hive)
    code, body = post(hive, "mod", "entity", {"name": "x-hwatch:host", "source": SRC, "new_identity": True})[0]
    assert (code, body["error"]) == (403, "entity-name-taken")
    code, body = post(hive, "mod", "entity", {"name": "x-hwatch:host", "source": SRC, "new_identity": True, "identity_ref": ref_})[0]
    assert code == 400
    code, body = post(hive, "mod", "entity", {"name": "x-hwatch:host", "source": SRC, "identity_ref": ["nobody", 1]})[0]
    assert (code, body["error"]) == (403, "unknown-entity")
    code, body = post(hive, "mod", "entity", {"name": "x-hwatch:other", "source": SRC, "identity_ref": ref_})[0]
    assert (code, body["error"]) == (400, "identity_ref names an entity of another name")
    code, body = post(hive, "mod", "entity", {"name": "x-hwatch:host", "source": SRC, "identity_ref": "not-a-pair"})[0]
    assert code == 400
    code, body = post(hive, "mod", "entity", {"name": "x-hwatch:host", "source": SRC, "new_identity": "yes"})[0]
    assert code == 400
    assert journal(hive) == before                                     # every refusal wrote nothing


def test_the_gate_refuses_an_update_of_an_entity_another_writer_created(hive):
    hv = hive.hv
    seeded = ent(hv, hive.plain, "x-hwatch:seeded", T % 1, "pre-seeded")
    project(hive, hive.entries + [seeded]).close()
    before = journal(hive)
    code, body = post(hive, "mod", "entity", {"name": "x-hwatch:seeded", "source": SRC, "identity_ref": ref(seeded)})[0]
    assert (code, body["error"]) == (403, "not-entity-owner")
    assert journal(hive) == before


# ── the mutants: each fails the test above it for the reason it is there ─────────────────────────────────────

def test_mutant_reading_every_entry_by_name_collapses_the_two_davids(hive, monkeypatch):
    hv = hive.hv
    monkeypatch.setattr(hv, "_entity_form", lambda entry: ("legacy", None))
    d1, d2 = new(hv, hive.plain, "david", T % 1), new(hv, hive.plain, "david", T % 2)
    assert len(ents(project(hive, hive.entries + [d1, d2]))) == 1


def test_mutant_without_the_authority_check_a_foreign_update_replaces_the_entity(hive, monkeypatch):
    hv = hive.hv
    monkeypatch.setattr(hv, "_link_authority", lambda entry, target, gov: "hard")
    early = device_sorted(hive, before=hive.plain)
    d1 = new(hv, early, "david", T % 1, attrs={"v": 1})
    foreign = upd(hv, hive.plain, d1, "david", T % 2, type_="hacked", attrs={"v": 2})
    assert [g[1] for g in ents(project(hive, hive.entries + [d1, foreign]))] == ["hacked"]


def test_mutant_moving_the_identity_to_the_lowest_entry_shifts_it_when_a_lower_node_updates(hive, monkeypatch):
    hv = hive.hv
    oseed, opub, _ = hive.owner
    low = device_sorted(hive, before=hive.plain)
    d1 = new(hv, hive.plain, "david", T % 5)
    owned = upd(hv, low, d1, "david", T % 2, owner=(oseed, opub))
    conn = project(hive, hive.entries + [owned, d1])
    row = conn.execute("SELECT id FROM entities").fetchone()[0]
    lowest = conn.execute("SELECT node_id, seq FROM journal_index WHERE kind = 'entity' AND local_id = ? "
                          "ORDER BY node_id, seq LIMIT 1", (row,)).fetchone()
    assert [lowest[0], lowest[1]] == ref(owned) != ref(d1)            # what `_index_lookup` returned before 3.0
    assert hv._index_lookup(conn, "entity", row) == ref(d1)           # and what it returns now


# ── a 2.4 node ────────────────────────────────────────────────────────────────────────────────────────────────

def _frozen(hv, begin, end, sha):
    src = VALIDATOR_FILE.read_text()
    text = src.split(begin, 1)[1].split(end, 1)[0]
    assert hashlib.sha256(text.encode()).hexdigest() == sha
    g = dict(hv.__dict__)
    exec(text, g)
    return g


def _frozen_validator(hv):
    return _frozen(hv, "# --- begin frozen 2.4 text ---\n", "# --- end frozen 2.4 text ---\n", VALIDATOR_SHA256)


def test_a_2_4_validator_accepts_the_new_fields(hive):
    hv = hive.hv
    g = _frozen_validator(hv)
    d1 = new(hv, hive.plain, "david", T % 1)
    u = upd(hv, hive.plain, d1, "david", T % 2)
    for e in (d1, u):
        assert e["type"] == "entity"
        assert g["_hostile_problem"](e) is None and g["_payload_problem"](e) is None and g["_unprojectable"](e) is None
    # and the live validator agrees on them, and still refuses a malformed field that 2.4 never looked at
    for e in (d1, u):
        assert hv._hostile_problem(e) is None and hv._payload_problem(e) is None
    bad = upd(hv, hive.plain, ["x", "not-int"], "david", T % 3)
    assert hv._payload_problem(bad) == "identity_ref has the wrong shape" and g["_payload_problem"](bad) is None
    assert hv._payload_problem(_entity(hv, hive.plain, "david", T % 4, new_identity="yes")) == "new_identity has the wrong shape"


def test_a_2_4_node_shows_one_entity_per_name_when_a_second_is_created(hive, monkeypatch):
    """The whole 2.4 reading: its `_entity_verdicts` (keyed by name) and its `persist_entity`, over the 2.4 schema."""
    hv = hive.hv
    g = _frozen(hv, "# --- begin frozen 2.4 verdicts ---\n", "# --- end frozen 2.4 verdicts ---\n", VERDICTS_SHA256)
    monkeypatch.setattr(hv, "_entity_resolution", lambda entries, gov: (*g["_entity_verdicts"](entries, gov), {}))
    d1 = new(hv, hive.plain, "david", T % 1, attrs={"v": 1})
    u = upd(hv, hive.plain, d1, "david", T % 2, type_="boss", attrs={"v": 2})
    d2 = new(hv, device_sorted(hive, after=hive.plain), "david", T % 3, attrs={"v": 3})
    own = new(hv, device_sorted(hive, before=hive.plain), "grace", T % 4, attrs={"v": 1})
    grace2 = new(hv, hive.mod, "x-hwatch:g", T % 5, source=SRC)
    entries = hive.entries + [d1, u, d2, own, grace2]
    project_oracle(hive, entries, monkeypatch)                          # the frozen 2.4 persist_entity over the 2.4 schema
    conn = hv.get_conn()
    try:
        assert [(r["name"], r["type"]) for r in conn.execute("SELECT name, type FROM entities ORDER BY name")] == [
            ("david", "boss"), ("grace", "person"), ("x-hwatch:g", "person")]
    finally:
        conn.close()
