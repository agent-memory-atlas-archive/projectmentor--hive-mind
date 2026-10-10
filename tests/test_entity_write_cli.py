"""3.0 PR 8 (plan 4.2, 4.5): the entity write path at the CLI. `entity add` says which entity it writes, `--new`
makes a second one of a taken name, `--entity` names one of several that share a name, and a name that more than
one entity holds is an error that lists them, exit 1, with nothing journaled.

Every test drives the real `hv`; the two-device cases use `HIVE_NODE_ID` (unsigned entries, pre-owner, so the
author rule is the node_id) against one journal.
"""
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

import _planes

PROJECT = Path(__file__).resolve().parent.parent


def _run(home, node, *args):
    env = dict(os.environ, HIVE_HOME=str(home))
    if node:
        env["HIVE_NODE_ID"] = node
    return subprocess.run([sys.executable, str(_planes.entry_for(args)), *args], env=env, capture_output=True, text=True)


def _ok(home, node, *args):
    r = _run(home, node, *args)
    assert r.returncode == 0, (args, r.stdout, r.stderr)
    return r


def _sid(node, seq):
    return "h:" + hashlib.sha256(f"{node}:{seq}".encode()).hexdigest()[:10]


def _entity_entries(hive):
    return [e for e in hive.entries() if e["type"] == "entity"]


def _rows(hive):
    return [tuple(r) for r in hive.query("SELECT name, type, ref_node, ref_seq FROM entities ORDER BY ref_node, ref_seq")]


def _sids(hive, name):
    return [_sid(r[0], r[1]) for r in hive.query(
        "SELECT ref_node, ref_seq FROM entities WHERE name = ? ORDER BY ref_node, ref_seq", (name,))]


def test_add_by_name_creates_then_updates_by_identity(hive):
    _ok(hive.home, "devA", "entity", "add", "--name", "David", "--type", "person")
    _ok(hive.home, "devA", "entity", "add", "--name", "David", "--type", "boss", "--attr", '{"k": 1}')
    first, second = _entity_entries(hive)
    assert first["payload"]["new_identity"] is True and "identity_ref" not in first["payload"]
    assert second["payload"]["identity_ref"] == [first["node_id"], first["seq"]] and "new_identity" not in second["payload"]
    assert _rows(hive) == [("David", "boss", first["node_id"], first["seq"])]
    assert "David ·" not in _ok(hive.home, "devA", "entity", "list").stdout          # a unique name is shown bare


def test_new_makes_a_second_entity_and_both_are_shown_with_their_ids(hive):
    _ok(hive.home, "devA", "entity", "add", "--name", "David")
    _ok(hive.home, "devA", "entity", "add", "--name", "Grace")
    _ok(hive.home, "devA", "entity", "add", "--name", "David", "--new", "--type", "other")
    assert sorted(r[0] for r in _rows(hive)) == ["David", "David", "Grace"]
    a, b = _sids(hive, "David")
    out = _ok(hive.home, "devA", "entity", "list").stdout
    assert f"David · {a}" in out and f"David · {b}" in out
    assert re.search(r"\] Grace \(", out)                                              # the unique name stays bare


def test_two_devices_each_adding_david_new_make_two_identities(hive):
    _ok(hive.home, "devA", "entity", "add", "--name", "David", "--new")
    _ok(hive.home, "devB", "entity", "add", "--name", "David", "--new")
    rows = _rows(hive)
    assert len(rows) == 2 and {r[2] for r in rows} == {"devA", "devB"}
    assert len(set(_sids(hive, "David"))) == 2


def test_a_name_held_by_two_entities_is_an_error_that_lists_both_and_writes_nothing(hive):
    _ok(hive.home, "devA", "entity", "add", "--name", "David")
    _ok(hive.home, "devA", "entity", "add", "--name", "David", "--new")
    a, b = _sids(hive, "David")
    hive.run("remember", "a fact about a David")
    before = len(hive.entries())
    for args in (("add", "--name", "David"), ("show", "--name", "David"),
                 ("link", "--name", "David", "--fact-id", hive.sid(1))):
        r = _run(hive.home, "devA", "entity", *args)
        assert r.returncode == 1, (args, r.stdout, r.stderr)
        assert a in r.stderr and b in r.stderr and "--entity" in r.stderr, r.stderr
    assert len(hive.entries()) == before                                               # nothing was journaled


def test_link_by_id_lands_on_the_entity_named(hive):
    _ok(hive.home, "devA", "entity", "add", "--name", "David")
    _ok(hive.home, "devA", "entity", "add", "--name", "David", "--new")
    a, b = _sids(hive, "David")
    hive.run("remember", "the second David likes tea")
    out = _ok(hive.home, "devA", "entity", "link", "--entity", b, "--fact-id", hive.sid(1)).stdout
    assert f"David · {b}" in out
    linked = hive.query("SELECT e.ref_node, e.ref_seq FROM entity_facts ef JOIN entities e ON e.id = ef.entity_id")
    assert [_sid(r[0], r[1]) for r in linked] == [b]
    assert "the second David likes tea" in _ok(hive.home, "devA", "entity", "show", "--entity", b).stdout
    assert "Linked facts" not in _ok(hive.home, "devA", "entity", "show", "--entity", a).stdout


def test_add_by_entity_updates_that_entity_only(hive):
    _ok(hive.home, "devA", "entity", "add", "--name", "David", "--type", "p1")
    _ok(hive.home, "devA", "entity", "add", "--name", "David", "--new", "--type", "p2")
    _a, b = _sids(hive, "David")
    _ok(hive.home, "devA", "entity", "add", "--entity", b, "--type", "p3")
    assert [r[1] for r in _rows(hive)] == ["p1", "p3"]


def test_entity_flag_misuse_is_refused_before_anything_is_written(hive):
    _ok(hive.home, "devA", "entity", "add", "--name", "David")
    _ok(hive.home, "devA", "entity", "add", "--name", "Grace")
    hive.run("remember", "a fact")
    (david,) = _sids(hive, "David")
    fact = hive.sid(1)
    before = len(hive.entries())
    cases = [
        (("add", "--name", "David", "--new", "--entity", david), 2),         # a create and an update at once
        (("add", "--new"), 1),                                               # nothing to create
        (("add", "--entity", fact), 1),                                      # a fact is not an entity
        (("add", "--entity", "3"), 1),                                       # a local id (2.0 refuses them)
        (("add", "--name", "Grace", "--entity", david), 1),                  # the id is David, not Grace
        (("show",), 1),
        (("link", "--fact-id", fact), 1),
    ]
    for args, rc in cases:
        r = _run(hive.home, "devA", "entity", *args)
        assert r.returncode == rc, (args, r.returncode, r.stdout, r.stderr)
    assert len(hive.entries()) == before


def test_a_non_creator_update_is_journaled_but_weigh_only(hive):
    _ok(hive.home, "devA", "entity", "add", "--name", "David", "--type", "mine")
    r = _run(hive.home, "devB", "entity", "add", "--name", "David", "--type", "hacked")
    assert r.returncode == 1 and "created by another device" in r.stderr, r.stderr
    updates = _entity_entries(hive)
    assert len(updates) == 2 and updates[1]["node_id"] == "devB" and "identity_ref" in updates[1]["payload"]
    assert [(r[0], r[1]) for r in _rows(hive)] == [("David", "mine")]
    _ok(hive.home, "devA", "doctor", "rebuild")                                      # and a rebuild agrees
    assert [(r[0], r[1]) for r in _rows(hive)] == [("David", "mine")]


def test_the_incremental_store_equals_a_rebuild(hive):
    for node, args in (("devA", ("--name", "David", "--type", "a")), ("devA", ("--name", "David", "--new")),
                       ("devB", ("--name", "David", "--new", "--attr", '{"x": 1}')), ("devA", ("--name", "Grace")),
                       ("devA", ("--name", "Grace", "--type", "p"))):
        _ok(hive.home, node, "entity", "add", *args)
    sql = ("SELECT name, type, attributes, first_seen, last_updated, ref_node, ref_seq FROM entities "
           "ORDER BY ref_node, ref_seq")
    maps = ("SELECT j.node_id, j.seq, e.ref_node, e.ref_seq FROM journal_index j JOIN entities e ON e.id = j.local_id "
            "WHERE j.kind = 'entity' ORDER BY j.node_id, j.seq")
    live, mapped = [tuple(r) for r in hive.query(sql)], [tuple(r) for r in hive.query(maps)]
    assert len(live) == 4 and len(mapped) == 5
    _ok(hive.home, "devA", "doctor", "rebuild")
    assert [tuple(r) for r in hive.query(sql)] == live
    assert [tuple(r) for r in hive.query(maps)] == mapped


def test_join_and_unjoin_take_the_unprefixed_end_by_id(hive):
    _ok(hive.home, "devA", "entity", "add", "--name", "David")
    _ok(hive.home, "devA", "entity", "add", "--name", "David", "--new")
    _ok(hive.home, "devA", "entity", "add", "--name", "x-hwatch:david")
    a, b = _sids(hive, "David")
    r = _run(hive.home, "devA", "entity", "join", "--name", "x-hwatch:david", "--to", "David")
    assert r.returncode == 1 and a in r.stderr and b in r.stderr                      # ambiguous, nothing written
    assert not [e for e in hive.entries() if e["type"] == "link"]
    _ok(hive.home, "devA", "entity", "join", "--name", "x-hwatch:david", "--to-entity", b)
    assert "x-hwatch:david" in _ok(hive.home, "devA", "entity", "show", "--entity", b).stdout
    assert "x-hwatch:david" not in _ok(hive.home, "devA", "entity", "show", "--entity", a).stdout
    wrong = _run(hive.home, "devA", "entity", "unjoin", "--name", "x-hwatch:david", "--to-entity", a)
    assert wrong.returncode == 1 and "is not joined" in wrong.stderr
    _ok(hive.home, "devA", "entity", "unjoin", "--name", "x-hwatch:david", "--to-entity", b)
    assert "x-hwatch:david" not in _ok(hive.home, "devA", "entity", "show", "--entity", b).stdout


def test_the_mcp_tool_passes_entity_through():
    src = (PROJECT / "integrations" / "mcp" / "hive_mcp.py").read_text()
    assert 'entity: str = ""' in src and 'args += ["--entity", entity.strip()]' in src
