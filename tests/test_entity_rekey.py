"""3.0 PR 7 (plan 4.3, 4.5): `entities` is keyed by the journal ref of its creating entry, behaviour identical.

The gate has two halves.
  * Byte-identical: a corpus of entity journals is projected twice, once by the live `persist_entity` over the 3.0
    schema and once by the FROZEN 2.4 function (`tests/oracles/persist_entity_2_4.py`) over the 2.4 `entities` DDL.
    Rows, fact attachments, edges, `journal_index` and `entity_view` JSON must be equal to the byte. The identity
    the new columns hold must be the ref `_index_lookup` returns, for the finding-6 journal (a lower `node_id`
    arriving later) as for the rest.
  * The `schema_version` migration: a 2.4-shaped store is rebuilt once and the second run does not touch it.
"""
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))
sys.path.insert(0, str(PROJECT / "tests" / "oracles"))
import persist_entity_2_4 as oracle_mod  # noqa: E402
import test_links as TL  # noqa: E402
from test_entity_authority import T, device_sorted, ent, link, mod_ent, ref  # noqa: E402
from test_module_api import Hive, hive  # noqa: E402,F401
from test_module_write import SRC, fact  # noqa: E402

ORACLE_FILE = PROJECT / "tests" / "oracles" / "persist_entity_2_4.py"
ORACLE_SHA256 = "f6d6e2cf1cf3846cae64e3e7113d3b4bb7c4eeefab8707945ac3d0669088f7e4"


def _frozen_text():
    src = ORACLE_FILE.read_text()
    return src.split("# --- begin frozen 2.4 text ---\n", 1)[1].split("# --- end frozen 2.4 text ---\n", 1)[0]


def test_the_oracle_is_the_frozen_text():
    assert hashlib.sha256(_frozen_text().encode()).hexdigest() == ORACLE_SHA256


# ── the corpus: each scenario returns the entries to add to the fixture's base journal ────────────────────────

def owner_ent(h, dev, name, ts, **kw):
    oseed, opub, _ = h.owner
    return TL._entry(h.hv, dev, "entity", {"name": name, "type": "person", "attributes": {"k": ts}, "source": "manual"},
                     ts, owner=(oseed, opub))


def s_create_and_update(h):
    hv, p = h.hv, h.plain
    return [ent(hv, p, "david", T % 1), ent(hv, p, "david", T % 2, type_="project", attrs={"a": 1}),
            ent(hv, p, "grace", T % 3), ent(hv, p, "naïve café ✓", T % 4, attrs={"k": [1, 2]})]


def s_non_creator_and_owner_rewrite(h):
    hv = h.hv
    other = device_sorted(h)
    return [ent(hv, h.plain, "david", T % 1), ent(hv, other, "david", T % 2, type_="project", attrs={"x": 1}),
            owner_ent(h, other, "david", T % 3), ent(hv, other, "grace", T % 4), ent(hv, h.plain, "grace", T % 5)]


def s_lower_node_arrives_later(h):
    """Finding 6: the device that sorts first wrote the name last. Replay order is (node_id, seq)."""
    hv = h.hv
    low = device_sorted(h, before=h.plain)
    return [ent(hv, h.plain, "david", T % 1), ent(hv, h.plain, "david", T % 2, attrs={"late": False}),
            ent(hv, low, "david", T % 3, attrs={"late": True})]


def s_links_facts_and_joins(h):
    hv, p = h.hv, h.plain
    david = ent(hv, p, "david", T % 1)
    mine = mod_ent(hv, h.mod, "x-hwatch:david", T % 2)
    f1 = TL._entry(hv, p, "fact", fact("david prefers tea"), T % 3)
    f2 = TL._entry(hv, h.mod, "fact", fact("david joined in 2019"), T % 4)
    legacy = TL._entry(hv, p, "entity_fact", {"entity_ref": ref(david), "fact_ref": ref(f1)}, T % 5)
    return [david, mine, f1, f2, legacy, link(hv, p, "entity", david, f1, T % 6),
            link(hv, h.mod, "entity", mine, f2, T % 7, source=SRC),
            link(hv, p, "same-as", mine, david, T % 8), ent(hv, p, "david", T % 9, attrs={"after": 1})]


def s_module_policy_and_odd_attributes(h):
    hv, p = h.hv, h.plain
    raw = TL._entry(hv, p, "entity", {"name": "stringy", "type": "x", "attributes": '{"a": 1}', "source": "manual"}, T % 3)
    bad = TL._entry(hv, p, "entity", {"name": "listy", "type": "x", "attributes": [1], "source": "manual"}, T % 4)
    return [mod_ent(hv, h.mod, "x-hwatch:one", T % 1), mod_ent(hv, h.mod, "x-other:stolen", T % 2),
            mod_ent(hv, h.other, "x-hwatch:stolen", T % 5), mod_ent(hv, h.mod, "plainname", T % 6), raw, bad,
            mod_ent(hv, h.mod, "x-hwatch:one", T % 7, attrs={"again": 1})]


CORPUS = {f.__name__[2:]: f for f in (s_create_and_update, s_non_creator_and_owner_rewrite,
                                      s_lower_node_arrives_later, s_links_facts_and_joins,
                                      s_module_policy_and_odd_attributes)}


# ── projecting under either function ──────────────────────────────────────────────────────────────────────────

def _write(h, entries):
    jd = Path(h.home) / "journal"
    for f in jd.glob("*.jsonl"):
        f.unlink()
    (jd / "2026-01-01.jsonl").write_text("\n".join(json.dumps(e) for e in entries) + "\n")


def _reset_schema(h):
    """Back to a store that has never seen the 3.0 schema, so the next init_db migrates it."""
    conn = h.hv.get_conn()
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '0')")
    conn.commit()
    conn.close()
    h.hv.init_db()


def project_live(h, entries):
    _write(h, entries)
    _reset_schema(h)
    h.hv.rebuild_db()


def project_oracle(h, entries, monkeypatch):
    hv = h.hv
    _write(h, entries)
    _reset_schema(h)
    conn = hv.get_conn()
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("DROP TABLE entity_facts")
    conn.execute("DROP TABLE entities")
    conn.executescript(oracle_mod.OLD_ENTITIES_DDL)
    conn.commit()
    conn.close()
    g = dict(hv.__dict__)
    exec(_frozen_text(), g)
    monkeypatch.setitem(hv._PASS1, "entity", g["persist_entity"])
    monkeypatch.setattr(hv, "persist_entity", g["persist_entity"])
    hv.rebuild_db()


def dump(h):
    """Everything the entity corpus can observe, with the identity columns left out (the oracle has none)."""
    hv = h.hv
    conn = hv.get_conn()
    try:
        q = lambda sql: [list(r) for r in conn.execute(sql)]  # noqa: E731
        out = {
            "entities": q("SELECT id, name, type, attributes, first_seen, last_updated FROM entities ORDER BY id"),
            "entity_facts": q("SELECT e.name, f.content, ef.confidence FROM entity_facts ef "
                              "JOIN entities e ON e.id = ef.entity_id JOIN facts f ON f.id = ef.fact_id "
                              "ORDER BY e.name, f.content"),
            "entity_fact_ids": q("SELECT entity_id, fact_id, confidence FROM entity_facts ORDER BY 1, 2"),
            "links": q("SELECT * FROM links ORDER BY kind, from_kind, from_id, to_kind, to_id, signer"),
            "journal_index": q("SELECT * FROM journal_index ORDER BY node_id, seq"),
            "views": {n: hv.entity_view(conn, n) for (n,) in conn.execute("SELECT name FROM entities ORDER BY id")},
            "views_bare": {n: hv.entity_view(conn, n, joins=False) for (n,) in conn.execute("SELECT name FROM entities ORDER BY id")},
        }
        return json.dumps(out, sort_keys=True, indent=1, default=str)
    finally:
        conn.close()


@pytest.mark.parametrize("name", list(CORPUS))
def test_projection_is_byte_identical_to_the_frozen_2_4_function(hive, monkeypatch, name):
    entries = hive.entries + CORPUS[name](hive)
    project_live(hive, entries)
    live = dump(hive)
    project_oracle(hive, entries, monkeypatch)
    old = dump(hive)
    assert json.loads(live)["entities"], "the scenario projected no entity: it proves nothing"
    assert live == old


@pytest.mark.parametrize("name", list(CORPUS))
def test_the_identity_is_the_ref_the_old_index_lookup_returns(hive, name):
    entries = hive.entries + CORPUS[name](hive)
    project_live(hive, entries)
    conn = hive.hv.get_conn()
    try:
        rows = conn.execute("SELECT id, name, ref_node, ref_seq FROM entities").fetchall()
        assert rows
        by_ref = {(e["node_id"], e["seq"]): e for e in entries}
        for r in rows:
            assert [r["ref_node"], r["ref_seq"]] == hive.hv._index_lookup(conn, "entity", r["id"]), r["name"]
            created_by = by_ref[(r["ref_node"], r["ref_seq"])]
            assert created_by["type"] == "entity" and created_by["payload"]["name"] == r["name"]
        # one identity per name in a legacy-only journal
        assert len({r["name"] for r in rows}) == len(rows)
    finally:
        conn.close()


def test_finding_6_the_group_identity_is_the_first_applied_entry(hive):
    """A lower node_id arriving later is replayed first: the creator the projection keeps is that entry, as before."""
    entries = hive.entries + s_lower_node_arrives_later(hive)
    project_live(hive, entries)
    conn = hive.hv.get_conn()
    try:
        r = conn.execute("SELECT ref_node, ref_seq FROM entities WHERE name = 'david'").fetchone()
        david = [e for e in entries if e["type"] == "entity" and e["payload"]["name"] == "david"]
        first = min(david, key=lambda e: (e["node_id"], e["seq"]))
        assert (r["ref_node"], r["ref_seq"]) == (first["node_id"], first["seq"])
    finally:
        conn.close()


def test_two_rows_may_share_a_name_but_not_an_identity(hive):
    project_live(hive, hive.entries)
    conn = hive.hv.get_conn()
    try:
        conn.execute("INSERT INTO entities (name, ref_node, ref_seq) VALUES ('d', 'n', 1)")
        conn.execute("INSERT INTO entities (name, ref_node, ref_seq) VALUES ('d', 'n', 2)")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO entities (name, ref_node, ref_seq) VALUES ('e', 'n', 2)")
    finally:
        conn.rollback()
        conn.close()


# ── the schema_version migration ──────────────────────────────────────────────────────────────────────────────

def _make_old_store(h):
    """A store shaped as 2.4 left it: UNIQUE name, no identity columns, no schema_version row."""
    conn = h.hv.get_conn()
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("DROP TABLE entity_facts")
    conn.execute("DROP TABLE entities")
    conn.executescript(oracle_mod.OLD_ENTITIES_DDL)
    conn.execute("DELETE FROM meta WHERE key = 'schema_version'")
    conn.commit()
    conn.close()


def _cols(h, table):
    conn = h.hv.get_conn()
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    finally:
        conn.close()


def test_an_old_store_is_rebuilt_once_and_the_second_run_is_a_no_op(hive):
    hv = hive.hv
    entries = hive.entries + s_links_facts_and_joins(hive)
    project_live(hive, entries)
    expect = dump(hive)
    _make_old_store(hive)
    assert "ref_node" not in _cols(hive, "entities")

    hv.init_db()                                      # first run: migrates
    assert {"ref_node", "ref_seq"} <= _cols(hive, "entities")
    conn = hv.get_conn()
    assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == hv.STORE_SCHEMA_VERSION
    assert conn.execute("SELECT count(*) FROM entities").fetchone()[0] == 0       # dropped, not yet rebuilt
    assert conn.execute("SELECT value FROM meta WHERE key = 'projected_journal_sig'").fetchone() is None
    conn.close()

    assert hv._ensure_store_current() is True         # the next store command rebuilds from the journal
    assert dump(hive) == expect                       # and loses nothing
    sentinel = hv.get_conn()
    sentinel.execute("INSERT INTO entities (name, ref_node, ref_seq) VALUES ('sentinel', 'n', 99)")
    sentinel.commit()
    sentinel.close()

    hv.init_db()                                      # second run: untouched
    assert hv._ensure_store_current() is False
    conn = hv.get_conn()
    try:
        assert conn.execute("SELECT count(*) FROM entities WHERE name = 'sentinel'").fetchone()[0] == 1
    finally:
        conn.close()


def test_a_fresh_store_is_born_at_the_current_version(tmp_path, monkeypatch):
    hv = TL._loadhv(tmp_path, monkeypatch)
    hv.init_db()
    conn = hv.get_conn()
    try:
        assert conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()[0] == hv.STORE_SCHEMA_VERSION
    finally:
        conn.close()
    assert {"ref_node", "ref_seq"} <= {r[1] for r in sqlite3.connect(tmp_path / "store.db").execute("PRAGMA table_info(entities)")}


def test_two_concurrent_writers_of_one_name_make_one_row(hive):
    """2.4 folded by name in one upsert under the write lock. The lookup and the insert must stay one write
    transaction: a second writer whose lookup ran before the first committed must not insert a second row."""
    import threading
    import time
    hv = hive.hv
    ea = ent(hv, hive.plain, "race", T % 1, attrs={"w": "A"})
    eb = ent(hv, hive.plain, "race", T % 2, attrs={"w": "B"})
    a = hv.get_conn()
    hv.persist_entity(a, ea)                          # the first writer holds its row uncommitted
    done = []

    def second():
        b = hv.get_conn()
        try:
            hv.persist_entity(b, eb)
            b.commit()
            done.append(True)
        finally:
            b.close()

    t = threading.Thread(target=second)
    t.start()
    time.sleep(0.5)                                   # the second writer's lookup runs while the first is open
    a.commit()
    a.close()
    t.join(30)
    assert done == [True]
    conn = hv.get_conn()
    try:
        rows = conn.execute("SELECT id, name, attributes FROM entities WHERE name = 'race'").fetchall()
        assert len(rows) == 1 and json.loads(rows[0][2]) == {"w": "B"}
    finally:
        conn.close()
