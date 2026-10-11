"""3.0 PR 9 (plan 4.4, 4.5): the entity surfaces and the store migration.

  * A store built by the FROZEN 2.4 `init_db` (`tests/oracles/init_db_2_4.py`) is migrated once by a 3.0 `hv`; the
    second run does not touch it.
  * `hv doctor` reports `entity-identity` ok on the migrated store, `N entities, M names shared`, and fails on a
    store that is not at the current schema or whose legacy name group was split.
  * The dashboard `/api/entities`, the CLI and the MCP `hive_entity` call (which is the CLI) show the id suffix
    only for a name more than one entity holds.
"""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "tests" / "oracles"))
import init_db_2_4  # noqa: E402

HV = PROJECT / "hv"


def _hv(home, *args, node=None):
    env = dict(os.environ, HIVE_HOME=str(home))
    if node:
        env["HIVE_NODE_ID"] = node
    return subprocess.run([sys.executable, str(HV), *args], env=env, capture_output=True, text=True)


def _ok(home, *args, node=None):
    r = _hv(home, *args, node=node)
    assert r.returncode == 0, (args, r.stdout, r.stderr)
    return r


def _sid(node, seq):
    return "h:" + hashlib.sha256(f"{node}:{seq}".encode()).hexdigest()[:10]


def _as_2_4(hive):
    """Replace the hive's store with one the 2.4 `init_db` builds (empty projection), as a node that updates from
    2.4 has it: UNIQUE `name`, no identity columns, no schema_version row."""
    for f in hive.home.glob("store.db*"):
        f.unlink()
    init_db_2_4.build(hive.home)
    conn = sqlite3.connect(hive.db)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(entities)")}
    has_version = conn.execute("SELECT 1 FROM meta WHERE key = 'schema_version'").fetchone()
    conn.close()
    assert "ref_node" not in cols and has_version is None


def _doctor(home):
    r = _hv(home, "doctor", "--format", "json")
    return next(c for c in json.loads(r.stdout)["checks"] if c["name"] == "entity-identity")


def test_the_frozen_2_4_init_db_is_unedited():
    assert hashlib.sha256(init_db_2_4.SRC.encode()).hexdigest() == init_db_2_4.SRC_SHA256


def test_a_2_4_store_is_migrated_once_and_the_second_run_is_a_no_op(hive):
    _ok(hive.home, "entity", "add", "--name", "Ada", "--type", "person")
    _ok(hive.home, "entity", "add", "--name", "Ada", "--type", "engineer")
    _ok(hive.home, "entity", "add", "--name", "Hive", "--type", "project")
    want = [tuple(r) for r in hive.query("SELECT name, type, ref_node, ref_seq FROM entities ORDER BY name")]
    assert len(want) == 2
    _as_2_4(hive)

    r = _ok(hive.home, "entity", "list")                      # any store command: init_db migrates, the rebuild fills
    assert "Ada" in r.stdout and "Hive" in r.stdout
    assert [tuple(x) for x in hive.query("SELECT name, type, ref_node, ref_seq FROM entities ORDER BY name")] == want
    assert hive.query("SELECT value FROM meta WHERE key = 'schema_version'")[0][0] == "3"

    conn = sqlite3.connect(hive.db)                           # a sentinel a rebuild would erase
    conn.execute("UPDATE entities SET last_updated = 'SENTINEL' WHERE name = 'Ada'")
    conn.commit()
    conn.close()
    _ok(hive.home, "entity", "list")
    _hv(hive.home, "doctor")                                  # (exit 1 here: authenticity, a modified checkout)
    assert hive.query("SELECT last_updated FROM entities WHERE name = 'Ada'")[0][0] == "SENTINEL"


def test_doctor_entity_identity_passes_after_the_migration(hive):
    _ok(hive.home, "entity", "add", "--name", "Ada")
    _as_2_4(hive)
    _ok(hive.home, "entity", "list")
    c = _doctor(hive.home)
    assert c["status"] == "ok" and c["detail"] == "1 entity, 0 names shared by more than one", c


def test_doctor_counts_a_shared_name(hive):
    _ok(hive.home, "entity", "add", "--name", "David", node="devA")
    _ok(hive.home, "entity", "add", "--name", "David", "--new", node="devB")
    _ok(hive.home, "entity", "add", "--name", "Solo")
    c = _doctor(hive.home)
    assert c["status"] == "ok" and c["detail"] == "3 entities, 1 name shared by more than one", c


def _load_hv(home):
    import importlib.util
    from importlib.machinery import SourceFileLoader
    os.environ["HIVE_HOME"] = str(home)
    loader = SourceFileLoader("hv_pr9", str(HV))
    spec = importlib.util.spec_from_loader("hv_pr9", loader)
    hv = importlib.util.module_from_spec(spec)
    loader.exec_module(hv)
    return hv


@pytest.fixture
def live_hv(hive, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(hive.home))
    return _load_hv(hive.home)


def test_doctor_fails_a_stale_schema_and_an_entity_without_a_ref(hive, live_hv):
    _ok(hive.home, "entity", "add", "--name", "Ada")
    hv = live_hv
    conn = hv.get_conn()
    entries = hv.merkle.read_all_entries(hv.JOURNAL_DIR)
    assert hv._entity_identity_check(conn, entries)["status"] == "ok"
    conn.execute("UPDATE meta SET value = '2' WHERE key = 'schema_version'")
    c = hv._entity_identity_check(conn, entries)
    assert c["status"] == "fail" and "schema 2" in c["detail"] and "doctor rebuild" in c["detail"]
    conn.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (hv.STORE_SCHEMA_VERSION,))
    conn.execute("UPDATE entities SET ref_node = NULL")
    c = hv._entity_identity_check(conn, entries)
    assert c["status"] == "fail" and "no identity ref" in c["detail"]
    conn.close()


def test_doctor_fails_a_legacy_name_group_split_across_entities(hive, live_hv):
    hv = live_hv
    hv.init_db()
    conn = hv.get_conn()
    legacy = [{"type": "entity", "node_id": "devA", "seq": s, "payload": {"name": "Ada", "type": "person"}}
              for s in (1, 2)]
    for i, e in enumerate(legacy, start=1):
        conn.execute("INSERT INTO entities (id, name, type, attributes, ref_node, ref_seq) VALUES (?, 'Ada', 'x', '{}', ?, ?)",
                     (i, e["node_id"], e["seq"]))
    conn.execute("INSERT INTO journal_index (node_id, seq, kind, local_id) VALUES ('devA', 1, 'entity', 1)")
    conn.execute("INSERT INTO journal_index (node_id, seq, kind, local_id) VALUES ('devA', 2, 'entity', 1)")
    assert hv._entity_identity_check(conn, legacy)["status"] == "ok"          # both fold into one identity
    conn.execute("UPDATE journal_index SET local_id = 2 WHERE seq = 2")
    c = hv._entity_identity_check(conn, legacy)                                # the second became its own entity
    assert c["status"] == "fail" and "Ada" in c["detail"]
    created = [dict(legacy[1], payload={"name": "Ada", "type": "person", "new_identity": True})]
    assert hv._entity_identity_check(conn, legacy[:1] + created)["status"] == "ok"   # mixed journal: two identities allowed
    conn.close()


def test_suffix_only_for_repeats_on_every_surface(hive):
    _ok(hive.home, "entity", "add", "--name", "David", node="devA")
    _ok(hive.home, "entity", "add", "--name", "David", "--new", node="devB")
    _ok(hive.home, "entity", "add", "--name", "Solo")
    ids = [_sid(r[0], r[1]) for r in hive.query("SELECT ref_node, ref_seq FROM entities WHERE name = 'David' ORDER BY id")]
    # the CLI, which is what the MCP `hive_entity` list/show actions run (`entity <action> [--name N]`)
    out = _ok(hive.home, "entity", "list").stdout
    assert "Solo (" in out and "Solo ·" not in out
    for i in ids:
        assert f"David · {i}" in out
    # the dashboard API
    sys.path.insert(0, str(PROJECT))
    import importlib.util
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("hv_pr9b", str(HV))
    spec = importlib.util.spec_from_loader("hv_pr9b", loader)
    hv = importlib.util.module_from_spec(spec)
    old = os.environ.get("HIVE_HOME")
    os.environ["HIVE_HOME"] = str(hive.home)
    try:
        loader.exec_module(hv)
        got = hv.api_entities()
    finally:
        if old is None:
            os.environ.pop("HIVE_HOME", None)
        else:
            os.environ["HIVE_HOME"] = old
    labels = {e["sid"]: e["label"] for e in got["entities"]}
    assert got["shared_names"] == 1
    for i in ids:
        assert labels[i] == f"David · {i}"
    assert [e["label"] for e in got["entities"] if e["name"] == "Solo"] == ["Solo"]


def test_mcp_hive_entity_is_the_cli():
    src = (PROJECT / "integrations" / "mcp" / "hive_mcp.py").read_text()
    body = src[src.index("def hive_entity"):]
    body = body[:body.index("\n@mcp.tool") if "\n@mcp.tool" in body else len(body)]
    assert 'args = ["entity", action]' in body and "_run_hv(args)" in body     # no formatting of its own


def test_the_dashboard_entities_route_is_loopback_only_and_served(hive):
    daemon = (PROJECT / "hive_sync_daemon.py").read_text()
    assert '"/api/entities"' in daemon.split("_LOOPBACK_ONLY = frozenset({")[1].split("})")[0]
    js = (PROJECT / "dashboard" / "app.js").read_text()
    assert "/api/entities" in js and "e.label" in js


def test_the_update_reports_entity_identity_after_the_rebuild(tmp_path):
    """`_update.sh`'s `_entity_identity_report`, run the way the update runs it (HIVE_DIR is the hive home): ok on a
    migrated store, FAIL (exit 1) on a store left at the old schema."""
    home = tmp_path / "install"
    home.mkdir()
    for f in list(PROJECT.glob("*.py")) + [HV]:
        (home / f.name).symlink_to(f)
    script = (PROJECT / "scripts" / "installer" / "_update.sh").read_text()
    fn = script[script.index("_entity_identity_report() {"):]
    fn = fn[:fn.index("\n}\n") + 3]

    def report():
        return subprocess.run(["bash", "-c", fn + '\n_entity_identity_report'], env=dict(os.environ, HIVE_DIR=str(home)),
                              capture_output=True, text=True)

    assert subprocess.run([sys.executable, str(home / "hv"), "entity", "add", "--name", "Ada"],
                          env=dict(os.environ, HIVE_HOME=str(home)), capture_output=True).returncode == 0
    r = report()
    assert r.returncode == 0 and r.stdout.strip() == "ok: 1 entity, 0 names shared by more than one", (r.stdout, r.stderr)
    conn = sqlite3.connect(home / "store.db")
    conn.execute("UPDATE meta SET value = '2' WHERE key = 'schema_version'")
    conn.commit()
    conn.close()
    r = report()
    assert r.returncode == 1 and r.stdout.startswith("FAIL: the store is at schema 2"), (r.stdout, r.stderr)
