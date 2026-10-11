"""A store written by a newer schema: `hv` names it, `hv doctor` flags it under `database`, and `hv doctor
rebuild` builds the store from the journal whatever `schema_version` and table shapes it finds."""
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

HV = Path(__file__).resolve().parent.parent / "hv"


def _hv(home, *args):
    env = dict(os.environ, HIVE_HOME=str(home), HOME=str(home))
    return subprocess.run([sys.executable, str(HV), *args], env=env, capture_output=True, text=True)


def _stamp_newer(hive):
    """The store as a newer `hv` leaves it: schema_version current+1 and an `entities` table this `hv` cannot use."""
    conn = sqlite3.connect(hive.db)
    conn.execute("DROP TABLE entity_facts")
    conn.execute("DROP TABLE entities")
    conn.execute("CREATE TABLE entities (uid TEXT PRIMARY KEY, label TEXT)")
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '4')")
    conn.commit()
    conn.close()


def _database_check(hive):
    r = _hv(hive.home, "doctor", "--format", "json")
    return next(c for c in json.loads(r.stdout)["checks"] if c["name"] == "database")


def test_a_newer_store_is_named_flagged_and_rebuilt_from_scratch(hive):
    assert _hv(hive.home, "remember", "alpha fact", "--tags", "t").returncode == 0
    assert _hv(hive.home, "entity", "add", "--name", "Ada", "--type", "person").returncode == 0
    _stamp_newer(hive)

    r = _hv(hive.home, "search", "alpha")
    assert r.returncode != 0
    assert "newer schema (4)" in r.stderr and "busy" not in r.stderr

    check = _database_check(hive)
    assert check["status"] == "fail" and "newer schema (4)" in check["detail"]

    r = _hv(hive.home, "doctor", "rebuild")
    assert r.returncode == 0, r.stderr
    assert hive.query("SELECT value FROM meta WHERE key = 'schema_version'")[0][0] == "3"
    assert [tuple(x) for x in hive.query("SELECT name FROM entities")] == [("Ada",)]
    assert not list(hive.home.glob("store.db.rebuild*"))

    r = _hv(hive.home, "search", "alpha")
    assert r.returncode == 0 and "alpha fact" in r.stdout
    assert _database_check(hive)["status"] == "ok"
    doctor = json.loads(_hv(hive.home, "doctor", "--format", "json").stdout)
    assert not [c for c in doctor["checks"] if c["name"] in ("database", "entity-identity") and c["status"] != "ok"]


def test_rebuild_replaces_a_store_that_is_not_a_database(hive):
    assert _hv(hive.home, "remember", "beta fact", "--tags", "t").returncode == 0
    for f in hive.home.glob("store.db-*"):
        f.unlink()
    hive.db.write_bytes(b"not a sqlite file" * 100)
    r = _hv(hive.home, "doctor", "rebuild")
    assert r.returncode == 0, r.stderr
    assert "beta fact" in _hv(hive.home, "search", "beta").stdout
