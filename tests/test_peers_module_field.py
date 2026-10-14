"""`api_peers` rows carry `module`: the module name for a module identity (the owner's `admit` marker), else None.

An additive read field. The marker records no host device, so there is no `host` key to invent."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent


def _hv(home, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(home))
    loader = importlib.machinery.SourceFileLoader(f"hvmod_peers_{os.urandom(4).hex()}", str(PROJECT / "hv"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def test_peer_rows_name_the_module_of_a_module_identity(tmp_path, monkeypatch):
    hv = _hv(tmp_path / "home", monkeypatch)
    gov = {"admitted": {"k1:device", "k1:module"}, "principals": {}, "purged": set(),
           "modules": {"k1:module": "hdash"}}
    monkeypatch.setattr(hv, "_governance_state", lambda entries: gov)
    rows = {r["device"]: r for r in hv.api_peers(probe=False)}
    assert rows["k1:module"]["module"] == "hdash"
    assert rows["k1:device"]["module"] is None
    assert all("host" not in r for r in rows.values())


def test_peer_rows_without_a_modules_map_read_none(tmp_path, monkeypatch):
    hv = _hv(tmp_path / "home", monkeypatch)
    gov = {"admitted": {"k1:device"}, "principals": {}, "purged": set()}
    monkeypatch.setattr(hv, "_governance_state", lambda entries: gov)
    assert [r["module"] for r in hv.api_peers(probe=False)] == [None]


def test_peer_rows_carry_seen_at_beside_seen(tmp_path, monkeypatch):
    """`seen_at` is the full timestamp of the device's latest entry (None when it has none); `seen` stays the date."""
    hv = _hv(tmp_path / "home", monkeypatch)
    gov = {"admitted": {"k1:a", "k1:b"}, "principals": {}, "purged": set()}
    monkeypatch.setattr(hv, "_governance_state", lambda entries: gov)
    entries = [{"node_id": "k1:a", "timestamp": "2026-10-14T01:02:03+00:00"}, {"node_id": "k1:a", "timestamp": "2026-10-14T09:30:00+00:00"},
               {"node_id": "k1:a", "timestamp": "2026-10-13T23:00:00+00:00"}]
    monkeypatch.setattr(hv.merkle, "read_all_entries", lambda d: entries)
    rows = {r["device"]: r for r in hv.api_peers(probe=False)}
    assert rows["k1:a"]["seen_at"] == "2026-10-14T09:30:00+00:00" and rows["k1:a"]["seen"] == "2026-10-14"
    assert rows["k1:b"]["seen_at"] is None and rows["k1:b"]["seen"] == "—"
