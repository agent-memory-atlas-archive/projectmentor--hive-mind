"""Session telemetry left core in 3.1 for the hwatch module (`hwatch telemetry`; its tests live in
projectmentor/hive-mind-hwatch). Core keeps `hv telemetry` as a forwarder and a read-only view of the store for the
loopback `/api/telemetry`. `hv` runs the module through `hive-mind module run` as a subprocess and imports nothing."""
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
HV = PROJECT / "hv"


def _env(tmp_path, installed, rc=7):
    home = tmp_path / "home"
    home.mkdir()
    if installed:
        (home / ".modules.json").write_text(json.dumps({"hwatch": {}}))
    log = tmp_path / "argv.txt"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "hive-mind"
    stub.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {log}\necho the-module-says-hello\necho oops >&2\nexit {rc}\n")
    stub.chmod(0o755)
    return dict(os.environ, HIVE_HOME=str(home), PATH=f"{bindir}:{os.environ['PATH']}"), log


def hv(env, *args):
    return subprocess.run([sys.executable, str(HV), *args], env=env, capture_output=True, text=True)


def test_report_and_list_forward_with_every_option_and_return_the_modules_status(tmp_path):
    env, log = _env(tmp_path, installed=True)
    r = hv(env, "telemetry", "report", "--since", "7d", "--by", "project", "--format", "json")
    assert r.returncode == 7 and "the-module-says-hello" in r.stdout
    assert log.read_text().split() == ["module", "run", "hwatch", "--", "telemetry", "report", "--since", "7d", "--by",
                                       "project", "--format", "json"]
    hv(env, "telemetry", "list", "--limit", "3")
    assert log.read_text().split() == ["module", "run", "hwatch", "--", "telemetry", "list", "--limit", "3"]
    hv(env, "telemetry")
    assert log.read_text().split() == ["module", "run", "hwatch", "--", "telemetry"]


def test_record_forwards_silently_and_exits_0_whatever_the_module_does(tmp_path):
    env, log = _env(tmp_path, installed=True, rc=7)
    r = hv(env, "telemetry", "record", "--event", "end", "--agent", "claude-code", "--identity", "u@n", "--session", "s1",
           "--cwd", "/tmp", "--transcript", "/tmp/t.jsonl")
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    assert log.read_text().split() == ["module", "run", "hwatch", "--", "telemetry", "record", "--event", "end", "--agent",
                                       "claude-code", "--identity", "u@n", "--session", "s1", "--cwd", "/tmp",
                                       "--transcript", "/tmp/t.jsonl"]


def test_record_without_the_module_prints_nothing_exits_0_and_runs_nothing(tmp_path):
    env, log = _env(tmp_path, installed=False)
    r = hv(env, "telemetry", "record", "--event", "start", "--agent", "claude-code")
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "") and not log.exists()


def test_record_with_the_module_installed_but_no_launcher_on_path_is_silent_too(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".modules.json").write_text(json.dumps({"hwatch": {}}))
    env = dict(os.environ, HIVE_HOME=str(home), PATH=str(Path(sys.executable).parent))
    r = hv(env, "telemetry", "record", "--event", "start")
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")


@pytest.mark.parametrize("verb", ["report", "list"])
def test_report_and_list_without_the_module_print_the_install_line_and_run_nothing(tmp_path, verb):
    env, log = _env(tmp_path, installed=False)
    r = hv(env, "telemetry", verb)
    assert r.returncode == 1 and not log.exists()
    assert "hive-mind module install hwatch --from https://github.com/projectmentor/hive-mind-hwatch" in r.stdout


def test_report_installed_but_no_launcher_on_path_says_so(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".modules.json").write_text(json.dumps({"hwatch": {}}))
    env = dict(os.environ, HIVE_HOME=str(home), PATH=str(Path(sys.executable).parent))
    r = hv(env, "telemetry", "report")
    assert r.returncode == 1 and "hive-mind module run hwatch -- telemetry" in r.stdout


def test_hv_help_names_the_forwarder_and_core_has_no_telemetry_writer():
    r = hv(dict(os.environ), "telemetry", "--help")
    assert "hwatch" in r.stdout
    src = (PROJECT / "hivemind" / "parts").glob("*.py")
    text = "\n".join(p.read_text() for p in src)
    for gone in ("INSERT OR IGNORE INTO telemetry_sessions", "CREATE TABLE IF NOT EXISTS telemetry_sessions", "def _telemetry_record"):
        assert gone not in text, gone
    assert not (PROJECT / "hivemind" / "parts" / "16_telemetry.py").exists()


def _store(home):
    d = home / ".telemetry"
    d.mkdir(parents=True)
    conn = sqlite3.connect(d / "telemetry.db")
    conn.execute("""CREATE TABLE telemetry_sessions (
        node_id TEXT NOT NULL, session_id TEXT NOT NULL, agent TEXT NOT NULL, agent_identity TEXT NOT NULL DEFAULT '',
        os_user TEXT, ip TEXT, project TEXT, cwd TEXT, started_at TEXT, ended_at TEXT, duration_s REAL,
        tokens_in INTEGER DEFAULT 0, tokens_out INTEGER DEFAULT 0, cache_read INTEGER DEFAULT 0,
        cache_creation INTEGER DEFAULT 0, cost_usd REAL, models TEXT, updated_at TEXT,
        PRIMARY KEY (node_id, session_id, agent, agent_identity))""")
    conn.execute("INSERT INTO telemetry_sessions (node_id, session_id, agent, project, started_at, tokens_in, tokens_out, "
                 "cost_usd) VALUES ('n','s1','claude-code','proj','2026-10-01T00:00:00.000+00:00',3,4,0.5)")
    conn.commit()
    conn.close()
    return d / "telemetry.db"


def _api(home):
    code = "import json,sync_common;print(json.dumps(sync_common.load_hv().api_telemetry(limit=5)))"
    r = subprocess.run([sys.executable, "-c", code], cwd=PROJECT, capture_output=True, text=True,
                       env=dict(os.environ, HIVE_HOME=str(home), HIVE_NODE_ID="n", PYTHONPATH=str(PROJECT)))
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_api_telemetry_reads_the_store_hwatch_writes_without_changing_it(tmp_path):
    home = tmp_path / "home"
    db = _store(home)
    before = db.read_bytes()
    t = _api(home)
    assert t["available"] and t["totals"]["sessions"] == 1 and t["recent"][0]["tokens_in"] == 3
    assert db.read_bytes() == before                        # opened read-only: no WAL switch, no schema write


def test_api_telemetry_with_no_store_is_empty_and_creates_nothing(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    t = _api(home)
    assert t["available"] and t["totals"].get("sessions", 0) == 0 and t["recent"] == []
    assert not (home / ".telemetry").exists()


def test_api_telemetry_reads_a_store_under_a_home_with_uri_special_characters(tmp_path):
    home = tmp_path / "a#b?c%20d"
    db = _store(home)
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO telemetry_sessions (node_id, session_id, agent, project, started_at, tokens_in) "
                 "VALUES ('n','s2','claude-code','proj','2026-10-02T00:00:00.000+00:00',9)")
    conn.commit()
    conn.close()
    t = _api(home)
    assert t["available"] and t["totals"]["sessions"] == 2
    assert [r["tokens_in"] for r in t["recent"]] == [9, 3]      # newest first


def test_session_hook_never_imports_a_module_planted_in_the_session_cwd(tmp_path):
    """The hook runs in whatever project the session opened: a json.py there must not run."""
    home = tmp_path / "home"
    home.mkdir()
    log = tmp_path / "argv.txt"
    fake_hv = home / "hv"
    fake_hv.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {log}\n")
    fake_hv.chmod(0o755)
    proj = tmp_path / "proj"
    proj.mkdir()
    marker = tmp_path / "planted-ran.txt"
    (proj / "json.py").write_text(f"open({str(marker)!r}, 'a').write('json')\n")
    r = subprocess.run(["bash", str(PROJECT / "scripts" / "common" / "session_hook.sh"), "start"],
                       env=dict(os.environ, HIVE_HOME=str(home)), cwd=proj, input='{"cwd": "/tmp", "session_id": "s1"}',
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert not marker.exists()
    assert "s1" in log.read_text().split()
