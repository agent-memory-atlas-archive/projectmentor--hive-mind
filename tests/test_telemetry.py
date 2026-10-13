"""Session telemetry is the hwatch module's (`hwatch telemetry`; its tests live in projectmentor/hive-mind-hwatch).
`hv telemetry` was removed in 4.0: it exits 2 with a pointer. Core keeps a read-only view of the store for the loopback
`/api/telemetry`, and the session hook runs the module directly."""
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
HV = PROJECT / "hv"
HOOK = PROJECT / "scripts" / "common" / "session_hook.sh"


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


@pytest.mark.parametrize("installed", [True, False])
@pytest.mark.parametrize("argv", [[], ["record", "--event", "start"], ["report", "--since", "7d"], ["list", "--limit", "3"]])
def test_hv_telemetry_is_removed_exit_2_with_the_pointer_and_runs_nothing(tmp_path, installed, argv):
    env, log = _env(tmp_path, installed=installed)
    r = hv(env, "telemetry", *argv)
    assert r.returncode == 2 and r.stdout == ""
    assert r.stderr.strip().count("\n") == 0 and "removed in 4.0" in r.stderr and "hwatch telemetry" in r.stderr
    assert not log.exists()


def _hook(env, event):
    return subprocess.run(["bash", str(HOOK), event], env=env, input='{"cwd": "/tmp", "session_id": "s1"}',
                          capture_output=True, text=True)


@pytest.mark.parametrize("event", ["start", "end"])
def test_session_hook_runs_the_module_directly_and_stays_silent(tmp_path, event):
    env, log = _env(tmp_path, installed=True, rc=7)
    r = _hook(env, event)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    argv = log.read_text().split()
    assert argv[:6] == ["module", "run", "hwatch", "--", "telemetry", "record"] and "hv" not in argv
    assert argv[argv.index("--event") + 1] == event and argv[argv.index("--session") + 1] == "s1"


def test_session_hook_without_the_module_or_any_launcher_is_silent_exit_0(tmp_path):
    env, log = _env(tmp_path, installed=False)
    env["PATH"] = str(Path(sys.executable).parent) + ":/usr/bin:/bin"
    (tmp_path / "bin" / "hive-mind").unlink()
    r = _hook(env, "start")
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "") and not log.exists()
    # the control plane is on PATH but the module is not installed: its refusal is swallowed
    (tmp_path / "b").mkdir()
    env2, _ = _env(tmp_path / "b", installed=False, rc=1)
    r = _hook(env2, "end")
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")


def test_mcp_telemetry_report_returns_the_pointer_as_text():
    pytest.importorskip("mcp")
    sys.path.insert(0, str(PROJECT / "integrations" / "mcp"))
    try:
        import hive_mcp
    finally:
        sys.path.pop(0)
    for view in ("report", "list"):
        out = hive_mcp.hive_telemetry_report(view=view, since="7d")
        assert "removed in 4.0" in out and "hwatch telemetry" in out


def test_no_doc_names_a_removed_verb_as_live():
    """`hv dash` and `hv telemetry` exit 2 since 4.0. A doc line that names one must say it is gone (or what it was);
    CONTRACT_HISTORY.md, CHANGELOG.md and docs/history/ are the record and are exempt."""
    said = re.compile(r"removed|gone|forwarded|exit(s)? 2|\bthen\b|was ")
    bad = []
    files = [PROJECT / "README.md", *sorted((PROJECT / "docs").glob("*.md"))]
    for f in files:
        if f.name == "CONTRACT_HISTORY.md":
            continue
        for n, line in enumerate(f.read_text().splitlines(), 1):
            if re.search(r"\bhv (dash|telemetry)\b", line) and not said.search(line):
                bad.append(f"{f.name}:{n}: {line.strip()[:90]}")
    assert not bad, bad


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


def test_session_hook_still_runs_the_module_where_timeout_is_missing(tmp_path):
    """macOS ships no `timeout`: the hook must cap the call another way, not silently skip it."""
    env, log = _env(tmp_path, installed=True, rc=7)
    # a PATH of just the stub dir plus a bin of symlinks to the tools the hook needs, minus timeout/gtimeout
    tools = tmp_path / "tools"
    tools.mkdir()
    import shutil
    for name in ("bash", "python3", "sed", "hostname", "id", "dirname", "env", "sh", "printf"):
        found = shutil.which(name)
        if found:
            (tools / name).symlink_to(found)
    env["PATH"] = f"{tmp_path / 'bin'}:{tools}"
    r = _hook(env, "start")
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    assert log.read_text().split()[:3] == ["module", "run", "hwatch"]


@pytest.mark.parametrize("no_timeout", [False, True])
def test_session_hook_never_imports_a_module_planted_in_the_session_cwd(tmp_path, no_timeout):
    """The hook runs in whatever project the session opened: a json.py / subprocess.py there must not run."""
    import shutil
    env, log = _env(tmp_path, installed=True, rc=0)
    tools = tmp_path / "tools"
    tools.mkdir()
    for name in ("bash", "python3", "sed", "hostname", "id", "dirname", "env", "sh", "printf") + (("timeout",) if not no_timeout else ()):
        found = shutil.which(name)
        if found:
            (tools / name).symlink_to(found)
    env["PATH"] = f"{tmp_path / 'bin'}:{tools}"
    proj = tmp_path / "proj"
    proj.mkdir()
    marker = tmp_path / "planted-ran.txt"
    for mod in ("json", "subprocess"):
        (proj / f"{mod}.py").write_text(f"open({str(marker)!r}, 'a').write({mod!r})\n")
    r = subprocess.run(["bash", str(HOOK), "start"], env=env, cwd=proj, input="{}", capture_output=True, text=True)
    assert r.returncode == 0
    assert not marker.exists()
    assert log.read_text().split()[:3] == ["module", "run", "hwatch"]
