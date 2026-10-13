"""B10 (private#58): a dashboard or daemon-side write path can never receive the owner passphrase.

The design is "the daemon proposes, the CLI signs": the passphrase is typed at the owner CLI (a tty), read
there, and the unlocked seed lives in the agent (#295). Nothing that serves HTTP or runs a cell reads it.
These tests pin each side of that: the daemon's code and routes, the agent's child environment, and the
environment a wired cell's shell gets (#399)."""
import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))

PASSPHRASE_ENVS = ("HIVE_OWNER_PASSPHRASE", "HIVE_OWNER_KEY_PASSPHRASE")


def test_the_daemon_neither_imports_nor_names_the_owner_secret_path(tmp_path):
    src = (PROJECT / "hive_sync_daemon.py").read_text()
    for needle in PASSPHRASE_ENVS + ("read_passphrase", "ownerkey", "owner_agent", "hivemind_owner", "getpass"):
        assert needle not in src, needle
    code = ("import sys; sys.path.insert(0, %r); import hive_sync_daemon; "
            "print(sorted(m for m in ('ownerkey', 'owner_agent', 'hivemind_owner') if m in sys.modules))" % str(PROJECT))
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60,
                       env={**os.environ, "HIVE_HOME": str(tmp_path)})
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "[]"                    # the owner-key code is not even loaded in the daemon


def test_the_daemon_has_one_write_route_and_it_takes_signed_entries_only():
    src = (PROJECT / "hive_sync_daemon.py").read_text()
    post = src[src.index("def do_POST"):]
    post = post[:post.index("\n    def ", 10)] if "\n    def " in post[10:] else post
    assert 'u.path != "/sync/ingest"' in post          # every other POST path is a 404
    assert "do_PUT" not in src and "do_DELETE" not in src and "do_PATCH" not in src


@pytest.mark.parametrize("path", ["/api/owner/unlock", "/api/unlock", "/api/governance", "/api/write", "/unlock", "/"])
def test_a_posted_passphrase_goes_nowhere(path):
    from test_peer_address import _daemon
    secret = "correct horse battery staple 7731"
    body = json.dumps({"passphrase": secret, "HIVE_OWNER_KEY_PASSPHRASE": secret}).encode()
    with _daemon(None) as port:
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=15)
        assert e.value.code == 404
        assert secret not in e.value.read().decode()


def test_the_agent_is_started_without_either_passphrase_variable(monkeypatch):
    import owner_agent
    seen = {}

    class _P:
        class stdin:
            written = b""

            @staticmethod
            def write(b):
                _P.stdin.written = b

            @staticmethod
            def close():
                pass

    def fake_popen(argv, **kw):
        seen.update(env=kw["env"], argv=argv)
        return _P()

    for n in PASSPHRASE_ENVS:
        monkeypatch.setenv(n, "hunter2-pass")
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    owner_agent.spawn(b"\x01" * 32, "/tmp/x.sock", 60, "pub", [])
    assert not any(n in seen["env"] for n in PASSPHRASE_ENVS)
    assert "hunter2-pass" not in " ".join(seen["argv"]) and "hunter2-pass" not in seen["env"].values()


def test_a_cells_shell_never_inherits_the_key_passphrase(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path))
    loader = importlib.machinery.SourceFileLoader("hvmod_b10", str(PROJECT / "hv"))
    spec = importlib.util.spec_from_loader("hvmod_b10", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    monkeypatch.setenv("HIVE_OWNER_KEY_PASSPHRASE", "hunter2-pass")
    env = m._child_env({"MYTOK": "v"})
    assert "HIVE_OWNER_KEY_PASSPHRASE" not in env and env["MYTOK"] == "v"


def test_module_children_scrub_both_passphrase_variables():
    import hive_modules
    assert set(PASSPHRASE_ENVS) <= set(hive_modules.SCRUBBED_ENV)
