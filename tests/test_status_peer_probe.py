"""`hive-mind status` probes each peer's /sync/hello with a signed request (#349).

A peer in sync read-auth `enforce` answers an unsigned /sync/hello with 401, so an unsigned probe showed
every healthy peer as "unreachable (401)" while `hv sync now` reported it in sync. The peer here is a
stub that answers 401 to an unsigned request and a hello to a signed one. Scratch HOME/HIVE_HOME only.
"""
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
STATUS = PROJECT / "scripts" / "installer" / "_status.sh"


def _peer(signed_only):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if signed_only and not self.headers.get("Hive-Auth-Sig"):
                self.send_response(401)
                self.end_headers()
                return
            body = json.dumps({"journal_summary": {"total": 7}}).encode()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _status(tmp_path, srv, keyed=True):
    hive_dir = tmp_path / "hivedir"
    hive_dir.mkdir()
    for p in PROJECT.iterdir():
        if p.name != ".peers.json" and not p.name.startswith(".git"):
            (hive_dir / p.name).symlink_to(p)
    (hive_dir / ".peers.json").write_text(json.dumps({"peers": [{"id": "gregorius", "url": f"http://127.0.0.1:{srv.server_port}"}]}))
    env = {**os.environ, "HIVE_DIR": str(hive_dir)}
    if keyed:
        subprocess.run(["python3", "-c", "import sync_common; sync_common.load_hv()._ensure_device_key()"],
                       cwd=PROJECT, env=env, check=True, timeout=60)
    r = subprocess.run(["bash", str(STATUS)], env=env, capture_output=True, text=True, timeout=60,
                       stdin=subprocess.DEVNULL)
    return next(l for l in r.stdout.splitlines() if "peer gregorius" in l)


def test_enforce_peer_shows_reachable(tmp_path):
    srv = _peer(signed_only=True)
    try:
        line = _status(tmp_path, srv)
    finally:
        srv.shutdown()
    assert "7 entries" in line and "unreachable" not in line


def test_unsigned_probe_401_reads_as_reachable_not_unreachable(tmp_path):
    srv = _peer(signed_only=True)
    try:
        line = _status(tmp_path, srv, keyed=False)          # no device key: nothing to sign with
    finally:
        srv.shutdown()
    assert "unreachable" not in line and "read-auth required" in line
