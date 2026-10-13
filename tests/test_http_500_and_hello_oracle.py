"""SN-12: an HTTP 500 carries a generic body and the exception goes to the local log only.
CK-6: /hive/info (and /sync/hello) sign only under the hello domain tag, over a server-chosen path and a
hex challenge, never over caller-chosen bytes."""
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hive_sync_daemon as d  # noqa: E402
import sync_common  # noqa: E402
from test_peer_address import _daemon  # noqa: E402
from test_hello_sig import _body, _did, _nonce  # noqa: E402

SECRET = "/home/secretuser/.hive/journal/boom-token-7731"


def _get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_get_500_is_generic_and_logs_locally(monkeypatch, capsys):
    def boom():
        raise RuntimeError(SECRET)
    monkeypatch.setattr(d, "_entries", boom)
    with _daemon(None) as port:
        status, text = _get(port, "/hive/info")
    assert status == 500
    assert json.loads(text) == {"error": "internal error"}
    assert SECRET not in text
    assert SECRET in capsys.readouterr().err


def test_post_500_is_generic_and_logs_locally(monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError(SECRET)
    monkeypatch.setattr(d.hv, "append_foreign_entries", boom)
    for gate in ("_csrf_ok", "_authorized", "_pinned"):          # reach the ingest body, past the gates
        monkeypatch.setattr(d.Handler, gate, lambda self, *a, **k: True)
    with _daemon(None) as port:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/sync/ingest", data=json.dumps({"entries": [{}]}).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=15)
            pytest.fail("expected a 500")
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read().decode()
    assert status == 500
    assert SECRET not in text and json.loads(text) == {"error": "internal error"}
    assert SECRET in capsys.readouterr().err


class _Rec:
    def __init__(self, seed):
        from _fs import FileSigner
        self._s, self.msgs = FileSigner(seed), []

    def public_key(self):
        return self._s.public_key()

    def sign(self, msg):
        self.msgs.append(msg)
        return self._s.sign(msg)


def test_hello_signature_is_domain_separated_over_a_hex_challenge():
    seed = os.urandom(32)
    dev = _did(seed)
    rec = _Rec(seed)
    n = _nonce()
    assert sync_common.sign_hello(_body(dev), n, "/hive/info", rec, dev)
    msg = rec.msgs[-1]
    assert msg.startswith(sync_common.HELLO_SIG_ALG.encode() + b"\n/hive/info\n" + n.encode() + b"\n")
    assert not msg.startswith(sync_common.HIVE_AUTH_ALG.encode())      # never readable as a sync request


@pytest.mark.parametrize("nonce", ["a" * 32 + "\n/sync/ingest", "zz" * 16, "ab", "a" * 65, "a" * 32 + "\n", "", None])
def test_caller_chosen_challenge_that_is_not_hex_is_not_signed(nonce):
    seed = os.urandom(32)
    dev = _did(seed)
    rec = _Rec(seed)
    assert sync_common.sign_hello(_body(dev), nonce, "/hive/info", rec, dev) is None
    assert rec.msgs == []


@pytest.mark.parametrize("path", ["/api/status", "/sync/ingest", "/hive/info\n" + "a" * 32, "", None])
def test_only_the_fixed_hello_paths_are_signed(path):
    seed = os.urandom(32)
    dev = _did(seed)
    rec = _Rec(seed)
    assert sync_common.sign_hello(_body(dev), _nonce(), path, rec, dev) is None
    assert rec.msgs == []
