"""The signer seam (3.1, phase 2): every signature core makes goes through `hivemind.crypto.signer`.

Behaviour-neutral by construction: the file backend signs the same bytes with the same function, so every
signature is byte-for-byte what the seed-taking code produced. And the seam is the only path from a seed to a
signature: no other core source calls `ed25519.sign`, and no signing function takes a seed.
"""

import ast
import base64
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

import ed25519  # noqa: E402
import sync_common  # noqa: E402
from _source import hv_sources  # noqa: E402
from hivemind.crypto import signer  # noqa: E402

SEED = bytes(range(32))

# Sources that may call ed25519.sign: the seam itself, the primitive, its known-answer self-test, and module
# signing (a module's own key, out of scope for the seam).
ALLOWED = {"hivemind/crypto/signer.py", "ed25519.py", "crypto_selftest.py", "hive_module_client.py"}

# Every function that signs, and the name of the parameter that now carries the signer.
SIGNING_FUNCTIONS = {"_sign_entry", "_sign_governance_payload", "sign_governance", "signed_request_headers", "sign_hello"}


def _core_sources():
    """(relative path, source) of every core Python file: the top-level modules, the parts and the seam. Not tests."""
    out = [(str(p.relative_to(PROJECT)), p.read_bytes()) for p in sorted(PROJECT.glob("*.py"))]
    out += [(str(p.relative_to(PROJECT)), b) for p, b in hv_sources()]
    out += [(str(p.relative_to(PROJECT)), p.read_bytes()) for p in sorted((PROJECT / "hivemind").rglob("*.py"))]
    seen, uniq = set(), []
    for name, b in out:
        if name not in seen:
            seen.add(name)
            uniq.append((name, b))
    return uniq


def test_the_seam_is_the_only_caller_of_ed25519_sign():
    offenders = []
    for name, src in _core_sources():
        if name in ALLOWED:
            continue
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "sign":
                v = node.func.value
                chain = ast.unparse(v)
                if "ed25519" in chain:
                    offenders.append(f"{name}:{node.lineno} {chain}.sign")
            if isinstance(node, ast.ImportFrom) and node.module == "ed25519" and any(a.name == "sign" for a in node.names):
                offenders.append(f"{name}:{node.lineno} from ed25519 import sign")
    assert not offenders, f"signing outside the signer seam: {offenders}"


def test_no_signing_function_takes_a_seed():
    found = set()
    for name, src in _core_sources():
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.FunctionDef) and node.name in SIGNING_FUNCTIONS:
                found.add(node.name)
                params = [a.arg for a in node.args.args + node.args.kwonlyargs]
                assert not [p for p in params if "seed" in p], f"{name}:{node.name} takes a raw seed: {params}"
                assert any("signer" in p for p in params), f"{name}:{node.name} has no signer parameter: {params}"
    assert found == SIGNING_FUNCTIONS, f"signing functions not found (renamed? update this list): {SIGNING_FUNCTIONS - found}"


def test_the_seam_imports_nothing_local_but_ed25519():
    """So `hv` can use it without reaching the owner-key code (2.0 S2)."""
    src = (PROJECT / "hivemind/crypto/signer.py").read_text()
    mods = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    assert mods == {"ed25519"}, mods


def test_file_signer_signs_the_same_bytes_as_the_seed_did():
    s = signer.FileSigner(SEED)
    assert s.public_key() == ed25519.pub_from_seed(SEED)
    for msg in (b"", b"x", b"a longer message " * 100):
        assert s.sign(msg) == ed25519.sign(msg, SEED)
        assert ed25519.verify(msg, s.sign(msg), s.public_key())


def test_the_wire_signatures_are_unchanged():
    """Hive-Auth and hello signatures are over the same canonical bytes, produced by the same primitive."""
    s = signer.FileSigner(SEED)
    pub = s.public_key()
    h = sync_common.signed_request_headers(s, "POST", "/sync/ingest", "a=1", b"body")
    msg = sync_common.sync_signing_bytes("POST", "/sync/ingest", "a=1", b"body", int(h["Hive-Auth-Ts"]), h["Hive-Auth-Nonce"])
    assert base64.b64decode(h["Hive-Auth-Sig"]) == ed25519.sign(msg, SEED)
    assert base64.b64decode(h["Hive-Auth-Pub"]) == pub
    assert sync_common.signed_request_headers(None, "GET", "/x", "") == {}
    assert sync_common.sign_hello({"node_id": "n"}, "ab" * 16, "/sync/hello", None, "n") is None


def test_the_signer_does_not_leak_the_seed():
    s = signer.FileSigner(SEED)
    assert SEED.hex() not in repr(s) and SEED not in repr(s).encode()
    assert not hasattr(s, "__dict__")                    # __slots__ only; nothing enumerates to a seed attribute by name
    assert signer.from_seed(None) is None


@pytest.mark.parametrize("bad", [b"", b"short", bytes(33), "a" * 32, None])
def test_a_malformed_seed_is_refused(bad):
    with pytest.raises(ValueError):
        signer.FileSigner(bad)
