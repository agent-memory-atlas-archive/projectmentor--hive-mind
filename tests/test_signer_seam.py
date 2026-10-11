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


def _signing_offenders(name, src):
    """Calls to ed25519's `sign` in `src`, following names bound to the module or to its `sign` attribute.
    Any name containing `ed25519` counts as the module (the hv parts share one namespace, so a file may use a name another bound).
    Documented limits: tuple/for/parameter bindings, importlib/__import__/sys.modules, relative or dotted imports."""
    tree = ast.parse(src)
    mods, signs = set(), set()                           # names bound to the module / to its `sign`

    def is_mod(n):
        if isinstance(n, ast.NamedExpr):
            return is_mod(n.value)
        return (isinstance(n, ast.Name) and (n.id in mods or "ed25519" in n.id)) or (isinstance(n, ast.Attribute) and "ed25519" in ast.unparse(n))

    def is_sign(n):
        if isinstance(n, ast.Name):
            return n.id in signs
        if isinstance(n, ast.Attribute):
            return n.attr == "sign" and is_mod(n.value)
        return (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "getattr" and len(n.args) == 2
                and is_mod(n.args[0]) and isinstance(n.args[1], ast.Constant) and n.args[1].value == "sign")

    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update((a.asname or a.name) for a in node.names if a.name == "ed25519")
        elif isinstance(node, ast.ImportFrom) and node.module == "ed25519":
            for a in node.names:
                if a.name == "*":
                    offenders.append(f"{name}:{node.lineno} from ed25519 import *")
                if a.name == "sign":
                    signs.add(a.asname or a.name)
                    offenders.append(f"{name}:{node.lineno} from ed25519 import sign")
    for _ in range(10):                                  # assignments, to a fixpoint (a = b; b = ed25519)
        before = (len(mods), len(signs))
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Assign):
                targets, value = [t for t in node.targets if isinstance(t, ast.Name)], node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                targets, value = [node.target], node.value
            elif isinstance(node, ast.NamedExpr):
                targets, value = [node.target], node.value
            else:
                continue
            for t in targets:
                if is_mod(value) and not isinstance(value, ast.Attribute):
                    mods.add(t.id)
                elif is_sign(value):
                    signs.add(t.id)
        if before == (len(mods), len(signs)):
            break
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and is_sign(node.func):
            offenders.append(f"{name}:{node.lineno} {ast.unparse(node.func)}(...)")
        elif isinstance(node, ast.Attribute) and node.attr == "sign" and is_mod(node.value):
            offenders.append(f"{name}:{node.lineno} {ast.unparse(node)} (reference)")   # passed as a value (map, partial)
    return offenders


def test_the_seam_is_the_only_caller_of_ed25519_sign():
    offenders = []
    for name, src in _core_sources():
        if name not in ALLOWED:
            offenders += _signing_offenders(name, src)
    assert not offenders, f"signing outside the signer seam: {offenders}"


@pytest.mark.parametrize("probe", [
    "import ed25519 as _ed25519\n_k = _ed25519\n_k.sign(b'm', s)\n",
    "import ed25519 as _ed25519\n_k = _ed25519\n_j = _k\n_j.sign(b'm', s)\n",
    "import ed25519 as _ed25519\nf = _ed25519.sign\nf(b'm', s)\n",
    "import ed25519 as _ed25519\nf = g = _ed25519.sign\ng(b'm', s)\n",
    "import ed25519 as _ed25519\nf = getattr(_ed25519, 'sign')\nf(b'm', s)\n",
    "import ed25519\nk = ed25519\nk.sign(b'm', s)\n",
    "from ed25519 import sign as f\nf(b'm', s)\n",
    "import ed25519 as _ed25519\n(k := _ed25519).sign(b'm', s)\n",
    "_ed25519.sign(b'm', s)\n",                             # bound by another file (the hv parts share one namespace)
    "ed25519.sign(b'm', s)\n",
    "from ed25519 import *\n",
    "import functools\np = functools.partial(_ed25519.sign, seed=s)\n",
    "list(map(_ed25519.sign, ms, ss))\n",
])
def test_the_guard_catches_planted_aliases(probe):
    assert _signing_offenders("probe.py", probe)


def test_the_guard_catches_a_sign_planted_in_a_part():
    part = next(p for p in sorted((PROJECT / "hivemind" / "parts").glob("11_*.py")))
    assert _signing_offenders(part.name, part.read_text() + "\ndef _planted(seed):\n    return _ed25519.sign(b'm', seed)\n")


def test_the_guard_ignores_unrelated_sign_calls():
    assert not _signing_offenders("ok.py", "import ed25519 as _ed25519\nk = _ed25519.verify\nk(1, 2, 3)\nsigner.sign(b'm')\nx = signer\nx.sign(b'm')\n")


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


def test_a_shadowing_hivemind_package_does_not_break_the_import(tmp_path):
    """A regular `hivemind` package elsewhere on the path (PyPI has one) must not beat ours: ours is regular too."""
    import subprocess

    shadow = tmp_path / "hivemind"
    shadow.mkdir()
    (shadow / "__init__.py").write_text("")
    code = f"import sys; sys.path.insert(0, {str(PROJECT)!r}); from hivemind.crypto import signer; print(signer.__file__)"
    env = {"PYTHONPATH": str(tmp_path), "PATH": "/usr/bin:/bin"}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().startswith(str(PROJECT))
