"""The part loader (3.1 PR 1, docs/design "3.1 plan" section 2.1).

`hv` is a header, a loader and a footer. Its body lives in `hivemind/parts/NN_<name>.py`, executed in order into
`hv`'s own namespace by the loader, from the one list `PARTS`. This file is the permanent half of the move gate:

* what the loader may do (its text, its list, its bytes-not-text read, the one exec in the tree);
* what the loaded namespace is (exactly `PARTS` more than the monolith defined; every code object in it comes from
  `hv` or a listed part);
* that the guards which read `hv`'s text read the parts too, proven by planting a violation in `01_identity` and
  watching each guard fail (directive h:157bd5e469: a guard is not trusted on its docstring).

What is NOT here, on purpose: equality with the pre-split `hv`. That is `scripts/common/hv_move_gate.py`, run against
the base of the PRs that move code. Kept forever it would freeze the parts.
"""

import ast
import builtins
import importlib.machinery
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))

import _planes  # noqa: E402
from _source import copy_hv, hv_sources, loader_span, monolith, parts_of  # noqa: E402

PARTS_DIR = PROJECT / "hivemind" / "parts"
SIZE_CAP = 1500          # lines per part (the plan's acceptance: files a reviewer can hold)
# The names pyflakes cannot see in the single-file form: placeholders the control plane binds at install time
# (`hivemind_ctl.install`) and `unforget`, resolved at run time. Nothing else may be undefined.
EXPECTED_UNDEFINED = {"admit_cmd", "unforget", "migrate_cmd"}


def _load(root, name):
    loader = importlib.machinery.SourceFileLoader(name, str(Path(root) / "hv"))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(mod)
    return mod


# ── the list ──────────────────────────────────────────────────────────────────────────────────────────

def test_parts_are_exactly_the_directory_in_order():
    on_disk = sorted(p.name for p in PARTS_DIR.iterdir() if p.name != "__pycache__")
    assert [Path(p).name for p in parts_of()] == on_disk, "PARTS must list every file in hivemind/parts, in order"
    assert all(re.fullmatch(r"\d\d_[a-z0-9_]+\.py", n) for n in on_disk), on_disk
    assert on_disk == sorted(on_disk) and len({n[:2] for n in on_disk}) == len(on_disk), "NN prefixes are unique"
    assert not (PROJECT / "hivemind" / "__init__.py").exists() and not (PARTS_DIR / "__init__.py").exists(), \
        "no package: a part is not importable"


def test_the_parts_are_tracked_files():
    out = subprocess.run(["git", "-C", str(PROJECT), "ls-files", "hivemind/parts"], capture_output=True, text=True)
    if out.returncode != 0:
        pytest.skip("not a git checkout")
    assert sorted(out.stdout.split()) == sorted(parts_of()), "the manifest hashes tracked files: a part must be one"


def test_no_part_is_over_the_size_cap():
    for path, data in hv_sources()[1:]:
        lines = data.count(b"\n")
        assert lines <= SIZE_CAP, f"{path.name} has {lines} lines (cap {SIZE_CAP})"


def test_a_part_has_no_future_import_and_no_coding_cookie():
    """compile() inherits the loader's future flags, so a part's own `from __future__` would be a different
    program; a cookie would change how its bytes decode."""
    for path, data in hv_sources():
        for node in ast.walk(ast.parse(data)):
            assert not (isinstance(node, ast.ImportFrom) and node.module == "__future__"), path.name
        assert not re.search(rb"coding[:=]", b"\n".join(data.split(b"\n")[:2])), f"{path.name} has a coding cookie"


# ── the loader itself ─────────────────────────────────────────────────────────────────────────────────

def _loader_tree():
    data = (PROJECT / "hv").read_bytes()
    start, end = loader_span(data)
    return ast.parse(data[start:end])


def test_the_loader_is_one_list_one_loop_and_nothing_else():
    body = _loader_tree().body
    assert [type(n).__name__ for n in body] == ["Assign", "For", "Delete"], [type(n).__name__ for n in body]
    names = {n.id for n in ast.walk(_loader_tree()) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(_loader_tree()) if isinstance(n, ast.Attribute)}
    # No glob, no listing, no environment, no config: the list is the whole authority over what runs.
    assert not (names | attrs) & {"glob", "rglob", "iterdir", "listdir", "scandir", "walk", "environ", "getenv",
                                  "HIVE_HOME", "JOURNAL_DIR", "KEY_DIR", "open", "read_text", "import_module"}
    assert {"read_bytes", "resolve", "parent"} <= attrs and {"compile", "exec", "globals"} <= names
    # The path comes from this file's real path, as the sys.path line above the imports does.
    assert "Path(__file__).resolve().parent" in ast.unparse(body[1])


# Every way the stdlib has to run code that is not written in the file being read. The loader's exec/compile are the
# only uses in the tree; everything here is banned outright, as an import, an `import from`, a bare name, an
# attribute or a string (so `getattr(mod, "run_path")` fails as well as `mod.run_path(...)`).
LOADER_ONLY = ("exec", "compile")
BANNED_MODULES = {"runpy", "importlib", "imp", "zipimport", "py_compile", "compileall", "marshal", "ctypes",
                  "builtins", "code", "codeop", "pkgutil", "pdb", "bdb", "timeit", "profile", "cProfile", "trace",
                  "doctest"}
BANNED_NAMES = {"eval", "__import__", "__builtins__", "import_module", "exec_module", "load_module", "run_path",
                "run_module", "execfile", "spec_from_file_location", "spec_from_loader", "module_from_spec",
                "SourceFileLoader", "SourcelessFileLoader", "ExtensionFileLoader", "load_source", "load_compiled",
                "load_dynamic", "InteractiveInterpreter", "InteractiveConsole", "compile_file", "compile_dir"}
# A module name is also banned as a string (`sys.modules["runpy"]`, `__import__` is already banned), except the
# short ones that are ordinary words here (`imp` is a local name for importance, "code" a key, "trace"/"profile" nouns).
BANNED_STRINGS = BANNED_NAMES | (BANNED_MODULES - {"imp", "code", "trace", "profile"})


def file_runner_violations(data):
    """(line, what) for each use in this source of exec, eval, a bare compile, or any file-running API. The loader
    block's own exec/compile are the caller's to allow (they are LOADER_ONLY)."""
    out = []
    for node in ast.walk(ast.parse(data)):
        if isinstance(node, ast.Import):
            out += [(node.lineno, f"import {a.name}") for a in node.names if a.name.split(".")[0] in BANNED_MODULES]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in BANNED_MODULES:
                out.append((node.lineno, f"from {node.module} import ..."))
            out += [(node.lineno, f"import {a.name}") for a in node.names if a.name in BANNED_NAMES | set(LOADER_ONLY)]
        elif isinstance(node, ast.Name) and (node.id in BANNED_NAMES or node.id in LOADER_ONLY):
            out.append((node.lineno, node.id))
        elif isinstance(node, ast.Attribute) and (node.attr in BANNED_NAMES or node.attr == "exec"):
            out.append((node.lineno, ast.unparse(node)))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in BANNED_STRINGS | set(LOADER_ONLY):
            out.append((node.lineno, repr(node.value)))
    return out


def outside_the_loader(name, violations, span=None):
    """The violations not allowed: only `hv`'s own exec/compile, on a line inside the loader block (`span` is its
    (first, last) line), are."""
    return [(line, what) for line, what in violations
            if not (name == "hv" and span and span[0] <= line <= span[1] and what.strip("'") in LOADER_ONLY)]


def test_the_one_exec_in_the_tree_is_the_loader():
    """Nothing else in `hv` or its parts compiles or evaluates code, imports by name, or runs a file as code
    (runpy, importlib loaders, `__import__` of a path, and the rest of BANNED_NAMES)."""
    for path, data in hv_sources():
        found = outside_the_loader(path.name, file_runner_violations(data), loader_lines())
        assert not found, f"{path.name}: {found}"


# One planted probe per file-running API: each has to be reported by the guard's own function.
FILE_RUNNER_PROBES = {
    "exec": "exec(open('x').read())",
    "eval": "eval('1')",
    "compile": "compile('1', 'x', 'exec')",
    "__import__": "__import__('x')",
    "runpy.run_path": "import runpy\nrunpy.run_path('x.py')",
    "runpy.run_module": "from runpy import run_module\nrun_module('x')",
    "runpy alias": "import runpy as r\nr.run_path('x')",
    "importlib.import_module": "import importlib\nimportlib.import_module('x')",
    "importlib.util loader": "import importlib.util\nimportlib.util.spec_from_file_location('m', 'x.py').loader.exec_module(None)",
    "from importlib.machinery": "from importlib.machinery import SourceFileLoader\nSourceFileLoader('m', 'x').load_module()",
    "imp.load_source": "import imp\nimp.load_source('m', 'x.py')",
    "zipimport": "import zipimport\nzipimport.zipimporter('x.zip').load_module('m')",
    "py_compile": "import py_compile\npy_compile.compile('x.py')",
    "marshal": "import marshal\nexec_ = marshal.loads(b'')",
    "ctypes": "import ctypes\nctypes.CDLL('x.so')",
    "sys.modules string": "import sys\nsys.modules['runpy'].run_path('x')",
    "builtins": "import builtins\ngetattr(builtins, 'ex' + 'ec')",
    "code.InteractiveInterpreter": "import code\ncode.InteractiveInterpreter().runsource('1')",
    "getattr by string": "m = object()\ngetattr(m, 'run_path')('x')",
    "alias of a runner": "f = __builtins__",
    "attribute only": "m = object()\nm.run_path('x')",
    "timeit": "import timeit\ntimeit.timeit('1')",
    "profile": "import profile\nprofile.run('1')",
    "cProfile": "import cProfile\ncProfile.run('1')",
    "trace": "import trace\ntrace.Trace().run('1')",
    "doctest": "import doctest\ndoctest.run_docstring_examples('x', {})",
}


@pytest.mark.parametrize("name", sorted(FILE_RUNNER_PROBES))
def test_the_exec_ban_reports_each_planted_file_runner(name):
    assert file_runner_violations(FILE_RUNNER_PROBES[name]), name


def test_the_loader_allowance_is_the_loaders_exec_and_compile_inside_its_span_only():
    span = (10, 20)
    for src, name, allowed in [
        ("exec(x)", "hv", True),
        ("compile(x, 'a', 'exec')", "hv", True),
        ("eval(x)", "hv", False),              # inside the span but not LOADER_ONLY
        ("import runpy", "hv", False),
        ("exec(x)", "01_identity.py", False),  # a part never gets the allowance
    ]:
        found = file_runner_violations("\n" * 14 + src)
        assert found and bool(outside_the_loader(name, found, span)) is (not allowed), src
    for pad in ("\n" * 4, "\n" * 24):  # before and after the loader block
        assert outside_the_loader("hv", file_runner_violations(pad + "exec(x)"), span), len(pad)


def test_the_exec_ban_is_quiet_on_ordinary_code():
    assert file_runner_violations("import re, subprocess\nre.compile('x')\nsubprocess.run(['ls'])\n") == []


def loader_lines():
    """(first, last) line of the loader block in `hv`."""
    data = (PROJECT / "hv").read_bytes()
    start, end = loader_span(data)
    return data[:start].count(b"\n") + 1, data[:end].count(b"\n")


def test_PARTS_is_a_tuple_of_package_relative_paths():
    parts = parts_of()
    assert isinstance(parts, tuple) and parts
    assert all(not os.path.isabs(p) and p.startswith("hivemind/parts/") for p in parts)
    hv = _planes.load_hv("/nonexistent-never-created", "hv_parts_list", control_plane=False)
    assert hv.PARTS == parts


def test_parts_are_read_as_bytes_so_a_c_locale_cannot_corrupt_them(tmp_path):
    """hv has non-ASCII in docstrings and literals and no coding cookie; a locale-decoded read would fail or
    mangle them on Windows or a C locale. Run under the strictest locale and read a non-ASCII docstring back."""
    code = ("import sync_common; hv = sync_common.load_hv(); "
            "print(hv._hkdf_sha256.__doc__.split()[3].encode('unicode_escape').decode())")
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONUTF8", "PYTHONIOENCODING")}
    env.update(LC_ALL="C", LANG="C", PYTHONCOERCECLOCALE="0", PYTHONUTF8="0", HIVE_HOME=str(tmp_path / "h"),
               HOME=str(tmp_path))
    r = subprocess.run([sys.executable, "-c", code], cwd=PROJECT, env=env, capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "\\u2192", (r.stdout, r.stderr)   # the arrow in the docstring


# ── the loaded namespace ──────────────────────────────────────────────────────────────────────────────

def _bound_names(tree):
    """Names the top level of a module binds at import: defs, classes, assignments, imports, loop, with and
    except targets, at any statement depth that is not inside a def, class, lambda or comprehension."""
    out = set()

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out.add(child.name)
                continue
            if isinstance(child, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                continue
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                out.update((a.asname or a.name).split(".")[0] for a in child.names)
            elif isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
                out.add(child.id)
            elif isinstance(child, ast.ExceptHandler) and child.name:
                out.add(child.name)
            visit(child)
    visit(tree)
    return out


def _inventory():
    """What the monolith defined, from its own text (the loader block replaced by the parts)."""
    return _bound_names(ast.parse(monolith()))


def _extra_names(mod):
    return {n for n in vars(mod) if not (n.startswith("__") and n.endswith("__"))} - _inventory()


def test_the_loaded_namespace_is_the_monolith_plus_PARTS_and_nothing_else(tmp_path):
    hv = _planes.load_hv(tmp_path / "h", "hv_ns", control_plane=False)
    assert _extra_names(hv) == {"PARTS"}
    assert {"_owner_unseal", "NotOnDataPlane", "HIVE_HOME", "KEY_DIR"} <= set(vars(hv)), "the part's names are loaded"


def test_the_namespace_check_fails_on_a_loader_that_leaks_its_loop_variable(tmp_path):
    copy_hv(tmp_path / "t")
    hv_file = tmp_path / "t" / "hv"
    text = hv_file.read_text()
    assert "\ndel _part\n" in text
    hv_file.write_text(text.replace("\ndel _part\n", "\n"))
    leaked = _extra_names(_load(tmp_path / "t", "hv_ns_leak"))
    assert leaked == {"PARTS", "_part"}, leaked


def test_hv_dunder_file_is_hvs_and_code_objects_name_their_part(tmp_path):
    hv = _planes.load_hv(tmp_path / "h", "hv_file", control_plane=False)
    assert Path(hv.__file__) == PROJECT / "hv"
    part = str(PROJECT / parts_of()[0])
    assert hv._owner_unseal.__code__.co_filename == part, "tracebacks name the part"
    assert hv.main.__code__.co_filename == str(PROJECT / "hv") or hv.main.__code__.co_filename in {
        str(PROJECT / p) for p in parts_of()}


def _free_names(src):
    """Names a part loads but binds nowhere in itself (its own defs, assignments, args, imports) and are not builtins."""
    tree, bound, loaded = ast.parse(src), set(dir(builtins)), set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name):
            (loaded if isinstance(n.ctx, ast.Load) else bound).add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)
        elif isinstance(n, ast.arg):
            bound.add(n.arg)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            bound.update((a.asname or a.name).split(".")[0] for a in n.names)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
    return loaded - bound


def test_a_part_is_not_a_module(tmp_path):
    """Imported alone it fails loudly: a NameError at its first free name at import time, or, for a part that is
    only definitions (nothing runs at import), at least one name its functions need that only `hv` binds. Nothing
    relies on the file name."""
    for rel in parts_of():
        loader = importlib.machinery.SourceFileLoader("a_part_alone", str(PROJECT / rel))
        mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("a_part_alone", loader))
        try:
            loader.exec_module(mod)
        except NameError:
            continue
        assert _free_names((PROJECT / rel).read_bytes()), f"{rel} imports alone and needs nothing from hv"


def _hv_code_sweep(mod, allowed):
    """Every code object of a function or class defined in `mod`'s namespace (recursing co_consts), its file name."""
    seen, bad = set(), []

    def code(co, owner):
        if co in seen:
            return
        seen.add(co)
        if co.co_filename not in allowed:
            bad.append((owner, co.co_filename))
        for c in co.co_consts:
            if isinstance(c, types.CodeType):
                code(c, owner)

    def visit(name, v, depth=0):
        if isinstance(v, types.FunctionType) and v.__globals__ is vars(mod):
            code(v.__code__, name)
        elif isinstance(v, type) and v.__module__ == mod.__name__ and depth < 4:
            for k, m in vars(v).items():
                inner = m.__func__ if isinstance(m, (staticmethod, classmethod)) else m
                visit(f"{name}.{k}", inner, depth + 1)
                if isinstance(m, property):
                    for f in (m.fget, m.fset, m.fdel):
                        if f is not None:
                            visit(f"{name}.{k}", f, depth + 1)

    for name, v in list(vars(mod).items()):
        visit(name, v)
    return seen, bad


def test_every_code_object_in_the_data_plane_comes_from_hv_or_a_listed_part(tmp_path):
    hv = _planes.load_hv(tmp_path / "h", "hv_sweep", control_plane=False)
    allowed = {str(PROJECT / "hv")} | {str(PROJECT / p) for p in parts_of()}
    seen, bad = _hv_code_sweep(hv, allowed)
    assert len(seen) > 500, "the sweep must actually walk hv"
    assert not bad, bad[:5]


def test_the_control_plane_adds_exactly_hivemind_owner(tmp_path):
    hv = _planes.load_hv(tmp_path / "h", "hv_sweep_ctl", control_plane=True)
    allowed = {str(PROJECT / "hv"), str(PROJECT / "hivemind_owner.py")} | {str(PROJECT / p) for p in parts_of()}
    seen, bad = _hv_code_sweep(hv, allowed)
    assert not bad, bad[:5]
    data_only = {str(PROJECT / "hv")} | {str(PROJECT / p) for p in parts_of()}
    assert _hv_code_sweep(hv, data_only)[1], "after install, hivemind_owner's code is in the namespace"


def test_the_sweep_fails_on_a_function_from_somewhere_else(tmp_path):
    hv = _planes.load_hv(tmp_path / "h", "hv_sweep_mut", control_plane=False)
    exec(compile("def _planted():\n    return 1\n", str(tmp_path / "elsewhere.py"), "exec"), vars(hv))
    allowed = {str(PROJECT / "hv")} | {str(PROJECT / p) for p in parts_of()}
    assert [o for o, _ in _hv_code_sweep(hv, allowed)[1]] == ["_planted"]


# ── runs through a symlink and from a copy ────────────────────────────────────────────────────────────

def test_a_symlinked_hv_runs_the_parts_beside_the_real_file(tmp_path):
    link = tmp_path / "bin" / "hv"
    link.parent.mkdir()
    link.symlink_to(PROJECT / "hv")
    r = subprocess.run([sys.executable, str(link), "version"], capture_output=True, text=True,
                       env=dict(os.environ, HIVE_HOME=str(tmp_path / "h")))
    assert r.returncode == 0 and "contract-version" in r.stdout, r.stderr


def test_an_hv_without_its_parts_refuses_to_run(tmp_path):
    shutil.copy(PROJECT / "hv", tmp_path / "hv")
    for f in PROJECT.glob("*.py"):
        shutil.copy(f, tmp_path / f.name)
    r = subprocess.run([sys.executable, str(tmp_path / "hv"), "version"], capture_output=True, text=True,
                       env=dict(os.environ, HIVE_HOME=str(tmp_path / "h")))
    assert r.returncode != 0 and "FileNotFoundError" in r.stderr and "01_identity.py" in r.stderr


# ── the linter: names resolve across the parts ────────────────────────────────────────────────────────

def _undefined(src_bytes, tmp_path):
    pyflakes = pytest.importorskip("pyflakes.api")
    from pyflakes import reporter
    import io
    out = io.StringIO()
    pyflakes.check(src_bytes.decode(), "hv", reporter.Reporter(out, out))
    return {m.group(1) for m in re.finditer(r"undefined name '([^']+)'", out.getvalue())}


def test_every_name_resolves_across_the_parts(tmp_path):
    """pyflakes (F821) on the single-file form: the check a split would otherwise lose, since each part alone is
    full of names defined elsewhere."""
    assert _undefined(monolith(), tmp_path) <= EXPECTED_UNDEFINED


def test_the_undefined_name_check_fails_on_a_typo_planted_in_a_part(tmp_path):
    root = tmp_path / "t"
    copy_hv(root)
    part = root / parts_of()[0]
    part.write_bytes(part.read_bytes() + b"\n\ndef _typo():\n    return _no_such_helper()\n")
    assert "_no_such_helper" in _undefined(monolith(root), tmp_path)


# ── the guards read the parts ─────────────────────────────────────────────────────────────────────────

def test_no_test_reads_hv_text_around_the_helper():
    """Bypass ban: `(PROJECT / "hv").read_text()` sees the file `hv`, not the code that runs. Tests use
    `_source.hv_text()`/`hv_sources()`. (A helper handed the path as an argument escapes a textual ban, so those
    call sites are in the plan's inventory and have been moved by hand.) test_update_script reads hv's bytes on
    purpose: it pins what the update script's `sed` sees of the file itself."""
    pat = re.compile(r"""["']hv["']\)?\)?\s*\.\s*read_(text|bytes)|\bHV\s*\.\s*read_(text|bytes)|\bPROJECT_HV\b.*read_""")
    allowed = {"test_update_script.py", "test_s2_split.py", "test_hv_parts.py"}
    for f in sorted((PROJECT / "tests").glob("*.py")):
        if f.name in allowed or f.name == "_source.py":
            continue
        for i, line in enumerate(f.read_text().splitlines(), 1):
            assert not pat.search(line), f"{f.name}:{i} reads hv's text directly: {line.strip()}"


GUARDS = [
    ("import-graph", "tests/test_s2_split.py::test_hv_never_reaches_the_signer_or_the_control_plane",
     "def _probe_graph():\n    import ownerkey\n    return ownerkey\n"),
    ("owner-sig", "tests/test_s2_split.py::test_no_owner_sig_is_produced_anywhere_hv_reaches",
     "def _probe_sign(p, seed):\n    p = dict(p)\n    p['owner_sig'] = _ed25519.sign(b'x', seed)\n    return p\n"),
    ("seed-read", "tests/test_ownerkey_boundary.py::test_hv_never_reads_the_seed_and_the_one_reader_is_on_the_control_plane",
     "def _probe_seed():\n    return OWNER_KEY_PATH.read_bytes()\n"),
    ("sealed-open", "tests/test_sealed_owner_key.py::test_the_data_plane_never_opens_a_sealed_key",
     "def _probe_open(env, pw):\n    return _owner_unseal(env, pw)\n"),
    ("control-plane", "tests/test_control_plane.py::test_hv_does_not_import_the_control_plane",
     "def _probe_ctl():\n    import hivemind_ctl\n    return hivemind_ctl\n"),
    ("exec-ban", "tests/test_hv_parts.py::test_the_one_exec_in_the_tree_is_the_loader",
     "def _probe_run():\n    import runpy\n    return runpy.run_path('x.py')\n"),
    ("module-management", "tests/test_module_lifecycle.py::test_the_data_plane_cannot_reach_module_management",
     "def _probe_mod():\n    import hive_modules\n    return hive_modules\n"),
]
# The verifier's probe, as one function planted in the first part: it reads the seed, opens it, signs as the
# owner, and reaches for the control plane, module management and runpy.
COMBINED_PROBE = ("def _probe_all(p, env, pw):\n    import ownerkey, hivemind_ctl, hive_modules, runpy\n"
                  "    seed = OWNER_KEY_PATH.read_bytes()\n    _owner_unseal(env, pw)\n"
                  "    p = dict(p)\n    p['owner_sig'] = _ed25519.sign(b'x', seed)\n    return p\n")


@pytest.fixture(scope="module")
def tree(tmp_path_factory):
    """A copy of the repository (sources and tests) in which guards can be run against a planted violation."""
    root = tmp_path_factory.mktemp("guards") / "repo"
    shutil.copytree(PROJECT, root, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", ".pytest_cache", "journal", "node_modules", "store.db*", ".csrf-token", ".journal.lock"))
    return root


def _run_guards(root, ids):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTEST_XDIST_WORKER", "PYTEST_CURRENT_TEST")}
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-n0", "-rA", *ids],
                       cwd=root, env=env, capture_output=True, text=True, timeout=600)
    return r, {i for i in ids if f"PASSED {i}" in r.stdout}, {i for i in ids if f"FAILED {i}" in r.stdout}


def _plant(root, probe, restore=None):
    part = root / parts_of(root)[0]
    original = part.read_bytes()
    part.write_bytes(original + b"\n\n" + probe.encode() + b"\n")
    return part, original


def test_the_guards_pass_on_the_unmodified_copy(tree):
    ids = [g[1] for g in GUARDS]
    r, passed, failed = _run_guards(tree, ids)
    assert passed == set(ids), r.stdout[-2000:] + r.stderr[-500:]


@pytest.mark.parametrize("name,node,probe", GUARDS, ids=[g[0] for g in GUARDS])
def test_each_guard_fails_on_its_violation_planted_in_01_identity(tree, name, node, probe):
    part, original = _plant(tree, probe)
    try:
        r, passed, failed = _run_guards(tree, [node])
        assert failed == {node}, f"{name}: the guard did not see a violation in a part\n" + r.stdout[-2000:]
    finally:
        part.write_bytes(original)


def test_the_verifiers_probe_in_01_identity_fails_all_the_guards(tree):
    part, original = _plant(tree, COMBINED_PROBE)
    try:
        ids = [g[1] for g in GUARDS]
        r, passed, failed = _run_guards(tree, ids)
        assert failed == set(ids), f"passed: {sorted(passed)}\n" + r.stdout[-2000:]
    finally:
        part.write_bytes(original)
