"""The source `hv` executes, for the tests that read it as text (3.1, the part split).

`hv` is a header, a loader and a footer; its body lives in `hivemind/parts/*.py`, run into `hv`'s namespace by
the loader's list `PARTS`. A guard that reads `(PROJECT / "hv").read_text()` sees only the file `hv`, so code
moved to a part would escape it (a seed-reading, owner-signing function planted in a part passed all five S2
guards). Every test that reads `hv`'s text uses this module instead.

The list comes from `hv` itself, parsed (never executed, never globbed): the files read are the files the
loader runs. A part that is not in `PARTS` is not code, and a name in `PARTS` with no file is an error.
"""

import ast
import shutil
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent


def parts_of(root=PROJECT):
    """`hv`'s `PARTS` as written in the file `root/hv`: the one top-level assignment, a tuple of strings."""
    found = []
    for node in ast.parse(Path(root, "hv").read_bytes()).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "PARTS" for t in node.targets):
            found.append(node)
    assert len(found) == 1, "hv must assign PARTS exactly once, at top level"
    parts = ast.literal_eval(found[0].value)
    assert isinstance(parts, tuple) and parts and all(isinstance(p, str) for p in parts), parts
    for p in parts:
        assert p.startswith("hivemind/parts/") and p.endswith(".py") and ".." not in p.split("/"), p
    return parts


def hv_sources(root=PROJECT):
    """[(path, bytes)]: `hv`, then each part in `PARTS` order. Bytes, as the loader reads them."""
    root = Path(root)
    out = [(root / "hv", (root / "hv").read_bytes())]
    for p in parts_of(root):
        out.append((root / p, (root / p).read_bytes()))
    return out


def hv_text(root=PROJECT):
    """All of `hv`'s executing source as one string (hv first, then the parts), for scanners that parse or
    search the whole. Line numbers in it mean nothing."""
    return "\n".join(b.decode("utf-8") for _, b in hv_sources(root))


def hv_tree(root=PROJECT):
    return ast.parse(hv_text(root))


def copy_hv(dst, root=PROJECT):
    """Copy `hv` and its parts tree into the directory `dst` (the copy must run, so it needs both)."""
    root, dst = Path(root), Path(dst)
    dst.mkdir(parents=True, exist_ok=True)
    shutil.copy(root / "hv", dst / "hv")
    shutil.copytree(root / "hivemind", dst / "hivemind", dirs_exist_ok=True)


LOADER_BEGIN = b"# --- part loader (3.1) "
LOADER_END = b"# --- end part loader "


def loader_span(hv_bytes):
    """(start, end) of the loader block in `hv`'s bytes: from its first marker line to the end of its last."""
    assert hv_bytes.count(LOADER_BEGIN) == 1 and hv_bytes.count(LOADER_END) == 1, "hv needs exactly one loader block"
    start = hv_bytes.index(LOADER_BEGIN)
    assert hv_bytes[start - 1:start] == b"\n", "the loader block must start a line"
    end = hv_bytes.index(b"\n", hv_bytes.index(LOADER_END)) + 1
    assert start < end
    return start, end


def monolith(root=PROJECT):
    """`hv` as one file: the loader block replaced by the parts, joined in `PARTS` order with nothing inserted.
    The text the linter and the name checks read: the names in it have to resolve."""
    sources = hv_sources(root)
    body = sources[0][1]
    start, end = loader_span(body)
    return body[:start] + b"".join(b for _, b in sources[1:]) + body[end:]
