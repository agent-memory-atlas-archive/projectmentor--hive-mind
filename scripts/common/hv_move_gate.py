#!/usr/bin/env python3
"""The move gate for the 3.1 part-split PRs (docs/design: "3.1 plan", section 2.1).

    hv_move_gate.py BASE_SHA        exit 0 iff `hv` with its loader block replaced by its parts is, byte for byte,
                                    the `hv` at BASE_SHA: nothing inserted, nothing dropped, nothing reordered.
    hv_move_gate.py --write FILE    write that single-file form (for a linter or a diff).

It gates the two PRs that move code (3.1 PR 1 and PR 2) against their base. It is not a permanent check: once the
move is done there is no old `hv` to compare with, and a permanent copy would freeze the parts.
"""
import io
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from _source import monolith  # noqa: E402


def main(argv):
    if len(argv) == 3 and argv[1] == "--write":
        Path(argv[2]).write_bytes(monolith(ROOT))
        return 0
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    archive = subprocess.run(["git", "-C", str(ROOT), "archive", argv[1], "hv", "hivemind/parts"], capture_output=True)
    if archive.returncode != 0:
        # a base from before PR 1 has no hivemind/parts: ask for `hv` alone
        archive = subprocess.run(["git", "-C", str(ROOT), "archive", argv[1], "hv"], capture_output=True)
    if archive.returncode != 0:
        print(f"hv_move_gate: cannot read hv at {argv[1]}: {archive.stderr.decode().strip()}", file=sys.stderr)
        return 2
    # The base may itself be split (PR 2's base is PR 1's merge): compare single-file forms, so the base `hv`
    # is the same bytes whether or not the base already had a loader.
    with tempfile.TemporaryDirectory() as tmp:
        tarfile.open(fileobj=io.BytesIO(archive.stdout)).extractall(tmp, filter="data")
        base_bytes = monolith(Path(tmp)) if (Path(tmp) / "hivemind").is_dir() else (Path(tmp) / "hv").read_bytes()
    base = type("B", (), {"stdout": base_bytes})
    now = monolith(ROOT)
    if now == base.stdout:
        print(f"move gate: header + parts + footer equal hv at {argv[1][:12]} ({len(now)} bytes)")
        return 0
    a, b = base.stdout.splitlines(True), now.splitlines(True)
    n = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
    print(f"move gate FAILED against {argv[1][:12]}: first difference at line {n + 1} "
          f"(base has {len(a)} lines, parts-joined has {len(b)})", file=sys.stderr)
    print(f"  base: {a[n][:100]!r}" if n < len(a) else "  base: <end>", file=sys.stderr)
    print(f"  now:  {b[n][:100]!r}" if n < len(b) else "  now:  <end>", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
