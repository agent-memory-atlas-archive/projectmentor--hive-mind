"""approvers id/hex validators must not accept a trailing newline (`$` matches before one; `fullmatch` does not)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import approvers


def test_id_ok_rejects_trailing_newline():
    assert approvers.id_ok("t")
    assert not approvers.id_ok("t\n")
    assert not approvers.id_ok("\n")


def test_hex64_ok_rejects_trailing_newline():
    h = "a" * 64
    assert approvers.hex64_ok(h)
    assert not approvers.hex64_ok(h + "\n")
