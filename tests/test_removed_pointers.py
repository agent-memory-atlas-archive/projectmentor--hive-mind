"""The 2.0 exit-2 pointers are gone (3.0, public #151; decision h:af137f9421, contract §7 close-out).

Through 2.x, `hv owner init`, `hv group admit`, `hv config set`, `hv admit`, `hv unforget`, `hv retract --owner`
and the rest of the moved commands printed the `hive-mind` form and exited 2. In 3.0 `hv`'s parser does not
define them: each is argparse's unknown command or unrecognized argument. Exit 2, nothing on stdout, no
`hive-mind` form named, and nothing written.

The argv list is frozen here, written out by hand rather than derived from `commandmap`, so deleting a table
row cannot shrink the test (the rule `test_removed_aliases` states).
"""

import argparse
import importlib.machinery
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

import commandmap  # noqa: E402
import _keys  # noqa: E402
from _source import copy_hv, hv_text  # noqa: E402

HV = PROJECT / "hv"
CTL = PROJECT / "hivemind_ctl.py"

# Every key of `commandmap.CONTROL_PLANE` at the head of this PR, plus the two flag forms, with and without
# the arguments a 2.x script would have typed.
CASES = [
    ["owner", "init"], ["owner", "init", "--force"], ["owner", "export"], ["owner", "export", "--out", "k"],
    ["owner", "import", "k"], ["owner", "standby", "k1:0000000000000000"], ["owner", "escrow"],
    ["owner", "restore"], ["owner", "nominate", "AAAA"], ["owner", "unnominate", "AAAA"],
    ["owner", "claim"], ["owner", "claim", "--mint"], ["owner", "transfer", "AAAA"],
    ["owner", "revoke-escrow"], ["owner", "revoke-escrow", "all"], ["owner", "heartbeat"],
    ["owner", "freeze-timestamps"], ["owner", "pin"], ["owner", "pin", "--set"], ["owner", "mint"],
    ["owner", "seal"],
    ["admit"], ["admit", "k1:0000000000000000", "--principal", "p"],
    ["group", "admit"], ["group", "admit", "k1:0000000000000000"], ["group", "revoke", "k1:0000000000000000"],
    ["group", "deny", "k1:0000000000000000"], ["group", "change", "k1:0000000000000000", "--principal", "p"],
    ["group", "purge", "k1:0000000000000000"], ["group", "retire", "k1:0000000000000000"],
    ["config", "set"], ["config", "set", "cap_self", "0.6"],
    ["config", "confidence", "set", "cap_self", "0.6"], ["config", "quorum", "set", "quorum_m", "2"],
    ["migrate", "forget"], ["migrate", "forget", "--check"],
    ["unforget"], ["unforget", "h:0000000000", "--reason", "r"],
    ["retract", "h:0000000000", "--owner"], ["retract", "--owner", "h:0000000000", "--reason", "r"],
    ["owner", "propose-election", "--mint"],
]


def _env(home):
    return dict(os.environ, HIVE_HOME=str(home), HIVE_IDENTITY_STASH=str(Path(home) / "stash"))


def _snapshot(*roots):
    """Every file under each root, by path and bytes. A missing root is recorded as missing."""
    out = {}
    for root in roots:
        root = Path(root)
        if not root.exists():
            out[str(root)] = None
            continue
        for p in sorted(root.rglob("*")):
            if p.is_file():
                out[str(p)] = p.read_bytes()
    return out


@pytest.fixture
def seeded(tmp_path):
    """A hive with a journal and a store."""
    home = tmp_path / "h"
    r = subprocess.run([sys.executable, str(HV), "remember", "a fact before the pointer ran",
                        "--source", "test"], env=_env(home), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (home / "store.db").exists() and (home / "journal").is_dir()
    return home


@pytest.mark.parametrize("argv", CASES, ids=" ".join)
def test_a_formerly_pointing_argv_is_refused_by_the_parser_and_acts_on_nothing(seeded, argv):
    home = seeded
    before = _snapshot(home, _keys.key_dir(home))
    r = subprocess.run([sys.executable, str(HV), *argv], env=_env(home), capture_output=True, text=True)
    assert r.returncode == 2, r.stdout + r.stderr
    assert r.stdout == "", f"a refused argv prints nothing on stdout: {r.stdout!r}"
    assert "hive-mind" not in r.stderr and "control plane" not in r.stderr and "Run:" not in r.stderr, r.stderr
    assert "usage:" in r.stderr, "the refusal is argparse's own"
    assert _snapshot(home, _keys.key_dir(home)) == before, "a refused argv must act on nothing"


def test_the_frozen_list_covers_every_control_plane_key():
    """The frozen list can only grow: a new control-plane key without a case here fails."""
    covered = {tuple(a[:n]) for a in CASES for n in (1, 2, 3)}
    missing = [k for k in commandmap.CONTROL_PLANE if tuple(k) not in covered]
    assert not missing, f"commandmap.CONTROL_PLANE keys with no frozen case: {missing}"


def test_the_control_plane_still_owns_the_flags():
    """`hive-mind retract <h:id> --owner` parses on the control plane; `hv retract <h:id> --owner` does not."""
    loader = importlib.machinery.SourceFileLoader("hv_pointers", str(HV))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader("hv_pointers", loader))
    loader.exec_module(m)
    ctl = m.build_parser(plane="control").parse_args(["retract", "h:0000000000", "--owner"])
    assert ctl.owner is True
    with pytest.raises(SystemExit) as e:
        m.build_parser(plane="data").parse_args(["retract", "h:0000000000", "--owner"])
    assert e.value.code == 2


def test_the_data_plane_parser_defines_none_of_the_control_plane_commands():
    loader = importlib.machinery.SourceFileLoader("hv_pointers2", str(HV))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader("hv_pointers2", loader))
    loader.exec_module(m)

    def paths(parser, prefix=()):
        out = {prefix} if prefix else set()
        for a in parser._actions:
            if isinstance(a, argparse._SubParsersAction):
                for name, sub in a.choices.items():
                    out |= paths(sub, prefix + (name,))
        return out

    data, control = paths(m.build_parser(plane="data")), paths(m.build_parser(plane="control"))
    assert data <= control, "the data plane defines nothing the control plane lacks"
    leaked = [k for k in commandmap.CONTROL_PLANE if tuple(k) in data and tuple(k) not in commandmap.STAYS]
    assert not leaked, f"control-plane commands in the data-plane parser: {leaked}"
    with pytest.raises(ValueError):
        m.build_parser(plane="other")


def test_the_pointer_machinery_is_gone():
    for name in ("pointer_text", "POINTER_EXIT", "MOVED", "RENAMED", "renamed", "renamed_text"):
        assert not hasattr(commandmap, name), name
    src = hv_text()
    for name in ("_moved_key", "def _point("):
        assert name not in src, name


@pytest.mark.parametrize("argv", [["owner", "init"], ["group", "admit", "k1:0000000000000000"], ["admit"],
                                  ["config", "set", "cap_self", "0.6"]])
def test_a_control_plane_command_still_works_on_hive_mind(tmp_path, argv):
    """The other half: `hive-mind` still routes the same argv (the routing table is kept). Its own error,
    if any, is about the hive's state, never `is not a control-plane command`."""
    r = subprocess.run([sys.executable, str(CTL), *argv], env=_env(tmp_path / "h"), capture_output=True, text=True)
    assert "is not a control-plane command" not in r.stderr, r.stderr
    assert "invalid choice" not in r.stderr and "unrecognized arguments" not in r.stderr, r.stderr


# Shipped shell, CI and adapters that still called a removed form would now exit 2, and under `|| true` or
# `>/dev/null 2>&1` that fails silently (the 2b gotcha).
_OLD_CALL = re.compile(
    r"""(?:\bhv|\$HV|\$\{HV\})["']?\s+(?:owner\s+(?:init|export|import|standby|escrow|restore|nominate|unnominate|claim|"""
    r"""transfer|revoke-escrow|heartbeat|freeze-timestamps|pin|mint|seal)|admit|unforget|migrate\s+forget|"""
    r"""group\s+(?:admit|revoke|deny|change|purge|retire)|config\s+(?:set|confidence|quorum))\b""")


def test_no_shipped_script_or_adapter_calls_a_removed_form():
    try:
        out = subprocess.run(["git", "-C", str(PROJECT), "ls-files", "-z"], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("not a git checkout")
    if out.returncode != 0:
        pytest.skip("not a git checkout")
    files = [f for f in out.stdout.decode().split("\0")
             if f.endswith((".sh", ".yml", ".yaml", ".json")) and not f.startswith("tests/")
             or f.startswith(("integrations/", "cells/")) and f.endswith((".py", ".md"))]
    assert files, "found no shipped files to check"
    hits = []
    for rel in files:
        for n, line in enumerate((PROJECT / rel).read_text(errors="replace").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if _OLD_CALL.search(line):
                hits.append(f"{rel}:{n}: {line.strip()}")
    assert not hits, "shipped code still calls a removed form on hv:\n" + "\n".join(hits)


def test_a_parser_split_mutant_fails_the_frozen_list(tmp_path):
    """The mutant: `hv.main` builds the full parser. A formerly pointing argv then parses, reaches a
    placeholder and refuses with a message instead of argparse's usage line, which the frozen case rejects."""
    import shutil
    root = tmp_path / "mutant"
    root.mkdir()
    for f in PROJECT.glob("*.py"):
        shutil.copy(f, root / f.name)
    src = hv_text()
    assert 'build_parser(plane="data").parse_args(sys.argv[1:])' in src
    copy_hv(root)
    for f in [root / "hv", *(root / "hivemind" / "parts").glob("*.py")]:
        f.write_text(f.read_text().replace('build_parser(plane="data").parse_args(sys.argv[1:])',
                                           'build_parser(plane="control").parse_args(sys.argv[1:])'))
    home = tmp_path / "h"
    r = subprocess.run([sys.executable, str(root / "hv"), "admit"], env=_env(home), capture_output=True, text=True)
    assert "usage:" not in r.stderr, "the mutant must differ from the real data-plane parser"


_PRESENT_TENSE = re.compile(r"pointers?\s+(?:stay|remain|are kept|are removed at|will be removed)|"
                            r"(?:stay|kept|remain)s?\s+through\s+2\.x", re.IGNORECASE)


def test_no_document_says_the_pointers_still_stay():
    """The §7 amendment is closed: the pointers are history. Past-tense mentions and the per-version history
    (`CONTRACT_HISTORY.md`, the changelogs, AGENT_INTEGRATION's `Changelog`) are exempt."""
    exempt = {"CHANGELOG.md", "docs/CONTRACT_HISTORY.md"}
    hits = []
    for path in sorted(list(PROJECT.glob("docs/*.md")) + [PROJECT / "README.md"]):
        rel = path.relative_to(PROJECT).as_posix()
        if rel in exempt:
            continue
        lines = path.read_text().split("\n")
        start = next((i for i, l in enumerate(lines) if l.startswith("**Changelog.**")), len(lines))
        for n, line in enumerate(lines[:start], 1):
            if _PRESENT_TENSE.search(line):
                hits.append(f"{rel}:{n}: {line.strip()}")
    assert not hits, "\n".join(hits)
