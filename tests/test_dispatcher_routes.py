"""#370: every `hive-mind <verb>` that the update script, the CLI reference and the notices name must route
through the dispatcher, and a notice must never send the owner to a `hive-mind` verb that the control plane
refuses (`hive-mind sync` is `hv sync now`)."""
import re
import subprocess
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
DISPATCHER = PROJECT / "scripts" / "installer" / "dispatcher.sh"
SOURCES = [PROJECT / "scripts" / "installer" / "_update.sh", PROJECT / "docs" / "CLI_REFERENCE.md",
           *sorted(PROJECT.glob("hivemind_*.py")), *sorted(PROJECT.glob("hive_*.py"))]
# a verb is *named as a command* in backticks, after "run:" / "then:", or at the start of a code line
NAMED = re.compile(r"(?:`|\b(?:run|then):\s+|^\s*(?:\$\s*)?|print\(\"\s*)hive-mind ([a-z][a-z-]*)", re.M)
NOT_VERBS = {"sync"}                      # named only to be corrected: asserted separately below


def _named_verbs():
    found = set()
    for f in SOURCES:
        found |= set(NAMED.findall(f.read_text()))
    return found - NOT_VERBS


def _tree(tmp_path):
    """A copy of the dispatcher over stubs: every handler it execs just reports that it was reached."""
    inst = tmp_path / "scripts" / "installer"
    inst.mkdir(parents=True)
    (inst / "dispatcher.sh").write_text(DISPATCHER.read_text())
    for n in sorted(set(re.findall(r'\$INSTALLER/([\w.-]+\.sh)', DISPATCHER.read_text()))):
        (inst / n).write_text('echo "ROUTED $0"\n')
    (tmp_path / "hivemind_ctl.py").write_text('import sys\nprint("ROUTED ctl", *sys.argv[1:])\n')
    return inst / "dispatcher.sh"


def test_the_scrape_finds_the_verbs_it_is_meant_to_check():
    assert {"migrate", "update", "owner", "module", "unforget"} <= _named_verbs()


@pytest.mark.parametrize("verb", sorted(_named_verbs()))
def test_named_verb_routes_through_the_dispatcher(verb, tmp_path):
    d = _tree(tmp_path)
    r = subprocess.run(["bash", str(d), verb, "forget", "--check"], capture_output=True, text=True, timeout=30,
                       env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HIVE_DIR": str(tmp_path)})
    assert "ROUTED" in r.stdout and "Usage: hive-mind" not in r.stdout, f"`hive-mind {verb}` is not routed: {r.stdout}"


def test_migrate_forget_reaches_the_control_plane_with_its_arguments(tmp_path):
    r = subprocess.run(["bash", str(_tree(tmp_path)), "migrate", "forget", "--check"], capture_output=True,
                       text=True, timeout=30, env={"PATH": "/usr/bin:/bin", "HIVE_DIR": str(tmp_path)})
    assert r.stdout.strip() == "ROUTED ctl migrate forget --check"


def test_no_notice_sends_the_owner_to_hive_mind_sync():
    for f in SOURCES:
        assert not re.search(r"hive-mind sync\b", f.read_text()), f"{f.name} names `hive-mind sync`; use `hv sync now`"
