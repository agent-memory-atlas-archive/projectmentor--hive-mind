"""Parser for the release-branch issue auto-close workflow (hive-mind#460)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "scripts" / "ci"))
import release_issue_close as ric  # noqa: E402

REPO = "projectmentor/hive-mind"


def p(text):
    return ric.parse_closing_refs(text, REPO)


@pytest.mark.parametrize("kw", ["close", "Closes", "CLOSED", "fix", "Fixes", "fixed", "resolve", "RESOLVES", "resolved"])
def test_keywords(kw):
    assert p(f"{kw} #12") == [12]


def test_colon_and_full_name():
    assert p("Closes: #5") == [5]
    assert p("Fixes projectmentor/hive-mind#7") == [7]
    assert p("fixes ProjectMentor/Hive-Mind#7") == [7]


def test_multiple_dedup_order():
    assert p("Closes #3\nFixes #1\nresolves #3") == [3, 1]


@pytest.mark.parametrize(
    "text",
    [
        "Closes projectmentor/hive-mind-private#59",
        "Fixes other/repo#4",
        "Closes xprojectmentor/hive-mind#4",
        "Closes projectmentor/hive-mind-private/#4",
        "Part of #460",
        "Refs #460",
        "Related to #5, see (#6)",
        "feat: thing (#470)",
        "prefix #3",
        "disclosed #3",
        "Closes #",
        "Closes #12abc",
        "Closes #0",
        "Closes 12",
    ],
)
def test_ignored(text):
    assert p(text) == []


def test_noise_ignored():
    assert p("see `Closes #9` here") == []
    assert p("```\nCloses #9\n```") == []
    assert p("~~~sh\nFixes #9\n~~~") == []
    assert p("```\nunterminated Closes #9") == []
    assert p("<!-- Closes #9 -->") == []
    assert p("Closes https://github.com/o/r/issues/9") == []
    assert p("fixes http://x.test/y#12") == []
    assert p("``Closes #9`` and Closes #10") == [10]


def test_real_after_fence():
    assert p("```\nx\n```\nCloses #8") == [8]


def test_none():
    assert p(None) == []


def test_main_dry_run_and_guards(tmp_path):
    env = {
        "PATH": os.environ["PATH"], "REPO": REPO, "PR_NUMBER": "50", "PR_TITLE": "t (#51)",
        "PR_BODY": "Closes #50\nPart of #2", "BASE_REF": "release/4.0", "MERGE_SHA": "abcdef1234567", "DRY_RUN": "1",
    }
    run = lambda e: subprocess.run([sys.executable, "-I", str(PROJECT / "scripts/ci/release_issue_close.py")], env=e, capture_output=True, text=True)
    r = run(env)  # only a self-reference: nothing to do, no gh call
    assert r.returncode == 0 and "nothing to do" in r.stdout
    r = run({**env, "MERGE_SHA": "not-a-sha; rm"})
    assert r.returncode == 1 and "malformed" in r.stdout
    r = run({**env, "PR_BODY": "\n".join(f"Closes #{i}" for i in range(100, 130))})
    assert r.returncode == 1 and "exceeds" in r.stdout
