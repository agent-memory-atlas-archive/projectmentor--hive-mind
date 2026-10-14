"""Strict duplicate-issue rule for the G2 workflow (hive-mind#493)."""

import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "scripts" / "ci"))
import duplicate_issue as di  # noqa: E402

T0 = datetime(2026, 10, 14, 4, 0, 0, tzinfo=timezone.utc)
BODY = "The doctor prints the wrong path when the stash is missing.\n\nSteps:\n1. run hv doctor\n2. read it\n"


def issue(num, title="Doctor path wrong", body=BODY, user="alice", minutes=0, state="open", **extra):
    t = (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"number": num, "title": title, "body": body, "user": {"login": user}, "created_at": t, "state": state, **extra}


def new_of(i):
    return {"title": i["title"], "body": i["body"], "user": i["user"]["login"], "created": di.parse_time(i["created_at"])}


def orig(new_issue, *cands):
    return di.find_original(new_of(new_issue), new_issue["number"], list(cands))


def test_strict_duplicate():
    assert orig(issue(2, minutes=3), issue(1)) == 1


def test_title_and_body_normalised():
    assert orig(issue(2, title="  DOCTOR   path wrong ", body=BODY.upper(), minutes=1), issue(1)) == 1


def test_small_body_edit_still_matches():
    assert orig(issue(2, body=BODY + "thanks", minutes=1), issue(1)) == 1


def test_different_title():
    assert orig(issue(2, title="Doctor path is wrong!", minutes=1), issue(1)) is None


def test_different_body():
    assert orig(issue(2, body="something else entirely about the dashboard", minutes=1), issue(1)) is None


def test_different_author_or_case_of_login():
    assert orig(issue(2, user="bob", minutes=1), issue(1)) is None
    assert orig(issue(2, user="Alice", minutes=1), issue(1)) == 1


def test_window():
    assert orig(issue(2, minutes=10), issue(1)) == 1
    assert orig(issue(2, minutes=11), issue(1)) is None


def test_original_must_be_open_older_and_an_issue():
    assert orig(issue(2, minutes=1), issue(1, state="closed")) is None
    assert orig(issue(2, minutes=1), issue(3)) is None  # a later number
    assert orig(issue(2, minutes=1), issue(1, pull_request={})) is None
    assert orig(issue(2, minutes=1), issue(2)) is None  # itself


def test_earliest_original_wins():
    assert orig(issue(3, minutes=5), issue(2, minutes=2), issue(1, minutes=0)) == 1


def test_empty_title_never_matches():
    assert orig(issue(2, title="", minutes=1), issue(1, title="")) is None


def test_malformed_candidate_skipped():
    bad = issue(1)
    del bad["created_at"]
    assert orig(issue(2, minutes=1), bad, issue(0, minutes=-1)) == 0


def test_long_bodies_equal_only():
    big = "x" * (di.MAX_COMPARE + 1)
    assert orig(issue(2, body=big, minutes=1), issue(1, body=big)) == 1
    assert orig(issue(2, body=big + "y", minutes=1), issue(1, body=big)) is None


def test_workflow_cannot_close_or_interpolate():
    wf = (PROJECT / ".github" / "workflows" / "duplicate-issue.yml").read_text()
    code = "\n".join(line for line in wf.splitlines() if not line.lstrip().startswith("#"))
    assert re.search(r"^permissions: \{\}$", code, re.M)
    assert re.findall(r"^\s+(\w[\w-]*): (read|write)\b", code, re.M) == [("issues", "write")]
    assert "pull_request_target" not in code
    for run in re.findall(r"run: (.*)", code):
        assert "${{" not in run
    src = (PROJECT / "scripts" / "ci" / "duplicate_issue.py").read_text()
    assert "issue close" not in src and "state=closed" not in src
    for line in code.splitlines():
        if "uses:" in line:
            assert re.search(r"@[0-9a-f]{40}\b", line)
