"""Strict duplicate-issue rule and the workflow's CI-01 shape (hive-mind#493)."""

import re
import sys
import time
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "scripts" / "ci"))
import duplicate_issue as di  # noqa: E402

BODY = "The agent crashes on start.\n\nSteps:\n1. run hv\n2. observe the traceback\n" * 3


def issue(n, title="Crash on start", body=BODY, author="alice", at="2026-10-14T10:00:00Z"):
    return {"number": n, "title": title, "body": body, "author": author, "created_at": at}


OLD = issue(10)


def dup(**kw):
    return di.is_duplicate(issue(11, at=kw.pop("at", "2026-10-14T10:05:00Z"), **kw), OLD)


def test_strict_match():
    assert dup()


def test_title_normalised():
    assert dup(title="  CRASH   on\tstart ")


def test_body_line_endings_and_trailing_space():
    assert dup(body=BODY.replace("\n", "\r\n") + "  \n")


def test_different_title():
    assert not dup(title="Crash on stop")


def test_empty_title_never_matches():
    assert not di.is_duplicate(issue(11, title="", at="2026-10-14T10:01:00Z"), issue(10, title=""))


def test_different_author():
    assert not dup(author="bob")


def test_outside_window():
    assert dup(at="2026-10-14T10:10:00Z")
    assert not dup(at="2026-10-14T10:10:01Z")


def test_older_is_not_flagged_against_newer():
    assert not di.is_duplicate(OLD, issue(11, at="2026-10-14T10:05:00Z"))


def test_body_similarity_threshold():
    big = "x" * 1000
    assert not di.is_duplicate(issue(11, body=big[:-100] + "y" * 100, at="2026-10-14T10:01:00Z"), issue(10, body=big))
    assert di.is_duplicate(issue(11, body=big[:-10] + "y" * 10, at="2026-10-14T10:01:00Z"), issue(10, body=big))


def test_different_body_same_title():
    assert not dup(body="Something else entirely.")


def test_oversize_body_not_compared():
    assert di.body_similarity("a" * (di.MAX_BODY_CHARS + 1), "a" * (di.MAX_BODY_CHARS + 1)) == 0.0


def test_worst_case_run_is_bounded():
    # repetitive near-identical bodies at the size cap, many same-title same-author candidates: the
    # quadratic SequenceMatcher case, times the most comparisons a run allows
    n = di.MAX_BODY_CHARS
    h = n // 2
    body = "a" * h + "b" * h  # same letters, different order: passes the quick ratios, fails ratio()
    new = issue(500, body="b" * h + "a" * h, at="2026-10-14T10:05:00Z")
    cands = [issue(100 + i, body=body, at="2026-10-14T10:01:00Z") for i in range(100)]
    t = time.monotonic()
    assert di.find_original(new, cands) is None
    assert time.monotonic() - t < 15
    calls = []
    real = di.body_similarity
    di.body_similarity = lambda a, b: calls.append(1) or 0.0
    try:
        di.find_original(new, cands)
    finally:
        di.body_similarity = real
    assert len(calls) == di.MAX_COMPARISONS


def test_find_original_picks_oldest():
    new = issue(12, at="2026-10-14T10:06:00Z")
    assert di.find_original(new, [issue(11, at="2026-10-14T10:02:00Z"), OLD])["number"] == 10
    assert di.find_original(new, []) is None
