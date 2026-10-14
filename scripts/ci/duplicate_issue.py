#!/usr/bin/env python3
"""Flag a newly opened issue that is a strict duplicate of an open one (hive-mind#493, design G2).

`.github/workflows/duplicate-issue.yml` runs this on `issues: opened`. The rule is deliberately narrow: an
OPEN issue of this repository that (1) has the same normalised title, (2) has a body at least 95 % similar,
(3) was opened by the same login, (4) within 10 minutes before the new one. A match gets a comment naming the
original and the `duplicate?` label. This script never closes, edits or deletes an issue.

The title and body are untrusted text. They arrive through environment variables only, are compared here, and
never reach a command line or the comment: the comment is fixed text plus one integer.

Environment: GH_TOKEN, REPO, ISSUE_NUMBER, ISSUE_TITLE, ISSUE_BODY, ISSUE_AUTHOR, ISSUE_CREATED_AT;
DRY_RUN=1 prints only.
"""

import difflib
import json
import os
import re
import subprocess
import sys
import unicodedata
from datetime import datetime, timedelta

LABEL = "duplicate?"
WINDOW = timedelta(minutes=10)
MIN_BODY_SIMILARITY = 0.95
MAX_BODY_CHARS = 2000  # a longer body is not compared: SequenceMatcher is quadratic on repetitive text
MAX_COMPARISONS = 5  # body comparisons per run; with the cap above, a run costs about a second at worst
MAX_CANDIDATES = 100


def norm_title(text):
    """Title with case, Unicode compatibility forms and runs of whitespace folded away."""
    return " ".join(unicodedata.normalize("NFKC", text or "").casefold().split())


def norm_body(text):
    return "\n".join(l.rstrip() for l in (text or "").replace("\r\n", "\n").replace("\r", "\n").strip().split("\n"))


def body_similarity(a, b):
    a, b = norm_body(a), norm_body(b)
    if len(a) > MAX_BODY_CHARS or len(b) > MAX_BODY_CHARS:
        return 0.0
    if a == b:
        return 1.0
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if sm.real_quick_ratio() < MIN_BODY_SIMILARITY or sm.quick_ratio() < MIN_BODY_SIMILARITY:
        return 0.0
    return sm.ratio()


def parse_time(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def same_origin(new, old):
    """The cheap conditions: older number, same author, same non-empty title, inside the window."""
    if old["number"] >= new["number"] or not new["author"] or old["author"] != new["author"]:
        return False
    if norm_title(old["title"]) != norm_title(new["title"]) or not norm_title(new["title"]):
        return False
    gap = parse_time(new["created_at"]) - parse_time(old["created_at"])
    if not timedelta(0) <= gap <= WINDOW:
        return False
    return True


def is_duplicate(new, old):
    """new/old: dicts with number, title, body, author, created_at. True only if all four conditions hold."""
    return same_origin(new, old) and body_similarity(old["body"], new["body"]) >= MIN_BODY_SIMILARITY


def find_original(new, candidates):
    """The oldest candidate that is a strict duplicate target for `new`, or None. At most MAX_COMPARISONS
    bodies are compared (oldest first), so an author's pile of look-alike issues cannot lengthen the run."""
    pool = sorted((c for c in candidates if same_origin(new, c)), key=lambda c: c["number"])
    for c in pool[:MAX_COMPARISONS]:
        if body_similarity(c["body"], new["body"]) >= MIN_BODY_SIMILARITY:
            return c
    return None


def _gh(*args, stdin=None):
    return subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60, input=stdin)


def _candidate(i):
    return {
        "number": i["number"],
        "title": i.get("title") or "",
        "body": i.get("body") or "",
        "author": (i.get("user") or {}).get("login", ""),
        "created_at": i["created_at"],
    }


def main():
    env = os.environ
    repo, num = env["REPO"], env["ISSUE_NUMBER"]
    dry = env.get("DRY_RUN") == "1"
    if not num.isdigit() or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        print("refusing: ISSUE_NUMBER or REPO is malformed")
        return 1
    new = {
        "number": int(num),
        "title": env.get("ISSUE_TITLE", ""),
        "body": env.get("ISSUE_BODY", ""),
        "author": env.get("ISSUE_AUTHOR", ""),
        "created_at": env["ISSUE_CREATED_AT"],
    }
    since = (parse_time(new["created_at"]) - WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ")
    r = _gh("api", f"repos/{repo}/issues?state=open&sort=created&direction=desc&per_page={MAX_CANDIDATES}&since={since}")
    if r.returncode != 0:
        print(f"lookup failed ({r.stderr.strip()[:200]})")
        return 1
    cands = [_candidate(i) for i in json.loads(r.stdout) if "pull_request" not in i]
    orig = find_original(new, cands)
    if orig is None:
        print("no strict duplicate; nothing to do")
        return 0
    o = orig["number"]
    if dry:
        print(f"DRY_RUN: #{num} would be flagged as a suspected duplicate of #{o}")
        return 0
    msg = (
        f"Suspected duplicate of #{o}: same title, a body at least 95% identical, same author, "
        f"opened within 10 minutes. Automatic check; nothing was closed. "
        f"If this is not a duplicate, remove the `{LABEL}` label."
    )
    failed = 0
    c = _gh("issue", "comment", num, "--repo", repo, "--body-file", "-", stdin=msg)
    failed += c.returncode != 0
    lab = _gh("api", f"repos/{repo}/issues/{num}/labels", "-f", f"labels[]={LABEL}")
    failed += lab.returncode != 0
    print(f"flagged #{num} as a suspected duplicate of #{o}" if not failed else f"FAILED: {(c.stderr + lab.stderr).strip()[:200]}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
