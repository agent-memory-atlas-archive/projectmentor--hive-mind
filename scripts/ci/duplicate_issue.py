#!/usr/bin/env python3
"""Flag a just-opened issue that duplicates an earlier open one: a comment naming the original and a label.

`.github/workflows/duplicate-issue.yml` runs this on `issues: opened` (hive-mind#493, slice G2 of the
owner-approval and hygiene design). It NEVER closes, locks or edits an issue: it adds the `duplicate?`
label and one comment, both reversible by a person, and the driver decides.

The strict rule, all four required: the normalised titles are equal, the bodies are at least 95 % similar,
the same login opened both, and the earlier one was opened no more than 10 minutes before. Same repository
only. Anything weaker is not flagged here (the driver's issue sweep lists the rest).

The title and body are untrusted text. They arrive through environment variables only and are compared,
never executed, never echoed into a command line; the only values that reach `gh` are integers, the
repository name from the runner, and fixed strings.

Environment: GH_TOKEN, REPO, ISSUE_NUMBER, ISSUE_TITLE, ISSUE_BODY, ISSUE_USER, ISSUE_CREATED_AT;
DRY_RUN=1 prints only.
"""

import difflib
import json
import os
import re
import subprocess
import sys
import unicodedata
from datetime import datetime, timedelta, timezone

WINDOW = timedelta(minutes=10)
MIN_SIMILARITY = 0.95
MAX_COMPARE = 20000  # bodies longer than this are compared for equality only (bounds the CPU spent)
LABEL = "duplicate?"
LABEL_COLOR = "cfd3d7"
_LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[bot\])?")
_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")


def normalise(text):
    """Case- and whitespace-insensitive form of a title or body."""
    return " ".join(unicodedata.normalize("NFKC", text or "").casefold().split())


def similarity(a, b):
    """Similarity of two normalised texts in [0, 1]."""
    if a == b:
        return 1.0
    if len(a) > MAX_COMPARE or len(b) > MAX_COMPARE:
        return 0.0
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if sm.real_quick_ratio() < MIN_SIMILARITY or sm.quick_ratio() < MIN_SIMILARITY:
        return 0.0
    return sm.ratio()


def parse_time(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def is_duplicate(new, old):
    """True when `old` (an earlier issue) is a strict duplicate of `new`. Both are dicts with
    title, body, user (login) and created (aware datetime)."""
    if old["user"].lower() != new["user"].lower():
        return False
    if not timedelta(0) <= new["created"] - old["created"] <= WINDOW:
        return False
    if normalise(old["title"]) != normalise(new["title"]) or not normalise(new["title"]):
        return False
    return similarity(normalise(old["body"]), normalise(new["body"])) >= MIN_SIMILARITY


def find_original(new, number, candidates):
    """Number of the earliest open issue of `candidates` (API issue dicts) that `new` duplicates, or None."""
    best = None
    for c in candidates:
        if "pull_request" in c or c.get("state") != "open" or c.get("number", number) >= number:
            continue
        try:
            old = {
                "title": c.get("title") or "",
                "body": c.get("body") or "",
                "user": (c.get("user") or {}).get("login") or "",
                "created": parse_time(c["created_at"]),
            }
        except (KeyError, ValueError):
            continue
        if old["user"] and is_duplicate(new, old) and (best is None or old["created"] < best[0]):
            best = (old["created"], c["number"])
    return best[1] if best else None


def _gh(*args):
    return subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)


def main():
    env = os.environ
    repo, num = env["REPO"], env["ISSUE_NUMBER"]
    user, created = env.get("ISSUE_USER", ""), env.get("ISSUE_CREATED_AT", "")
    dry = env.get("DRY_RUN") == "1"
    if not (num.isdigit() and _LOGIN.fullmatch(user) and _TIME.fullmatch(created)):
        print("refusing: ISSUE_NUMBER, ISSUE_USER or ISSUE_CREATED_AT is malformed")
        return 1
    new = {
        "title": env.get("ISSUE_TITLE", ""),
        "body": env.get("ISSUE_BODY", ""),
        "user": user,
        "created": parse_time(created),
    }
    since = (new["created"] - WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ")
    r = _gh("api", f"repos/{repo}/issues?state=open&sort=created&direction=desc&per_page=100&since={since}")
    if r.returncode != 0:
        print(f"refusing: could not list issues ({r.stderr.strip()[:200]})")
        return 1
    orig = find_original(new, int(num), json.loads(r.stdout))
    if orig is None:
        print("no strict duplicate; nothing to do")
        return 0
    if dry:
        print(f"DRY_RUN: would flag #{num} as a possible duplicate of #{orig}")
        return 0
    _gh("api", "--method", "POST", f"repos/{repo}/labels", "-f", f"name={LABEL}", "-f", f"color={LABEL_COLOR}")
    msg = (
        f"Possible duplicate of #{orig}: same title, a body at least 95 % the same, the same author, "
        "opened within 10 minutes. This was flagged automatically and nothing was closed; a maintainer "
        f"will decide. If it is not a duplicate, remove the `{LABEL}` label."
    )
    c = _gh("issue", "comment", num, "--repo", repo, "--body", msg)
    lab = _gh("issue", "edit", num, "--repo", repo, "--add-label", LABEL)
    print(f"flagged #{num} as a possible duplicate of #{orig}")
    for what, p in (("comment", c), ("label", lab)):
        if p.returncode != 0:
            print(f"FAILED {what}: {p.stderr.strip()[:200]}")
    return 1 if c.returncode or lab.returncode else 0


if __name__ == "__main__":
    sys.exit(main())
