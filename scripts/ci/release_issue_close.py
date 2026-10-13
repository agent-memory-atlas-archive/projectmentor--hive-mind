#!/usr/bin/env python3
"""Close the issues a PR names with a closing keyword once it merges into a release/* branch.

GitHub honours `Closes #N` only on the default branch, so work merged into release/* leaves its issues
open. `.github/workflows/release-issue-close.yml` runs this after such a merge (hive-mind#460).

The PR title and body are untrusted text. They arrive through environment variables only, are parsed
here, and only integers ever reach a command line. Only a closing keyword closes, and only an issue of
THIS repository: `Part of #N`, `Refs #N`, `(#N)` in a title, `other/repo#N` and anything inside a code
span, code fence, HTML comment or URL are ignored.

Environment: GH_TOKEN, REPO, PR_NUMBER, PR_TITLE, PR_BODY, BASE_REF, MERGE_SHA; DRY_RUN=1 prints only.
"""

import json
import os
import re
import subprocess
import sys

MAX_CLOSE = 25  # a PR naming more than this is not a normal PR; close none rather than sweep

_FENCE = re.compile(r"^[ \t]*(```|~~~).*?^[ \t]*\1[^\n]*$|^[ \t]*(```|~~~).*\Z", re.S | re.M)
_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.S)
_SPAN = re.compile(r"(`+)(?:(?!\1).)+?\1", re.S)
_URL = re.compile(r"(?:https?|ftp)://\S+|\bwww\.\S+", re.I)
_CLOSE = re.compile(
    r"(?<![\w/#.-])(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)(?::[ \t]*|[ \t]+)"
    r"((?:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)?)#(\d{1,9})(?![\w#/-])",
    re.I,
)


def strip_noise(text):
    """Remove the parts of Markdown in which a keyword must not count."""
    for rx in (_COMMENT, _FENCE, _SPAN, _URL):
        text = rx.sub(" ", text)
    return text


def parse_closing_refs(text, repo):
    """Issue numbers in `text` that a closing keyword ties to `repo` ("owner/name"), in order, deduplicated."""
    found = []
    for m in _CLOSE.finditer(strip_noise(text or "")):
        other, num = m.group(1), int(m.group(2))
        if other and other.lower() != repo.lower():
            continue
        if num > 0 and num not in found:
            found.append(num)
    return found


def _gh(*args):
    return subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)


def main():
    env = os.environ
    repo, pr = env["REPO"], env["PR_NUMBER"]
    base, sha = env.get("BASE_REF", ""), env.get("MERGE_SHA", "")
    dry = env.get("DRY_RUN") == "1"
    if not (pr.isdigit() and re.fullmatch(r"[0-9a-f]{7,64}", sha)):
        print("refusing: PR_NUMBER or MERGE_SHA is malformed")
        return 1
    nums = parse_closing_refs(env.get("PR_TITLE", "") + "\n" + env.get("PR_BODY", ""), repo)
    nums = [n for n in nums if n != int(pr)]
    if len(nums) > MAX_CLOSE:
        print(f"refusing: {len(nums)} closing references exceeds {MAX_CLOSE}")
        return 1
    if not nums:
        print("no closing keywords for this repository; nothing to do")
        return 0
    failed = 0
    for n in nums:
        r = _gh("api", f"repos/{repo}/issues/{n}")
        if r.returncode != 0:
            print(f"skip #{n}: lookup failed ({r.stderr.strip()[:200]})")
            continue
        issue = json.loads(r.stdout)
        if "pull_request" in issue:
            print(f"skip #{n}: is a pull request")
        elif issue.get("state") != "open":
            print(f"skip #{n}: already closed")
        elif dry:
            print(f"DRY_RUN: would close #{n}")
        else:
            msg = f"Closed by #{pr} ({sha[:12]}) on {base}."
            c = _gh("issue", "close", str(n), "--repo", repo, "--reason", "completed", "--comment", msg)
            print(f"closed #{n}" if c.returncode == 0 else f"FAILED #{n}: {c.stderr.strip()[:200]}")
            failed += c.returncode != 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
