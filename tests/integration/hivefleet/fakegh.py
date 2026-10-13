"""fakegh: a stateful fake GitHub for the integration tests (slice C of private docs/design/integration_tests_4x.md).

hwatch reaches GitHub only by running `gh api -i <path>`; there is no base-URL setting. So the fake has two halves: a `gh`
shim that goes first on a node's PATH and relays each call over loopback, and a small HTTP server (a thread of the test
process, bound to 127.0.0.1) holding the state. Unlike `tests/ghfake.py` in hwatch-dev, which answers fixed routes per
call, this keeps repos, issues, pull requests with `base` and `head`, comments, reviews and check runs, and changes them
the way GitHub does: a merge can delete the head branch and then retarget or close the pull requests stacked on it; every
list answers an ETag and a conditional request with the same tag answers 304; a rate-limit counter answers the real
403/429 headers; an event log records every request so a test can read back what a node asked, and what it posted.

The REST subset is the one hwatch's GitHub channel uses (pulls, reviews, issues, comments, check runs, workflow runs,
labels, rate_limit, search, and POST of a comment). Anything else answers 404 and is logged, so a new call is visible.
"""
import hashlib
import json
import re
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import free_port

SHIM = r'''#!/usr/bin/env python3
"""A `gh` that relays `gh api` to fakegh. Only the flags hwatch passes: -i, -X, -H, --input -."""
import http.client
import os
import sys

argv = sys.argv[1:]
url = os.environ["FAKEGH_ADDR"]
if argv[:2] == ["auth", "status"]:
    conn = http.client.HTTPConnection(url, timeout=30)
    conn.request("GET", "/__login")
    login = conn.getresponse().read().decode()
    print(f"github.com\n  ✓ Logged in to github.com account {login} (keyring)\n  - Active account: true")
    sys.exit(0)
if argv[:2] != ["api", "-i"]:
    sys.stderr.write("fakegh: unsupported gh call: " + " ".join(argv) + "\n")
    sys.exit(2)
method, headers, body, path = "GET", {}, None, None
rest = argv[2:]
i = 0
while i < len(rest):
    a = rest[i]
    if a == "-X":
        method = rest[i + 1]; i += 2
    elif a == "-H":
        k, _, v = rest[i + 1].partition(":"); headers[k.strip()] = v.strip(); i += 2
    elif a == "--input":
        body = sys.stdin.buffer.read(); i += 2
    else:
        path = a; i += 1
headers["X-Fakegh-Client"] = os.environ.get("FAKEGH_CLIENT", "")
conn = http.client.HTTPConnection(url, timeout=30)
conn.request(method, "/" + path.lstrip("/"), body=body, headers=headers)
r = conn.getresponse()
data = r.read().decode()
out = f"HTTP/2.0 {r.status} {r.reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in r.getheaders()
                                                      if k.lower() not in ("server", "date", "content-length")) + "\r\n" + data
sys.stdout.write(out)
if r.status >= 300:
    sys.stderr.write(f"gh: HTTP {r.status}\n")
    sys.exit(1)
'''


def _stamp(epoch):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch)))


class FakeGitHub:
    """State and server. Mutators (`open_pr`, `comment`, `merge`, ...) are called by the test; the HTTP side only reads, except
    for POST of a comment, which is how a node's `hwatch post` lands. Everything is guarded by one lock."""

    def __init__(self, repo="o/r", login="acct"):
        self.repo = repo
        self.login = login
        self.lock = threading.RLock()
        self.offset = 0             # seconds the fake clock is ahead of the wall clock; advance() moves it
        self._last = 0
        self.next_id = 1000
        self.issues = {}            # number -> issue/PR dict (a PR has "pull")
        self.comments = []          # issue comments, in creation order
        self.reviews = []           # (number, review)
        self.checks = {}            # sha -> [check run]
        self.requests = []          # (method, path, status, client) of every request, the event log
        self.rate = {"limit": 5000, "remaining": 5000, "reset": 1_800_000_000}
        self.fail_next = []         # [(status, headers)] to answer instead of the next requests
        self.etag_hits = 0
        self.branches = {"main": "0" * 40}
        self.repo_labels = {"security"}        # hwatch's label precheck needs the workflow's override label to exist
        self._server = ThreadingHTTPServer(("127.0.0.1", free_port()), self._handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    # ---- plumbing ----------------------------------------------------------------------------

    @property
    def addr(self):
        return "%s:%d" % self._server.server_address

    def close(self):
        self._server.shutdown()
        self._server.server_close()

    def install(self, bin_dir, client=""):
        """Put the `gh` shim into `bin_dir`; returns the env a node needs to reach this server."""
        shim = bin_dir / "gh"
        shim.write_text(SHIM)
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
        return {"FAKEGH_ADDR": self.addr, "FAKEGH_CLIENT": client}

    def now(self):
        return _stamp(time.time() + self.offset)

    def advance(self, seconds):
        """Move the fake clock forward without sleeping (the plan's `Clock`): later stamps are this much later."""
        with self.lock:
            self.offset += seconds

    def _tick(self):
        """A stamp for a change: wall clock plus the offset, never earlier than the last one handed out."""
        self._last = max(self._last, int(time.time() + self.offset))
        return _stamp(self._last)

    def _id(self):
        self.next_id += 1
        return self.next_id

    # ---- state the test sets up and changes -----------------------------------------------------

    def _item(self, title, author, assoc, labels, body):
        n = max(self.issues, default=0) + 1
        stamp = self._tick()
        item = {"number": n, "title": title, "state": "open", "body": body, "created_at": stamp, "updated_at": stamp,
                "user": {"login": author}, "author_association": assoc, "labels": [{"name": x} for x in labels],
                "html_url": f"https://github.com/{self.repo}/issues/{n}", "closed_at": None, "merged_at": None}
        self.issues[n] = item
        return item

    def open_issue(self, title="an issue", author="ann", assoc="MEMBER", labels=(), body=""):
        with self.lock:
            return self._item(title, author, assoc, labels, body)["number"]

    def open_pr(self, title="a change", base="main", head=None, author="ann", assoc="MEMBER", labels=(), sha=None, body=""):
        """A pull request from branch `head` (default `pr-<n>`) into `base`. Its head sha is stable until `push`."""
        with self.lock:
            item = self._item(title, author, assoc, labels, body)
            n = item["number"]
            head = head or f"pr-{n}"
            sha = sha or hashlib.sha1(f"{self.repo}:{head}:{n}:0".encode()).hexdigest()
            self.branches[head] = sha
            item["pull"] = {"base": base, "head_ref": head, "sha": sha, "pushes": 0, "merged_by": None}
            item["html_url"] = f"https://github.com/{self.repo}/pull/{n}"
            return n

    def push(self, number):
        """A new commit on the PR's head branch: new head sha, `updated_at` moves."""
        with self.lock:
            it = self.issues[number]
            pr = it["pull"]
            pr["pushes"] += 1
            pr["sha"] = hashlib.sha1(f"{self.repo}:{pr['head_ref']}:{number}:{pr['pushes']}".encode()).hexdigest()
            self.branches[pr["head_ref"]] = pr["sha"]
            it["updated_at"] = self._tick()
            return pr["sha"]

    def comment(self, number, body, author="ann", assoc="MEMBER"):
        with self.lock:
            stamp = self._tick()
            cid = self._id()
            row = {"id": cid, "body": body, "user": {"login": author}, "author_association": assoc, "created_at": stamp,
                   "updated_at": stamp, "issue_url": f"https://api.github.com/repos/{self.repo}/issues/{number}",
                   "html_url": f"https://github.com/{self.repo}/issues/{number}#issuecomment-{cid}"}
            self.comments.append(row)
            self.issues[number]["updated_at"] = stamp
            return cid

    def check_run(self, sha, name="ci", conclusion="success"):
        with self.lock:
            stamp = self._tick()
            self.checks.setdefault(sha, []).append({"id": self._id(), "name": name, "conclusion": conclusion, "status": "completed",
                                                    "completed_at": stamp, "app": {"slug": "ci"}, "html_url": f"https://github.com/{self.repo}/runs/1"})

    def merge(self, number, method="merge", delete_branch=True, retarget=True, by="owner"):
        """Merge PR `number` into its base, as GitHub does it. `method` is merge | squash | rebase. With `delete_branch`, the head
        branch goes, and every open PR whose base was that branch is retargeted to the merged PR's base (`retarget=True`, the
        "automatically delete head branches" behaviour) or closed (`retarget=False`, what GitHub does when the base is gone and the
        PR can no longer be retargeted). A squash merge writes a new commit on the base: a stacked child still carries the
        parent's original commits and shows `mergeable: CONFLICTING` until it is rebased (the incident of h:a3f0ba6b6a)."""
        with self.lock:
            it = self.issues[number]
            pr = it["pull"]
            stamp = self._tick()
            it.update(state="closed", closed_at=stamp, merged_at=stamp, updated_at=stamp)
            pr["merged_by"], pr["merge_method"] = by, method
            merge_sha = hashlib.sha1(f"{self.repo}:{number}:{method}:merge".encode()).hexdigest()
            self.branches[pr["base"]] = merge_sha
            pr["merge_sha"] = merge_sha
            children = [c for c in self.issues.values() if c.get("pull") and c["state"] == "open" and c["pull"]["base"] == pr["head_ref"]]
            if delete_branch:
                self.branches.pop(pr["head_ref"], None)
                for child in children:
                    cp = child["pull"]
                    if retarget:
                        cp["base"] = pr["base"]
                    else:
                        child.update(state="closed", closed_at=stamp)
                    child["updated_at"] = stamp
            for child in children:                                    # whether or not retargeted, a squash leaves its commits behind
                child["pull"]["conflicting"] = method in ("squash", "rebase") and child["state"] == "open"
            return merge_sha

    def rebase_onto_base(self, number):
        """What the stacked PR's author does after a squash merge: rebase; new head sha, no longer conflicting."""
        sha = self.push(number)
        self.issues[number]["pull"]["conflicting"] = False
        return sha

    def rate_limit(self, remaining=0, status=403):
        """From now on every request answers `status` with X-RateLimit-Remaining: `remaining` (0 = exhausted) until `rate_reset()`."""
        with self.lock:
            self.rate["remaining"] = remaining
            self._rate_status = status

    def rate_reset(self):
        with self.lock:
            self.rate["remaining"] = self.rate["limit"]
            self._rate_status = None

    _rate_status = None

    # ---- what the test reads back -----------------------------------------------------------------

    def posted(self):
        """Comments a node posted through `gh api -X POST .../comments` (not the ones the test created with `comment`)."""
        with self.lock:
            return [c for c in self.comments if c.get("posted_by_node")]

    def requested(self, needle="", method=None):
        with self.lock:
            return [r for r in self.requests if needle in r[1] and (method is None or r[0] == method)]

    # ---- the REST side --------------------------------------------------------------------------------

    def _pull_json(self, it):
        pr = it["pull"]
        out = {k: v for k, v in it.items() if k != "pull"}
        out.update(
            head={"ref": pr["head_ref"], "sha": pr["sha"], "repo": {"full_name": self.repo}},
            base={"ref": pr["base"], "sha": self.branches.get(pr["base"], "0" * 40), "repo": {"full_name": self.repo}},
            merged=bool(it["merged_at"]), mergeable=not pr.get("conflicting", False),
            mergeable_state="dirty" if pr.get("conflicting") else "clean")
        return out

    def _issue_json(self, it):
        out = {k: v for k, v in it.items() if k != "pull"}
        if "pull" in it:
            out["pull_request"] = {"url": f"https://api.github.com/repos/{self.repo}/pulls/{it['number']}"}
        return out

    def _route(self, method, path, query, body):
        """`(status, body)` for a request, or None for 404."""
        repo = re.escape(self.repo)
        m = re.fullmatch(rf"/repos/{repo}/(.*)", path)
        if path == "/rate_limit":
            return 200, {"resources": {"core": {k: self.rate[k] for k in ("limit", "remaining", "reset")}}}
        if path == "/search/issues":
            return 200, {"items": []}
        if not m:
            return None
        rest, q = m.group(1), {k: v[0] for k, v in query.items()}
        state = q.get("state", "open")
        if method == "POST":
            mm = re.fullmatch(r"issues/(\d+)/comments", rest)
            if not mm or int(mm.group(1)) not in self.issues:
                return None
            cid = self.comment(int(mm.group(1)), json.loads(body or b"{}").get("body", ""), author=self.login, assoc="OWNER")
            self.comments[-1]["posted_by_node"] = True
            return 201, self.comments[-1]
        if method != "GET":
            return None
        if rest == "pulls":
            rows = [self._pull_json(i) for i in self.issues.values() if i.get("pull") and (state == "all" or i["state"] == state)]
            return 200, sorted(rows, key=lambda r: r["updated_at"], reverse=True)
        if rest == "issues":
            rows = [self._issue_json(i) for i in self.issues.values() if (state == "all" or i["state"] == state)]
            return 200, sorted(rows, key=lambda r: r["created_at"], reverse=True)
        if rest == "labels":
            return 200, [{"name": n} for n in sorted(self.repo_labels | {lab["name"] for i in self.issues.values() for lab in i["labels"]})]
        if rest in ("issues/comments", "pulls/comments"):
            since = q.get("since", "")
            return 200, ([c for c in self.comments if c["created_at"] >= since] if rest == "issues/comments" else [])
        if rest == "actions/runs":
            return 200, {"workflow_runs": []}
        mm = re.fullmatch(r"(issues|pulls)/(\d+)/comments", rest)       # one item's thread (the hourly reconcile reads it)
        if mm:
            n, since = int(mm.group(2)), q.get("since", "")
            if n not in self.issues:
                return None
            rows = [c for c in self.comments if c["issue_url"].endswith(f"/issues/{n}") and c["created_at"] >= since]
            return 200, rows if mm.group(1) == "issues" else []
        mm = re.fullmatch(r"pulls/(\d+)", rest)
        if mm:
            it = self.issues.get(int(mm.group(1)))
            return (200, self._pull_json(it)) if it and it.get("pull") else None
        mm = re.fullmatch(r"issues/(\d+)", rest)
        if mm:
            it = self.issues.get(int(mm.group(1)))
            return (200, self._issue_json(it)) if it else None
        mm = re.fullmatch(r"pulls/(\d+)/reviews", rest)
        if mm:
            return 200, [r for n, r in self.reviews if n == int(mm.group(1))]
        mm = re.fullmatch(r"commits/([0-9a-f]+)/check-runs", rest)
        if mm:
            runs = self.checks.get(mm.group(1), [])
            return 200, {"total_count": len(runs), "check_runs": runs}
        return None

    def _handler(self):
        gh = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def _serve(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                u = urlsplit(self.path)
                client = self.headers.get("X-Fakegh-Client", "")
                with gh.lock:
                    status, headers, out = gh._answer(self.command, u.path, parse_qs(u.query), body, self.headers.get("If-None-Match"))
                    gh.requests.append((self.command, u.path + (f"?{u.query}" if u.query else ""), status, client))
                data = json.dumps(out).encode() if out is not None and not isinstance(out, bytes) else (out or b"")
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _serve

            def log_message(self, *a):
                pass

        return Handler

    def _rate_headers(self, remaining=None):
        return {"X-RateLimit-Limit": str(self.rate["limit"]),
                "X-RateLimit-Remaining": str(self.rate["remaining"] if remaining is None else remaining),
                "X-RateLimit-Reset": str(self.rate["reset"])}

    def _answer(self, method, path, query, body, if_none_match):
        if path == "/__login":
            return 200, {}, self.login.encode()
        if self.fail_next:
            status, extra = self.fail_next.pop(0)
            return status, {**self._rate_headers(), **extra}, {"message": "injected failure"}
        if self._rate_status and path != "/rate_limit":
            return self._rate_status, self._rate_headers(0), {"message": "API rate limit exceeded"}
        got = self._route(method, path, query, body)
        if got is None:
            return 404, self._rate_headers(), {"message": "Not Found"}
        status, out = got
        headers = {}
        if method == "GET" and status == 200 and path != "/rate_limit":
            tag = '"%s"' % hashlib.sha1(json.dumps(out, sort_keys=True).encode()).hexdigest()[:16]
            headers["Etag"] = tag
            if if_none_match == tag:
                self.etag_hits += 1
                return 304, {**self._rate_headers(), **headers}, None
            self.rate["remaining"] = max(0, self.rate["remaining"] - 1)          # only a 200 costs quota, as on GitHub
        return status, {**self._rate_headers(), **headers}, out
