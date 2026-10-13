"""fakegh itself (slice C): the stateful behaviour S1 and S2 rely on, through the `gh` shim a node runs, with no hwatch needed."""
import json
import sys

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="harness is Linux-first")]


@pytest.fixture
def gh(fleet, fakegh):
    node = fleet[0]
    env = node.env(**fakegh.install(node.bin, client=node.name))

    def call(*args, stdin=None):
        r = node.run(["gh", "api", "-i", *args], env=env, input=stdin)
        head, _, body = r.stdout.replace("\r\n", "\n").partition("\n\n")
        lines = head.split("\n")
        return int(lines[0].split()[1]), {k.lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}, \
            (json.loads(body) if body.strip() else None), r.returncode
    return call


def test_lists_are_etagged_and_a_conditional_request_costs_no_quota(gh, fakegh):
    fakegh.open_pr()
    status, headers, body, rc = gh("repos/o/r/pulls?state=open")
    assert (status, rc, len(body)) == (200, 0, 1) and headers["etag"]
    remaining = int(headers["x-ratelimit-remaining"])
    status, h2, body, rc = gh("repos/o/r/pulls?state=open", "-H", f"If-None-Match: {headers['etag']}")
    assert (status, body, rc) == (304, None, 1) and int(h2["x-ratelimit-remaining"]) == remaining      # gh exits 1 on 304, as the real one
    fakegh.open_pr()
    status, h3, body, _ = gh("repos/o/r/pulls?state=open", "-H", f"If-None-Match: {headers['etag']}")
    assert status == 200 and len(body) == 2 and h3["etag"] != headers["etag"] and int(h3["x-ratelimit-remaining"]) == remaining - 1


def test_a_merge_deletes_the_branch_and_retargets_the_child_and_a_squash_leaves_it_conflicting(gh, fakegh):
    a = fakegh.open_pr(head="a")
    b = fakegh.open_pr(base="a", head="b")
    assert gh(f"repos/o/r/pulls/{b}")[2]["base"]["ref"] == "a"
    fakegh.merge(a, method="squash")
    pr = gh(f"repos/o/r/pulls/{b}")[2]
    assert pr["base"]["ref"] == "main" and pr["mergeable"] is False and pr["mergeable_state"] == "dirty"
    assert "a" not in fakegh.branches and gh(f"repos/o/r/pulls/{a}")[2]["merged"] is True
    sha = fakegh.rebase_onto_base(b)
    pr = gh(f"repos/o/r/pulls/{b}")[2]
    assert pr["head"]["sha"] == sha and pr["mergeable"] is True


def test_a_merge_with_no_retarget_closes_the_child_and_a_merge_commit_does_not_conflict_it(gh, fakegh):
    a, b = fakegh.open_pr(head="a"), fakegh.open_pr(base="a", head="b")
    fakegh.merge(a, method="merge", retarget=False)
    assert gh(f"repos/o/r/pulls/{b}")[2]["state"] == "closed"
    a2, b2 = fakegh.open_pr(head="a2"), fakegh.open_pr(base="a2", head="b2")
    fakegh.merge(a2, method="merge", retarget=True)
    pr = gh(f"repos/o/r/pulls/{b2}")[2]
    assert pr["state"] == "open" and pr["base"]["ref"] == "main" and pr["mergeable"] is True


def test_the_rate_limit_answers_the_real_headers_and_a_post_lands_as_the_logged_in_account(gh, fakegh):
    n = fakegh.open_issue()
    status, _, body, rc = gh("-X", "POST", f"repos/o/r/issues/{n}/comments", "--input", "-", stdin=json.dumps({"body": "hi"}))
    assert (status, rc) == (201, 0) and body["user"]["login"] == "acct" and [c["body"] for c in fakegh.posted()] == ["hi"]
    fakegh.rate_limit(remaining=0, status=403)
    status, headers, _, rc = gh(f"repos/o/r/issues/{n}")
    assert (status, rc, headers["x-ratelimit-remaining"]) == (403, 1, "0")
    fakegh.rate_reset()
    assert gh(f"repos/o/r/issues/{n}")[0] == 200


def test_an_unknown_call_is_a_visible_404(gh, fakegh):
    assert gh("repos/o/r/not-a-thing")[0] == 404
    assert fakegh.requested("not-a-thing")[0][2] == 404
