"""S2 stacked-PR merge (slice C of private docs/design/integration_tests_4x.md).

PR B is based on PR A's branch. Merging A deletes its branch and GitHub then retargets B to A's base (the "delete head branches"
setting) or closes B; and a squash merge leaves B carrying A's original commits, so B goes CONFLICTING until it is rebased. fakegh
does all of that statefully; the real `hwatch serve` polls it. Incident record (h:a3f0ba6b6a): hive-mind#435 (C2) was stacked on
#432 (C1); after C1 was squash-merged (`c43309f`), #435 still carried C1's commits and went CONFLICTING, and needed a rebase and a
range-diff to keep its clearances. The working pattern since: merge the base PR with `--merge`, then retarget the stacked one.

What hwatch must do (and what it does not read: it never reads a PR's `base` or `mergeable`, only its head sha and state):
- A's merge is delivered once (one `closed` event); B is neither re-opened as new nor re-woken by the retarget;
- B's pending wake survives, unchanged, and its seat runs exactly once afterwards;
- B's recorded head sha is GitHub's, before and after the merge, so a clearance bound to a sha cannot be applied to a head that moved;
- after the rebase B's new head is delivered once, under its new sha;
- a PR closed by the merge (no retarget) is delivered once as closed and dropped from the open set.
"""
import sys

import pytest

from hivefleet import wait_for

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="hwatch's launcher is linux-systemd")]

ASK = "**Implementer:** please take this"


def _keys(hw, kind):
    return [k for k in hw.seen() if k.startswith(kind + ":")]


@pytest.fixture
def stack(hwatch_node, fakegh):
    """A (main <- a) and B (a <- b); hwatch is watching, the seat is off, and B has an addressed comment queued."""
    hw = hwatch_node
    a = fakegh.open_pr(title="C1", head="a")
    b = fakegh.open_pr(title="C2", base="a", head="b")
    hw.set_seat(False)                                                      # B's wake stays pending until a test turns the seat on
    hw.start()
    hw.wait_tick(0)
    assert hw.watched_sha(a) == fakegh.issues[a]["pull"]["sha"] and hw.watched_sha(b) == fakegh.issues[b]["pull"]["sha"]
    fakegh.comment(b, ASK, author="owner-user", assoc="OWNER")
    hw.tick()
    assert [w["goal"] for w in hw.pending()] == [f"github:o/r#{b}"]
    return hw, fakegh, a, b


@pytest.mark.parametrize("method", ["merge", "squash"])
def test_a_retargeted_child_is_not_a_new_request(stack, method):
    hw, gh, a, b = stack
    wake = hw.pending()[0]
    old_sha = gh.issues[b]["pull"]["sha"]
    gh.merge(a, method=method, delete_branch=True, retarget=True)
    pr = gh.issues[b]["pull"]
    assert pr["base"] == "main" and (pr.get("conflicting", False) is (method == "squash"))     # the fake did what GitHub does
    hw.tick()
    assert len(_keys(hw, "closed")) == 1 and f"o/r#{a}@" in _keys(hw, "closed")[0]           # A's merge, once
    assert _keys(hw, "opened") == [] and _keys(hw, "head") == []                              # B is not new and has not moved
    assert hw.pending() == [wake], "the retarget changed B's pending wake"
    assert hw.watched_sha(b) == old_sha == gh.issues[b]["pull"]["sha"]
    hw.tick()                                                                                 # and a further tick adds nothing
    assert len(_keys(hw, "closed")) == 1 and hw.pending() == [wake]
    sha = gh.rebase_onto_base(b) if method == "squash" else gh.push(b)                        # B's author rebases (squash) or pushes on
    assert sha != old_sha and not gh.issues[b]["pull"].get("conflicting")
    hw.tick()
    assert _keys(hw, "head") == [f"head:o/r#{b}@{sha}"]                                       # one head event, under the new sha
    assert hw.watched_sha(b) == sha
    assert hw.pending() == [wake]
    hw.set_seat(True)
    hw.tick()
    wait_for(lambda: len(hw.starts()) == 1, what="B's seat to start")
    assert f"github:o/r#{b}" in hw.starts()[0]["prompt"]
    hw.tick()
    assert len(hw.starts()) == 1, "B's seat ran again after the stack moved"


def test_a_child_closed_by_the_merge_is_delivered_once(stack):
    hw, gh, a, b = stack
    gh.merge(a, method="squash", delete_branch=True, retarget=False)
    assert gh.issues[b]["state"] == "closed" and gh.issues[b]["merged_at"] is None
    hw.tick()
    closed = _keys(hw, "closed")
    assert sorted(k.split("@")[0] for k in closed) == sorted([f"closed:o/r#{a}", f"closed:o/r#{b}"])
    assert hw.watched_sha(b) is None                                        # no longer tracked as open
    hw.tick()
    assert sorted(_keys(hw, "closed")) == sorted(closed)                    # not delivered again
    assert _keys(hw, "opened") == []
