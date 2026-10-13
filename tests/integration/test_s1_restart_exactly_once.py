"""S1 restart exactly-once (slice C of private docs/design/integration_tests_4x.md; the incident is hwatch-dev#91, four duplicate PRs).

The real `hwatch serve` runs on a real node against fakegh and a fake seat runtime (no model). One addressed post must give one
session for the seat, however the service is restarted between the session starting and the session's wake being settled.
A restart ticks at once, so a restart is also how these tests step the service without waiting for the 30 s tick.

Reverting hwatch-dev#91's fix (`start_service` and `derive_states` dropping the record of a dead session that still holds wakes)
turns the first two tests red: the wake stays queued and the next tick launches a second session. hwatch-dev's CI runs that
mutation. Not covered here (see the PR): `hive-mind update` as the restarter (the plan's `node.update()`), and a session that
survives the restart (adoption), which needs a systemd user scope the CI runner does not have.
"""
import signal
import sys

import pytest

from hivefleet import wait_for

pytestmark = [pytest.mark.integration, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="hwatch's launcher is linux-systemd")]

ASK = "**Implementer:** please take this"


def _goal(n):
    return f"github:o/r#{n}"


def _addressed(hw, gh, n):
    """Start the service on a quiet repo (its first poll delivers nothing), then post one addressed comment and let one tick take it."""
    hw.start()
    hw.wait_tick(0)
    gh.comment(n, ASK, author="owner-user", assoc="OWNER")
    return hw.tick()


def _settled(hw):
    """No wake queued and no session recorded: everything handed to a session was settled."""
    return not hw.pending() and not hw.sessions()


@pytest.fixture
def pr(fakegh):
    return fakegh.open_pr()


def test_a_restart_between_session_start_and_exit_gives_one_session(hwatch_node, fakegh, pr):
    hw = hwatch_node
    _addressed(hw, fakegh, pr)
    wait_for(lambda: len(hw.starts()) == 1, what="the seat to start")
    assert [w["goal"] for w in hw.pending()] == [_goal(pr)] and len(hw.sessions()) == 1   # claimed: handed to a live session
    for _ in range(2):                                                      # kill -9 the service (and, with no systemd scope, the session) twice
        before = hw.ticks()
        hw.kill(signal.SIGKILL)
        hw.start()
        hw.wait_tick(before)
    assert len(hw.starts()) == 1, "a restart re-delivered a ref already handed to a session"
    assert _settled(hw)
    assert [r["ref"] for r in hw.log_rows("choice.jsonl")] == [f"github:comment:{fakegh.comments[0]['id']}"]
    assert len(hw.session_logs()) == 1


def test_a_session_that_exited_before_the_service_died_is_not_relaunched(hwatch_node, fakegh, pr):
    hw = hwatch_node
    _addressed(hw, fakegh, pr)
    wait_for(lambda: len(hw.starts()) == 1, what="the seat to start")
    hw.release()                                                            # the session exits on its own ...
    wait_for(lambda: not hw.seat_running(hw.starts()[0]["pid"]), what="the session to exit")
    before = hw.ticks()
    hw.kill(signal.SIGKILL)                                                 # ... and the service dies before its next tick settles the wake
    hw.start()
    hw.wait_tick(before)
    assert len(hw.starts()) == 1
    assert _settled(hw)


@pytest.mark.xfail(strict=True, reason="hwatch-dev#94: a draining service never reaps a session that exited, so it waits out stop_grace")
def test_a_graceful_restart_waits_for_the_session_and_gives_one_session(hwatch_node, fakegh, pr):
    hw = hwatch_node
    _addressed(hw, fakegh, pr)
    wait_for(lambda: len(hw.starts()) == 1, what="the seat to start")
    hw.node.signal("hwatch", signal.SIGTERM)                                # `systemctl restart`: drain, which waits for a session that is not restart-safe
    wait_for(lambda: hw.service().get("draining"), what="the service to start draining")
    assert hw.node.alive("hwatch")                                          # still waiting on the held session
    hw.release()
    assert hw.node.wait("hwatch", timeout=10) == 0
    before = hw.ticks()
    hw.start()
    hw.wait_tick(before)
    assert len(hw.starts()) == 1
    assert _settled(hw)


def test_a_new_ref_after_the_restart_still_gets_its_session(hwatch_node, fakegh, pr):
    """The other half of exactly-once: settling the old ref must not swallow the next one."""
    hw = hwatch_node
    _addressed(hw, fakegh, pr)
    wait_for(lambda: len(hw.starts()) == 1, what="the seat to start")
    hw.kill(signal.SIGKILL)
    hw.release()
    fakegh.comment(pr, ASK + " again", author="owner-user", assoc="OWNER")
    before = hw.ticks()
    hw.start()
    hw.wait_tick(before)
    wait_for(lambda: len(hw.starts()) == 2, what="the second ref's session")
    assert len(hw.starts()) == 2 and "again" in hw.starts()[1]["prompt"]
