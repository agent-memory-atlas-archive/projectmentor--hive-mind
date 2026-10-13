"""Fixtures for the integration tests. Run with `pytest -m integration tests/integration` (the default run skips them)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import _realhome                                    # noqa: E402  (tests/_realhome.py)
from hivefleet import Fleet                          # noqa: E402
from hivefleet.fakegh import FakeGitHub              # noqa: E402
from hivefleet.hwatch import TREE as HWATCH_TREE, HwatchNode   # noqa: E402
from hivefleet.publisher import ThrowawayPublisher   # noqa: E402


# Resolved at import, before any fixture points CLAUDE_CONFIG_DIR / HIVE_IDENTITY_STASH at the per-test sandbox.
REAL = _realhome.session_paths()


def _real_state():
    p = REAL
    return _realhome.snapshot(p["claude"], p["stash"], p["hive"], p["key_dir"], p["keys_root"])


@pytest.fixture
def fleet_factory(tmp_path):
    """fleet_factory(n) -> Fleet of n nodes under a temp root. At teardown every node's processes are killed, the logs of a
    failed test are kept in the report, and the real account is asserted unchanged (nothing outside the node dirs moved)."""
    made = []
    before = _real_state()

    def make(n=1, **kw):
        fleet = Fleet(tmp_path / "fleet", n, **kw)
        made.append(fleet)
        fleet.assert_scrubbed()
        return fleet

    yield make
    for fleet in made:
        fleet.shutdown()
    changes = _realhome.diff(before, _real_state())
    assert not changes, "an integration test touched the real account: " + "; ".join(changes)


@pytest.fixture
def fleet(fleet_factory):
    return fleet_factory(1)


@pytest.fixture
def publisher(tmp_path):
    """A fresh throwaway module publisher whose seed lives in memory only; its fixture repos go under this test's temp dir."""
    return ThrowawayPublisher(tmp_path / "publisher")


@pytest.fixture
def fakegh():
    """A stateful fake GitHub on loopback; its event log is `fakegh.requests`."""
    gh = FakeGitHub()
    yield gh
    gh.close()


@pytest.fixture
def hwatch_node(fleet, fakegh):
    """hwatch from `HWATCH_TREE` configured on a fresh node against `fakegh`, seat `implementer` backed by a fake runtime that
    holds until released. Not started: the test starts it. Skips without a tree (hwatch is a private repository)."""
    if not HWATCH_TREE:
        pytest.skip("HWATCH_TREE is not set: hwatch is a private repository; hive-mind-hwatch-dev's CI runs these against its own tree")
    return HwatchNode(fleet[0], fakegh)
