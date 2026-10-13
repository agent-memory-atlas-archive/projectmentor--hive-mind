"""Slice G (private docs/design/integration_tests_4x.md §3): sync on loopback trust, the macOS subset. `lo0` aliases need root on
macOS, so the daemon is reached from 127.0.0.1, which it trusts by source address: the production Hive-Auth path is NOT exercised
here (S4 covers it on Linux; an admitted-device residual of the harness, accepted for 3.x). Proves: two real daemons converge a fact
in both directions and agree on the merkle root. A failure means: divergent journals on the platform CI runs only there."""
import json

import pytest

from hivefleet.mesh import Mesh

pytestmark = pytest.mark.integration


@pytest.fixture
def mesh(fleet_factory):
    m = Mesh(fleet_factory(2), "127.0.0.1").build()
    # The daemon answers a loopback request only if `Host` names its own port (421 otherwise, DNS-rebinding guard), so the peers
    # dial each daemon directly: the partition proxy that S4 uses would forward the proxy's port in `Host`.
    for i, node in enumerate(m.fleet):
        peers = [{"id": f"n{j}", "url": f"http://127.0.0.1:{m.fleet[j].port('sync')}"} for j in range(2) if j != i]
        (node.home / ".peers.json").write_text(json.dumps(
            {"self": f"n{i}", "bind": "127.0.0.1", "port": node.port("sync"), "sync_auth": "enforce", "peers": peers}))
    for i in range(2):
        m.start(i)
    yield m
    m.close()


def test_two_nodes_converge_on_loopback(mesh):
    for i in range(2):
        r = mesh.fleet[i].hv("remember", f"loopback from n{i}", "--tags", "g", env=mesh.env(mesh.fleet[i]))
        assert r.returncode == 0, r.stderr
    assert mesh.converge()
    want = ["loopback from n0", "loopback from n1"]
    assert [mesh.facts(i) for i in range(2)] == [want] * 2
    assert mesh.root(0) == mesh.root(1)
