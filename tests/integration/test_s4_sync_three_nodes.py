"""S4 Sync, three nodes (private docs/design/integration_tests_4x.md §4). node <-> node over the production auth path.

Three real daemons bind a NON-loopback address in HIVE_SYNC_AUTH=enforce (the daemon trusts all of 127.0.0.0/8 by source address, so
the plan's `127.0.0.2` alias would skip the check; the host's LAN address is what sync_auth_smoke.sh uses too) and dial each other
through a Proxy per peer pair. Proves: a fact, a module-written fact and a revocation converge; a partition heals; a revoked
device is refused in both directions; an unsigned, a replayed and a tampered request are refused. A failure means: divergent
journals, or a revoked device still synced. Skips visibly when the host has no non-loopback address."""
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request

import pytest

from hivefleet import CORE, lan_ip, wait_for
from hivefleet.mesh import Mesh

pytestmark = pytest.mark.integration
LAN = lan_ip()
needs_lan = pytest.mark.skipif(LAN is None, reason="no non-loopback address on this host: the enforce path needs a remote source")
sys.path.insert(0, str(CORE))


@pytest.fixture
def mesh(fleet_factory):
    m = Mesh(fleet_factory(3), LAN).build()
    for i in range(3):
        m.start(i)
    yield m
    m.close()


def remember(m, i, text):
    r = m.fleet[i].hv("remember", text, "--tags", "s4", env=m.env(m.fleet[i]))
    assert r.returncode == 0, r.stderr


def authors(m, i):
    db = sqlite3.connect(m.fleet[i].home / "store.db")
    try:
        return {r[0] for r in db.execute("SELECT DISTINCT node_id FROM journal_index")}
    finally:
        db.close()


def signed_headers(node, path, query):
    out = node.run([sys.executable, "-c", "import json,sync_common as s;print(json.dumps(s.sign_sync_request('GET',%r,%r)))" % (path, query)],
                   cwd=CORE).stdout
    return json.loads(out)


def get(m, i, path, query, headers=None):
    url = f"http://{LAN}:{m.fleet[i].port('sync', LAN)}{path}?{query}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


@needs_lan
def test_a_fact_from_each_node_converges_under_enforce(mesh):
    for i in range(3):
        remember(mesh, i, f"alpha from n{i}")
    assert mesh.converge()
    want = [f"alpha from n{i}" for i in range(3)]
    assert [mesh.facts(i) for i in range(3)] == [want] * 3
    assert len({mesh.root(i) for i in range(3)}) == 1
    # enforce is really on: the same read, unsigned, from a non-loopback source is refused
    code, _ = get(mesh, 0, "/sync/chunk", f"node={mesh.ids[0]}&start=1&end=9")
    assert code == 401


@needs_lan
def test_a_module_written_fact_converges(mesh):
    import ed25519
    import hive_module_client as client
    seed = os.urandom(32)
    mod = client.device_id_for_pub(ed25519.pub_from_seed(seed))
    mesh.ctl(mesh.fleet[0], "group", "admit", mod, "--principal", "p1", "--module", "hwatch")
    assert mesh.converge()
    port = mesh.fleet[1].port("module")
    wait_for(lambda: client.ModuleClient(seed, port).request("GET", "/v1/tip")[0] == 200, 20, 0.3, "n1's module API")
    code, body = client.ModuleClient(seed, port).write("fact", {"content": "hwatch saw the deploy", "tags": [], "importance": 0.5,
                                                                "source": "x-hwatch"})
    assert code == 200 and body["accepted"] == 1, body
    assert mesh.converge()
    for i in range(3):
        assert "hwatch saw the deploy" in mesh.facts(i) and mod in authors(mesh, i), f"n{i}"
    assert len({mesh.root(i) for i in range(3)}) == 1


@needs_lan
def test_partition_and_heal(mesh):
    remember(mesh, 0, "before the cut")
    assert mesh.converge()
    mesh.cut(2, 0), mesh.cut(2, 1)
    remember(mesh, 0, "written on n0 during the cut")
    remember(mesh, 2, "written on n2 during the cut")
    for _ in range(2):
        for i in range(3):
            mesh.sync(i)
    assert "written on n0 during the cut" in mesh.facts(1) and "written on n0 during the cut" not in mesh.facts(2)
    assert "written on n2 during the cut" not in mesh.facts(0) + mesh.facts(1)
    assert mesh.root(2) != mesh.root(0) and mesh.root(0) == mesh.root(1)
    mesh.heal(2, 0), mesh.heal(2, 1)
    assert mesh.converge()
    both = sorted(["before the cut", "written on n0 during the cut", "written on n2 during the cut"])
    assert [mesh.facts(i) for i in range(3)] == [both] * 3


@needs_lan
def test_a_revoked_device_is_refused_in_both_directions(mesh):
    remember(mesh, 0, "before the revoke")
    assert mesh.converge()
    mesh.ctl(mesh.fleet[0], "group", "revoke", mesh.ids[2])
    mesh.sync(0), mesh.sync(1)                                       # the revoke reaches the other admitted node
    remember(mesh, 2, "from the revoked device")
    remember(mesh, 0, "after the revoke")
    for _ in range(2):
        for i in range(3):
            mesh.sync(i)
    assert "from the revoked device" not in mesh.facts(0) + mesh.facts(1)          # its push is refused ...
    assert "after the revoke" not in mesh.facts(2) and "after the revoke" in mesh.facts(1)   # ... and so is its pull
    code, body = get(mesh, 0, "/sync/chunk", f"node={mesh.ids[0]}&start=1&end=9", signed_headers(mesh.fleet[2], "/sync/chunk", f"node={mesh.ids[0]}&start=1&end=9"))
    assert (code, body.get("detail")) == (401, "not-admitted")


@needs_lan
def test_a_replayed_or_tampered_request_is_refused(mesh):
    q = f"node={mesh.ids[0]}&start=1&end=9"
    h = signed_headers(mesh.fleet[1], "/sync/chunk", q)
    assert get(mesh, 0, "/sync/chunk", q, h)[0] == 200
    code, body = get(mesh, 0, "/sync/chunk", q, h)                   # the same bytes again: the nonce is spent
    assert (code, body.get("detail")) == (401, "replayed-nonce")
    fresh = signed_headers(mesh.fleet[1], "/sync/chunk", q)
    code, body = get(mesh, 0, "/sync/chunk", f"node={mesh.ids[1]}&start=1&end=9", fresh)   # a signature moved to another query
    assert (code, body.get("detail")) == (401, "bad-signature")
