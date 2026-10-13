"""A sync mesh over a Fleet: one real owner, every node admitted, real daemons in HIVE_SYNC_AUTH=enforce on a non-loopback
address, and a Proxy on each directed peer pair so a test can cut and heal any link (private docs/design/integration_tests_4x.md S4)."""
import json
import sys

from . import CORE, wait_for
from .proxy import Proxy

PASSPHRASE = "integration-pass"       # seals the throwaway owner key of a test node; it protects nothing real
DAEMON = "import hive_sync_daemon as d; d.serve_forever()"


class Mesh:
    def __init__(self, fleet, lan):
        self.fleet, self.lan = fleet, lan
        self.proxies = {}                # (i, j) -> Proxy that node i dials to reach node j
        self.ids = []
        self.pw = {"HIVE_OWNER_PASSPHRASE": PASSPHRASE, "HIVE_OWNER_KEY_PASSPHRASE": PASSPHRASE}

    # ── setup ────────────────────────────────────────────────────────────────────────────────────────
    def env(self, node, **extra):
        return node.env(HIVE_SYNC_AUTH="enforce", HIVE_MODULE_PORT=str(node.port("module")), **extra)

    def ctl(self, node, *args, check=True):
        r = node.run([sys.executable, CORE / "hivemind_ctl.py", *args], env=node.env(**self.pw), cwd=CORE)
        assert not check or r.returncode == 0, f"{node.name}: ctl {args}: {r.stdout}{r.stderr}"
        return r

    def build(self, admit=None):
        """Identities on every node, node 0 the owner, `admit` (default all) admitted, a full mesh of peers through proxies."""
        nodes = list(self.fleet)
        for n in nodes:
            assert n.hv("config", "identity", "init").returncode == 0
        self.ids = [(n.home / ".device-id").read_text().strip() for n in nodes]
        self.ctl(nodes[0], "owner", "init")
        for i in (range(len(nodes)) if admit is None else admit):
            self.ctl(nodes[0], "group", "admit", self.ids[i], "--principal", f"p{i}")
        for i, a in enumerate(nodes):
            for j, b in enumerate(nodes):
                if i != j:
                    self.proxies[(i, j)] = Proxy(self.lan, a.port(f"to{j}", self.lan), (self.lan, b.port("sync", self.lan)))
            self.write_peers(i)
        return self

    def write_peers(self, i):
        node = self.fleet[i]
        peers = [{"id": f"n{j}", "url": f"http://{self.lan}:{self.proxies[(i, j)].port}"}
                 for j in range(len(self.fleet.nodes)) if j != i]
        (node.home / ".peers.json").write_text(json.dumps(
            {"self": f"n{i}", "bind": self.lan, "port": node.port("sync", self.lan), "sync_auth": "enforce", "peers": peers}))

    def start(self, i):
        node = self.fleet[i]
        node.spawn("sync", [sys.executable, "-c", DAEMON], cwd=CORE, env=self.env(node))
        wait_for(lambda: self.root_via_http(i) is not None or not node.alive("sync"), 45, 0.3, f"daemon n{i} to serve")
        assert node.alive("sync"), f"daemon n{i} exited:\n{node.log('sync')[-2000:]}"

    def root_via_http(self, i):
        import urllib.request
        node = self.fleet[i]
        try:
            with urllib.request.urlopen(f"http://{self.lan}:{node.port('sync', self.lan)}/sync/merkle-root", timeout=2) as r:
                return json.loads(r.read()).get("root_hash")
        except OSError:
            return None

    # ── reads and actions ────────────────────────────────────────────────────────────────────────────
    def sync(self, i):
        return self.fleet[i].hv("sync", "now", env=self.env(self.fleet[i]), timeout=120)

    def root(self, i):
        out = self.fleet[i].hv("doctor", "merkle").stdout
        return next((ln.split()[1] for ln in out.splitlines() if ln.startswith("Root:")), None)

    def facts(self, i):
        import sqlite3
        db = sqlite3.connect(self.fleet[i].home / "store.db")
        try:
            return sorted(r[0] for r in db.execute("SELECT content FROM facts"))
        finally:
            db.close()

    def cut(self, a, b):
        self.proxies[(a, b)].cut(), self.proxies[(b, a)].cut()

    def heal(self, a, b):
        self.proxies[(a, b)].heal(), self.proxies[(b, a)].heal()

    def converge(self, rounds=4):
        """Sync every node `rounds` times over; True once all roots agree."""
        for _ in range(rounds):
            for i in range(len(self.fleet.nodes)):
                self.sync(i)
            if len({self.root(i) for i in range(len(self.fleet.nodes))}) == 1:
                return True
        return False

    def close(self):
        for p in self.proxies.values():
            p.close()
