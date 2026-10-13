"""Driving the real module lifecycle on a node: owner setup and `hive-mind module ...` (slice B)."""
import json
import sys

from . import CORE

CTL = CORE / "hivemind_ctl.py"
_PASSPHRASE = "integration-test-passphrase"


def module_env(node):
    """The node's environment plus its own modules directory and a non-interactive owner-key passphrase."""
    return node.env(HIVE_MODULES_DIR=str(node.dir / "modules"), HIVE_OWNER_KEY_PASSPHRASE=_PASSPHRASE)


def ctl(node, *args, **kw):
    """`hive-mind <args>` (the control plane) in the node's environment; the node's modules directory is its own."""
    return node.run([sys.executable, CTL, *args], env=module_env(node), **kw)


def make_owner(node, principal="op"):
    """A node that owns its own hive and has admitted itself: identity, owner key, group membership."""
    (node.home / ".peers.json").write_text(json.dumps({"port": node.port("sync"), "peers": []}))   # doctor probes this node's port
    assert node.hv("config", "identity", "init").returncode == 0
    r = ctl(node, "owner", "init")
    assert r.returncode == 0, r.stderr
    who = node.hv("whoami").stdout
    device = next(line.split()[1] for line in who.splitlines() if line.startswith("device:"))
    r = ctl(node, "group", "admit", device, "--principal", principal)
    assert r.returncode == 0, r.stderr
    return device


def module_add(node, repo, publisher_pub, name="fixture"):
    return ctl(node, "module", "add", name, "--from", repo, "--publisher", publisher_pub)


def modules_state(node):
    return json.loads((node.home / ".modules.json").read_text())
