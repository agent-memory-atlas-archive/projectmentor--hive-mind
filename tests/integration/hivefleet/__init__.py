"""hivefleet: N real Hive Mind nodes on one host, for the integration tests (private docs/design/integration_tests_4x.md).

Each node has its own HIVE_HOME, HIVE_IDENTITY_STASH, HOME and XDG_RUNTIME_DIR under one temp root, free ports, and a
scrubbed environment. Nodes run the real `hv`; nothing is imported in-process. Slice A holds the fleet, the scrub, ports,
process control and the isolation assertion; the partition proxy, `update`, fakegh and the test publisher come in later slices.
"""
import os
import random
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

CORE = Path(__file__).resolve().parents[3]
HV = CORE / "hv"

# The only variables a node inherits from the runner. Everything else (HIVE_*, GH_TOKEN, seat variables, a CI HOME) is
# dropped: the #38 lesson, a runner variable that leaks in makes a test pass on one machine and not another.
_KEEP = ("LANG", "LC_ALL", "TZ", "PYTHONUSERBASE", "SYSTEMROOT")
_SAFE_PATH = ("/usr/local/bin", "/usr/bin", "/bin")


def free_port(host="127.0.0.1"):
    """A TCP port nothing listens on now, drawn below the kernel's ephemeral range (as smoke_free_port in _smoke_daemon.sh)."""
    rng = random.SystemRandom()
    for _ in range(200):
        port = rng.randint(20000, 32767)
        s = socket.socket()
        try:
            s.bind((host, port))
        except OSError:
            continue
        finally:
            s.close()
        return port
    raise RuntimeError("free_port: no free port in 20000-32767")


def lan_ip():
    """This host's non-loopback address as the kernel routes it, or None (a locked-down runner). The sync daemon trusts all of
    127.0.0.0/8 by source address, so only a non-loopback bind exercises the production Hive-Auth path (as sync_auth_smoke.sh)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    return None if ip.startswith("127.") else ip


def wait_for(cond, timeout=30.0, interval=0.1, what="condition"):
    """Poll `cond` until it returns a truthy value (returned) or `timeout` passes. Never a fixed sleep."""
    deadline = time.monotonic() + timeout
    while True:
        got = cond()
        if got:
            return got
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout}s waiting for {what}")
        time.sleep(interval)


class Node:
    def __init__(self, root, name, bin_dirs=()):
        self.name = name
        self.dir = Path(root) / name
        self.home = self.dir / "hive"            # HIVE_HOME
        self.stash = self.dir / "stash"          # HIVE_IDENTITY_STASH
        self.userhome = self.dir / "home"        # HOME
        self.runtime = self.dir / "run"          # XDG_RUNTIME_DIR
        self.logs = self.dir / "logs"
        self.bin = self.dir / "bin"              # first on PATH: stubs a test puts here
        for d in (self.home, self.stash, self.userhome, self.logs, self.bin):
            d.mkdir(parents=True)
        self.runtime.mkdir(mode=0o700)
        self.ports = {}
        self._bin_dirs = [str(b) for b in bin_dirs]
        self._procs = {}
        # `hv` is run as $HIVE_HOME/hv by the hooks; link the checkout's, so the hook finds the real one.
        (self.home / "hv").symlink_to(HV)

    def port(self, service, host="127.0.0.1"):
        if service not in self.ports:
            self.ports[service] = free_port(host)
        return self.ports[service]

    def env(self, **extra):
        env = {k: os.environ[k] for k in _KEEP if k in os.environ}
        env.update(
            HIVE_HOME=str(self.home), HIVE_IDENTITY_STASH=str(self.stash), HOME=str(self.userhome),
            XDG_RUNTIME_DIR=str(self.runtime), USER="node", LOGNAME="node", TMPDIR=str(self.dir),
            PATH=os.pathsep.join([str(self.bin), *self._bin_dirs, *_SAFE_PATH]),
        )
        env.update(extra)
        return env

    def run(self, argv, cwd=None, input=None, timeout=60, env=None, **kw):
        """Run argv to completion in this node's environment; returns the CompletedProcess (text)."""
        return subprocess.run([str(a) for a in argv], env=env or self.env(), cwd=cwd or self.dir, input=input,
                              capture_output=True, text=True, timeout=timeout, **kw)

    def hv(self, *args, **kw):
        return self.run([sys.executable, HV, *args], **kw)

    def spawn(self, service, argv, cwd=None, env=None):
        """Start a long-lived process in its own session (so kill() takes its children too); output goes to logs/<service>.log."""
        self.stop(service)
        log = open(self.logs / f"{service}.log", "ab")
        try:
            self._procs[service] = subprocess.Popen([str(a) for a in argv], env=env or self.env(), cwd=cwd or self.dir,
                                                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                                    start_new_session=True)
        finally:
            log.close()
        return self._procs[service]

    def alive(self, service):
        p = self._procs.get(service)
        return p is not None and p.poll() is None

    def kill(self, service, sig=signal.SIGKILL):
        """Signal the service's whole process group and reap it; returns its exit status (negative = signal)."""
        p = self._procs.get(service)
        if p is None:
            return None
        if p.poll() is None:
            try:
                os.killpg(p.pid, sig)
            except ProcessLookupError:
                pass
        try:
            return p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            return p.wait(timeout=10)

    def stop(self, service):
        rc = self.kill(service, signal.SIGTERM)
        self._procs.pop(service, None)
        return rc

    def restart(self, service, argv, **kw):
        self.kill(service, signal.SIGKILL)
        return self.spawn(service, argv, **kw)

    def shutdown(self):
        for service in list(self._procs):
            self.stop(service)

    def log(self, service):
        p = self.logs / f"{service}.log"
        return p.read_text(errors="replace") if p.exists() else ""


class Fleet:
    def __init__(self, root, n=1, bin_dirs=()):
        self.root = Path(root).resolve()
        self.nodes = [Node(self.root, f"n{i}", bin_dirs) for i in range(n)]

    def __getitem__(self, i):
        return self.nodes[i]

    def __iter__(self):
        return iter(self.nodes)

    def shutdown(self):
        for node in self.nodes:
            node.shutdown()

    def assert_scrubbed(self):
        """No runner variable that could steer a node (HIVE_*, GH_*, seat variables) is in any node's environment, and
        every node path is inside the fleet root."""
        for node in self.nodes:
            env = node.env()
            leaked = sorted(k for k in env if k.startswith(("GH_", "GITHUB_", "CLAUDE", "ANTHROPIC")) or
                            (k.startswith("HIVE_") and k not in ("HIVE_HOME", "HIVE_IDENTITY_STASH")))
            assert not leaked, f"{node.name}: runner variables leaked into the node: {leaked}"
            for k in ("HIVE_HOME", "HIVE_IDENTITY_STASH", "HOME", "XDG_RUNTIME_DIR", "TMPDIR"):
                assert Path(env[k]).resolve().is_relative_to(self.root), f"{node.name}: {k}={env[k]} is outside the fleet root"
