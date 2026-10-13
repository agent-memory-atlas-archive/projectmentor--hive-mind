"""S5 (plan docs/design/integration_tests_4x.md): the owner-unlock agent as a real process, with the real `hive-mind` CLI.

Unlock once, then a module install and a governed `config set` both sign through the socket with no passphrase (the CLI has no
tty and no passphrase in its environment, so a prompt would cancel); idle expiry ends the process and removes the socket; a
symlinked or wrongly-moded socket directory is refused by the client and by the agent; a second uid is closed before any byte.

The second-uid tests need root (the harness drops to `nobody` for the client side) and skip with a visible reason otherwise; the
`integration` CI job runs this file a second time under sudo (see .github/workflows/ci.yml). The module is published with the
unit tests' throwaway key (`test_module_lifecycle._publish`) until slice B's test publisher lands.
"""
import base64
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

import _planes
import owner_agent
from hivefleet import CORE, wait_for
from test_module_lifecycle import _publish

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the agent's peer checks are specified for Linux first")]

PASS = "s5-owner-key-passphrase"
ROOT = os.geteuid() == 0
try:
    NOBODY = pwd.getpwnam("nobody").pw_uid
except KeyError:
    NOBODY = None
needs_uid = pytest.mark.skipif(
    not ROOT or NOBODY is None or NOBODY == os.geteuid(),
    reason="a second uid needs root and a `nobody` user: CI runs this file again under sudo; otherwise run it as root "
           "(for example in a container) to exercise the uid boundary")


class Owner:
    """One node that has an owner key sealed with PASS and its own device admitted: the state `owner unlock` needs."""

    def __init__(self, fleet, tmp):
        self.node = fleet[0]
        self.runtime = Path(tempfile.mkdtemp(prefix="s5-"))                 # short: AF_UNIX paths are capped near 100 bytes
        self.runtime.chmod(0o700)
        self.modules = self.node.dir / "modules"
        self.repo = self.node.dir / "repo"
        self.env_extra = dict(XDG_RUNTIME_DIR=str(self.runtime), HIVE_MODULES_DIR=str(self.modules))
        self.ctl("config", "identity", "init", passphrase=True)
        self.ctl("owner", "init", passphrase=True)
        device = next(l.split()[1] for l in self.ctl("whoami").stdout.splitlines() if l.startswith("device:"))
        self.ctl("group", "admit", device, "--principal", "op", passphrase=True)

    def ctl(self, *args, passphrase=False, check=True, **kw):
        """Run a command in the node. The key passphrase is in the environment only when `passphrase` (a prompt cancels)."""
        extra = dict(self.env_extra, **({"HIVE_OWNER_KEY_PASSPHRASE": PASS} if passphrase else {}))
        entry = _planes.CTL if args[:2] in (("owner", "unlock"), ("owner", "lock"), ("owner", "status")) else _planes.entry_for(args)
        r = self.node.run([sys.executable, entry, *args], env=self.node.env(**extra),
                          stdin=subprocess.DEVNULL, start_new_session=True, **kw)
        if check:
            assert r.returncode == 0, r.stderr + r.stdout
        return r

    def unlock(self, *args, check=True):
        rfd, wfd = os.pipe()
        os.write(wfd, (PASS + "\n").encode())
        os.close(wfd)
        try:
            r = self.node.run([sys.executable, _planes.CTL, "owner", "unlock", "--passphrase-fd", str(rfd), *args],
                              env=self.node.env(**self.env_extra), stdin=subprocess.DEVNULL, start_new_session=True,
                              pass_fds=(rfd,))
        finally:
            os.close(rfd)
        if check:
            assert r.returncode == 0, r.stderr + r.stdout
        return r

    @property
    def sockdir(self):
        return self.runtime / "hive-mind"

    @property
    def sock(self):
        return Path(owner_agent.socket_path(self.node.home, self.node.env(**self.env_extra)))

    def seed(self):
        out = self.node.dir / "export.json"
        self.ctl("owner", "export", "--plaintext", "--out", str(out), passphrase=True)
        try:
            return base64.b64decode(json.loads(out.read_text())["seed"])
        finally:
            out.unlink()

    def agent_pid(self):
        return int(self.unlock("--module", "demo").stdout.split("pid ")[1].split(")")[0])


@pytest.fixture
def owner(fleet):
    o = Owner(fleet, None)
    yield o
    o.ctl("owner", "lock", check=False)
    shutil.rmtree(o.runtime, ignore_errors=True)


def _gone(pid):
    try:
        return "Z" in Path(f"/proc/{pid}/status").read_text().split("State:")[1][:4]
    except OSError:
        return True


def test_one_unlock_then_a_module_install_and_a_governed_write_sign_through_the_socket(owner):
    pub = _publish(owner.repo)
    add = ("module", "add", "demo", "--from", str(owner.repo), "--publisher", pub)
    locked = owner.ctl(*add, check=False)                       # no agent: the prompt cancels, nothing is installed
    assert locked.returncode == 1 and "Cancelled" in locked.stderr and not (owner.modules / "demo").exists()

    r = owner.unlock("--module", "demo", "--for", "30m")
    pid = int(r.stdout.split("pid ")[1].split(")")[0])
    assert pid != os.getpid() and os.getsid(pid) == pid and os.getppid() != pid       # its own session (setsid), not our child's group
    assert owner.sock.is_socket() and (owner.sock.stat().st_mode & 0o777) == 0o600

    r = owner.ctl(*add)
    assert "signed by agent: admit" in r.stderr and "installed module demo" in r.stdout
    assert (owner.modules / "demo").is_dir()
    r = owner.ctl("config", "set", "x-demo:poll", "60")
    assert "signed by agent: set-config" in r.stderr
    status = owner.ctl("owner", "status").stdout
    assert "unlocked" in status and "admit" in status and "set-config" in status

    assert owner.ctl("owner", "lock").returncode == 0
    wait_for(lambda: _gone(pid), 15, what="the agent to exit")
    assert not owner.sock.exists()
    assert "locked (no agent)" in owner.ctl("owner", "status").stdout


def test_idle_expiry_ends_the_process_and_removes_the_socket(owner):
    # `unlock --for` is bounded at one minute; the agent itself takes any idle, so start it with 3 s to keep the test short.
    owner.sockdir.mkdir(mode=0o700)
    proc = owner_agent.spawn(owner.seed(), str(owner.sock), 3.0, _owner_pub(owner), [])
    wait_for(lambda: owner.sock.is_socket(), 15, what="the agent socket")
    assert owner_agent.Client(str(owner.sock)).status()["ok"]
    t0 = time.monotonic()
    assert wait_for(lambda: proc.poll() is not None, 30, what="idle expiry") is True
    assert time.monotonic() - t0 < 25 and not owner.sock.exists()
    assert "locked (no agent)" in owner.ctl("owner", "status").stdout


def _owner_pub(owner):
    return owner_agent.base64.b64encode(owner_agent._sigseam.from_seed(owner.seed()).public_key()).decode()


@pytest.mark.parametrize("how", ["symlink", "mode", "foreign-file"])
def test_a_bad_socket_directory_is_refused_on_both_sides(owner, how):
    d = owner.sockdir
    if how == "symlink":
        target = owner.runtime / "elsewhere"
        target.mkdir(mode=0o700)
        d.symlink_to(target)
    elif how == "mode":
        d.mkdir(mode=0o700)
        d.chmod(0o755)
    else:
        d.write_text("not a directory")
    # The client side: `status` finds no agent and `unlock` refuses to create or use the directory.
    assert "locked (no agent)" in owner.ctl("owner", "status").stdout
    r = owner.unlock("--module", "demo", check=False)
    assert r.returncode != 0 and "unlocked" not in r.stdout
    # The agent side: started by hand into that directory, it refuses to bind and exits, leaving no socket.
    proc = owner_agent.spawn(owner.seed(), str(owner.sock), 60.0, _owner_pub(owner), [])
    assert wait_for(lambda: proc.poll() is not None, 15, what="the agent to refuse") is True
    assert not owner.sock.is_socket()


def _as_nobody(code, *args, timeout=30):
    """Run `code` (python3 -I -c) as the `nobody` uid, from `/`, with only a scrubbed PATH."""
    return subprocess.run([sys.executable, "-I", "-c", code, str(CORE), *args], user=NOBODY, group=65534, cwd="/",
                          env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=timeout)


_PROBE = """
import socket, sys
sys.path.insert(0, sys.argv[1])
import owner_agent
sock = sys.argv[2]
try:
    owner_agent.Client(sock).status()
    print("client: answered")
except owner_agent.AgentError as e:
    print("client: refused", e)
s = socket.socket(socket.AF_UNIX); s.settimeout(5)
try:
    s.connect(sock)
except OSError as e:
    print("connect:", e.__class__.__name__)
    raise SystemExit(0)
try:
    owner_agent.write_frame(s, {"op": "status"})
    got = s.recv(16)
except (ConnectionResetError, BrokenPipeError):
    got = b""
print("connect: ok, bytes back:", len(got))
"""


@needs_uid
def test_a_second_uid_is_closed_before_any_byte(owner):
    pid = owner.agent_pid()
    assert owner_agent.Client(str(owner.sock)).status()["ok"]            # the owner's uid is served
    # Behind the directory and file modes: nobody cannot reach the socket at all.
    out = _as_nobody(_PROBE, str(owner.sock))
    assert "client: refused" in out.stdout and "client: answered" not in out.stdout, out.stdout + out.stderr
    assert "connect: PermissionError" in out.stdout, out.stdout + out.stderr
    # Behind the peer-credential check: open the modes on purpose, so the agent's own SO_PEERCRED test is all that is left.
    owner.runtime.chmod(0o755)
    owner.sockdir.chmod(0o755)
    owner.sock.chmod(0o666)
    out = _as_nobody(_PROBE, str(owner.sock))
    assert "client: refused" in out.stdout, out.stdout + out.stderr                       # the client refuses a directory it does not own
    assert "bytes back: 0" in out.stdout, out.stdout + out.stderr                         # the agent closed without a reply
    owner.sockdir.chmod(0o700)
    owner.runtime.chmod(0o700)
    status = owner_agent.Client(str(owner.sock)).status()
    assert status["ok"] and status["signed"] == 0 and not _gone(pid)                      # nothing was signed, the agent still serves us
    assert not [r for r in status["ring"] if r["ok"]]
