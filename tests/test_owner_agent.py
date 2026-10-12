"""3.1 #295: the owner-unlock agent (design: hive-mind-private docs/design/owner_unlock_agent_3_1.md, section 6).

The agent holds the owner seed in its own memory and signs only allowlisted governance acts. Policy, clocks and the
socket are exercised in-process; the hardening, the zeroing and the one-prompt-per-session behaviour run the real
`hive-mind` CLI against a temp hive. The passphrase reaches `owner unlock` only through `--passphrase-fd`."""

import base64
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
import ed25519  # noqa: E402
import merkle  # noqa: E402
import owner_agent  # noqa: E402
import ownerkey  # noqa: E402
from hivemind.crypto import signer as sigseam  # noqa: E402
from test_module_lifecycle import _publish, units  # noqa: E402,F401
from test_succession import _run, _device_id  # noqa: E402

LINUX = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the agent's checks are specified for Linux first")

SEED = bytes(range(7, 39))
PUB = base64.b64encode(ed25519.pub_from_seed(SEED)).decode()
DEV = "k1:" + "ab" * 8
DEV2 = "k1:" + "cd" * 8
PASS = "test-owner-key-passphrase"            # conftest seals every test hive with it


def body(**kw):
    return merkle._canonical({**kw, "owner_pub": PUB})


def policy(modules=("demo",), states=None, installed=("demo",)):
    states = states or {}
    return owner_agent.Policy(PUB, modules, lambda d: states.get(d, "other"), lambda m: m in installed)


class FakeClocks:
    def __init__(self):
        self.m, self.w, self.b = 1000.0, 5e8, 7000.0

    def mono(self):
        return self.m

    def wall(self):
        return self.w

    def boot(self):
        return self.b

    def advance(self, s, suspended=0.0):
        self.m += s
        self.w += s + suspended
        self.b += s + suspended


def agent(clk=None, **kw):
    return owner_agent.Agent(SEED, "/nonexistent/x.sock", kw.pop("idle", 900), kw.pop("pol", None) or policy(),
                             clocks=clk or FakeClocks(), **kw)


def sign(a, b):
    return a._sign({"body": base64.b64encode(b).decode()}, 1)


ADMIT = dict(action="admit", device_id=DEV, module="demo", principal="op")

# ---- the allowlist (tests 7, 8, 12) -----------------------------------------------------------------------------------


def test_the_allowed_acts_sign_and_verify_byte_identically_to_the_file_signer():
    a = agent()
    for b in (body(**ADMIT), body(action="set-config", key="x-demo:poll", value="30")):
        r = sign(a, b)
        assert r["ok"], r
        sig = base64.b64decode(r["sig"])
        assert ed25519.verify(b, sig, ed25519.pub_from_seed(SEED))
        assert sig == sigseam.FileSigner(SEED).sign(b)
    assert sign(a, body(action="revoke", device_id=DEV))["ok"]            # DEV was admitted this session


@pytest.mark.parametrize("why,b", [
    ("admit without a module (a voting device)", body(action="admit", device_id=DEV, principal="op")),
    ("admit of a module not named", body(**{**ADMIT, "module": "other"})),
    ("revoke of a device not admitted this session", body(action="revoke", device_id=DEV2)),
    ("quorum_m", body(action="set-config", key="quorum_m", value="2")),
    ("forget_writers", body(action="set-config", key="forget_writers", value="owner")),
    ("cap_self", body(action="set-config", key="cap_self", value="0.5")),
    ("x-other: under --module demo", body(action="set-config", key="x-other:k", value="1")),
    ("transfer", body(action="transfer", to="x")),
    ("rotate", body(action="rotate")),
    ("retract", body(retracts_ref="a", reason="r")),
    ("an owner-signed link", body(kind="supports", from_ref="a", to_ref="b")),
    ("an unknown action", body(action="frobnicate")),
    ("an extra key", body(**ADMIT, extra="1")),
    ("a missing key", body(action="admit", device_id=DEV, module="demo")),
    ("non-canonical bytes", b'{"action": "revoke", "device_id": "%s", "owner_pub": "%s"}' % (DEV.encode(), PUB.encode())),
    ("an owner_pub for another key", merkle._canonical({**ADMIT, "owner_pub": base64.b64encode(bytes(32)).decode()})),
    ("duplicate keys", b'{"action":"admit","action":"revoke"}'),
    ("not JSON", b"\xff\xfe"),
    ("a non-string value", body(action="set-config", key="x-demo:k", value=5)),
    ("an oversize value", body(action="set-config", key="x-demo:k", value="v" * 5000)),
])
def test_everything_else_is_refused(why, b):
    r = sign(agent(), b)
    assert r["ok"] is False, why


def test_a_plain_unlock_signs_no_admit_and_only_installed_modules_config():
    a = agent(pol=policy(modules=()))
    assert sign(a, body(**ADMIT))["ok"] is False
    assert sign(a, body(action="set-config", key="x-demo:k", value="1"))["ok"]
    assert sign(a, body(action="set-config", key="x-other:k", value="1"))["ok"] is False


def test_admit_is_refused_for_an_admitted_or_purged_device_and_signs_with_nothing_installed():
    assert sign(agent(pol=policy(states={DEV: "purged"})), body(**ADMIT))["ok"] is False
    assert sign(agent(pol=policy(states={DEV: "admitted"})), body(**ADMIT))["ok"] is False
    assert sign(agent(pol=policy(states={DEV: None})), body(**ADMIT))["ok"] is False        # governance unreadable
    assert sign(agent(pol=policy(installed=())), body(**ADMIT))["ok"]     # no .modules.json row at admit time


def test_a_revoke_needs_the_same_session_and_a_restarted_agent_forgets():
    a = agent()
    assert sign(a, body(action="revoke", device_id=DEV))["ok"] is False
    assert sign(a, body(**ADMIT))["ok"]
    assert sign(a, body(action="revoke", device_id=DEV))["ok"]
    assert sign(agent(), body(action="revoke", device_id=DEV))["ok"] is False


def test_the_ring_holds_acts_never_values_or_signatures():
    a = agent()
    sign(a, body(action="set-config", key="x-demo:k", value="SECRET-VALUE"))
    sign(a, body(action="transfer", to="x"))
    dump = json.dumps(a.status())
    assert "SECRET-VALUE" not in dump and "owner_sig" not in dump
    assert [r["ok"] for r in a.ring] == [True, False]


# ---- bounds, clocks and zeroing (tests 4, 5, 14 of the design's list) ----------------------------------------------------

@pytest.mark.parametrize("text,ok", [("30s", False), ("59", False), ("1m", True), ("15m", True), ("8h", True),
                                     ("8h1s", False), ("9h", False), ("soon", False)])
def test_for_is_bounded_to_one_minute_through_eight_hours(text, ok):
    if ok:
        owner_agent.parse_duration(text)
    else:
        with pytest.raises(ValueError):
            owner_agent.parse_duration(text)


def test_a_signed_act_resets_idle_and_the_hard_cap_is_not_extended():
    clk = FakeClocks()
    a = agent(clk, idle=600)
    clk.advance(500)
    assert sign(a, body(**ADMIT))["ok"]
    clk.advance(500)
    assert a.tick() is None                                   # idle was reset at t=500
    clk.advance(101)
    assert a.tick() == "idle expiry"
    clk = FakeClocks()
    a = agent(clk, idle=3600)
    for _ in range(16):                                       # keep it busy: idle never expires
        clk.advance(3000)
        sign(a, body(action="set-config", key="x-demo:k", value="1"))
        if a.tick():
            break
    assert a.why_locked == "hard cap" and clk.m - 1000 <= owner_agent.HARD_CAP + 3000


def test_wall_clock_and_monotonic_expire_whichever_is_first():
    clk = FakeClocks()
    a = agent(clk, idle=600)
    clk.w += 700                                               # the wall clock jumped, monotonic did not
    assert a.tick() == "idle expiry"


def test_a_suspend_resume_jump_locks_at_once():
    clk = FakeClocks()
    a = agent(clk, idle=3600)
    clk.advance(10)
    assert a.tick() is None
    clk.b += 30                                                # CLOCK_BOOTTIME ran, MONOTONIC did not: we slept
    assert a.tick() == "suspend/resume"


def test_a_locked_agent_zeroes_its_page_and_unlinks_only_its_own_socket(tmp_path):
    import mmap
    d = Path(tempfile.mkdtemp(dir="/tmp")); os.chmod(d, 0o700)
    a = owner_agent.Agent(SEED, str(d / "a.sock"), 900, policy(), clocks=FakeClocks())
    a.buf = mmap.mmap(-1, mmap.PAGESIZE); a.buf[:32] = SEED
    a.bind()
    a.shutdown()
    assert bytes(a.buf[:32]) == bytes(32) and not (d / "a.sock").exists() and a.signer is None


# ---- the socket (test 6, 10) -----------------------------------------------------------------------------------------------

@pytest.fixture
def served():
    d = Path(tempfile.mkdtemp(dir="/tmp"))
    os.chmod(d, 0o700)
    made = []

    def start(**kw):
        a = owner_agent.Agent(SEED, str(d / "a.sock"), 900, policy(), **kw)
        a.bind()
        t = threading.Thread(target=a.run, daemon=True)
        t.start()
        made.append((a, t))
        return a, owner_agent.Client(str(d / "a.sock"))
    start.dir = d
    yield start
    for a, t in made:
        a.do_lock("test end")
        t.join(3)


@LINUX
def test_the_socket_is_0600_in_a_0700_directory_and_serves_status(served):
    a, c = served()
    assert stat.S_IMODE(os.lstat(a.sock_path).st_mode) == 0o600
    st = c.status()
    assert st["public_key"] == PUB and "seed" not in json.dumps(st)


@LINUX
def test_a_foreign_or_loose_or_symlinked_directory_is_refused(tmp_path):
    loose = Path(tempfile.mkdtemp(dir="/tmp")); os.chmod(loose, 0o755)
    with pytest.raises(owner_agent.AgentError):
        owner_agent.check_dir(str(loose))
    real = Path(tempfile.mkdtemp(dir="/tmp")); os.chmod(real, 0o700)
    link = Path(tempfile.mkdtemp(dir="/tmp")) / "l"; os.symlink(real, link)
    with pytest.raises(owner_agent.AgentError):
        owner_agent.check_dir(str(link))
    with pytest.raises(owner_agent.AgentError):
        owner_agent.Client(str(loose / "a.sock")).status()
    a = owner_agent.Agent(SEED, str(loose / "a.sock"), 900, policy())
    with pytest.raises(owner_agent.AgentError):
        a.bind()


def test_there_is_no_op_that_unlocks_or_returns_the_seed(served):
    a, c = served()
    for op in ("unlock", "seed", "export", "get"):
        assert c.request({"op": op}) == {"ok": False, "why": "unknown op"}


def test_a_connection_from_another_uid_is_closed_without_a_reply(served):
    a, c = served(peer_uid_fn=lambda conn: os.getuid() + 1)
    s = socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(a.sock_path)
    try:                       # macOS may already have closed the socket (EPIPE) by the time we write
        owner_agent.write_frame(s, {"op": "status"})
        assert s.recv(10) == b""
    except (ConnectionResetError, BrokenPipeError):
        pass


def test_a_second_unlock_finds_the_first_and_a_stale_socket_is_replaced(served, tmp_path):
    a, c = served()
    assert c.status()["ok"]
    dead = served.dir / "dead.sock"
    s = socket.socket(socket.AF_UNIX); s.bind(str(dead)); s.close()      # a leftover socket file nobody listens on
    with pytest.raises(owner_agent.AgentError):
        owner_agent.Client(str(dead)).status()
    assert stat.S_ISSOCK(os.lstat(dead).st_mode)


def test_flood_is_bounded_and_does_not_delay_the_next_legitimate_request(served, monkeypatch):
    monkeypatch.setattr(owner_agent, "READ_DEADLINE", 0.5)
    a, c = served()
    big = socket.socket(socket.AF_UNIX); big.settimeout(3); big.connect(a.sock_path)
    big.sendall(struct.pack(">I", owner_agent.MAX_FRAME + 1))              # oversize: closed
    assert big.recv(10) == b""
    stalled = socket.socket(socket.AF_UNIX); stalled.connect(a.sock_path)
    stalled.sendall(b"\x00\x00")                                           # a stalled read
    t0 = time.monotonic()
    assert c.status()["ok"] and time.monotonic() - t0 < 0.4
    time.sleep(0.7)
    stalled.settimeout(1); assert stalled.recv(10) == b""                  # closed at the deadline


def test_the_21st_sign_in_a_minute_and_the_501st_are_refused():
    clk = FakeClocks()
    a = agent(clk)
    ok = [sign(a, body(action="set-config", key="x-demo:k", value=str(i)))["ok"] for i in range(22)]
    assert ok == [True] * 20 + [False] * 2
    clk.advance(61)
    assert sign(a, body(action="set-config", key="x-demo:k", value="again"))["ok"]
    a.signed = owner_agent.SIGNS_TOTAL
    clk.advance(61)
    assert sign(a, body(action="set-config", key="x-demo:k", value="more"))["ok"] is False


def test_ten_refusals_in_a_minute_back_off():
    clk = FakeClocks()
    a = agent(clk)
    for _ in range(10):
        sign(a, body(action="transfer", to="x"))
    r = sign(a, body(**ADMIT))
    assert r == {"ok": False, "why": "busy"}
    clk.advance(31)
    assert sign(a, body(**ADMIT))["ok"]


def test_the_ninth_concurrent_connection_gets_busy(served, monkeypatch):
    monkeypatch.setattr(owner_agent, "READ_DEADLINE", 3)
    a, c = served()
    held = []
    for _ in range(owner_agent.MAX_CONN):
        s = socket.socket(socket.AF_UNIX); s.connect(a.sock_path); held.append(s)
    time.sleep(0.3)
    assert c.request({"op": "status"}, timeout=2) == {"ok": False, "why": "busy"}
    for s in held:
        s.close()


# ---- the chain signer (test 9) -------------------------------------------------------------------------------------------

class Stub:
    def __init__(self, sig=None, err=None):
        self.sig, self.err, self.calls = sig, err, 0

    def sign(self, b):
        self.calls += 1
        if self.err:
            raise owner_agent.AgentError(self.err)
        return self.sig(b)


def test_a_refusal_falls_back_to_the_file_key_once_and_says_why():
    said, asked = [], []
    stub = Stub(err="not on the allowlist")
    cs = owner_agent.ChainSigner(stub, ed25519.pub_from_seed(SEED), lambda: asked.append(1) or sigseam.FileSigner(SEED), said.append)
    b = body(action="transfer", to="x")
    s1, s2 = cs.sign(b), cs.sign(b)
    assert ed25519.verify(b, s1, ed25519.pub_from_seed(SEED)) and s1 == s2
    assert len(asked) == 1 and len(said) == 1 and "not on the allowlist" in said[0]


def test_a_bad_signature_from_the_agent_is_not_used():
    said = []
    cs = owner_agent.ChainSigner(Stub(sig=lambda b: bytes(64)), ed25519.pub_from_seed(SEED),
                                 lambda: sigseam.FileSigner(SEED), said.append)
    assert ed25519.verify(b"m", cs.sign(b"m"), ed25519.pub_from_seed(SEED)) and said


def test_a_cancelled_fallback_signs_nothing():
    cs = owner_agent.ChainSigner(Stub(err="busy"), ed25519.pub_from_seed(SEED), lambda: None, lambda m: None)
    with pytest.raises(RuntimeError):
        cs.sign(b"m")


def test_the_gate_wants_margin_and_the_named_acts():
    st = {"idle_left": 900, "hard_left": 9000, "budget_left": 500, "backoff": 0, "modules": ["demo"], "admitted": [DEV]}
    assert owner_agent.gate_ok(st, [])
    assert owner_agent.gate_ok(st, [("admit", "demo"), ("revoke", None)])
    assert not owner_agent.gate_ok(st, [("admit", "other")])
    assert owner_agent.gate_ok(st, [("revoke", DEV)]) and not owner_agent.gate_ok(st, [("revoke", DEV2)])
    assert not owner_agent.gate_ok({**st, "idle_left": 59}, [])
    assert not owner_agent.gate_ok({**st, "budget_left": 99}, [])
    assert not owner_agent.gate_ok(st, [("transfer", None)])


def test_the_seam_and_the_governance_signer_are_untouched():
    for f in ("hivemind/crypto/signer.py", "ownerkey.py"):
        assert "owner_agent" not in (PROJECT / f).read_text()
    src = (PROJECT / "owner_agent.py").read_text()
    assert "ed25519.sign" not in src and "_ed25519.sign" not in src


# ---- the real CLI (tests 1-3, 11, 13, 14, 16) ----------------------------------------------------------------------------

@pytest.fixture
def hive(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_MODULES_DIR", str(tmp_path / "modules"))
    monkeypatch.delenv("TERMUX_VERSION", raising=False)
    run = Path(tempfile.mkdtemp(dir="/tmp")); os.chmod(run, 0o700)
    home = tmp_path / "A"
    env = dict(os.environ, HIVE_HOME=str(home), HIVE_IDENTITY_STASH=str(tmp_path / "stash"), XDG_RUNTIME_DIR=str(run),
               HIVE_OWNER_KEY_PASSPHRASE=PASS)
    env.pop("HIVE_KEY_DIR", None)
    h = type("H", (), {})()
    h.home, h.env, h.run, h.tmp = home, env, run, tmp_path
    h.ctl = lambda *a, **kw: ctl(h, *a, **kw)
    for k in ("HIVE_HOME", "HIVE_IDENTITY_STASH", "XDG_RUNTIME_DIR"):
        monkeypatch.setenv(k, env[k])
    _run(home, "config", "identity", "init")
    _run(home, "owner", "init")
    _run(home, "group", "admit", _device_id(home), "--principal", "op")
    yield h
    ctl(h, "owner", "lock", check=False)


def ctl(h, *args, passphrase=False, check=True, no_pass=True, fd=None):
    """Run `hive-mind`; the key passphrase is NOT in the environment unless `passphrase` (a prompt then cancels)."""
    env = dict(h.env)
    if no_pass and not passphrase:
        env.pop("HIVE_OWNER_KEY_PASSPHRASE")
    r = subprocess.run([sys.executable, str(PROJECT / "hivemind_ctl.py"), *args], env=env, capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, start_new_session=True)
    if check:
        assert r.returncode == 0, r.stderr + r.stdout
    return r


def unlock(h, *args, pw=PASS, check=True):
    rfd, wfd = os.pipe()
    os.write(wfd, (pw + "\n").encode()); os.close(wfd)
    env = dict(h.env); env.pop("HIVE_OWNER_KEY_PASSPHRASE")
    try:
        r = subprocess.run([sys.executable, str(PROJECT / "hivemind_ctl.py"), "owner", "unlock", "--passphrase-fd", str(rfd), *args],
                           env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, start_new_session=True,
                           pass_fds=(rfd,))
    finally:
        os.close(rfd)
    if check:
        assert r.returncode == 0, r.stderr + r.stdout
    return r


def _sock(h):
    return owner_agent.socket_path(h.home, h.env)


@LINUX
def test_unlock_hardens_the_process_holds_no_seed_on_disk_and_lock_ends_it(hive):
    seed = ownerkey_seed(hive)
    r = unlock(hive, "--module", "demo", "--for", "30m")
    pid = int(r.stdout.split("pid ")[1].split(")")[0])
    with pytest.raises(PermissionError):                     # PR_SET_DUMPABLE=0: /proc/<pid>/environ and mem are root's
        Path(f"/proc/{pid}/environ").read_bytes()
    limits = Path(f"/proc/{pid}/limits").read_text()
    assert [l for l in limits.splitlines() if l.startswith("Max core file size")][0].split()[4:6] == ["0", "0"]
    for needle in (seed, base64.b64encode(seed), PASS.encode()):
        assert needle not in Path(f"/proc/{pid}/cmdline").read_bytes()
        assert needle not in (r.stdout + r.stderr).encode()
    for root in (hive.home, hive.run):                       # nothing under the hive or the runtime dir holds the seed
        for p in root.rglob("*"):
            if p.is_file() and p.name not in ("owner-key.sealed", ".owner-key.sealed"):
                assert seed not in p.read_bytes() and base64.b64encode(seed) not in p.read_bytes()
    assert [p.name for p in hive.run.rglob("*") if p.is_file() or p.is_socket()] == [Path(_sock(hive)).name]
    assert "unlocked" in hive.ctl("owner", "status").stdout
    assert "already unlocked" in unlock(hive, "--module", "demo").stdout
    hive.ctl("owner", "lock")
    for _ in range(50):
        if not Path(f"/proc/{pid}").exists() or "Z" in Path(f"/proc/{pid}/status").read_text().split("State:")[1][:4]:
            break
        time.sleep(0.1)
    assert not os.path.exists(_sock(hive))
    assert "locked" in hive.ctl("owner", "status").stdout


def ownerkey_seed(h):
    out = h.tmp / "export.json"
    h.ctl("owner", "export", "--plaintext", "--out", str(out), passphrase=True)
    return base64.b64decode(json.loads(out.read_text())["seed"])


@LINUX
def test_unlock_refuses_a_wrong_passphrase_and_ignores_the_env_passphrase(hive):
    assert unlock(hive, pw="wrong", check=False).returncode == 1
    assert not os.path.exists(_sock(hive))
    r = hive.ctl("owner", "unlock", passphrase=True, check=False)       # env set, no tty, no fd
    assert r.returncode == 1 and "ignored" in r.stderr and not os.path.exists(_sock(hive))


@LINUX
def test_for_out_of_bounds_is_refused(hive):
    assert hive.ctl("owner", "unlock", "--for", "30s", check=False).returncode == 2
    assert hive.ctl("owner", "unlock", "--for", "9h", check=False).returncode == 2


@LINUX
def test_one_passphrase_for_a_session_and_none_for_the_commands(hive, tmp_path):
    pub = _publish(tmp_path / "repo")
    add = ("module", "add", "demo", "--from", str(tmp_path / "repo"), "--publisher", pub)
    locked = hive.ctl(*add, check=False)                                  # no agent: the prompt cancels, nothing written
    assert locked.returncode == 1 and "Cancelled" in locked.stderr and not (tmp_path / "modules" / "demo").exists()
    unlock(hive, "--module", "demo")
    r = hive.ctl(*add)
    assert "signed by agent: admit" in r.stderr and "installed module demo" in r.stdout
    hive.ctl("config", "set", "x-demo:poll", "60")
    again = hive.ctl("config", "set", "x-demo:poll", "60")
    assert "nothing to sign" in again.stdout
    signed = json.loads(json.dumps(owner_agent.Client(_sock(hive)).status()))["signed"]
    hive.ctl("config", "set", "x-demo:poll", "60")
    assert owner_agent.Client(_sock(hive)).status()["signed"] == signed
    hive.ctl("module", "quota", "demo", "--entry-bytes", "100000", check=False)
    assert hive.ctl("module", "remove", "demo").returncode == 0
    ring = owner_agent.Client(_sock(hive)).status()["ring"]
    assert [x["act"].split()[0] for x in ring if x["ok"]] == ["admit", "set-config", "revoke"]


@LINUX
def test_a_plain_unlock_prompts_up_front_for_module_add_before_anything_is_fetched(hive, tmp_path):
    pub = _publish(tmp_path / "repo")
    unlock(hive)
    r = hive.ctl("module", "add", "demo", "--from", str(tmp_path / "repo"), "--publisher", pub, check=False)
    assert r.returncode == 1 and "Cancelled" in r.stderr
    assert not (tmp_path / "modules" / "demo").exists()


@LINUX
def test_a_link_with_an_owner_signature_still_prompts_while_unlocked(hive):
    unlock(hive, "--module", "demo")
    r = hive.ctl("remember", "a fact", "--supports", "f:nothing", check=False)
    assert "Cancelled" in r.stderr


@LINUX
def test_an_agent_locked_after_the_gate_still_leaves_nothing(hive, tmp_path):
    pub = _publish(tmp_path / "repo")
    unlock(hive, "--module", "demo")
    hive.ctl("owner", "lock")
    r = hive.ctl("module", "add", "demo", "--from", str(tmp_path / "repo"), "--publisher", pub, check=False)
    assert r.returncode == 1 and not (tmp_path / "modules" / "demo").exists()


def test_a_revoke_that_cannot_be_signed_after_a_failed_add_is_never_silent(monkeypatch, capsys):
    import hive_modules
    lib = type("L", (), {"_ensure_key_dir": staticmethod(lambda: Path(tempfile.mkdtemp()))})()

    def cancelled(*a):
        raise RuntimeError("the owner key could not be unlocked")
    lib._group_change = cancelled
    monkeypatch.setattr(hive_modules, "_device_state", lambda lib, d: "admitted")
    monkeypatch.setattr(hive_modules, "modules_dir", lambda: Path(tempfile.mkdtemp()))
    monkeypatch.setattr(hive_modules, "remove_units", lambda n: None)
    hive_modules._undo_add(lib, "demo", DEV)
    assert f"device {DEV} is still admitted as a module device" in capsys.readouterr().err


def test_a_failed_mlock_is_stated_in_status():
    a = agent(mlocked=False)
    assert a.status()["mlocked"] is False
    assert agent(mlocked=True).status()["mlocked"] is True


@LINUX
def test_install_set_fleet_exits_5_when_the_agent_is_for_another_module_and_writes_nothing(hive, tmp_path, units):
    schema = {"board": {"type": "string", "max": 20, "scope": "fleet", "description": "A board"},
              "mode": {"type": "string", "max": 20, "description": "A mode"}}
    pub = _publish(tmp_path / "repo", config_schema=schema, min_core="3.1", contract=1, config=None)
    inst = ("module", "install", "demo", "--from", str(tmp_path / "repo"), "--publisher", pub)
    hive.ctl(*inst, "--set", "mode=a", passphrase=True)
    unlock(hive, "--module", "other")
    cfg, state = tmp_path / "modules" / "demo" / "config", hive.home / ".modules.json"
    before = (cfg.read_bytes(), state.read_bytes())
    r = hive.ctl(*inst, "--set", "mode=z", "--set-fleet", "board=b2", "--json", check=False)
    o = json.loads(r.stdout)
    assert r.returncode == 5 and o["exit"] == 5 and o["result"] == "locked"
    assert (cfg.read_bytes(), state.read_bytes()) == before
    assert "passphrase" not in " ".join(o["warnings"]) + r.stderr
    assert owner_agent.gate_ok({"idle_left": 999, "hard_left": 999, "budget_left": 99, "modules": ["other"]},
                               [("set-config", "demo")]) is False
