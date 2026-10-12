"""The owner-unlock agent (3.1, #295; design: hive-mind-private docs/design/owner_unlock_agent_3_1.md).

`hive-mind owner unlock` prompts for the passphrase once, unseals the owner seed and hands it, over an anonymous pipe,
to a fresh per-user process running THIS file. The agent keeps the seed in its own memory only (never a file, argv, env or
log), listens on a private Unix socket, and answers one question: "sign these exact canonical bytes?" It signs only when
the bytes parse as an allowlisted governance act (`Policy`), and says no to everything else; the CLI then falls back to
today's per-command passphrase prompt. The seed is never sent to a client, and there is no op that unlocks, returns a
seed, or signs arbitrary bytes.

It is a second `Signer` backend behind the signer seam: `ChainSigner` asks the agent first and falls back to a
`FileSigner`. This file produces signatures only through `hivemind.crypto.signer`; verification stays `ed25519.verify`.
`ownerkey.sign_governance` and the seam itself are unchanged, and no journal, entry, signature, governance, projection or
sync byte changes.

**Control plane only** (2.0 S2): `hv` never imports this file. It is also an entry point (`python3 -I owner_agent.py`),
so the path setup below is inside `_agent_main`, never at import.

Best effort and stated as such: `PR_SET_DUMPABLE=0`, no core dump, `mlock` of the seed page. The bundled pure-Python
signer builds big integers on the ordinary heap and `FileSigner` keeps an immutable copy of the seed; CPython cannot zero
or lock either, so swap and hibernation are a residual (docs/THREAT_MODEL.md). Process exit is the real guarantee.
"""

import base64
import ctypes
import hashlib
import json
import mmap
import os
import select
import signal
import socket
import stat
import struct
import sys
import threading
import time
from collections import deque

if __name__ == "__main__":      # entry point only (`python3 -I` puts no directory on sys.path): this file's own, unresolved
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import merkle
import vocabulary
from hivemind.crypto import signer as _sigseam

try:
    import ed25519 as _ed25519
except Exception:                   # no bundled crypto: no agent
    _ed25519 = None

# ---- bounds (design §1, §2, §4) ----------------------------------------------------------------------------------
IDLE_DEFAULT, IDLE_MIN, IDLE_MAX = 15 * 60, 60, 8 * 3600
HARD_CAP = 12 * 3600
MAX_FRAME = 64 * 1024
READ_DEADLINE = 5.0
MAX_CONN = 8
SIGNS_PER_MINUTE, SIGNS_TOTAL = 20, 500
REFUSALS_PER_MINUTE, BACKOFF = 10, 30.0
RING = 200
GATE_MIN_IDLE = 60.0
GATE_MIN_BUDGET = SIGNS_TOTAL // 5
BOOT_JUMP = 5.0
SOCKET_CHECK = 5.0
UNIX_PATH_MAX = 100


class AgentError(Exception):
    """The agent cannot be reached or used: no agent, a bad socket directory, a bad reply. Never fatal to the
    caller: the CLI falls back to the passphrase prompt."""


# ---- the socket path and directory checks (client and agent share them) -------------------------------------------

def _runtime_dir(env=None):
    env = os.environ if env is None else env
    xdg = env.get("XDG_RUNTIME_DIR")
    if xdg and os.path.isabs(xdg):
        return os.path.join(xdg, "hive-mind")
    return os.path.join(env.get("TMPDIR") or "/tmp", f"hive-mind-{os.getuid()}")


def socket_path(hive_home, env=None):
    """`<runtime dir>/owner-agent-<h>.sock`, `<h>` the first 12 hex of sha256(realpath(HIVE_HOME)): one agent per
    user per hive home. The name is a hash, so the path stays under the AF_UNIX limit and discloses nothing."""
    h = hashlib.sha256(os.path.realpath(str(hive_home)).encode()).hexdigest()[:12]
    path = os.path.join(_runtime_dir(env), f"owner-agent-{h}.sock")
    if len(path.encode()) > UNIX_PATH_MAX:
        raise AgentError(f"the socket path is too long for AF_UNIX ({len(path)} > {UNIX_PATH_MAX}): set XDG_RUNTIME_DIR "
                         "or TMPDIR to a shorter directory")
    return path


def check_dir(path, create=False):
    """The socket's directory must be a real directory (not a symlink) owned by this uid at mode exactly 0700, or the
    caller refuses: a lookalike directory someone else pre-created cannot capture requests."""
    if create:
        try:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError as e:
            raise AgentError(f"cannot create {path}: {e}")
    try:
        st = os.lstat(path)
    except OSError as e:
        raise AgentError(f"{path}: {e.strerror}")
    if not stat.S_ISDIR(st.st_mode):
        raise AgentError(f"{path} is not a directory")
    if st.st_uid != os.getuid():
        raise AgentError(f"{path} is not owned by this user")
    if stat.S_IMODE(st.st_mode) != 0o700:
        raise AgentError(f"{path} is mode {stat.S_IMODE(st.st_mode):04o}, not 0700")


# ---- framing: a 4-byte length, then JSON; one request per connection ------------------------------------------------

def _recv_exact(conn, n, deadline):
    buf = b""
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("read deadline")
        conn.settimeout(left)
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def read_frame(conn, deadline):
    (n,) = struct.unpack(">I", _recv_exact(conn, 4, deadline))
    if n > MAX_FRAME:
        raise ValueError("oversize")
    obj = json.loads(_recv_exact(conn, n, deadline))
    if not isinstance(obj, dict):
        raise ValueError("not an object")
    return obj


def write_frame(conn, obj):
    data = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    conn.sendall(struct.pack(">I", len(data)) + data)


# ---- the allowlist (design §3) ---------------------------------------------------------------------------------------

_KEYS = {"admit": {"action", "device_id", "module", "principal", "owner_pub"},
         "revoke": {"action", "device_id", "owner_pub"},
         "set-config": {"action", "key", "value", "owner_pub"}}


def _device_id_ok(d):
    return (isinstance(d, str) and d.startswith("k1:") and len(d) == 19
            and all(c in "0123456789abcdef" for c in d[3:]))


class Policy:
    """Decides whether the agent signs a body. `check` is pure (it mutates nothing); `commit` records an admit once
    the signature has been made. `probe(device_id)` returns "admitted", "purged", "other" or None (cannot tell: the
    act is refused). `installed(module)` says a plain unlock may touch that module's config."""

    def __init__(self, owner_pub_b64, modules, probe, installed):
        self.owner_pub = owner_pub_b64
        self.modules = frozenset(modules)
        self.probe = probe
        self.installed = installed
        self.admitted_session = set()

    def check(self, body):
        """(ok, why, act) for the exact canonical bytes `body`. `act` is a short description, never a value."""
        try:
            obj = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return False, "not JSON", "?"
        if not isinstance(obj, dict):
            return False, "not an object", "?"
        try:
            if merkle._canonical(obj) != body:        # what is inspected is what is signed
                return False, "not canonical", "?"
        except (TypeError, ValueError):
            return False, "not canonical", "?"
        action = obj.get("action")
        if not isinstance(action, str):
            return False, "no action", "?"
        keys = _KEYS.get(action)
        if keys is None:
            return False, "not on the allowlist", action[:32]
        if set(obj) != keys:
            return False, "wrong key set", action
        if obj["owner_pub"] != self.owner_pub:
            return False, "owner_pub is not this key", action
        if action == "admit":
            return self._admit(obj)
        if action == "revoke":
            d = obj["device_id"]
            if not _device_id_ok(d):
                return False, "bad device id", action
            if d not in self.admitted_session:
                return False, "device not admitted this session", f"revoke {d}"
            return True, "", f"revoke {d}"
        return self._set_config(obj)

    def _admit(self, obj):
        d, m = obj["device_id"], obj["module"]
        if not _device_id_ok(d):
            return False, "bad device id", "admit"
        if not isinstance(obj["principal"], str) or not obj["principal"] or len(obj["principal"]) > 256:
            return False, "bad principal", "admit"
        if not vocabulary.valid_module_name(m):
            return False, "bad module name", "admit"
        act = f"admit {d} (module {m})"
        if m not in self.modules:
            return False, "module not named by --module", act
        if self.probe(d) != "other":
            return False, "device already admitted or purged, or governance unreadable", act
        return True, "", act

    def _set_config(self, obj):
        k, v = obj["key"], obj["value"]
        sp = vocabulary.split_module_name(k)
        if sp is None:
            return False, "not a module config key", "set-config"
        act = f"set-config {k}"
        if not isinstance(v, str) or len(v) > vocabulary.MODULE_VALUE_MAX:
            return False, "bad value", act
        m = sp[0]
        if self.modules:
            if m not in self.modules:
                return False, "module not named by --module", act
        elif not self.installed(m):
            return False, "module not installed", act
        return True, "", act

    def commit(self, body):
        obj = json.loads(body.decode("utf-8"))
        if obj.get("action") == "admit":
            self.admitted_session.add(obj["device_id"])


# ---- clocks (injectable for tests) ----------------------------------------------------------------------------------

class Clocks:
    def mono(self):
        return time.monotonic()

    def wall(self):
        return time.time()

    def boot(self):
        try:
            return time.clock_gettime(time.CLOCK_BOOTTIME)
        except (AttributeError, OSError):
            return None


def peer_uid(conn):
    """The connecting process's uid, or None if the platform cannot say (the connection is then refused)."""
    try:
        if hasattr(socket, "SO_PEERCRED"):
            _pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            return uid
        if sys.platform == "darwin":                        # LOCAL_PEERCRED: struct xucred {version, uid, ...}
            data = conn.getsockopt(0, 1, 76)
            return struct.unpack_from("=II", data)[1]
    except OSError:
        pass
    return None


def peer_pid(conn):
    try:
        if hasattr(socket, "SO_PEERCRED"):
            return struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[0]
    except OSError:
        pass
    return None


def _peer_exe(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except (OSError, TypeError):
        return "?"


# ---- the agent ------------------------------------------------------------------------------------------------------

class Agent:
    """Holds the signer and answers on `sock_path`. `run()` returns once locked; the caller then exits the process."""

    def __init__(self, seed, sock_path, idle, policy, clocks=None, uid=None, mlocked=False, peer_uid_fn=peer_uid):
        self.signer = _sigseam.FileSigner(seed)
        if base64.b64encode(self.signer.public_key()).decode() != policy.owner_pub:
            raise ValueError("the seed is not the owner key")
        self.sock_path, self.idle, self.policy = sock_path, idle, policy
        self.clk = clocks or Clocks()
        self.uid = os.getuid() if uid is None else uid
        self.mlocked = mlocked
        self._peer_uid = peer_uid_fn
        self.t0, self.w0 = self.clk.mono(), self.clk.wall()
        self.last_mono, self.last_wall = self.t0, self.w0
        self.boot_off = self._boot_off()
        self.signed = 0
        self.sign_times = deque()
        self.refusals = deque()
        self.backoff_until = 0.0
        self.ring = deque(maxlen=RING)
        self.lock = threading.Lock()
        self.conns = 0
        self.stop = threading.Event()
        self.why_locked = None
        self.sock = None
        self.ino = None
        self.buf = None                               # the mmap page holding the seed

    # -- lifetime
    def _boot_off(self):
        b = self.clk.boot()
        return None if b is None else b - self.clk.mono()

    def idle_left(self):
        return min(self.last_mono + self.idle - self.clk.mono(), self.last_wall + self.idle - self.clk.wall())

    def hard_left(self):
        return min(self.t0 + HARD_CAP - self.clk.mono(), self.w0 + HARD_CAP - self.clk.wall())

    def tick(self):
        """Lock on expiry, a suspend/resume jump or a vanished socket."""
        if self.idle_left() <= 0:
            return self.do_lock("idle expiry")
        if self.hard_left() <= 0:
            return self.do_lock("hard cap")
        off = self._boot_off()
        if off is not None and self.boot_off is not None and abs(off - self.boot_off) > BOOT_JUMP:
            return self.do_lock("suspend/resume")
        return None

    def socket_alive(self):
        try:
            st = os.lstat(self.sock_path)
        except OSError:
            return False
        return stat.S_ISSOCK(st.st_mode) and st.st_ino == self.ino

    def do_lock(self, why):
        if self.why_locked is None:
            self.why_locked = why
            self.stop.set()
        return why

    def shutdown(self):
        """Zero the seed page, drop the signer, unlink our socket. The caller exits the process (the real guarantee)."""
        self.signer = None
        if self.buf is not None:
            try:
                ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(self.buf)), 0, len(self.buf))
            except Exception:
                pass
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            try:
                if self.socket_alive():
                    os.unlink(self.sock_path)
            except OSError:
                pass

    # -- the socket
    def bind(self):
        check_dir(os.path.dirname(self.sock_path))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            s.bind(self.sock_path)
        finally:
            os.umask(old)
        st = os.lstat(self.sock_path)
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != self.uid:
            s.close()
            raise AgentError("the socket is not ours")
        os.chmod(self.sock_path, 0o600)
        s.listen(MAX_CONN)
        self.sock, self.ino = s, st.st_ino

    def run(self):
        last_check = self.clk.mono()
        try:
            while not self.stop.is_set():
                r, _, _ = select.select([self.sock], [], [], 0.5)
                self.tick()
                if self.clk.mono() - last_check >= SOCKET_CHECK:
                    last_check = self.clk.mono()
                    if not self.socket_alive():
                        self.do_lock("socket removed")
                if not r or self.stop.is_set():
                    continue
                try:
                    conn, _ = self.sock.accept()
                except OSError:
                    continue
                with self.lock:
                    busy = self.conns >= MAX_CONN
                    if not busy:
                        self.conns += 1
                if busy:
                    self._reply_close(conn, {"ok": False, "why": "busy"})
                    continue
                threading.Thread(target=self._serve, args=(conn,), daemon=True).start()
        finally:
            self.shutdown()
        return self.why_locked

    @staticmethod
    def _reply_close(conn, obj):
        try:
            conn.settimeout(1.0)
            write_frame(conn, obj)
        except OSError:
            pass
        finally:
            conn.close()

    def _serve(self, conn):
        try:
            if self._peer_uid(conn) != self.uid:     # before reading a byte; closed without a reply
                return
            pid = peer_pid(conn)
            try:
                req = read_frame(conn, time.monotonic() + READ_DEADLINE)
            except (OSError, ValueError, TimeoutError):
                return
            with self.lock:
                if self.signer is None:
                    return
                reply = self._handle(req, pid)
            try:
                conn.settimeout(READ_DEADLINE)
                write_frame(conn, reply)
            except OSError:
                pass
        finally:
            conn.close()
            with self.lock:
                self.conns -= 1

    # -- the ops: status, sign, lock. There is no unlock and no op that returns the seed.
    def _log(self, pid, op, act, ok, why):
        self.ring.append({"t": int(self.clk.wall()), "pid": pid, "exe": _peer_exe(pid), "op": op,
                          "act": act, "ok": ok, "why": why})

    def _handle(self, req, pid):
        op = req.get("op")
        if op == "status":
            return self.status()
        if op == "lock":
            self._log(pid, "lock", "-", True, "")
            self.do_lock("owner lock")
            return {"ok": True}
        if op == "sign":
            return self._sign(req, pid)
        return {"ok": False, "why": "unknown op"}

    def status(self):
        now = self.clk.mono()
        budget = SIGNS_TOTAL - self.signed
        return {"ok": True, "public_key": base64.b64encode(self.signer.public_key()).decode(),
                "idle_left": max(0, int(self.idle_left())), "hard_left": max(0, int(self.hard_left())),
                "idle": self.idle, "modules": sorted(self.policy.modules),
                "admitted": sorted(self.policy.admitted_session), "signed": self.signed, "budget_left": budget,
                "mlocked": self.mlocked, "backoff": max(0, int(self.backoff_until - now)),
                "allowlist": ["admit (module device, --module only)", "revoke (device admitted this session)",
                              "set-config x-<module>:<key>"],
                "ring": list(self.ring)}

    def _refuse(self, pid, act, why):
        now = self.clk.mono()
        while self.refusals and now - self.refusals[0] > 60:
            self.refusals.popleft()
        self.refusals.append(now)
        if len(self.refusals) >= REFUSALS_PER_MINUTE:
            self.backoff_until = now + BACKOFF
        self._log(pid, "sign", act, False, why)
        return {"ok": False, "why": why}

    def _sign(self, req, pid):
        now = self.clk.mono()
        if now < self.backoff_until:
            return {"ok": False, "why": "busy"}
        try:
            body = base64.b64decode(req.get("body") or "", validate=True)
        except (ValueError, TypeError):
            return self._refuse(pid, "?", "bad body")
        while self.sign_times and now - self.sign_times[0] > 60:
            self.sign_times.popleft()
        if len(self.sign_times) >= SIGNS_PER_MINUTE or self.signed >= SIGNS_TOTAL:
            self._log(pid, "sign", "-", False, "rate limit")
            return {"ok": False, "why": "busy"}
        ok, why, act = self.policy.check(body)
        if not ok:
            return self._refuse(pid, act, why)
        sig = self.signer.sign(body)
        self.policy.commit(body)
        self.signed += 1
        self.sign_times.append(now)
        self.last_mono, self.last_wall = now, self.clk.wall()          # a signed act resets the idle timer
        self._log(pid, "sign", act, True, "")
        return {"ok": True, "sig": base64.b64encode(sig).decode(), "act": act}


# ---- the client ----------------------------------------------------------------------------------------------------

class Client:
    def __init__(self, path):
        self.path = path
        self.last_act = ""

    def request(self, obj, timeout=READ_DEADLINE):
        d = os.path.dirname(self.path)
        try:
            check_dir(d)
            st = os.lstat(self.path)
        except (AgentError, OSError) as e:
            raise AgentError(f"no agent ({e})")
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.getuid():
            raise AgentError("the agent socket is not ours")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(self.path)
            write_frame(s, obj)
            return read_frame(s, time.monotonic() + timeout)
        except (OSError, ValueError, TimeoutError, ConnectionError) as e:
            raise AgentError(f"agent unreachable ({e.__class__.__name__})")
        finally:
            s.close()

    def status(self):
        r = self.request({"op": "status"})
        if not r.get("ok"):
            raise AgentError(r.get("why", "status refused"))
        return r

    def sign(self, body):
        """The 64-byte signature, or raises AgentError with the agent's reason."""
        r = self.request({"op": "sign", "body": base64.b64encode(body).decode()})
        if not r.get("ok"):
            raise AgentError(r.get("why", "refused"))
        self.last_act = r.get("act", "")
        return base64.b64decode(r["sig"])

    def lock(self):
        return self.request({"op": "lock"}).get("ok", False)


class ChainSigner(_sigseam.Signer):
    """The agent first, then the file key. `public_key()` comes from the agent's `status` (a public value, so no
    prompt is needed to learn the node holds the owner key). `sign` tries the agent; on a refusal or an unreachable
    agent it asks `fallback()` for a FileSigner (one passphrase prompt per process, as today), saying why on stderr.
    A refusal is never an error and never a silent drop."""

    __slots__ = ("_client", "_pub", "_fallback", "_say", "_fb")

    def __init__(self, client, public_key, fallback, say=None):
        self._client, self._pub, self._fallback, self._fb = client, public_key, fallback, None
        self._say = say or (lambda m: print(m, file=sys.stderr))   # every agent-signed act and every fallback is said

    def public_key(self):
        return self._pub

    def sign(self, message):
        if self._fb is None:
            try:
                sig = self._client.sign(message)
                if _ed25519 is not None and not _ed25519.verify(message, sig, self._pub):
                    raise AgentError("the agent returned a signature that does not verify")
                self._say(f"signed by agent: {getattr(self._client, 'last_act', '')}")
                return sig
            except AgentError as e:
                self._say(f"owner agent did not sign ({e}): using the passphrase")
        if self._fb is None:
            self._fb = self._fallback()
            if self._fb is None or self._fb.public_key() != self._pub:
                self._fb = None
                raise RuntimeError("the owner key could not be unlocked, so nothing was signed")
        return self._fb.sign(message)

    def __repr__(self):
        return "<ChainSigner>"


def gate_ok(status, acts):
    """Whether the agent would sign every act in `acts` for a whole command, with margin (design §3 Gates).
    `acts` is a list of (action, arg): ("admit", module), ("revoke", device_id or None for the device the same run
    just admitted). An empty list is the public-key check alone."""
    if status.get("idle_left", 0) < GATE_MIN_IDLE or status.get("hard_left", 0) < GATE_MIN_IDLE:
        return False
    if status.get("budget_left", 0) < GATE_MIN_BUDGET or status.get("backoff", 0) > 0:
        return False
    for action, arg in acts:
        if action == "admit":
            if arg not in status.get("modules", ()):
                return False
        elif action == "revoke":
            if arg is not None and arg not in status.get("admitted", ()):
                return False
        else:
            return False
    return True


# ---- the CLI: hive-mind owner unlock | lock | status -----------------------------------------------------------------

_DUR = {"s": 1, "m": 60, "h": 3600}


def parse_duration(text):
    """`15m`, `90s`, `2h` (a bare number is seconds), within the 1m to 8h bounds; ValueError otherwise."""
    t = str(text).strip().lower()
    try:
        secs = float(t[:-1]) * _DUR[t[-1]] if t[-1:] in _DUR else float(t)
    except (ValueError, IndexError):
        raise ValueError(f"{text!r} is not a duration (15m, 2h)")
    if not IDLE_MIN <= secs <= IDLE_MAX:
        raise ValueError("--for must be between 1m and 8h")
    return secs


def _clock(ts):
    return time.strftime("%H:%M", time.localtime(ts))


def _read_unlock_passphrase(fd):
    """The passphrase for `unlock`: `--passphrase-fd N` (one line, the automation path the tests use), else
    getpass on /dev/tty. $HIVE_OWNER_KEY_PASSPHRASE is ignored (env is readable by same-uid and child processes). No
    tty and no fd: refuse. Returns the passphrase, or None to cancel."""
    if fd is not None:
        data = bytearray()
        while True:
            c = os.read(fd, 1)
            if not c or c == b"\n":
                break
            data += c
        pw = data.decode("utf-8", "replace")
        for i in range(len(data)):
            data[i] = 0
        return pw or None
    try:
        tty = open("/dev/tty", "r+")
        tty.close()
    except OSError:
        raise AgentError("no terminal to ask for the passphrase on: run `owner unlock` at a terminal")
    import getpass
    try:
        pw = getpass.getpass("Owner key passphrase (blank line / Ctrl-C to cancel): ")
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return pw or None


def cmd_unlock(lib, argv, out=print):
    import argparse
    ap = argparse.ArgumentParser(prog="hive-mind owner unlock")
    ap.add_argument("--for", dest="idle", default="15m", help="idle timeout, reset by each signed act (1m to 8h)")
    ap.add_argument("--module", action="append", default=[], help="a module the agent may admit and configure (repeatable)")
    ap.add_argument("--passphrase-fd", type=int, default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    try:
        idle = parse_duration(a.idle)
    except ValueError as e:
        print(f"hive-mind: {e}", file=sys.stderr)
        return 2
    for m in a.module:
        if not vocabulary.valid_module_name(m):
            print(f"hive-mind: {m!r} is not a valid module name", file=sys.stderr)
            return 2
    if os.environ.get(lib._KEY_PASSPHRASE_ENV) is not None:
        print(f"hive-mind: ${lib._KEY_PASSPHRASE_ENV} is ignored by `owner unlock` (the environment is readable by "
              "other processes); type the passphrase at the prompt.", file=sys.stderr)
    path = socket_path(lib.HIVE_HOME)
    check_dir(os.path.dirname(path), create=True)
    client = Client(path)
    try:
        st = client.status()
        print(f"already unlocked (idle expiry in {int(st['idle_left'] // 60)}m, hard cap in {int(st['hard_left'] // 3600)}h)")
        return 0
    except AgentError:
        pass
    try:
        lst = os.lstat(path)
        if not stat.S_ISSOCK(lst.st_mode) or lst.st_uid != os.getuid():
            print(f"hive-mind: {path} exists and is not our socket; refusing to start over it", file=sys.stderr)
            return 1
        os.unlink(path)                                   # a stale socket: connect was refused, and it is ours
    except FileNotFoundError:
        pass
    if not lib._is_file(lib.OWNER_SEALED_PATH):
        print("hive-mind: no sealed owner key on this device (run `hive-mind owner seal` first, or this is not the owner "
              "machine); nothing to unlock", file=sys.stderr)
        return 1
    now = time.time()
    print("Owner unlock: for the next %s of inactivity (at most 12h), a process running as you can obtain signatures for:\n"
          "  - admit a MODULE device for: %s\n  - revoke a module device this session admitted\n"
          "  - set x-<module>: config for: %s\n"
          "Nothing else is signed (transfer, rotate, forget, voting devices, links): each of those still asks for the "
          "passphrase. Expires about %s.\n"
          % (a.idle, ", ".join(a.module) or "(no module: a plain unlock admits nothing)",
             ", ".join(a.module) or "installed modules", _clock(now + idle)))
    seed = None
    for attempt in range(1, 4):
        pw = _read_unlock_passphrase(a.passphrase_fd)
        if pw is None:
            print("Cancelled: the owner key stays sealed.", file=sys.stderr)
            return 1
        try:
            import ownerkey
            seed = ownerkey.load_sealed(lib.OWNER_SEALED_PATH, pw, lib._owner_unseal)
            break
        except (ValueError, KeyError) as e:
            if attempt == 3 or a.passphrase_fd is not None:
                print(f"hive-mind: could not unlock the owner key ({e})", file=sys.stderr)
                return 1
            print("Wrong passphrase, try again.", file=sys.stderr)
    pub = base64.b64encode(lib._sigseam.from_seed(seed).public_key()).decode()
    gov = lib._governance_state(merkle.read_all_entries(lib.JOURNAL_DIR))
    if gov.get("owner_pub") != pub:
        print("hive-mind: this key is not the hive's governance owner; not unlocking.", file=sys.stderr)
        return 1
    proc = spawn(seed, path, idle, pub, a.module)
    for _ in range(100):
        try:
            client.status()
            break
        except AgentError:
            if proc.poll() is not None:
                print("hive-mind: the agent did not start", file=sys.stderr)
                return 1
            time.sleep(0.1)
    else:
        print("hive-mind: the agent did not start", file=sys.stderr)
        return 1
    print(f"unlocked: idle expiry {a.idle}, hard cap 12h (agent pid {proc.pid}); `hive-mind owner lock` to end it")
    return 0


def cmd_lock(lib, argv, out=print):
    try:
        Client(socket_path(lib.HIVE_HOME)).lock()
    except AgentError:
        print("not unlocked")
        return 0
    print("locked: the agent has exited and its seed page is cleared")
    return 0


def cmd_status(lib, argv, out=print):
    try:
        st = Client(socket_path(lib.HIVE_HOME)).status()
    except AgentError:
        print("locked (no agent)")
        return 0
    print(f"unlocked: public key {st['public_key']}")
    print(f"  idle expiry in {st['idle_left']}s (of {int(st['idle'])}s), hard cap in {st['hard_left']}s")
    print(f"  modules named: {', '.join(st['modules']) or '(none)'}; devices admitted this session: "
          f"{', '.join(st['admitted']) or '(none)'}")
    print(f"  signed {st['signed']} act(s), {st['budget_left']} left")
    if not st["mlocked"]:
        print("  seed page not locked in memory (mlock failed): swap may hold it; use encrypted swap")
    for r in st["ring"][-20:]:
        print(f"  {_clock(r['t'])} pid {r['pid']} {r['exe']} {r['op']} {r['act']} {'ok' if r['ok'] else 'REFUSED: ' + r['why']}")
    return 0


COMMANDS = {"unlock": cmd_unlock, "lock": cmd_lock, "status": cmd_status}


# ---- the agent process --------------------------------------------------------------------------------------------

def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _harden():
    """Best effort: no core dump, not dumpable (stops same-uid /proc/pid/mem and unprivileged ptrace)."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    try:
        if sys.platform.startswith("linux"):
            _libc().prctl(4, 0, 0, 0, 0)                  # PR_SET_DUMPABLE
        elif sys.platform == "darwin":
            _libc().ptrace(31, 0, 0, 0)                   # PT_DENY_ATTACH
    except Exception:
        pass


def _read_seed(fd=0):
    got = bytearray()
    while len(got) < 32:
        chunk = os.read(fd, 32 - len(got))
        if not chunk:
            break
        got += chunk
    return got


def _agent_main(argv):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--for", dest="idle", type=float, required=True)
    ap.add_argument("--owner-pub", required=True)
    ap.add_argument("--module", action="append", default=[])
    a = ap.parse_args(argv)
    seed = _read_seed(0)
    os.close(0)
    if len(seed) != 32 or _ed25519 is None:
        return 2
    os.setsid()
    os.chdir("/")
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    os.closerange(3, 4096)
    _harden()
    buf = mmap.mmap(-1, mmap.PAGESIZE)
    buf[:32] = bytes(seed)
    for i in range(len(seed)):
        seed[i] = 0
    mlocked = False
    try:
        mlocked = _libc().mlock(ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(buf))), mmap.PAGESIZE) == 0
    except Exception:
        pass
    lib_holder = []

    def lib():
        if not lib_holder:
            import importlib.machinery
            import importlib.util
            root = os.path.dirname(os.path.abspath(__file__))
            loader = importlib.machinery.SourceFileLoader("hvlib_agent", os.path.join(root, "hv"))
            mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("hvlib_agent", loader))
            loader.exec_module(mod)
            lib_holder.append(mod)
        return lib_holder[0]

    def probe(device_id):
        try:
            h = lib()
            gov = h._governance_state(merkle.read_all_entries(h.JOURNAL_DIR))
        except Exception:
            return None
        if device_id in gov["purged"]:
            return "purged"
        return "admitted" if device_id in gov["admitted"] else "other"

    def installed(module):
        try:
            h = lib()
            data = json.loads((h.HIVE_HOME / ".modules.json").read_text())
            return isinstance(data, dict) and isinstance(data.get(module), dict)
        except Exception:
            return False

    agent = Agent(bytes(buf[:32]), a.socket, a.idle, Policy(a.owner_pub, a.module, probe, installed), mlocked=mlocked)
    agent.buf = buf
    agent.bind()
    signal.signal(signal.SIGTERM, lambda *_: agent.do_lock("terminated"))
    agent.run()
    os._exit(0)                                           # exit, not zeroing, is the guarantee for what CPython can't reach


def spawn(seed, sock_path, idle, owner_pub_b64, modules):
    """Start the agent process with the seed on an anonymous pipe (stdin). argv and env carry nothing secret."""
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    env = {k: v for k, v in os.environ.items() if k not in ("HIVE_OWNER_KEY_PASSPHRASE", "HIVE_OWNER_PASSPHRASE")}
    argv = [sys.executable, "-I", os.path.join(here, "owner_agent.py"), "--socket", sock_path,
            "--for", str(idle), "--owner-pub", owner_pub_b64]
    for m in modules:
        argv += ["--module", m]
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         close_fds=True, env=env, cwd="/")
    try:
        p.stdin.write(bytes(seed))
        p.stdin.close()
    except OSError:
        pass
    return p


if __name__ == "__main__":
    sys.exit(_agent_main(sys.argv[1:]) or 0)
