from hivemind.crypto import signer as _sigseam   # the signing seam: every device signature is made through it
HIVE_HOME = Path(os.environ.get("HIVE_HOME", Path.home() / "projects" / "hive-mind"))
DB_PATH = HIVE_HOME / "store.db"
JOURNAL_DIR = HIVE_HOME / "journal"
# Private keys live OUTSIDE the working tree (2.0 PR 3a, private #27). HIVE_HOME is the git checkout,
# the directory every agent CLI runs in and some index; keyperm's 0600 does not stop a tool running as
# the same user from reading a seed that sits in it. So the seeds live in a KEY DIRECTORY (0700):
# $HIVE_KEY_DIR if set, else the path recorded in $HIVE_HOME/.key-dir, else a default derived from this
# checkout's path. The pointer is written when a key is first written there, so renaming the checkout
# keeps its keys, and the default needs no hive_id (a device key exists before any hive does). Importing
# hv never creates the directory. Keys still at the legacy root paths keep working, with a keyperm
# advisory; `hv doctor --fix` relocates the device key and `hive-mind doctor --fix` the owner key.
KEY_DIR_POINTER = HIVE_HOME / ".key-dir"


def _default_key_dir():
    return (Path.home() / ".hive" / "keys"
            / hashlib.sha256(str(HIVE_HOME.resolve()).encode()).hexdigest()[:16])


def _resolve_key_dir():
    env = os.environ.get("HIVE_KEY_DIR")
    if env:
        return Path(env).expanduser()
    try:
        if KEY_DIR_POINTER.exists():
            recorded = KEY_DIR_POINTER.read_text().strip()
            if recorded:
                return Path(recorded)
    except OSError:
        pass
    return _default_key_dir()


def _effective_key_path(name, legacy):
    """The key dir's `name`, unless only the legacy file in the working tree exists (then that one)."""
    new = KEY_DIR / name
    try:
        if not new.exists() and legacy.exists():
            return legacy
    except OSError:
        pass
    return new


KEY_DIR = _resolve_key_dir()
LEGACY_DEVICE_KEY_PATH = HIVE_HOME / ".device-key"
LEGACY_OWNER_KEY_PATH = HIVE_HOME / ".owner-key"
LEGACY_OWNER_PUB_PATH = HIVE_HOME / ".owner-pub"


def _ensure_key_dir():
    """Create the key directory (0700, and ~/.hive and ~/.hive/keys when this creates them) and record it
    in $HIVE_HOME/.key-dir. Called before any key is written; never at import. Returns the directory."""
    d = KEY_DIR
    for p in reversed([d, *d.parents]):
        if p.exists():
            continue
        p.mkdir(exist_ok=True)
        try:
            if p == d or p.name in (".hive", "keys"):
                os.chmod(p, 0o700)
        except OSError:
            pass
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    try:
        if not KEY_DIR_POINTER.exists() or KEY_DIR_POINTER.read_text().strip() != str(d):
            HIVE_HOME.mkdir(parents=True, exist_ok=True)
            KEY_DIR_POINTER.write_text(str(d) + "\n")
    except OSError:
        pass
    return d


def _write_private(path, text):
    """Write a private file (0600) into the key directory, creating it first."""
    _ensure_key_dir()
    # Temp file + fsync + os.replace in the same directory (SECREV C CK-4): a crash leaves the old key or the
    # new one, never a torn file. The temp is created 0600 by os.open itself, so the seed is never on disk
    # at a wider mode, whatever the umask; no chmod after.
    path = Path(os.path.realpath(path))
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


# Device identity (Phase D-identity). A node is identified by an Ed25519 DEVICE KEY, not a
# self-declared hostname. device_id = "k1:" + first 16 hex of sha256(pubkey); the 32-byte seed
# lives in the key directory as `device-key` (0600, never synced, never in the source manifest), and
# the derived fingerprint (public) is cached at HIVE_HOME/.device-id so resolving NODE_ID stays cheap.
# Journal entries are signed by the device key and verified on ingest, so a peer cannot forge
# another node's identity to launder corroboration. A key is minted only by `hv config identity init` or the
# migration — importing hv NEVER creates one, so a legacy hostname node keeps its identity until
# it is deliberately migrated. HIVE_NODE_ID still overrides (tests / two instances on one box).
DEVICE_KEY_PATH = _effective_key_path("device-key", LEGACY_DEVICE_KEY_PATH)
DEVICE_ID_PATH = HIVE_HOME / ".device-id"


def _device_seed():
    """The 32-byte device seed if this device has a key, else None. Read-only; never creates."""
    try:
        if _ed25519 is None or not DEVICE_KEY_PATH.exists():
            return None
        seed = base64.b64decode(DEVICE_KEY_PATH.read_text().strip())
        return seed if len(seed) == 32 else None
    except Exception:
        return None


def _device_signer():
    """This device's signer (key-file backend), or None when it has no key. Every device signature is made
    through it: callers hold `sign(bytes)`, never the seed."""
    return _sigseam.from_seed(_device_seed())


def _device_id_for_pub(pub):
    """Stable, collision-safe device fingerprint: 'k1:' + first 16 hex of sha256(pubkey)."""
    return "k1:" + hashlib.sha256(pub).hexdigest()[:16]


def _resolve_node_id():
    """HIVE_NODE_ID override, else the cached device fingerprint (or one derived from the seed),
    else the hostname (legacy, pre-migration)."""
    env = os.environ.get("HIVE_NODE_ID")
    if env:
        return env
    try:
        if DEVICE_ID_PATH.exists():
            did = DEVICE_ID_PATH.read_text().strip()
            if did:
                return did
    except Exception:
        pass
    seed = _device_seed()
    if seed is not None:
        return _device_id_for_pub(_ed25519.pub_from_seed(seed))
    return socket.gethostname()


# Hostnames that are NOT unique enough to be a node label on their own. Containers, fresh WSL2
# installs, and minimal images routinely report one of these, so two unrelated boxes would both
# show up as "linux" in the hive (the label rides in the join-request an owner approves).
_GENERIC_HOSTNAMES = {
    "", "linux", "localhost", "localhost.localdomain",
    "ubuntu", "debian", "kali", "raspberrypi", "archlinux",
}


def _machine_suffix():
    """A short, stable per-machine suffix for disambiguating a generic hostname. Prefers the device
    fingerprint (already collision-safe), else /etc/machine-id; returns None if neither is available."""
    did = None
    try:
        if DEVICE_ID_PATH.exists():
            did = DEVICE_ID_PATH.read_text().strip()
    except Exception:
        did = None
    if not did:
        seed = _device_seed()
        if seed is not None and _ed25519 is not None:
            did = _device_id_for_pub(_ed25519.pub_from_seed(seed))
    if did:
        return did.split(":")[-1][:6]            # last 6 hex of the fingerprint
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            mid = Path(p).read_text().strip()
            if mid:
                return mid[:6]
        except Exception:
            continue
    return None


def _human_label():
    """Human-readable node label. HIVE_NODE_LABEL wins; otherwise the hostname — but a GENERIC
    hostname (linux/localhost/blank, common on containers/WSL) is suffixed with a short stable
    per-machine id so two such nodes don't both surface as 'linux' in the hive."""
    env = os.environ.get("HIVE_NODE_LABEL")
    if env:
        return env
    host = (socket.gethostname() or "").strip()
    if host.lower() in _GENERIC_HOSTNAMES:
        suf = _machine_suffix()
        base = host or "node"
        return f"{base}-{suf}" if suf else base
    return host


NODE_ID = _resolve_node_id()
NODE_LABEL = _human_label()


# Owner identity (governance root). A separate Ed25519 key, distinct from the device key, is the
# root of trust for governance: it admits devices, tags their principal, and sets tunable confidence
# parameters. Those declarations are JOURNALED as owner-signed `governance` entries, so every node
# derives the same admitted set / principal map / config and confidence stays identical across nodes
# (the convergence invariant). Minted only by `hv owner init`; importing hv never creates it.
OWNER_KEY_PATH = _effective_key_path("owner-key", LEGACY_OWNER_KEY_PATH)
# The owner key's PUBLIC half, written by the control plane whenever it reads or writes the key (2.0 PR 2b).
# `hv` reads this, never the seed, to tell whether this device holds the established owner's key.
OWNER_PUB_PATH = _effective_key_path("owner-pub", LEGACY_OWNER_PUB_PATH)
# The owner key SEALED at rest (2.0 PR 3b, private #27): the passphrase envelope `owner escrow` already
# writes (scrypt, then ChaCha20-Poly1305), in the key directory only. Every new owner key is written sealed
# and the control plane unlocks it once per `hive-mind` command. A plaintext OWNER_KEY_PATH still works,
# and doctor fails until `hive-mind owner seal` converts it. The distinct name is what lets `hv` tell the
# two forms apart from `stat` alone, without opening either.
OWNER_SEALED_PATH = KEY_DIR / "owner-key.sealed"
# Genesis pin (hive-mind-private #14). Genesis used to be "the earliest valid self-signed `owner`
# act wins", and an entry's timestamp is written by whoever made the entry — so a rival `owner` act
# carrying an EARLIER timestamp TOOK the hive, before or after genesis, and silenced the real owner's
# later acts (only the current owner's acts are honoured). This file records the one `owner` act this
# node accepted and is the authority for both ingest and the projection. It is written only by a
# deliberate act (`owner init`, a join carrying the genesis fingerprint, or `hv owner pin` after a
# trust-on-first-use pull). Per-node data like the device key: 0600, never synced, never journaled,
# never in the signed source manifest. A node with no pin keeps the legacy rule so a mixed fleet still
# converges, and `hv doctor genesis` fails until the operator pins.
GENESIS_PIN_PATH = HIVE_HOME / ".genesis-pin"



_OWNER_KEY_SIZES = {44, 45}         # base64 of a 32-byte seed, with or without the trailing newline
_OWNER_SEALED_SIZES = range(128, 4097)   # the sealed envelope: about 240 bytes of JSON


class NotOnDataPlane(Exception):
    """Raised by a data-plane placeholder for an owner step (2.0 S2, public #136): the key boundary. `hv`
    cannot owner-sign, so the step refuses and acts on nothing. On the control plane
    `hivemind_ctl.install` replaces every placeholder with the real owner step, so it is never raised there.

    `key` is a `commandmap.FLAG_CONDITIONAL` key when a hive policy (`capsule_putters`, `cell_writers`)
    needs an owner-signed write, which `dispatch` explains; otherwise it only labels the refused step."""

    def __init__(self, key):
        super().__init__(key)
        self.key = key


def _owner_key_state(gov=None):
    """Whether THIS device holds the owner key, answered WITHOUT reading the seed (2.0 S2): one of
    'absent', 'unknown', 'present' or 'held'.

    - 'absent': no key file, sealed or plaintext.
    - 'unknown': the key's location cannot be examined (permission denied, e.g. a key directory the
      agent user cannot search). A two-state check would report "not held" here as a fact, which is a lie.
    - 'present': a key file exists but its public half is not recorded (`OWNER_PUB_PATH`), or `gov` has
      no owner to compare with, so `hv` cannot say whose key it is.
    - 'held': a key file exists and its recorded public half is the established owner's.

    The comparison reads only the public sidecar, which the control plane writes whenever it touches the
    key. A stale or forged sidecar misleads a display, never authority: authority is a signature `hv`
    cannot produce."""
    st = sizes = None
    for path, sizes in ((OWNER_SEALED_PATH, _OWNER_SEALED_SIZES), (OWNER_KEY_PATH, _OWNER_KEY_SIZES)):
        try:
            st = path.stat()
        except FileNotFoundError:
            continue
        except OSError:
            return "unknown"
        break
    if st is None:
        return "absent"
    # A plaintext seed is base64 of 32 bytes: 44 characters, 45 with the newline every writer adds; a
    # sealed one is a JSON envelope of a few hundred bytes (2.0 PR 3b). Anything else in the key's place
    # (a directory, an empty or truncated file) is not a key `hv` can vouch for, whatever the sidecar says.
    # Garbage of the right length still passes: that is the irreducible cost of never reading the file
    # (#159 review).
    if not stat.S_ISREG(st.st_mode) or st.st_size not in sizes:
        return "present"
    try:
        owner_id = (gov or {}).get("owner_id")
        if not owner_id or not OWNER_PUB_PATH.exists():
            return "present"
        pub = base64.b64decode(OWNER_PUB_PATH.read_text().strip())
        return "held" if len(pub) == 32 and _owner_id_for_pub(pub) == owner_id else "present"
    except Exception:
        return "present"


def _owner_key_form():
    """Which form of the owner key this device keeps, from the file names alone (2.0 PR 3b): 'plaintext',
    'sealed' or None. A sealed key with a plaintext one beside it is 'plaintext', since the seed is then
    readable either way. Never opens a key file."""
    def _is_file(p):
        try:
            return p.is_file()
        except OSError:
            return False
    if _is_file(OWNER_KEY_PATH) or _is_file(LEGACY_OWNER_KEY_PATH) or _is_file(KEY_DIR / "owner-key"):
        return "plaintext"
    return "sealed" if _is_file(OWNER_SEALED_PATH) else None


def _owner_id_for_pub(pub):
    """Owner fingerprint: 'o1:' + first 16 hex of sha256(pubkey)."""
    return "o1:" + hashlib.sha256(pub).hexdigest()[:16]


def _canon_pub(b64):
    """Canonical base64 of a 32-byte ed25519 public key, or None if it isn't one. Used so a
    nomination's `successor_owner_pub` and a claim's embedded `owner_pub` compare as strings
    regardless of base64 whitespace/padding differences."""
    try:
        raw = base64.b64decode(b64)
        if len(raw) != 32 or (_ed25519 is not None and _ed25519.is_small_order(raw)):
            return None                  # CK-7: a small-order key verifies messages nobody signed
        return base64.b64encode(raw).decode()
    except Exception:
        return None


def _hkdf_sha256(ikm, salt, info, n):
    """HKDF-SHA256 (RFC 5869) → n bytes. Derives INDEPENDENT enc/MAC subkeys from a CEK or an X25519
    shared secret, so one raw key never directly keys both the cipher and the MAC (key separation)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()           # extract
    out, t, i = b"", b"", 0                                        # expand
    while len(out) < n:
        i += 1
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
    return out[:n]


_OWNER_SEAL_ALG = "scrypt-chacha20poly1305-v2"


def _owner_seal(seed, passphrase):
    """Encrypt the 32-byte owner seed under a passphrase: scrypt (memory-hard) derives a key, then ONE
    ChaCha20-Poly1305 (RFC 8439) seal. The scrypt params n/r/p are bound as the AEAD AAD, so tampering
    with the stored cost parameters is detected (not just self-healed by a derived-key mismatch).
    Returns the envelope. (v2 — replaced the hand-rolled SHA-256-CTR+HMAC v1.)"""
    if _chacha is None:
        raise RuntimeError("chacha20poly1305 module unavailable")
    salt = os.urandom(16)
    n, r, p = 1 << 16, 8, 1                                   # 64 MiB — within the 128 MiB maxmem ceiling
    key = hashlib.scrypt(passphrase.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * 1024 * 1024)
    nonce = os.urandom(12)
    aad = f"{_OWNER_SEAL_ALG}|{n}|{r}|{p}".encode()
    ct, tag = _chacha.encrypt(key, nonce, seed, aad)
    return {"enc": _OWNER_SEAL_ALG, "n": n, "r": r, "p": p,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ct": base64.b64encode(ct).decode(),
            "tag": base64.b64encode(tag).decode()}


def _owner_unseal(env, passphrase):
    """Decrypt an owner-seed envelope (v2 only — the hand-rolled v1 scheme is gone). ChaCha20-Poly1305
    authenticates before releasing the seed. Raises ValueError on a wrong passphrase / tampering, or on
    a legacy/unknown `enc` scheme (re-mint with `hive-mind owner escrow`)."""
    if _chacha is None:
        raise RuntimeError("chacha20poly1305 module unavailable")
    if env.get("enc") != _OWNER_SEAL_ALG:
        raise ValueError(f"unsupported owner-seal scheme {env.get('enc')!r} — re-run `hive-mind owner escrow`")
    salt, nonce, ct, tag = (base64.b64decode(env[k]) for k in ("salt", "nonce", "ct", "tag"))
    n, r, p = int(env["n"]), int(env["r"]), int(env["p"])
    key = hashlib.scrypt(passphrase.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * 1024 * 1024)
    aad = f"{_OWNER_SEAL_ALG}|{n}|{r}|{p}".encode()
    try:
        return _chacha.decrypt(key, nonce, ct, tag, aad)
    except ValueError:
        raise ValueError("wrong passphrase or corrupted file")


# `_read_passphrase` and `_stash_owner_key` moved to the control plane with every owner-key write
# (2.0 PR 2b, `hivemind_owner.py`).


