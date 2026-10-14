"""Owner approval slice A3: the owner passphrase in the OS keystore, so a gated agent can unlock at boot.

Design: hive-mind-private docs/design/owner_approval_and_hygiene.md sections 3 and 6 (row A3). Three sources:

  dpapi      Windows DPAPI (CurrentUser scope) through `powershell.exe` interop, for the owner node on WSL. The ciphertext
             blob is a 0600 file in the key directory; only the Windows user can unprotect it.
  libsecret  the Secret Service (`secret-tool`).
  keychain   the macOS login keychain (`security`).

Every call to the outside goes through one boundary, `run(argv, data) -> (returncode, stdout)`: tests pass a fake, so no
real keystore is needed. The passphrase travels on a pipe, never in argv or the environment. Executables are fixed
absolute paths (no PATH search). Nothing here opens the sealed owner key: the caller checks a passphrase before it is
stored. Nothing is journaled, signed or synced; the record of which source is in use is a node-local, non-secret file.

The residual (THREAT_MODEL): a stored passphrase is readable by any process of the same user on this node that can ask
the same keystore for it. That is why it is used only with `--gated`."""

import base64
import hashlib
import json
import os
import subprocess

SOURCES = ("dpapi", "libsecret", "keychain")
RECORD = ".owner-keystore.json"        # {"source", "stored"}: no secret
BLOB = ".owner-passphrase.dpapi"       # dpapi only: the DPAPI ciphertext, base64
SERVICE = "hive-mind-owner-passphrase"
ENTROPY = "hive-mind-owner-passphrase-v1"
POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
SECRET_TOOL = ("/usr/bin/secret-tool",)
SECURITY = ("/usr/bin/security",)
MAX_OUT = 4096


REASONS = {"unavailable": "this keystore is not usable on this node (see `hive-mind owner keystore status`)",
           "missing": "nothing is stored there for this hive (run `hive-mind owner keystore store`), or the keystore is locked",
           "failed": "the keystore tool failed",
           "malformed": "the stored value is not ours or is malformed"}


class KeystoreError(Exception):
    """A keystore failure. The message never carries the passphrase or a blob; `code` is a key of REASONS, a fixed text
    a caller can print without echoing anything that came from the keystore."""

    def __init__(self, message, code="failed"):
        super().__init__(message)
        self.code = code


def run_default(argv, data, timeout=30):
    try:
        r = subprocess.run(argv, input=data, capture_output=True, timeout=timeout, cwd="/")
    except (OSError, subprocess.SubprocessError) as e:
        raise KeystoreError(f"{os.path.basename(argv[0])} did not run ({type(e).__name__})")
    return r.returncode, r.stdout[:MAX_OUT]


def _exe(candidates):
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def is_wsl():
    try:
        with open("/proc/sys/kernel/osrelease") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def available(source):
    """Whether this node can use `source`: a bool and, when False, why."""
    if source not in SOURCES:
        return False, f"unknown keystore source {source!r}"
    if source == "dpapi":
        if not is_wsl():
            return False, "dpapi needs WSL (Windows interop); this is not WSL"
        return (True, "") if _exe((POWERSHELL,)) else (False, f"{POWERSHELL} not found (WSL interop disabled?)")
    if source == "libsecret":
        return (True, "") if _exe(SECRET_TOOL) else (False, "secret-tool not found (install libsecret-tools)")
    return (True, "") if _exe(SECURITY) else (False, "/usr/bin/security not found (keychain needs macOS)")


def _account(hive_home):
    """One keystore entry per hive home, so two hives of one user do not share a passphrase."""
    return hashlib.sha256(os.path.realpath(str(hive_home)).encode()).hexdigest()[:16]


_PS_PROTECT = """$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$b=[Convert]::FromBase64String([Console]::In.ReadLine())
$e=[Text.Encoding]::UTF8.GetBytes('%s')
$o=[Security.Cryptography.ProtectedData]::%s($b,$e,[Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Out.Write([Convert]::ToBase64String($o))
"""


def _ps(verb, data, run):
    script = _PS_PROTECT % (ENTROPY, verb)
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    rc, out = run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", enc], data)
    if rc != 0 or not out:
        raise KeystoreError(f"powershell.exe DPAPI {verb.lower()} failed (exit {rc})")
    return out.strip()


def store(source, passphrase, key_dir, hive_home, run=None, now=None):
    """Put `passphrase` (str) in the keystore and write the record. Raises KeystoreError."""
    run = run or run_default
    ok, why = available(source)
    if not ok:
        raise KeystoreError(why, "unavailable")
    if not passphrase or "\n" in passphrase or "\r" in passphrase or "\0" in passphrase:
        raise KeystoreError("the passphrase is empty or has a line break")
    raw = passphrase.encode("utf-8")
    key_dir = str(key_dir)
    if source == "dpapi":
        blob = _ps("Protect", base64.b64encode(raw) + b"\n", run)
        _write_private(os.path.join(key_dir, BLOB), blob.decode("ascii"))
    elif source == "libsecret":
        rc, _ = run([SECRET_TOOL[0], "store", "--label", "hive-mind owner passphrase", "service", SERVICE,
                     "account", _account(hive_home)], raw)
        if rc != 0:
            raise KeystoreError(f"secret-tool store failed (exit {rc}); is a Secret Service running and unlocked?")
    else:
        cmd = f"add-generic-password -U -s {SERVICE} -a {_account(hive_home)} -X {base64.b64encode(raw).hex()}\n"
        rc, _ = run([SECURITY[0], "-i"], cmd.encode())      # stdin, not argv: the passphrase never shows in `ps`
        if rc != 0:
            raise KeystoreError(f"security add-generic-password failed (exit {rc})")
    _write_private(os.path.join(key_dir, RECORD), json.dumps({"source": source, "stored": int(now or 0)}))


def fetch(source, key_dir, hive_home, run=None):
    """The stored passphrase (str). Raises KeystoreError; the message never carries the secret."""
    run = run or run_default
    ok, why = available(source)
    if not ok:
        raise KeystoreError(why, "unavailable")
    if source == "dpapi":
        try:
            with open(os.path.join(str(key_dir), BLOB), "rb") as f:
                blob = f.read(MAX_OUT).strip()
        except OSError:
            raise KeystoreError("no stored passphrase for dpapi: run `hive-mind owner keystore store --source dpapi`", "missing")
        raw = base64.b64decode(_ps("Unprotect", blob + b"\n", run), validate=True)
    elif source == "libsecret":
        rc, out = run([SECRET_TOOL[0], "lookup", "service", SERVICE, "account", _account(hive_home)], b"")
        if rc != 0 or not out:
            raise KeystoreError("no stored passphrase in the Secret Service (or it is locked): "
                                "run `hive-mind owner keystore store --source libsecret`", "missing")
        raw = out
    else:
        rc, out = run([SECURITY[0], "find-generic-password", "-s", SERVICE, "-a", _account(hive_home), "-w"], b"")
        if rc != 0 or not out.strip():
            raise KeystoreError("no stored passphrase in the keychain: run `hive-mind owner keystore store --source keychain`", "missing")
        try:
            raw = base64.b64decode(out.strip(), validate=True)
        except ValueError:
            raise KeystoreError("the keychain entry is not ours", "malformed")
    try:
        pw = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise KeystoreError("the stored passphrase is not text", "malformed")
    if not pw or "\n" in pw:
        raise KeystoreError("the stored passphrase is empty or malformed", "malformed")
    return pw


def clear(key_dir, hive_home, run=None):
    """Remove the stored passphrase and the record. Best effort on the keystore side; returns the source cleared."""
    run = run or run_default
    rec = read_record(key_dir)
    src = rec["source"] if rec else None
    if src == "libsecret":
        run([SECRET_TOOL[0], "clear", "service", SERVICE, "account", _account(hive_home)], b"")
    elif src == "keychain":
        run([SECURITY[0], "delete-generic-password", "-s", SERVICE, "-a", _account(hive_home)], b"")
    for name in (BLOB, RECORD):
        try:
            os.unlink(os.path.join(str(key_dir), name))
        except FileNotFoundError:
            pass
    return src


def read_record(key_dir):
    """The non-secret record, or None. Never raises."""
    try:
        with open(os.path.join(str(key_dir), RECORD)) as f:
            r = json.load(f)
        return r if isinstance(r, dict) and r.get("source") in SOURCES else None
    except (OSError, ValueError):
        return None


def describe(key_dir):
    """One line naming the keystore in use, or None when none is stored. For `owner status` and `doctor`."""
    r = read_record(key_dir)
    return None if r is None else f"{r['source']} (the owner passphrase is stored for boot unlock; gated mode only)"


def _write_private(path, text):
    tmp = f"{path}.tmp{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
