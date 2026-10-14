"""Owner approval slice A3: boot unlock from the OS keystore, only with --gated (design: hive-mind-private
docs/design/owner_approval_and_hygiene.md sections 3 and 6, row A3).

No real keystore is reachable from CI. Every call to PowerShell interop, secret-tool and security goes through the one
boundary `keystore.run_default`; these tests replace it with a fake that behaves like each tool (DPAPI is a keyed XOR
here, only so the blob is not the plaintext). NOT tested here, because it needs the machine: real DPAPI through
powershell.exe on DESKTOP-EGMBL5A, WSL interop inside a systemd user unit at boot, a real Secret Service, a real keychain."""

import base64
import importlib.machinery
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
import keystore  # noqa: E402
import owner_agent  # noqa: E402
from test_owner_agent import PASS, SEED, LINUX, FakeClocks, hive, policy, _sock  # noqa: E402,F401
from test_owner_approval_a1 import PHONE, RP, add_flags, run_ctl  # noqa: E402,F401


class FakeInterop:
    """powershell.exe (DPAPI), secret-tool and security, as `run(argv, data) -> (rc, out)`. Keeps every argv it saw."""

    def __init__(self):
        self.calls, self.secrets = [], {}

    def __call__(self, argv, data, timeout=30):
        self.calls.append((list(argv), data))
        exe = os.path.basename(argv[0])
        if exe == "powershell.exe":
            script = base64.b64decode(argv[-1]).decode("utf-16-le")
            raw = base64.b64decode(data.strip())
            key = b"dpapi-user-key"
            xor = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
            if ".Protect(" in script or "::Protect" in script:
                return 0, base64.b64encode(b"BLOB" + xor)
            blob = raw
            if not blob.startswith(b"BLOB"):
                return 1, b""
            return 0, base64.b64encode(bytes(b ^ key[i % len(key)] for i, b in enumerate(blob[4:])))
        if exe == "secret-tool":
            attrs = tuple(argv[argv.index("service"):]) if "service" in argv else ()
            if argv[1] == "store":
                self.secrets[attrs] = data
                return 0, b""
            if argv[1] == "lookup":
                return (0, self.secrets[attrs]) if attrs in self.secrets else (1, b"")
            if argv[1] == "clear":
                self.secrets.pop(attrs, None)
                return 0, b""
        if exe == "security":
            if argv[1] == "-i":
                parts = data.decode().split()
                svc, acct, hexpw = parts[parts.index("-s") + 1], parts[parts.index("-a") + 1], parts[parts.index("-X") + 1]
                self.secrets[(svc, acct)] = bytes.fromhex(hexpw)
                return 0, b""
            if argv[1] == "find-generic-password":
                k = (argv[argv.index("-s") + 1], argv[argv.index("-a") + 1])
                return (0, self.secrets[k] + b"\n") if k in self.secrets else (44, b"")
            if argv[1] == "delete-generic-password":
                self.secrets.pop((argv[argv.index("-s") + 1], argv[argv.index("-a") + 1]), None)
                return 0, b""
        return 127, b""


@pytest.fixture
def interop(monkeypatch):
    f = FakeInterop()
    monkeypatch.setattr(keystore, "run_default", f)
    monkeypatch.setattr(keystore, "available", lambda source: (True, ""))
    return f


@pytest.mark.parametrize("source", keystore.SOURCES)
def test_each_source_round_trips_and_the_secret_never_reaches_an_argv(tmp_path, interop, source):
    keystore.store(source, "correct horse battery", tmp_path, tmp_path / "home", now=7)
    assert keystore.fetch(source, tmp_path, tmp_path / "home") == "correct horse battery"
    assert keystore.read_record(tmp_path)["source"] == source and "horse" not in (tmp_path / keystore.RECORD).read_text()
    for argv, _ in interop.calls:
        assert not any("horse" in w for w in argv) and not any(base64.b64encode(b"correct horse battery").decode() in w for w in argv)
    assert source in keystore.describe(tmp_path) and "gated" in keystore.describe(tmp_path)
    assert keystore.clear(tmp_path, tmp_path / "home") == source
    assert keystore.read_record(tmp_path) is None and keystore.describe(tmp_path) is None
    with pytest.raises(keystore.KeystoreError):
        keystore.fetch(source, tmp_path, tmp_path / "home")


def test_dpapi_keeps_only_ciphertext_in_a_0600_file_and_uses_current_user_scope(tmp_path, interop):
    keystore.store("dpapi", "s3cret-pass", tmp_path, tmp_path)
    blob = tmp_path / keystore.BLOB
    assert stat.S_IMODE(blob.stat().st_mode) == 0o600 and stat.S_IMODE((tmp_path / keystore.RECORD).stat().st_mode) == 0o600
    assert b"s3cret-pass" not in base64.b64decode(blob.read_bytes()) and b"s3cret-pass" not in blob.read_bytes()
    script = base64.b64decode(interop.calls[0][0][-1]).decode("utf-16-le")
    assert "DataProtectionScope]::CurrentUser" in script and keystore.ENTROPY in script
    assert interop.calls[0][0][0] == keystore.POWERSHELL                        # a fixed path, not a PATH search


def test_a_failing_interop_is_an_error_without_the_secret(tmp_path, monkeypatch):
    monkeypatch.setattr(keystore, "available", lambda s: (True, ""))
    monkeypatch.setattr(keystore, "run_default", lambda argv, data, timeout=30: (1, b""))
    for src in keystore.SOURCES:
        with pytest.raises(keystore.KeystoreError) as e:
            keystore.store(src, "topsecret", tmp_path, tmp_path)
        assert "topsecret" not in str(e.value)
    assert keystore.read_record(tmp_path) is None                                # a failed store leaves no record


@pytest.mark.parametrize("bad", ["", "a\nb", "a\0b"])
def test_an_unstorable_passphrase_is_refused(tmp_path, interop, bad):
    with pytest.raises(keystore.KeystoreError):
        keystore.store("libsecret", bad, tmp_path, tmp_path)


def test_one_hive_home_per_entry(tmp_path, interop):
    keystore.store("libsecret", "one", tmp_path, tmp_path / "a")
    keystore.store("libsecret", "two", tmp_path, tmp_path / "b")
    assert keystore.fetch("libsecret", tmp_path, tmp_path / "a") == "one"
    assert keystore.fetch("libsecret", tmp_path, tmp_path / "b") == "two"


def test_availability_names_why(monkeypatch):
    monkeypatch.setattr(keystore, "is_wsl", lambda: False)
    ok, why = keystore.available("dpapi")
    assert not ok and "WSL" in why
    assert keystore.available("nope")[0] is False


def test_the_agent_itself_refuses_a_keystore_seed_without_the_gate():
    with pytest.raises(ValueError, match="gated"):
        owner_agent.Agent(SEED, "/nonexistent/x.sock", 900, policy(), clocks=FakeClocks(), keystore="dpapi")
    a = owner_agent.Agent(SEED, "/nonexistent/x.sock", 900, policy(), clocks=FakeClocks())
    assert a.status()["keystore"] is None
    assert owner_agent._agent_main(["--socket", "/x", "--for", "9", "--owner-pub", "x", "--keystore", "dpapi"]) == 2


def _lib(h):
    loader = importlib.machinery.SourceFileLoader("hvlib_a3", str(PROJECT / "hv"))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("hvlib_a3", loader))
    loader.exec_module(mod)
    import hivemind_ctl
    return hivemind_ctl.install(mod)


@LINUX
def test_unlock_with_a_keystore_source_needs_gated(hive, interop, capsys):
    lib = _lib(hive)
    assert owner_agent.cmd_unlock(lib, ["--passphrase-source", "dpapi"]) == 2
    assert "needs --gated" in capsys.readouterr().err
    assert owner_agent.cmd_unlock(lib, ["--gated", "--rp-id", RP, "--passphrase-source", "dpapi", "--passphrase-fd", "0"]) == 2
    assert "exclusive" in capsys.readouterr().err


@LINUX
def test_boot_unlock_end_to_end_through_the_fake_keystore(hive, interop, capsys):
    run_ctl(hive, *add_flags(PHONE), "--break-glass", passphrase_fd=PASS)
    lib = _lib(hive)
    assert owner_agent.cmd_unlock(lib, ["--gated", "--rp-id", RP, "--passphrase-source", "dpapi"]) == 1
    assert "nothing is stored there" in capsys.readouterr().err                     # nothing stored yet
    rfd, wfd = os.pipe()
    os.write(wfd, (PASS + "\n").encode())
    os.close(wfd)
    assert owner_agent.cmd_keystore(lib, ["store", "--source", "dpapi", "--passphrase-fd", str(rfd)]) == 0
    os.close(rfd)
    rfd, wfd = os.pipe()
    os.write(wfd, b"wrong\n")
    os.close(wfd)
    assert owner_agent.cmd_keystore(lib, ["store", "--source", "libsecret", "--passphrase-fd", str(rfd)]) == 1
    os.close(rfd)
    assert "does not open" in capsys.readouterr().err and keystore.read_record(lib._ensure_key_dir())["source"] == "dpapi"
    capsys.readouterr()
    try:
        assert owner_agent.cmd_unlock(lib, ["--gated", "--rp-id", RP, "--passphrase-source", "dpapi"]) == 0
        st = owner_agent.Client(_sock(hive)).status()
        assert st["gated"] and st["keystore"] == "dpapi"
        capsys.readouterr()
        owner_agent.cmd_status(lib, [])
        out = capsys.readouterr().out
        assert "unlocked from dpapi" in out and "stored for boot unlock" in out
        # the gate still holds: the unlocked agent signs nothing for a caller with no ticket and no delegation
        r = owner_agent.Client(_sock(hive)).request({"op": "sign", "body": base64.b64encode(b"{}").decode()})
        assert not r.get("ok")
    finally:
        run_ctl(hive, "owner", "lock", check=False)
    # a stale stored passphrase fails closed, with no retry loop and no prompt
    keystore.store("dpapi", "stale-passphrase", lib._ensure_key_dir(), lib.HIVE_HOME)
    assert owner_agent.cmd_unlock(lib, ["--gated", "--rp-id", RP, "--passphrase-source", "dpapi"]) == 1
    assert "stale" in capsys.readouterr().err
    assert owner_agent.cmd_keystore(lib, ["clear"]) == 0 and keystore.read_record(lib._ensure_key_dir()) is None


@LINUX
def test_status_when_locked_names_the_keystore(hive, interop, capsys):
    lib = _lib(hive)
    owner_agent.cmd_status(lib, [])
    assert "keystore" not in capsys.readouterr().out
    keystore.store("libsecret", "x", lib._ensure_key_dir(), lib.HIVE_HOME)
    owner_agent.cmd_status(lib, [])
    out = capsys.readouterr().out
    assert "locked (no agent)" in out and "keystore: libsecret" in out


def test_the_unit_is_a_oneshot_that_stays_up_and_holds_nothing_secret(tmp_path):
    text = owner_agent.render_unit("/opt/hive/hivemind_ctl.py", "dpapi", "owner.ts.net", 8444, 1, False, "/home/u/.hive")
    assert "Type=oneshot" in text and "RemainAfterExit=yes" in text and "WantedBy=default.target" in text
    assert '"--gated"' in text and '"--passphrase-source" "dpapi"' in text and '"owner" "lock"' in text
    assert 'Environment="HIVE_HOME=/home/u/.hive"' in text and "allow-synced" not in text
    assert '"--rp-id" "owner.ts.net"' in text
    assert "--allow-synced" in owner_agent.render_unit("/c", "libsecret", "h", 1, 2, True, "/h")


@LINUX
def test_boot_unit_install_remove(hive, interop, monkeypatch, tmp_path, capsys):
    lib = _lib(hive)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    ran = []
    monkeypatch.setattr(owner_agent, "_sh", lambda argv: (ran.append(argv), (0, ""))[1])
    assert owner_agent.cmd_boot_unit(lib, ["install", "--rp-id", RP]) == 1                  # nothing stored
    keystore.store("dpapi", "x", lib._ensure_key_dir(), lib.HIVE_HOME)
    assert owner_agent.cmd_boot_unit(lib, ["install"]) == 2                                  # --rp-id is required
    assert owner_agent.cmd_boot_unit(lib, ["install", "--rp-id", "bad host"]) == 2
    assert owner_agent.cmd_boot_unit(lib, ["install", "--rp-id", RP]) == 0
    unit = Path(owner_agent.unit_path())
    assert unit.is_file() and "--passphrase-source" in unit.read_text()
    assert ["systemctl", "--user", "enable", owner_agent.UNIT_NAME] in ran
    assert any(a[:2] == ["loginctl", "enable-linger"] for a in ran)
    capsys.readouterr()
    owner_agent.cmd_status(lib, [])
    assert "boot unlock: the user unit is installed" in capsys.readouterr().out
    assert owner_agent.cmd_boot_unit(lib, ["remove"]) == 0 and not unit.exists()
    monkeypatch.setattr(owner_agent, "_sh", lambda argv: (127, ""))
    assert owner_agent.cmd_boot_unit(lib, ["install", "--rp-id", RP]) == 1                  # no user systemd


@LINUX
def test_doctor_names_the_keystore(hive, interop):
    lib = _lib(hive)
    row = lambda: [c for c in lib._doctor_status() if c["name"] == "owner-keystore"][0]
    assert row()["status"] == "ok" and "no OS keystore" in row()["detail"]
    keystore.store("dpapi", "x", lib._ensure_key_dir(), lib.HIVE_HOME)
    assert row()["status"] == "ok" and "dpapi" in row()["detail"] and "trust: full" in row()["detail"]
    os.unlink(Path(lib._ensure_key_dir()) / keystore.BLOB)
    assert row()["status"] == "warn" and "blob is missing" in row()["detail"]
