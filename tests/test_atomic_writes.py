"""SECREV C SN-13 / CK-4: .peers.json and the device key are written temp + fsync + os.replace, so a crash
between write and rename leaves the old file intact; the key is 0600 from creation, whatever the umask."""

import os
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

import sync_common

if os.name == "nt":
    pytest.skip("POSIX file modes only", allow_module_level=True)


def _crash(monkeypatch):
    def boom(src, dst):
        raise OSError("simulated crash before rename")
    monkeypatch.setattr(os, "replace", boom)


def test_peers_write_crash_keeps_old_file(tmp_path, monkeypatch):
    p = tmp_path / ".peers.json"
    p.write_text('{"peers": []}')
    _crash(monkeypatch)
    with pytest.raises(OSError):
        sync_common.atomic_write_text(p, '{"peers": [{"url": "x"}]}')
    assert p.read_text() == '{"peers": []}'
    assert [q.name for q in tmp_path.iterdir()] == [".peers.json"]      # temp cleaned up


def test_peers_write_replaces_and_keeps_mode(tmp_path):
    p = tmp_path / ".peers.json"
    p.write_text("old")
    os.chmod(p, 0o640)
    sync_common.atomic_write_text(p, "new")
    assert p.read_text() == "new" and (p.stat().st_mode & 0o777) == 0o640


def _write_private():
    import importlib.machinery, importlib.util
    loader = importlib.machinery.SourceFileLoader("hv_atomic_probe", str(PROJECT / "hv"))
    spec = importlib.util.spec_from_loader("hv_atomic_probe", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


@pytest.fixture
def hv(tmp_path, monkeypatch):
    monkeypatch.setenv("HIVE_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("HIVE_KEY_DIR", str(tmp_path / "keys"))
    (tmp_path / "home").mkdir()
    return _write_private()


@pytest.mark.parametrize("umask", [0o000, 0o022])
def test_key_created_0600_from_the_start(hv, tmp_path, monkeypatch, umask):
    old = os.umask(umask)
    modes = []
    real_replace = os.replace
    def spy(src, dst):
        modes.append(os.stat(src).st_mode & 0o777)       # mode at the moment before it becomes the key
        return real_replace(src, dst)
    monkeypatch.setattr(os, "replace", spy)
    try:
        path = Path(hv.KEY_DIR) / "device-key"
        hv._write_private(path, "seed\n")
    finally:
        os.umask(old)
    assert modes == [0o600] and (path.stat().st_mode & 0o777) == 0o600


def test_key_write_crash_keeps_old_key(hv, monkeypatch):
    path = Path(hv.KEY_DIR) / "device-key"
    hv._write_private(path, "OLD\n")
    _crash(monkeypatch)
    with pytest.raises(OSError):
        hv._write_private(path, "NEW\n")
    assert path.read_text() == "OLD\n" and (path.stat().st_mode & 0o777) == 0o600
    assert [q.name for q in path.parent.iterdir()] == ["device-key"]
