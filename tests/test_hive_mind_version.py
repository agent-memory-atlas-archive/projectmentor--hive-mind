"""`hive-mind version` and the version header of `hive-mind status` (#468).

Release info is read from real throwaway git checkouts: on a tag, between tags, and with no tags at all.
"""
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

import hive_version  # noqa: E402

GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")


def _git(root, *a):
    return subprocess.run(["git", "-C", str(root), *a], env=GIT_ENV, capture_output=True, text=True, check=True).stdout.strip()


def _commit(root, name):
    (root / name).write_text(name)
    _git(root, "add", name)
    _git(root, "-c", "commit.gpgsign=false", "commit", "-q", "-m", name)
    return _git(root, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    return r


class FakeLib:
    CONTRACT_VERSION = "9.9"

    def __init__(self, level="official"):
        self.level = level
        self.calls = 0
        self.HIVE_HOME = Path("/nonexistent-hive-home")

    def _verify_status(self, root, check_anchor=True, pinned_pub=None):
        self.calls += 1
        return {"level": self.level}


def test_on_a_tag(repo):
    sha = _commit(repo, "a")
    _git(repo, "tag", "v3.1.1")
    info = hive_version.release_info(repo)
    assert info["release"] == "v3.1.1" and info["commit"] == sha and info["commits_since_tag"] == 0


def test_between_tags(repo):
    _commit(repo, "a")
    _git(repo, "tag", "v3.1.1")
    _commit(repo, "b")
    sha = _commit(repo, "c")
    info = hive_version.release_info(repo)
    assert info["release"] == f"v3.1.1+2 ({sha[:7]})"
    assert info["tag"] == "v3.1.1" and info["commits_since_tag"] == 2


def test_no_tags(repo, capsys):
    sha = _commit(repo, "a")
    info = hive_version.release_info(repo)
    assert info["release"] is None and info["commit"] == sha
    assert hive_version.main(FakeLib(), ["--no-verify"], repo) == 0
    out = capsys.readouterr().out
    assert "no release tag" in out and sha in out


def test_not_a_git_checkout(tmp_path):
    info = hive_version.release_info(tmp_path)
    assert info["release"] is None and info["commit"] is None


def test_json_has_every_field_and_verifies(repo, capsys):
    sha = _commit(repo, "a")
    _git(repo, "tag", "v1.2.3")
    lib = FakeLib("official")
    assert hive_version.main(lib, ["--json"], repo) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["release"] == "v1.2.3" and d["commit"] == sha and d["contract_version"] == "9.9"
    assert d["verify"] == "Official" and lib.calls == 1


@pytest.mark.parametrize("level", ["modified", "fork", "offline_ok", "no_manifest"])
def test_anything_short_of_official_is_not_verified(repo, capsys, level):
    _commit(repo, "a")
    assert hive_version.main(FakeLib(level), ["--json"], repo) == 0
    assert json.loads(capsys.readouterr().out)["verify"] == "not verified"


def test_no_verify_skips_the_check(repo, capsys):
    _commit(repo, "a")
    lib = FakeLib()
    hive_version.main(lib, ["--no-verify", "--json"], repo)
    assert lib.calls == 0 and json.loads(capsys.readouterr().out)["verify"] == "not checked"


def test_unknown_flag_is_refused(repo):
    assert hive_version.main(FakeLib(), ["--bogus"], repo) == 2


def test_brief_lists_modules_with_publisher_prefix(repo, capsys, monkeypatch):
    import base64
    import hive_modules
    _commit(repo, "a")
    _git(repo, "tag", "v3.1.1")
    pub = base64.b64encode(bytes(range(32))).decode()
    monkeypatch.setattr(hive_modules, "load_state", lambda lib: {"hwatch": {"version": "0.4.0", "publisher": pub}})
    lib = FakeLib()
    assert hive_version.main(lib, ["--brief"], repo) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("hive-mind v3.1.1") and "contract 9.9" in out[0]
    assert out[1] == f"  module hwatch 0.4.0  publisher {hive_modules.fingerprint(pub)}"
    assert lib.calls == 0


def _ctl(tmp_path, *argv):
    env = dict(os.environ, HIVE_HOME=str(tmp_path / "h"), HIVE_IDENTITY_STASH=str(tmp_path / "stash"))
    return subprocess.run([sys.executable, str(PROJECT / "hivemind_ctl.py"), *argv], env=env, capture_output=True, text=True)


@pytest.mark.parametrize("word", ["version", "--version"])
def test_ctl_and_dispatcher_route_version(tmp_path, word):
    r = _ctl(tmp_path, word, "--json", "--no-verify")
    assert r.returncode == 0, r.stderr
    assert set(json.loads(r.stdout)) >= {"release", "commit", "contract_version", "verify"}
    env = dict(os.environ, HIVE_DIR=str(PROJECT), HIVE_HOME=str(tmp_path / "h"), HIVE_IDENTITY_STASH=str(tmp_path / "stash"))
    d = subprocess.run(["bash", str(PROJECT / "scripts/installer/dispatcher.sh"), word, "--json", "--no-verify"],
                       env=env, capture_output=True, text=True)
    assert d.returncode == 0, d.stderr
    assert json.loads(d.stdout)["contract_version"] == json.loads(r.stdout)["contract_version"]


def test_hv_version_is_unchanged(tmp_path):
    env = dict(os.environ, HIVE_HOME=str(tmp_path / "h"), HIVE_IDENTITY_STASH=str(tmp_path / "stash"))
    r = subprocess.run([sys.executable, str(PROJECT / "hv"), "version"], env=env, capture_output=True, text=True)
    assert r.stdout.strip().startswith("hv contract-version ") and len(r.stdout.splitlines()) == 1
    h = subprocess.run([sys.executable, str(PROJECT / "hv"), "--help"], env=env, capture_output=True, text=True)
    assert "not the release" in " ".join(h.stdout.split())


def test_status_script_shows_the_version_header():
    text = (PROJECT / "scripts/installer/_status.sh").read_text()
    assert "hivemind_ctl.py\" version --brief" in text
    assert text.index("version --brief") < text.index("# Daemon")
