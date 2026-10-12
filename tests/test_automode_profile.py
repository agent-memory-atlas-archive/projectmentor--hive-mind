"""The Claude Code auto-mode operator profile merges into settings.json without clobbering (#343)."""
import json
import subprocess
import sys

from conftest import PROJECT

SCRIPT = PROJECT / "integrations" / "claude-code" / "automode.py"


def _run(tmp_path, *args):
    return subprocess.run([sys.executable, "-I", str(SCRIPT), *args, "--claude-dir", str(tmp_path)],
                          capture_output=True, text=True, timeout=60)


def _env(tmp_path):
    return json.loads((tmp_path / "settings.json").read_text())["autoMode"]["environment"]


def test_fresh_install_idempotent(tmp_path):
    assert _run(tmp_path, "install", "/opt/hm").returncode == 0
    first = (tmp_path / "settings.json").read_text()
    assert all(l.startswith("[hive-managed v1] ") for l in _env(tmp_path))
    assert _run(tmp_path, "install", "/opt/hm").returncode == 0
    assert (tmp_path / "settings.json").read_text() == first
    assert _run(tmp_path, "check", "/opt/hm").returncode == 0


def test_user_settings_preserved_and_old_block_replaced(tmp_path):
    user = {"permissions": {"allow": ["Bash(ls:*)"]}, "model": "x",
            "autoMode": {"environment": ["mine", "[hive-managed v0] old"], "other": 1}}
    (tmp_path / "settings.json").write_text(json.dumps(user))
    assert _run(tmp_path, "check", "/opt/hm").returncode == 1
    assert _run(tmp_path, "install", "/opt/hm").returncode == 0
    cfg = json.loads((tmp_path / "settings.json").read_text())
    assert cfg["permissions"] == user["permissions"] and cfg["model"] == "x"
    assert cfg["autoMode"]["other"] == 1
    env = cfg["autoMode"]["environment"]
    assert env[0] == "mine" and not any("v0" in l for l in env) and len(env) == 3
    assert (tmp_path / "settings.json.bak.automode").exists()
    assert _run(tmp_path, "uninstall").returncode == 0
    assert json.loads((tmp_path / "settings.json").read_text())["autoMode"] == {"environment": ["mine"],
                                                                               "other": 1}


def test_uninstall_leaves_no_empty_block(tmp_path):
    _run(tmp_path, "install", "/opt/hm")
    _run(tmp_path, "uninstall")
    assert json.loads((tmp_path / "settings.json").read_text()) == {}


def test_unparseable_or_odd_settings_untouched(tmp_path):
    for body in ("{not json", "[1]", json.dumps({"autoMode": {"environment": "str"}})):
        (tmp_path / "settings.json").write_text(body)
        assert _run(tmp_path, "install", "/opt/hm").returncode == 2
        assert (tmp_path / "settings.json").read_text() == body
