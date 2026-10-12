"""3.1 `hive-mind update` brings the installed modules along (#390): `module refresh` is what the updater runs. Each module
goes to the newest signed version at its recorded source that this core admits; one that stays on its installed
version is warned about; one with no version that admits the core is disabled, loudly, and comes back on a later run."""

import os
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "tests"))
from test_module_doctor import _mod  # noqa: E402
from test_module_lifecycle import LINUX_ONLY, OTHER_SEED, _publish, _state, hive, units  # noqa: E402,F401
from test_succession import _run  # noqa: E402

HOOK = {"run.sh": "#!/bin/sh\nexit 0\n", "hooks/stop": "#!/bin/sh\nexit 0\n"}


def add(home, repo, pub):
    return _run(home, "module", "add", "demo", "--from", str(repo), "--publisher", pub)


def refresh(home, *extra):
    return _run(home, "module", "refresh", *extra, check=False)


def break_installed(tmp_path):
    (tmp_path / "modules" / "demo" / "run.sh").write_text("#!/bin/sh\necho owned\n")     # no longer matches its digest


@LINUX_ONLY
def test_refresh_updates_to_the_newest_version_and_a_second_run_changes_nothing(hive, tmp_path, units):
    pub = _publish(tmp_path / "repo")
    add(hive, tmp_path / "repo", pub)
    dev = _state(hive)["demo"]["device_id"]
    _publish(tmp_path / "repo", version="1.1.0")
    r = refresh(hive, "--check")
    assert r.returncode == 0 and "would update 1.0.0 -> 1.1.0" in r.stdout and _state(hive)["demo"]["version"] == "1.0.0"
    r = refresh(hive)
    assert r.returncode == 0 and "updated module demo to 1.1.0" in r.stdout
    assert _state(hive)["demo"]["version"] == "1.1.0" and _state(hive)["demo"]["device_id"] == dev
    state = (hive / ".modules.json").read_bytes()
    again = refresh(hive)
    assert again.returncode == 0 and "demo 1.1.0 is current" in again.stdout and (hive / ".modules.json").read_bytes() == state


@LINUX_ONLY
def test_a_failed_update_of_a_compatible_module_warns_and_keeps_it_running(hive, tmp_path, units):
    pub = _publish(tmp_path / "repo")
    add(hive, tmp_path / "repo", pub)
    _publish(tmp_path / "repo", version="2.0.0", min_core="99.0")           # no version admits this core but the installed one
    r = refresh(hive)
    assert r.returncode == 0 and "was NOT updated" in r.stderr and "demo" in r.stderr and "still works" in r.stderr
    assert _state(hive)["demo"]["version"] == "1.0.0" and "disabled" not in _state(hive)["demo"]
    _publish(tmp_path / "repo", version="2.0.0", seed=OTHER_SEED)           # a different signer is refused, as today
    r = refresh(hive)
    assert "was NOT updated" in r.stderr and "pinned" in r.stderr and _state(hive)["demo"]["version"] == "1.0.0"
    _publish(tmp_path / "repo", version="0.9.0")                             # and an older signed version is never installed
    r = refresh(hive)
    assert "only goes forward" in r.stderr and _state(hive)["demo"]["version"] == "1.0.0"
    for odd in ("1.0.0-rc1", "1.0.0.1", "v2.0.0", "1.0", "0.9.0+9"):         # not orderable, or not newer: never installed
        _publish(tmp_path / "repo", version=odd)
        r = refresh(hive)
        assert "only goes forward" in r.stderr and _state(hive)["demo"]["version"] == "1.0.0", odd


@LINUX_ONLY
def test_no_compatible_version_disables_the_module_loudly_then_a_fix_brings_it_back(hive, tmp_path, units):
    unit_dir, calls = units
    pub = _publish(tmp_path / "repo", service={"command": ["run.sh"]})
    add(hive, tmp_path / "repo", pub)
    break_installed(tmp_path)                                               # the installed copy no longer verifies
    _publish(tmp_path / "repo", version="2.0.0", seed=OTHER_SEED, service={"command": ["run.sh"]})
    before = len(calls())
    r = refresh(hive, "--check")
    assert "would DISABLE" in r.stdout and "disabled" not in _state(hive)["demo"]
    r = refresh(hive)
    assert r.returncode == 0 and "module demo is DISABLED" in r.stderr and "hive-mind module update demo" in r.stderr
    rec = _state(hive)["demo"]
    assert rec["disabled"]["reason"] and rec["version"] == "1.0.0"
    stops = [c for c in calls()[before:] if "disable --now" in c]
    assert stops and all("hive-module-demo." in c for c in stops)           # only the module's own units are touched
    assert not [c for c in calls()[before:] if "kill" in c or ".scope" in c]
    check = _mod(hive)[1]
    assert "disabled-incompatible" in check["detail"] and check["status"] == "fail"
    assert _run(hive, "module", "run", "demo", check=False).returncode == 1
    state = (hive / ".modules.json").read_bytes()
    assert "stays DISABLED" in refresh(hive).stderr and (hive / ".modules.json").read_bytes() == state    # idempotent
    reapply = len(calls())
    _run(hive, "module", "reapply")
    assert not [c for c in calls()[reapply:] if "restart" in c or "enable" in c]    # the units stay off
    _publish(tmp_path / "repo", version="2.1.0", service={"command": ["run.sh"]})          # the fix is published
    r = refresh(hive)
    assert "updated module demo to 2.1.0" in r.stdout
    rec = _state(hive)["demo"]
    assert rec["version"] == "2.1.0" and "disabled" not in rec
    assert "disabled-incompatible" not in _mod(hive)[1]["detail"]


@LINUX_ONLY
def test_a_disabled_module_runs_no_hooks(hive, tmp_path, units):
    pub = _publish(tmp_path / "repo", files={**HOOK, "hooks/stop": f"#!/bin/sh\ntouch {tmp_path}/ran\n"})
    add(hive, tmp_path / "repo", pub)
    dispatch = PROJECT / "scripts" / "common" / "hive_dispatch.sh"
    env = {"PATH": os.environ["PATH"], "HOME": os.environ["HOME"], "HIVE_HOME": str(hive),
           "HIVE_MODULES_DIR": str(tmp_path / "modules")}

    def fire():
        subprocess.run(["bash", str(dispatch), "stop"], input=b"{}", env=env, timeout=30, capture_output=True)
        return (tmp_path / "ran").exists()
    assert fire()                                                           # the hook runs while the module is enabled
    (tmp_path / "ran").unlink()
    break_installed(tmp_path)
    _publish(tmp_path / "repo", version="2.0.0", seed=OTHER_SEED, files={**HOOK, "hooks/stop": "#!/bin/sh\n"})   # a wrong signer
    refresh(hive)
    assert "disabled" in _state(hive)["demo"]
    assert not fire()
