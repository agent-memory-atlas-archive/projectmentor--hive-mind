"""The installer scripts run in the directory the operator started `hive-mind` from, which may be one an unadmitted party can
write. Their `python3 -c` / `python3 -` calls that run before the script `cd`s into the checkout must not put that directory on
`sys.path` (`-I`), or a planted `json.py` / `requests.py` there runs as the operator. Each test plants a module that leaves a
marker if imported, and fails if `-I` is taken off the call it exercises."""
import os
import re
import subprocess
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
INSTALLER = PROJECT / "scripts" / "installer"


def _plant(tmp_path, module):
    proj = tmp_path / "proj"
    proj.mkdir()
    marker = tmp_path / "planted-ran.txt"
    (proj / f"{module}.py").write_text(f"open({str(marker)!r}, 'a').write({module!r})\n")
    return proj, marker


def _call(script, pattern):
    """The shell text of the one `python3 ... ` call in `script` that matches `pattern`, as the script has it today."""
    m = re.search(pattern, (INSTALLER / script).read_text())
    assert m, f"{script}: no call matching {pattern!r}"
    return m.group(0)


def test_status_peer_probe_never_imports_a_module_planted_in_the_callers_cwd(tmp_path):
    proj, marker = _plant(tmp_path, "json")
    hive = tmp_path / "hive"
    hive.mkdir()
    (hive / ".peers.json").write_text('{"peers": []}')
    r = subprocess.run(["bash", str(INSTALLER / "_status.sh")], cwd=proj, env=dict(os.environ, HIVE_DIR=str(hive)),
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
    assert r.returncode == 0, r.stderr
    assert not marker.exists()


def test_install_requests_probe_never_imports_a_module_planted_in_the_callers_cwd(tmp_path):
    proj, marker = _plant(tmp_path, "requests")
    call = _call("_install_node.sh", r'python3 [^\n]*?-c "import requests"')
    r = subprocess.run(["bash", "-c", f"{call} 2>/dev/null; true"], cwd=proj, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0
    assert not marker.exists()


def test_install_tailscale_state_probe_never_imports_a_module_planted_in_the_callers_cwd(tmp_path):
    proj, marker = _plant(tmp_path, "json")
    call = _call("_install_node.sh", r'python3 [^\n]*?-c "import sys,json; d=json.load\(sys.stdin\)[^"]*"')
    r = subprocess.run(["bash", "-c", f"printf '{{}}' | {call}; true"], cwd=proj, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0
    assert not marker.exists()


def test_every_update_call_that_reads_the_callers_cwd_is_isolated():
    """`_update.sh` runs its inline Python from wherever `hive-mind update` was started: every inline call is `-I`."""
    text = (INSTALLER / "_update.sh").read_text()
    calls = re.findall(r"python3 (?!\"\$HIVE_DIR)([^\n]*)", text)
    assert calls
    for rest in calls:
        assert rest.startswith("-I ") or " -I " in rest.split("<<")[0], f"_update.sh: python3 without -I: {rest[:60]!r}"
