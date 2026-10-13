"""S6 (plan docs/design/integration_tests_4x.md): session_hook.sh where the runner has no `timeout` or `gtimeout` (macOS
without coreutils). The hook is best-effort and non-blocking: it exits 0, still records telemetry (here: still calls the
module through `hive-mind module run hwatch`), and keeps the child bounded at 12 s. On Linux the test strips both from PATH.

Guards the `timeout`/`gtimeout` fallback of hive-mind#440 (ported to main in #442): without it `timeout 12 ...` is "command not found", `|| true` hides it, and
the telemetry call is silently skipped."""
import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from hivefleet import CORE

HOOK = CORE / "scripts" / "common" / "session_hook.sh"
TOOLS = ("bash", "python3", "sed", "hostname", "id", "dirname", "env", "sh", "printf", "sleep", "cat", "touch")
pytestmark = pytest.mark.integration


def _node_without_timeout(fleet, stub_body):
    node = fleet[0]
    tools = node.dir / "tools"
    tools.mkdir()
    for name in TOOLS:
        found = shutil.which(name)
        assert found, f"{name} is needed on the runner"
        (tools / name).symlink_to(found)
    assert not (tools / "timeout").exists() and not (tools / "gtimeout").exists()
    (node.home / ".modules.json").write_text(json.dumps({"hwatch": {}}))
    stub = node.bin / "hive-mind"
    stub.write_text("#!/bin/sh\n" + stub_body)
    stub.chmod(0o755)
    env = node.env(PATH=f"{node.bin}:{tools}")
    return node, env


def _hook(node, env, event="start"):
    proc = Path(node.dir / "project")
    proc.mkdir(exist_ok=True)
    return subprocess.run(["bash", str(HOOK), event], env=env, cwd=proc, input=json.dumps({"cwd": str(proc), "session_id": "s6"}),
                          capture_output=True, text=True, timeout=40)


def test_hook_still_records_when_there_is_no_timeout(fleet):
    node, env = _node_without_timeout(fleet, f'printf "%s\\n" "$@" > {fleet[0].dir}/argv.txt\n')
    r = _hook(node, env)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    argv = (node.dir / "argv.txt").read_text().split()
    assert argv[:5] == ["module", "run", "hwatch", "--", "telemetry"] and "record" in argv and "s6" in argv


def test_hook_keeps_the_child_bounded_when_there_is_no_timeout(fleet):
    node, env = _node_without_timeout(fleet, f"touch {fleet[0].dir}/started\nsleep 60\ntouch {fleet[0].dir}/finished\n")
    t0 = time.monotonic()
    r = _hook(node, env, "end")
    elapsed = time.monotonic() - t0
    assert r.returncode == 0
    assert (node.dir / "started").exists(), "the module was never called"
    assert not (node.dir / "finished").exists()
    assert 10 <= elapsed < 25, f"the child must be capped at 12 s, the hook took {elapsed:.1f}s"
