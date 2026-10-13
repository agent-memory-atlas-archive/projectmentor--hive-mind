"""The harness itself: scrubbed environment, node directories, ports, process control."""
import signal
import sys

import pytest

from hivefleet import free_port, wait_for

pytestmark = pytest.mark.integration


def test_runner_variables_never_reach_a_node(fleet_factory, monkeypatch):
    for k in ("GH_TOKEN", "HIVE_KEY_DIR", "HIVE_SEAT", "ANTHROPIC_API_KEY", "CLAUDE_CONFIG_DIR", "GITHUB_TOKEN"):
        monkeypatch.setenv(k, "leak")
    fleet = fleet_factory(2)
    fleet.assert_scrubbed()
    for node in fleet:
        out = node.run([sys.executable, "-c", "import os,sys;sys.stdout.write(repr(sorted(os.environ)))"]).stdout
        assert "leak" not in out and not any(k in out for k in ("GH_TOKEN", "HIVE_SEAT", "ANTHROPIC", "CLAUDE"))
    assert fleet[0].home != fleet[1].home and fleet[0].port("sync") != fleet[1].port("sync")


def test_real_hv_runs_against_the_node_home_only(fleet):
    node = fleet[0]
    assert node.hv("config", "identity", "init").returncode == 0
    assert any(node.home.iterdir())


def test_kill_and_restart_a_service(fleet):
    node = fleet[0]
    node.spawn("sleeper", [sys.executable, "-c", "import time;time.sleep(300)"])
    assert node.alive("sleeper")
    assert node.kill("sleeper") == -signal.SIGKILL and not node.alive("sleeper")
    node.restart("sleeper", [sys.executable, "-c", "print('up', flush=True);import time;time.sleep(300)"])
    wait_for(lambda: "up" in node.log("sleeper"), what="the restarted service to log")


def test_free_port_is_below_the_ephemeral_range():
    assert 20000 <= free_port() <= 32767
