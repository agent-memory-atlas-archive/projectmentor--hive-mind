"""Driving a real `hwatch serve` on a node, against fakegh and a fake seat runtime (slice C).

The module tree comes from `HWATCH_TREE` (a checkout of hive-mind-hwatch-dev): hwatch is a private repo, so core's public CI
has no tree and these scenarios skip with that reason; hwatch-dev's CI sets it. The service runs as the module manifest's
`service.command` says (`python3 -I hwatch serve`), in the node's environment, with `gh` and the seat runtime first on PATH.
"""
import json
import os
import stat
import sys
import time
from pathlib import Path

from . import wait_for

TREE = os.environ.get("HWATCH_TREE")

# The fake seat: logs one JSON line per start, then holds until the test releases it (a file), so the test decides when the
# session "exits". It reads its prompt from stdin like claude -p, and never calls a model.
FAKE_CLAUDE = r'''#!/usr/bin/env python3
import json, os, sys, time
d = os.environ["FAKE_SEAT_DIR"]
if "--version" in sys.argv:
    print("fake-claude 0"); raise SystemExit(0)
if sys.argv[1:2] in (["auth"], ["models"]):     # hwatch's auth probe (hive-mind-hwatch-dev#100): logged in, not a start
    raise SystemExit(0)
prompt = sys.stdin.read()
n = len([f for f in os.listdir(d) if f.startswith("start-")])
open(os.path.join(d, "start-%d.json" % n), "w").write(json.dumps({"argv": sys.argv[1:], "pid": os.getpid(), "cwd": os.getcwd(), "prompt": prompt}))
rel = os.path.join(d, "release")
while not os.path.exists(rel):
    time.sleep(0.05)
raise SystemExit(int(open(rel).read().strip() or 0))
'''


class HwatchNode:
    """hwatch on one Node: its config file, its workflow, its fake seat; `start()`/`kill()`/`restart()` run the real service."""

    def __init__(self, node, gh, role="implementer", repo="o/r", tree=None, extra=None):
        self.node, self.gh, self.role, self.repo = node, gh, role, repo
        self.tree = Path(tree or TREE)
        self.seat = node.dir / "seat"
        self.seat.mkdir()
        (node.bin / "claude").write_text(FAKE_CLAUDE)
        (node.bin / "claude").chmod(0o755)
        # No systemd user scope on any runner: hwatch probes `systemd-run --user --scope` and, where it works, lets a session
        # outlive the service (restart-safe, adopted). Whether that works depends on the machine, so every node says it does not
        # and the sessions stay the service's children, the same everywhere.
        (node.bin / "systemd-run").write_text("#!/bin/sh\nexit 1\n")
        (node.bin / "systemd-run").chmod(0o755)
        self.settings = node.dir / "seat-settings.json"
        self.settings.write_text('{"permissions": {"deny": ["Bash(gh pr merge *)"]}}\n')
        self.config = {
            "workflows": "dev-team", "roles": role, "tick": "30s", "stalled": "1h",
            "channel.github.type": "github", "channel.github.repos": repo, "channel.github.login": gh.login,
            "channel.github.author_classes": "owner,member,collaborator",
            f"seat.{role}.enabled": "true", f"seat.{role}.settings": str(self.settings), f"seat.{role}.runtime": "claude",
            f"seat.{role}.model": "sonnet-5.5", **(extra or {})}
        self.write_config()
        self.env = {**node.env(HIVE_MODULES_DIR=str(node.dir / "modules"), FAKE_SEAT_DIR=str(self.seat),
                               HWATCH_STARTUP_WAIT="0"), **gh.install(node.bin, client=node.name)}

    def write_config(self):
        path = self.node.dir / "modules" / "hwatch" / "config"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.config))

    def cli(self, *args, **kw):
        return self.node.run([sys.executable, "-I", self.tree / "hwatch", *args], env=self.env, **kw)

    def start(self):
        return self.node.spawn("hwatch", [sys.executable, "-I", self.tree / "hwatch", "serve"], env=self.env)

    def kill(self, sig=9):
        return self.node.kill("hwatch", sig)

    def restart(self):
        self.kill()
        return self.start()

    # the fake seat -------------------------------------------------------------------------------
    def starts(self):
        return [json.loads(p.read_text()) for p in sorted(self.seat.glob("start-*.json"), key=lambda p: int(p.stem[6:]))]

    def release(self, rc=0):
        (self.seat / "release").write_text(str(rc))

    @staticmethod
    def seat_running(pid):
        """True while the process exists and is not a zombie (a session its parent has not reaped has exited)."""
        try:
            return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
        except (OSError, IndexError):
            return False

    # the service's own state ----------------------------------------------------------------------
    def state(self):
        try:
            return json.loads((self.node.home / "hwatch" / "state.json").read_text())
        except (OSError, ValueError):
            return {}

    def service(self):
        return self.state().get("service") or {}

    def ticks(self):
        return self.service().get("ticks", 0)

    def wait_tick(self, after, timeout=40):
        """Wait until the *running* service has finished a tick beyond `after` (the count rises after collect, route and
        launch, so a rise means that tick's launch step ran). A restart ticks at once, so this is quick, not a 30 s tick."""
        pid = self.node.pid("hwatch")
        return wait_for(lambda: self.service().get("pid") == pid and self.ticks() > after, timeout=timeout,
                        what=f"a tick beyond {after} by pid {pid}")

    def pending(self, role=None):
        wakes = self.state().get("wakes") or {}
        return [w for r, ws in wakes.items() if role in (None, r) for w in ws]

    def sessions(self):
        return self.state().get("sessions") or {}

    def seen(self):
        """Keys of every event the engine has taken in (`closed:o/r#1@...`, `head:o/r#2@<sha>`): what a tick delivered."""
        return sorted((self.state().get("seen") or {}).get("github") or {})

    def watched_sha(self, number):
        """The head sha hwatch last recorded for a pull request, from its GitHub cursor."""
        cur = (self.state().get("cursors") or {}).get("github") or {}
        return (((cur.get("repos") or {}).get(self.repo) or {}).get("prs") or {}).get(str(number), {}).get("sha")

    def tick(self):
        """One more tick, without waiting 30 s: stop the service gracefully (no live session, so it drains at once) and start
        it; a start ticks immediately."""
        before = self.ticks()
        self.node.stop("hwatch")
        self.start()
        return self.wait_tick(before)

    def set_seat(self, enabled):
        self.config[f"seat.{self.role}.enabled"] = "true" if enabled else "false"
        self.write_config()

    def session_logs(self):
        return sorted((self.node.home / "hwatch" / "log" / self.role).glob("*.log"))

    def log_rows(self, name):
        p = self.node.home / "hwatch" / "log" / name
        return [json.loads(line) for line in p.read_text().splitlines() if line.strip()] if p.exists() else []
