"""`hive-mind owner present` and `owner member` (hive-mind#512; the CLI verbs the approval module calls instead of importing
the agent client). JSON on stdin, the agent's reply as JSON on stdout. They run the real CLI against a real gated agent
process; the passkeys are made here, as in the A1 tests. The agent, not the verb, is the gate: these tests check that the
verb forwards exactly, passes the refusal through with exit 1, never prompts, and refuses a malformed request with exit 2."""

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
import approvers  # noqa: E402
import owner_agent  # noqa: E402
from test_owner_agent import LINUX, PASS, hive, _sock  # noqa: E402,F401
from test_owner_approval_a1 import (DESKTOP, PHONE, RP, add_flags, gov_entries, member_assertion, run_ctl,  # noqa: E402,F401
                                    ticket_assertion)


def verb(h, name, payload, raw=None, env=None):
    """Run `hive-mind owner <name>` with `payload` (or the raw bytes) on stdin; (returncode, parsed stdout or None, stderr)."""
    e = dict(h.env)
    e.pop("HIVE_OWNER_KEY_PASSPHRASE", None)
    e.update(env or {})
    data = raw if raw is not None else json.dumps(payload).encode()
    r = subprocess.run([sys.executable, str(PROJECT / "hivemind_ctl.py"), "owner", name], env=e, input=data,
                       capture_output=True, start_new_session=True, timeout=60)
    out = r.stdout.decode()
    return r.returncode, (json.loads(out) if out.strip() else None), r.stderr.decode()


def gated_with_phone(h):
    run_ctl(h, *add_flags(PHONE), "--break-glass", passphrase_fd=PASS)
    run_ctl(h, "owner", "unlock", "--gated", "--rp-id", RP, passphrase_fd=PASS)


@LINUX
def test_present_approves_through_the_agent_and_the_ticket_then_signs(hive):
    gated_with_phone(hive)
    try:
        argv = ["config", "set", "x-demo:poll", "45"]
        planned = json.loads(run_ctl(hive, *argv, "--plan", "--json").stdout)["bodies"]
        tickets = [{"id": "T-1", "acts": [b["sha256"] for b in planned]}]
        rc, reply, err = verb(hive, "present", {"tickets": tickets, "assertion": ticket_assertion(PHONE, tickets)})
        assert rc == 0 and reply["ok"] is True and reply["tickets"] == ["T-1"], err
        before = len(gov_entries(hive.home))
        run_ctl(hive, *argv, env={"HIVE_APPROVAL_TICKET": "T-1"})
        assert len(gov_entries(hive.home)) == before + 1
        # the same ticket again is the agent's refusal, passed through: exit 1, the reply on stdout, nothing on a prompt
        rc, reply, _ = verb(hive, "present", {"tickets": tickets, "assertion": ticket_assertion(PHONE, tickets)})
        assert rc == 1 and reply["ok"] is False and "already used" in reply["why"]
        # an assertion over other hashes is refused, and writes no ticket
        other = [{"id": "T-2", "acts": ["ab" * 32]}]
        rc, reply, _ = verb(hive, "present", {"tickets": other, "assertion": ticket_assertion(PHONE, tickets)})
        assert rc == 1 and reply["ok"] is False
        r = run_ctl(hive, *argv[:3], "46", env={"HIVE_APPROVAL_TICKET": "T-2"}, check=False)
        assert r.returncode != 0 and len(gov_entries(hive.home)) == before + 1
    finally:
        run_ctl(hive, "owner", "lock", check=False)


@LINUX
def test_member_enrols_a_second_approver_with_one_tap_and_refuses_a_wrong_tap(hive):
    gated_with_phone(hive)
    try:
        plan = json.loads(run_ctl(hive, *add_flags(DESKTOP), "--plan", "--json").stdout)
        rec = plan["record"]
        bad = member_assertion(PHONE, "approver-add", {**rec, "label": "other"})
        rc, reply, _ = verb(hive, "member", {"kind": "approver-add", "record": rec, "assertions": [bad]})
        assert rc == 1 and reply["ok"] is False
        assert DESKTOP.id not in run_ctl(hive, "owner", "approver", "list").stdout
        good = member_assertion(PHONE, "approver-add", rec)
        rc, reply, err = verb(hive, "member", {"kind": "approver-add", "record": rec, "assertions": [good]})
        assert rc == 0 and reply["ok"] is True and reply["record"]["id"] == DESKTOP.id and "owner_sig" in reply["record"], err
    finally:
        run_ctl(hive, "owner", "lock", check=False)


@LINUX
@pytest.mark.parametrize("name,payload", [
    ("present", {"tickets": [], "assertion": {}}),
    ("member", {"kind": "approver-add", "record": {}, "assertions": []}),
])
def test_no_agent_is_a_json_refusal_with_exit_1(hive, name, payload):
    rc, reply, _ = verb(hive, name, payload)
    assert rc == 1 and reply["ok"] is False and "no agent" in reply["why"]


@LINUX
@pytest.mark.parametrize("name,raw", [
    ("present", b""), ("present", b"not json"), ("present", b"[]"), ("present", b"[\"tickets\",\"assertion\"]"), ("present", b"{}"),
    ("present", json.dumps({"tickets": [], "assertion": {}, "op": "sign"}).encode()),     # no extra key reaches the agent
    ("present", json.dumps({"tickets": []}).encode()),
    ("present", b"\xff\xfe"),
    ("member", json.dumps({"kind": "approver-add"}).encode()),
    ("member", json.dumps({"kind": "x", "record": {}, "assertions": [], "break_glass": True}).encode()),
])
def test_a_malformed_request_is_exit_2_and_never_reaches_an_agent(hive, name, raw):
    rc, reply, err = verb(hive, name, None, raw=raw)
    assert rc == 2 and reply is None and err.startswith("hive-mind:")


@LINUX
def test_a_terminal_on_stdin_is_refused_not_read(hive):
    import pty
    master, slave = pty.openpty()
    try:
        e = dict(hive.env)
        r = subprocess.run([sys.executable, str(PROJECT / "hivemind_ctl.py"), "owner", "present"], env=e, stdin=slave,
                           capture_output=True, text=True, timeout=60, start_new_session=True)
    finally:
        os.close(master)
        os.close(slave)
    assert r.returncode == 2 and "not a terminal" in r.stderr


@LINUX
def test_an_oversize_request_is_refused_before_parsing(hive):
    rc, reply, err = verb(hive, "present", None, raw=b" " * ((1 << 20) + 1))
    assert rc == 2 and reply is None and "too large" in err
