"""duplicate-issue.yml follows the CI-01 rules (hive-mind#493)."""

import ast
import re
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent

WF = (PROJECT / ".github" / "workflows" / "duplicate-issue.yml").read_text()
WF_CODE = "\n".join(l for l in WF.splitlines() if not l.lstrip().startswith("#"))


def test_trigger_is_issues_opened_only():
    assert re.search(r"(?m)^on:\n  issues:\n    types: \[opened\]\n", WF_CODE)
    assert "pull_request" not in WF_CODE and "workflow_run" not in WF_CODE


def test_permissions_least_privilege():
    assert re.search(r"(?m)^permissions: \{\}$", WF_CODE)
    perms = re.search(r"(?m)^    permissions:\n((?:      \S.*\n)+)", WF_CODE).group(1)
    assert sorted(re.findall(r"(\w[\w-]*): (\w+)", perms)) == [("contents", "read"), ("issues", "write")]


def test_actions_pinned_to_sha():
    for ref in re.findall(r"uses: (\S+)", WF_CODE):
        assert re.fullmatch(r".+@[0-9a-f]{40}", ref), ref


def test_no_event_text_in_run():
    for run in re.findall(r"(?m)^\s+run: (.*)$", WF_CODE):
        assert "${{" not in run, run
    assert "github.event" in WF_CODE and "env:" in WF_CODE


def test_checks_out_default_branch_without_credentials():
    assert "persist-credentials: false" in WF_CODE
    assert "ref:" not in WF_CODE
    assert "github.event.issue" not in WF_CODE.split("env:")[0]


def test_script_never_closes():
    # every string passed to gh or subprocess, in any spelling (quoted, f-string, spaced), is checked token by token
    tree = ast.parse((PROJECT / "scripts" / "ci" / "duplicate_issue.py").read_text())
    banned = {"close", "closed", "delete", "lock", "reopen", "transfer", "--reason", "-x", "patch", "put"}
    seen = []
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        name = getattr(call.func, "id", None) or getattr(call.func, "attr", "")
        if name in ("_gh", "run"):
            for const in (n for a in call.args for n in ast.walk(a) if isinstance(n, ast.Constant)):
                if isinstance(const.value, str):
                    seen += re.findall(r"[\w-]+", const.value.lower())
    assert "api" in seen and "comment" in seen
    assert not banned & set(seen), banned & set(seen)


def test_job_is_bounded():
    assert re.search(r"(?m)^    timeout-minutes: [1-5]\b", WF_CODE)
    assert re.search(r"(?m)^    concurrency:\n      group: \S+\n      cancel-in-progress: false\b", WF_CODE)
