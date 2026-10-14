"""duplicate-issue.yml follows the CI-01 rules (hive-mind#493)."""

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
    src = (PROJECT / "scripts" / "ci" / "duplicate_issue.py").read_text()
    code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
    assert not re.search(r'"close"|"delete"|state=closed|"--reason"|-X["\' ]*(DELETE|PATCH)', code)
