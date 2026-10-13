"""sign.yml's one self-retry (#473), exercised without a real push: a local bare repo stands in for the
remote and a fake pytest stands in for the suite."""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SIGN_PUSH = ROOT / "scripts" / "ci" / "sign_push.sh"
FLAKE = ROOT / "scripts" / "ci" / "flake_retry.py"
WF = (ROOT / ".github" / "workflows" / "sign.yml").read_text()
ISSUE = "# https://github.com/projectmentor/hive-mind/issues/463"


def git(cwd, *a, check=True):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a], cwd=cwd,
                          check=check, capture_output=True, text=True)


# ---- sign_push.sh against a fake remote -------------------------------------------------------------

@pytest.fixture
def repos(tmp_path):
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    work = tmp_path / "work"
    git(tmp_path, "clone", "-q", str(remote), str(work))
    (work / "verify.json").write_text("{}\n")
    git(work, "add", "."); git(work, "commit", "-qm", "base"); git(work, "push", "-q", "origin", "HEAD:main")
    other = tmp_path / "other"
    git(tmp_path, "clone", "-q", str(remote), str(other))
    return remote, work, other


def run_sign(work, mode, tmp_path, retry_of=""):
    out = tmp_path / "gh_output"
    out.write_text("")
    env = {**os.environ, "GITHUB_OUTPUT": str(out), "RETRY_OF": retry_of, "GIT_TERMINAL_PROMPT": "0",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    r = subprocess.run(["bash", str(SIGN_PUSH), mode, "origin", "main"], cwd=work, env=env, capture_output=True, text=True)
    kv = dict(l.split("=", 1) for l in out.read_text().split())
    return r, kv


def advance(other):
    (other / "x.txt").write_text("x")
    git(other, "add", "."); git(other, "commit", "-qm", "newer"); git(other, "push", "-q", "origin", "HEAD:main")


def test_tip_current(repos, tmp_path):
    _, work, _ = repos
    r, kv = run_sign(work, "tip", tmp_path)
    assert r.returncode == 0 and kv == {"state": "current", "retry": "false"}


def test_tip_stale_retries_once_not_twice(repos, tmp_path):
    _, work, other = repos
    advance(other)
    assert run_sign(work, "tip", tmp_path)[1] == {"state": "stale", "retry": "true"}
    assert run_sign(work, "tip", tmp_path, retry_of="a" * 40)[1] == {"state": "stale", "retry": "false"}


def test_push_signs_and_pushes(repos, tmp_path):
    remote, work, _ = repos
    (work / "verify.json").write_text('{"signed": 1}\n')
    r, kv = run_sign(work, "push", tmp_path)
    assert r.returncode == 0 and kv == {"state": "pushed", "retry": "false"}
    assert git(remote, "log", "-1", "--format=%s", "main").stdout.strip() == "chore: re-sign source manifest [skip ci]"


def test_push_unchanged_commits_nothing(repos, tmp_path):
    remote, work, _ = repos
    before = git(remote, "rev-parse", "main").stdout
    assert run_sign(work, "push", tmp_path)[1] == {"state": "unchanged", "retry": "false"}
    assert git(remote, "rev-parse", "main").stdout == before


def test_push_never_signs_a_head_that_is_not_the_tip(repos, tmp_path):
    remote, work, other = repos
    advance(other)
    tip = git(remote, "rev-parse", "main").stdout
    (work / "verify.json").write_text('{"signed": 1}\n')
    r, kv = run_sign(work, "push", tmp_path)
    assert kv == {"state": "stale", "retry": "true"}
    assert git(remote, "rev-parse", "main").stdout == tip
    assert git(work, "log", "-1", "--format=%s").stdout.strip() == "base"      # nothing was committed either


def _race_hook(remote, other_sha_file):
    hook = remote / "hooks" / "pre-receive"
    hook.write_text(f"#!/bin/sh\nunset GIT_QUARANTINE_PATH GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES\ngit update-ref refs/heads/main $(cat {other_sha_file})\nexit 1\n")
    hook.chmod(0o755)


def test_push_race_sets_retry_once(repos, tmp_path):
    remote, work, other = repos
    advance(other)                                # main = newer; the hook below makes the push race look real
    newer = tmp_path / "newer"
    newer.write_text(git(remote, "rev-parse", "main").stdout.strip())
    git(remote, "update-ref", "refs/heads/main", git(work, "rev-parse", "HEAD").stdout.strip())   # main is HEAD again
    _race_hook(remote, newer)                     # the push is rejected, and main has moved on by then
    (work / "verify.json").write_text('{"signed": 1}\n')
    r, kv = run_sign(work, "push", tmp_path)
    assert r.returncode == 0 and kv == {"state": "raced", "retry": "true"}, r.stderr + r.stdout
    assert git(remote, "rev-parse", "main").stdout.strip() == newer.read_text()


def test_push_race_in_the_retry_run_does_not_retry_again(repos, tmp_path):
    remote, work, other = repos
    advance(other)
    newer = tmp_path / "newer"
    newer.write_text(git(remote, "rev-parse", "main").stdout.strip())
    git(remote, "update-ref", "refs/heads/main", git(work, "rev-parse", "HEAD").stdout.strip())
    _race_hook(remote, newer)
    (work / "verify.json").write_text('{"signed": 1}\n')
    r, kv = run_sign(work, "push", tmp_path, retry_of="b" * 40)
    assert r.returncode == 0 and kv == {"state": "raced", "retry": "false"}


def test_push_rejected_without_a_race_fails(repos, tmp_path):
    remote, work, _ = repos
    hook = remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n"); hook.chmod(0o755)
    (work / "verify.json").write_text('{"signed": 1}\n')
    r, kv = run_sign(work, "push", tmp_path)
    assert r.returncode == 1 and "retry" not in kv


# ---- flake_retry.py with a fake suite ----------------------------------------------------------------

FAKE = """\
import sys, os
args = sys.argv[1:]
ids = [a for a in args if '::' in a]
fail = os.environ['FAKE_FAIL'].split(',') if os.environ.get('FAKE_FAIL') else []
state = os.environ['FAKE_STATE']
runs = open(state).read().count('x') if os.path.exists(state) else 0
open(state, 'a').write('x')
if ids:                                   # the retry: pass if FAKE_RETRY_OK
    sys.exit(0 if os.environ.get('FAKE_RETRY_OK') else 1)
for f in fail:
    print('FAILED ' + f + ' - boom')
print('%d failed, 5 passed in 0.1s' % len(fail) if fail else '5 passed in 0.1s')
sys.exit(int(os.environ.get('FAKE_RC', '1' if fail else '0')))
"""


def run_flake(tmp_path, listing, fail, retry_ok=True, rc=None):
    (tmp_path / "list.txt").write_text(listing)
    (tmp_path / "fake.py").write_text(FAKE)
    env = {**os.environ, "FAKE_FAIL": ",".join(fail), "FAKE_STATE": str(tmp_path / "runs"),
           "FAKE_RETRY_OK": "1" if retry_ok else ""}
    if rc is not None:
        env["FAKE_RC"] = str(rc)
    r = subprocess.run([sys.executable, "-I", str(FLAKE), "--list", str(tmp_path / "list.txt"), "--",
                        sys.executable, "-I", str(tmp_path / "fake.py")], env=env, capture_output=True, text=True)
    runs = (tmp_path / "runs").read_text().count("x") if (tmp_path / "runs").exists() else 0
    return r, runs


LIST = f"# header\n\ntests/a.py::test_one  {ISSUE}\n"


def test_green_runs_once(tmp_path):
    r, runs = run_flake(tmp_path, LIST, [])
    assert r.returncode == 0 and runs == 1


def test_listed_failure_is_rerun_once_and_passes(tmp_path):
    r, runs = run_flake(tmp_path, LIST, ["tests/a.py::test_one[x y]"])
    assert r.returncode == 0 and runs == 2


def test_listed_failure_that_fails_again_fails(tmp_path):
    r, runs = run_flake(tmp_path, LIST, ["tests/a.py::test_one"], retry_ok=False)
    assert r.returncode == 1 and runs == 2                                      # one retry, no loop


@pytest.mark.parametrize("fail", [["tests/a.py::test_two"], ["tests/a.py::test_one", "tests/a.py::test_other"],
                                  ["tests/a.py::test_one_more"]])
def test_unlisted_failure_fails_without_retry(tmp_path, fail):
    r, runs = run_flake(tmp_path, LIST, fail)
    assert r.returncode == 1 and runs == 1


def test_exit_2_is_never_retried(tmp_path):
    r, runs = run_flake(tmp_path, LIST, ["tests/a.py::test_one"], rc=2)
    assert r.returncode == 2 and runs == 1


def test_list_line_without_issue_is_rejected(tmp_path):
    r, runs = run_flake(tmp_path, "tests/a.py::test_one\n", ["tests/a.py::test_one"])
    assert r.returncode != 0 and runs == 0


# ---- the workflow itself (CI-01 rules) --------------------------------------------------------------

def _jobs():
    body = "\n".join(l for l in WF.splitlines() if not l.lstrip().startswith("#")).split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", body)
    return dict(zip(parts[1::2], parts[2::2]))


def test_actions_are_pinned_to_shas():
    uses = re.findall(r"(?m)^\s*-?\s*uses:\s*(\S+)", WF)
    assert uses and all(re.fullmatch(r".+@[0-9a-f]{40}", u) for u in uses)


def test_no_expression_is_interpolated_into_a_run_block():
    for name, text in _jobs().items():
        for m in re.finditer(r"(?ms)^\s+run:\s*(?:\||>)?\s*\n?(.*?)(?=^\s+(?:- |[a-z-]+:)|\Z)", text):
            assert "${{" not in m.group(1), f"{name}: expression inside run:"


def test_retry_job_has_least_permissions_and_runs_no_repo_code():
    retry = _jobs()["retry"]
    assert re.search(r"(?m)^      actions: write$", retry) and "secrets." not in retry
    assert "checkout" not in retry and "scripts/" not in retry
    assert "needs.sign.outputs.retry == 'true'" in retry
    assert re.search(r"(?m)^permissions:\n  contents: read$", WF)


def test_every_listed_flake_has_an_issue_link():
    text = (ROOT / ".github" / "flaky-tests.txt").read_text()
    sys.path.insert(0, str(ROOT / "scripts" / "ci"))
    try:
        import flake_retry
    finally:
        sys.path.pop(0)
    assert flake_retry.load_list(text)
