#!/usr/bin/env python3
"""Run the test suite; re-run once, and only, the failures that are on the pinned flake list.

    flake_retry.py --list .github/flaky-tests.txt -- python3 -m pytest -q -n auto

The command is run with `-rfE` added. If it exits 0, so do we. If it exits 1 and EVERY failed or errored
test is on the list (each list line: a pytest id, then `# <issue url>`), the command is run once more with
just those ids. Anything else (exit 2+, an unlisted failure, a failure count the summary lines do not
account for) fails as it would have. One retry, never a loop."""
import re
import subprocess
import sys

ISSUE = re.compile(r"#\s*(https://github\.com/[\w.-]+/[\w.-]+/issues/\d+)\s*$")
FAIL_LINE = re.compile(r"^(?:FAILED|ERROR) (.+?)(?: - .*)?$")
COUNT = re.compile(r"(\d+) (failed|errors?)\b")


def load_list(text):
    ids = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = ISSUE.search(line)
        if not m:
            raise ValueError(f"flake list line {n} has no issue link: {raw!r}")
        test_id = line[:m.start()].strip()
        if not test_id or " " in test_id:
            raise ValueError(f"flake list line {n} is not one test id: {raw!r}")
        ids.append(test_id)
    return ids


def listed(test_id, ids):
    return any(test_id == i or test_id.startswith(i + "[") for i in ids)


def failures(output):
    """(failed ids from the short summary, number of failed+errored tests the final line reports)."""
    ids = [m.group(1) for l in output.splitlines() if (m := FAIL_LINE.match(l.strip()))]
    last = [l for l in output.splitlines() if COUNT.search(l)]
    reported = sum(int(n) for n, _ in COUNT.findall(last[-1])) if last else -1
    return ids, reported


def main(argv):
    if "--" not in argv or argv[:1] != ["--list"] or len(argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    list_path, cmd = argv[1], argv[argv.index("--") + 1:]
    with open(list_path) as f:
        flaky = load_list(f.read())
    first = subprocess.run(cmd + ["-rfE"], capture_output=True, text=True)
    sys.stdout.write(first.stdout)
    sys.stderr.write(first.stderr)
    if first.returncode == 0:
        return 0
    failed, reported = failures(first.stdout)
    if first.returncode != 1 or not failed or len(failed) != reported or not all(listed(t, flaky) for t in failed):
        print("flake_retry: failure is not wholly on the pinned flake list; not retrying", file=sys.stderr)
        return first.returncode
    print(f"::notice::flake_retry: re-running {len(set(failed))} listed flaky test(s) once")
    second = subprocess.run(cmd + sorted(set(failed)), text=True)
    return second.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
