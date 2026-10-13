"""`hive-mind version`: which release, which commit, which contract, and whether that commit verifies (#468).

`hv version` stays the contract version for scripts. This answers the operator's question, "what is this node
running?", from the checkout itself: `git describe --tags` for the release, `git rev-parse HEAD` for the commit,
and the same `_verify_status` layers `hv verify` runs. Read-only. Never raises on a missing git or tag.
"""

import json
import re
import subprocess
from pathlib import Path

_DESCRIBE = re.compile(r"^(?P<tag>.+)-(?P<n>\d+)-g(?P<sha>[0-9a-f]+)$")


def _git(root, *args):
    try:
        r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def release_info(root):
    """{release, tag, commits_since_tag, commit, short}: release is `v3.1.1`, `v3.1.1+2 (aacadf9)` between tags,
    or None when the checkout has no tag or is not a git checkout."""
    commit = _git(root, "rev-parse", "HEAD")
    short = commit[:7] if commit else None
    out = {"release": None, "tag": None, "commits_since_tag": None, "commit": commit, "short": short}
    d = _git(root, "describe", "--tags", "--long")
    m = _DESCRIBE.match(d) if d else None
    if m:
        n = int(m["n"])
        out.update(tag=m["tag"], commits_since_tag=n,
                   release=m["tag"] if n == 0 else f"{m['tag']}+{n} ({short or m['sha']})")
    return out


def verify_state(lib, root):
    """(label, level) from `_verify_status`, the check `hv verify` prints. Official only when every layer holds."""
    try:
        level = lib._verify_status(Path(root))["level"]
    except Exception:
        return "not verified", "error"
    return ("Official" if level == "official" else "not verified"), level


def module_rows(lib):
    """[{name, version, publisher}] for each installed module; publisher is the key fingerprint prefix."""
    import hive_modules
    rows = []
    for name, rec in sorted(hive_modules.load_state(lib).items()):
        if not isinstance(rec, dict):
            continue
        try:
            pub = hive_modules.fingerprint(rec["publisher"])
        except Exception:
            pub = "?"
        rows.append({"name": name, "version": str(rec.get("version", "?")), "publisher": pub})
    return rows


def headline(info):
    return (f"hive-mind {info['release']}" if info["release"]
            else f"hive-mind (no release tag{', ' + info['short'] if info['short'] else ''})")


def main(lib, argv, root):
    """`version [--json] [--no-verify] [--brief]`. --brief is the `status` header: the line plus the modules, no verify."""
    flags = set(argv)
    bad = flags - {"--json", "--no-verify", "--brief", "-h", "--help"}
    if bad or "-h" in flags or "--help" in flags:
        print("Usage: hive-mind version [--json] [--no-verify]\n"
              "  Print the installed release, commit, contract version and verify state.\n"
              "  --no-verify skips the verify check (it makes one network request). `hv version` prints only the contract version.")
        return 0 if not bad else 2
    info = release_info(root)
    brief = "--brief" in flags
    if brief or "--no-verify" in flags:
        label, level = "not checked", None
    else:
        label, level = verify_state(lib, root)
    contract = lib.CONTRACT_VERSION
    if "--json" in flags:
        print(json.dumps({"release": info["release"], "tag": info["tag"], "commits_since_tag": info["commits_since_tag"],
                          "commit": info["commit"], "contract_version": contract, "verify": label,
                          "verify_level": level}, sort_keys=True))
        return 0
    if brief:
        print(f"{headline(info)}  commit {info['short'] or '?'}  contract {contract}")
        for r in module_rows(lib):
            print(f"  module {r['name']} {r['version']}  publisher {r['publisher']}")
        return 0
    print(headline(info))
    print(f"commit:   {info['commit'] or 'unknown'}")
    print(f"contract: {contract}")
    print(f"verify:   {label}" + (f" ({level})" if level and level != "official" else ""))
    return 0
