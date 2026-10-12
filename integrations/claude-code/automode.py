#!/usr/bin/env python3
"""Install / remove the hive-mind Claude Code auto-mode "operator" profile in settings.json.

Claude Code's auto-mode classifier only knows what `autoMode.environment` tells it; without it the
operator's routine long-lived watchers (driver-watch, hwatch) get refused. This merges a small,
versioned set of environment lines into <claude dir>/settings.json.

Merge, never clobber: our lines carry the MARK prefix and are the only ones this script ever adds,
replaces or removes; every other key and every user line is left as-is. Re-running is a no-op (the file is
not even rewritten). A settings.json that is not a JSON object is left untouched.

    automode.py install   <hive-checkout> [--claude-dir DIR]
    automode.py uninstall [--claude-dir DIR]
    automode.py check     <hive-checkout> [--claude-dir DIR]   # exit 1 when out of date
"""
import json
import os
import sys
import tempfile
from pathlib import Path

VERSION = 1
MARK = "[hive-managed v%d] " % VERSION
_ANY_MARK = "[hive-managed"          # any version: a newer profile replaces an older one


def profile(hive_dir):
    return [MARK + line for line in (
        "The operator runs hive-mind (checkout at %s; GitHub org projectmentor, repos "
        "projectmentor/hive-mind and its module repos) on purpose. Its CLIs are operator tools: "
        "hv, hive-mind (including `hive-mind module config`), and ssh to other admitted nodes." % hive_dir,
        "Long-lived background watchers (driver-watch, hwatch) started with run_in_background are "
        "intended and routine, not unsafe agent creation.",
    )]


def _is_ours(line):
    return isinstance(line, str) and line.startswith(_ANY_MARK)


def _load(path):
    if not path.exists():
        return {}
    try:
        cfg = json.loads(path.read_text())
    except Exception:
        return None
    return cfg if isinstance(cfg, dict) else None


def _merged(cfg, lines):
    """Return cfg with our lines replaced by `lines` (empty -> removed); None if not mergeable."""
    am = cfg.get("autoMode", {})
    if not isinstance(am, dict):
        return None
    env = am.get("environment", [])
    if not isinstance(env, list):
        return None
    new = [l for l in env if not _is_ours(l)] + list(lines)
    out = dict(cfg)
    am = dict(am)
    if new:
        am["environment"] = new
    else:
        am.pop("environment", None)
    if am:
        out["autoMode"] = am
    else:
        out.pop("autoMode", None)
    return out


def _write(path, cfg):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".settings.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(cfg, indent=2) + "\n")
        if path.exists():
            os.chmod(tmp, path.stat().st_mode & 0o777)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def run(action, hive_dir, claude_dir):
    path = Path(claude_dir) / "settings.json"
    cfg = _load(path)
    if cfg is None:
        print("auto-mode: %s is not a JSON object; left untouched" % path, file=sys.stderr)
        return 2
    want = profile(hive_dir) if action in ("install", "check") else []
    out = _merged(cfg, want)
    if out is None:
        print("auto-mode: autoMode.environment in %s has an unexpected shape; left untouched" % path,
              file=sys.stderr)
        return 2
    if out == cfg:
        print("auto-mode: %s already up to date" % path)
        return 0
    if action == "check":
        print("auto-mode: %s is out of date; run integrations/claude-code/install.sh" % path)
        return 1
    if path.exists():
        try:
            Path(str(path) + ".bak.automode").write_text(path.read_text())
        except OSError:
            pass
    _write(path, out)
    print("auto-mode: %s %s" % (path, "profile installed" if want else "profile removed"))
    return 0


def main(argv):
    args = list(argv)
    claude_dir = os.environ.get("CLAUDE_CONFIG_DIR") or str(Path.home() / ".claude")
    if "--claude-dir" in args:
        i = args.index("--claude-dir")
        claude_dir = args[i + 1]
        del args[i:i + 2]
    if not args or args[0] not in ("install", "uninstall", "check"):
        print(__doc__, file=sys.stderr)
        return 64
    if args[0] != "uninstall" and len(args) < 2:
        print(__doc__, file=sys.stderr)
        return 64
    return run(args[0], args[1] if len(args) > 1 else "", claude_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
