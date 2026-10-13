#!/usr/bin/env bash
# Hive Mind session telemetry hook.
#
# Records Claude Code session start/end into the LOCAL telemetry lane via
# `hwatch telemetry record` — NOT into the facts corpus. Telemetry is observability
# (who/where/when + token usage + cost), not knowledge; it lives in its own
# local-only store (.telemetry/) and never enters the journal/merkle. Wired from
# the GLOBAL ~/.claude/settings.json so it fires for every Claude Code session.
#
# Session telemetry is the hwatch module's (`hv telemetry` was removed in 4.0). This hook runs the module directly and
# is a silent no-op when it is not installed.
#
# Contract: best-effort and NON-BLOCKING. Every path exits 0 and the module call is
# capped with `timeout`, so it can never fail or slow a session.
#
# Usage (from settings.json):  session_hook.sh start  |  session_hook.sh end
# Reads the hook JSON on stdin (cwd + session_id).

event="${1:-start}"

# The module's command: through the control plane when it is on PATH, else the module's own launcher. Neither: do nothing.
if command -v hive-mind >/dev/null 2>&1; then
    set -- hive-mind module run hwatch -- telemetry record
elif command -v hwatch >/dev/null 2>&1; then
    set -- hwatch telemetry record
else
    exit 0
fi

# Pull cwd + session id out of the hook's stdin JSON (best-effort; python3 is
# always present since hv itself is python). Two lines so a cwd with spaces is safe.
parsed=$(python3 -c 'import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get("cwd", ""))
    print(d.get("session_id") or d.get("sessionId") or "")
except Exception:
    print(); print()' 2>/dev/null)
cwd=$(printf '%s\n' "$parsed" | sed -n '1p')
sid=$(printf '%s\n' "$parsed" | sed -n '2p')
[ -n "$cwd" ] || cwd="$PWD"

node="$(hostname 2>/dev/null || echo node)"
user="$(id -un 2>/dev/null || echo "${USER:-user}")"

# Record into the telemetry lane. --identity keeps this instance distinct from
# other agents (and other machines) sharing the "claude-code" name; hwatch also
# captures node/os_user/ip and, on end, token usage + cost from the transcript.
# macOS has no `timeout` (coreutils' is `gtimeout`): fall back to a python3 cap so the 12s bound holds there too.
if command -v timeout >/dev/null 2>&1; then
    cap() { timeout 12 "$@"; }
elif command -v gtimeout >/dev/null 2>&1; then
    cap() { gtimeout 12 "$@"; }
else
    cap() { python3 -c 'import subprocess, sys
try:
    sys.exit(subprocess.run(sys.argv[1:], timeout=12).returncode)
except Exception:
    sys.exit(124)' "$@"; }
fi
cap "$@" \
    --event "$event" \
    --agent claude-code \
    --identity "${user}@${node}" \
    --session "$sid" \
    --cwd "$cwd" \
    </dev/null >/dev/null 2>&1 || true

exit 0
