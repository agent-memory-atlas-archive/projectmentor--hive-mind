#!/usr/bin/env bash
# =============================================================================
# _units.sh — single source of truth for the hive-mind systemd USER units.
#
# Sourced by _install_node.sh (fresh install) and _update.sh (so already-
# installed nodes re-apply the hardened daemon unit + the self-heal timer on
# `hive-mind update`, not only on a fresh install).
#
# All functions are idempotent: re-running overwrites the unit files in place
# and reloads. A child process cannot reload its parent shell, but it CAN own
# the daemon's lifecycle — so systemd is made the sole, self-cleaning owner.
# =============================================================================

# write_systemd_units <hive_dir> [service_name]
#   Writes hive-sync.service (hardened), hive-doctor.service + hive-doctor.timer
#   (periodic `hv doctor --fix` self-heal), then reloads + enables them.
#   No-op (returns 0) when there is no usable user systemd manager — so callers
#   that don't track INIT_SYSTEM (e.g. _update.sh) can call it unconditionally.
write_systemd_units() {
  local hive_dir="$1" svc="${2:-hive-sync}"

  # A wrong/empty hive_dir would write a broken ExecStart (e.g. /hive_sync_daemon.py).
  if [ -z "$hive_dir" ] || [ ! -f "$hive_dir/hive_sync_daemon.py" ]; then
    echo "write_systemd_units: invalid hive_dir '$hive_dir' (no hive_sync_daemon.py)" >&2
    return 1
  fi

  # Only act when a user systemd bus is actually reachable.
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl --user show-environment >/dev/null 2>&1 || return 0

  local unit_dir="$HOME/.config/systemd/user"
  mkdir -p "$unit_dir"

  # ── the sync daemon, hardened ──────────────────────────────────────────────
  # ExecStartPre kills any EXTERNAL stray daemon (started outside systemd, e.g.
  # an old install or a manual run) before the managed one starts — on a restart
  # systemd has already torn down its own control-group, and the new process has
  # not forked yet, so this only ever hits true orphans. Frees port 9876 for the
  # canonical daemon. The pattern is anchored to the python interpreter running
  # hive_sync_daemon.py (how every launch path starts it) so it can't match an editor,
  # tail, or grep that merely mentions the filename. KillMode=control-group reaps
  # the whole tree (no zombies). Restart=always + a generous StartLimit keep it up
  # without a tight crash loop.
  cat > "$unit_dir/$svc.service" << UNIT
[Unit]
Description=Hive Mind sync daemon
After=network.target
StartLimitIntervalSec=300
StartLimitBurst=20

[Service]
Type=simple
WorkingDirectory=$hive_dir
ExecStartPre=-/usr/bin/pkill -f python3.*hive_sync_daemon.py
ExecStart=/usr/bin/python3 $hive_dir/hive_sync_daemon.py
Restart=always
RestartSec=5
KillMode=control-group
StandardOutput=journal
StandardError=journal
Environment=HIVE_HOME=$hive_dir

[Install]
WantedBy=default.target
UNIT

  # ── self-heal oneshot: `hv doctor --fix` (no-op when healthy) ───────────────
  cat > "$unit_dir/hive-doctor.service" << UNIT
[Unit]
Description=Hive Mind self-heal (hv doctor --fix)
After=network.target

[Service]
Type=oneshot
WorkingDirectory=$hive_dir
ExecStart=/usr/bin/python3 $hive_dir/hv doctor --fix
Environment=HIVE_HOME=$hive_dir
Environment=HIVE_DOCTOR_MODE=timer
StandardOutput=journal
StandardError=journal
UNIT

  # ── boot pass: `hv doctor --boot` once per boot, after the sync daemon is asked for ───────
  # The same doctor as the timer (no second code path): it waits, within a bound, for the daemon to answer, checks,
  # fixes, rechecks and records one `boot` fact. Wants= (not Requires=): a daemon that fails must still be reported.
  cat > "$unit_dir/hive-doctor-boot.service" << UNIT
[Unit]
Description=Hive Mind boot pass (hv doctor --boot)
After=network.target hive-sync.service
Wants=hive-sync.service

[Service]
Type=exec
WorkingDirectory=$hive_dir
ExecStart=/usr/bin/python3 $hive_dir/hv doctor --boot
Environment=HIVE_HOME=$hive_dir
Environment=HIVE_DOCTOR_MODE=boot
TimeoutStartSec=600
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
UNIT

  # ── timer: heal shortly after boot, then every 15 min ──────────────────────
  cat > "$unit_dir/hive-doctor.timer" << UNIT
[Unit]
Description=Run hive doctor --fix on boot and periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

  systemctl --user daemon-reload
  systemctl --user enable "$svc" --quiet 2>/dev/null || true
  systemctl --user enable --now hive-doctor.timer --quiet 2>/dev/null || true
  systemctl --user enable hive-doctor-boot.service --quiet 2>/dev/null || true
  write_wsl_logon_task
}

# write_wsl_logon_task
#   WSL2 only: a Windows logon task that starts this distro, so the user units (and the boot pass) run after a reboot
#   without anyone opening a terminal. Idempotent (/F replaces); a no-op anywhere else, or without schtasks.exe.
#   The distro and user names go into a command line, so anything but a plain name is refused rather than quoted.
write_wsl_logon_task() {
  grep -qi microsoft "${HIVE_PROC_VERSION:-/proc/version}" 2>/dev/null || return 0
  command -v schtasks.exe >/dev/null 2>&1 || return 0
  local distro="${WSL_DISTRO_NAME:-}" user
  user="$(id -un)"
  case "$distro$user" in *[!A-Za-z0-9._-]*|"") return 0 ;; esac
  [ -n "$distro" ] && [ -n "$user" ] || return 0
  schtasks.exe /Create /F /SC ONLOGON /RL LIMITED /TN "HiveMind-WSL-$distro" \
    /TR "wsl.exe -d $distro -u $user --exec /usr/bin/sleep infinity" >/dev/null 2>&1 || true
}
