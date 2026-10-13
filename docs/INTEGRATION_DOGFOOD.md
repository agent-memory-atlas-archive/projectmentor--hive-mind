# Release dogfood checklist

The integration suite (`tests/integration`, `pytest -m integration`) covers what a CI runner can reproduce without credentials, a
device or a network we do not own. This list is the rest. The driver runs it by hand on the real fleet before a release; a
failed item blocks the release the way a red CI job does. Each item is a few commands and the output to expect.

Rules: use a throwaway GitHub repo and a throwaway node directory (`HIVE_HOME=$(mktemp -d)`) for anything that writes; never
the real hive, the real publisher seed or a real repo. Do not paste tokens or seeds into a report. Note the result of each item
(pass, fail, not run and why) on the release PR.

Not here: anything the suite already proves (sync convergence and refusals, module install of fixtures, the owner agent, the
`timeout`-less session hook, restart exactly-once).

## 1. Real tailnet and `tailscale serve`

1. On two nodes of the fleet: `tailscale status` lists both. On node A: `hv sync auth` shows `enforce`.
2. `hv remember "dogfood $(date +%s)" --tags dogfood` on A, then `hv sync now` on B. Expect `1 peer(s)` and no `unreachable`.
3. `hv doctor` on both: no `sync-bind` or `sync-daemon` failure; the daemon is bound to the tailnet address, not `0.0.0.0`.
4. Where the dashboard is published: `tailscale serve status` shows it; the URL loads from a second device, and an unsigned request
   to `/sync/chunk` over the tailnet address returns `401`.

## 2. Real GitHub, throwaway repo

1. Create a private throwaway repo, add a seat and a PR from branch X to `main`, post `**Verifier:** head <sha>` on it.
2. `hwatch wait` on the verifier seat returns once, with that ref. Restart the hwatch service (`hive-mind update`) while the seat
   runs: no second session for the same ref (`choice.jsonl` has one row per ref).
3. Stack a second PR on X's branch. Merge X with `--merge`, retarget the stack: no wake on the child as new. Repeat with a squash
   merge: the child shows the base's commits, as in hive-mind#435. Delete the repo.

## 3. Real `claude` and `grok`

1. `claude -p "reply with ok"` and `grok` equivalent, from a seat's launcher: each exits 0 and prints a reply. The session hook
   records a start and an end row (`hv telemetry` shows both).
2. A seat launched through `hwatch` runs under its own uid and cannot read the owner's key directory.

## 4. Termux / runit on a phone

1. `hive-mind install` completes; `sv status` lists the sync service as `run`.
2. Kill the daemon (`sv kill hive-sync`); runit restarts it within 10 s and `hv sync now` still works.
3. `hv doctor` reports no platform failure.

## 5. Windows portproxy

1. From Windows, `netsh interface portproxy show v4tov4` lists the sync port to the WSL address.
2. A peer on the tailnet reaches `http://<windows-tailnet-ip>:<port>/sync/hello`; after a Windows reboot the proxy rule is still
   present and `hv sync now` from WSL reaches the peer.

## 6. macOS launchd (the CI runner has no login session)

1. `hive-mind install`; `launchctl print gui/$UID/com.projectmentor.hive-sync` shows `state = running`.
2. Reboot: the service is running again without a login shell. `hv doctor` is clean.
3. `PATH` without coreutils (`env -i PATH=/usr/bin:/bin ...`): a session start still records telemetry.

## 7. Hosted relay

Only if one exists: skipped until then.
