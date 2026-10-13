#!/usr/bin/env bash
# Guards for .github/workflows/sign.yml's push of the re-signed manifest. Writes `state=` (and `retry=`) to
# $GITHUB_OUTPUT (stdout when unset). No secret is read; the workflow passes only the remote, the branch and
# the retry_of input, as arguments or env, never interpolated into the shell.
#
#   sign_push.sh tip    REMOTE BRANCH      state=current when HEAD is the remote branch tip, else state=stale
#   sign_push.sh push   REMOTE BRANCH      commit verify.json(.sig) if changed and push it. state=pushed|unchanged|
#                                          stale (tip moved before the commit) | raced (push rejected because the
#                                          tip moved). Any other push failure fails the step.
#
# retry=true is emitted for stale/raced unless RETRY_OF is non-empty (this run IS the one retry), so a head is
# retried once: the dispatched run never dispatches.
set -euo pipefail
out() { echo "$1" >> "${GITHUB_OUTPUT:-/dev/stdout}"; }
mode=${1:?mode}; remote=${2:?remote}; branch=${3:?branch}
retry_flag() {
  if [ -n "${RETRY_OF:-}" ]; then out retry=false; else out retry=true; fi
}
tip() { git ls-remote --exit-code "$remote" "refs/heads/$branch" | cut -f1; }
head=$(git rev-parse HEAD)
case "$mode" in
  tip)
    if [ "$(tip)" = "$head" ]; then out state=current; out retry=false
    else echo "HEAD $head is not the tip of $remote/$branch; not signing it"; out state=stale; retry_flag; fi ;;
  push)
    if [ "$(tip)" != "$head" ]; then echo "tip moved; not signing"; out state=stale; retry_flag; exit 0; fi
    git add verify.json
    [ -f verify.json.sig ] && git add verify.json.sig
    if git diff --cached --quiet; then echo "manifest already current; nothing to commit"; out state=unchanged; out retry=false; exit 0; fi
    # [skip ci] matters: an App token's push DOES trigger workflows; the path filter also keeps this commit
    # from re-running sign.yml.
    git commit -m "chore: re-sign source manifest [skip ci]"
    if git push "$remote" "HEAD:refs/heads/$branch"; then out state=pushed; out retry=false; exit 0; fi
    # Rejected. It is a race only if the branch moved past the commit we signed; anything else is a real failure.
    now=$(tip || true)
    if [ -n "$now" ] && [ "$now" != "$head" ]; then
      echo "push rejected: $branch moved from $head to $now"; out state=raced; retry_flag; exit 0
    fi
    echo "push rejected and $branch did not move" >&2; exit 1 ;;
  *) echo "unknown mode $mode" >&2; exit 2 ;;
esac
