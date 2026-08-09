#!/usr/bin/env bash
# sync-sha: 6e84b7c8cb73f9c86aa7362a7aa923b82eea4044d86a1987f20854d576975279
# fetch-verify.sh URL EXPECTED_SHA256 OUTFILE
#
# Download URL to OUTFILE and verify its sha256 against EXPECTED_SHA256.
# On mismatch: print the actual sha and exit 1 (fails the CI job — a changed
# or tampered upstream archive never reaches the build).
#
# Pass EXPECTED_SHA256="-" to skip verification and just print the computed
# sha (used by bump.yml to harvest fresh hashes for a version bump).
#
# If OUTFILE already exists with the right sha (warm actions/cache hit) the
# download is skipped — the sha check still runs, so a poisoned cache is caught.
set -euo pipefail

url="${1:?usage: fetch-verify.sh URL SHA256 OUTFILE}"
want="${2:?missing expected sha256}"
out="${3:?missing output path}"

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

if [ -f "$out" ] && [ "$want" != "-" ] && [ "$(sha_of "$out")" = "$want" ]; then
  echo "cache hit (sha ok): $out"
  exit 0
fi

# stderr, not stdout: in "-" mode stdout must carry ONLY the final
# "$got  $out" line, which compute-versions.sh reads as the digest.
echo "downloading: $url" >&2
# -f: fail on HTTP errors; -S: show errors; -L: follow redirects; retries.
# --connect-timeout/--max-time: a stalled upstream must not hold a runner open.
curl -fSL --retry 3 --retry-delay 2 \
  --connect-timeout 30 --max-time 300 -o "$out" "$url"

got="$(sha_of "$out")"
if [ "$want" = "-" ]; then
  echo "$got  $out"
  exit 0
fi

if [ "$got" != "$want" ]; then
  echo "::error::sha256 MISMATCH for $url" >&2
  echo "  expected: $want" >&2
  echo "  actual:   $got" >&2
  exit 1
fi
echo "sha256 verified: $out"
