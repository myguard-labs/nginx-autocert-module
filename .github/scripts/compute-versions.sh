#!/usr/bin/env bash
# sync-sha: dec2234912aea677cbd8ccf84ac3229cac6315ba82c363054b30d5ada87c7dba
# compute-versions.sh -- resolve the latest upstream versions + their sha256 and
# rewrite .github/versions.env in place. Used by bump.yml (weekly). Prints a
# short summary of what it resolved to stdout, which bump.yml quotes into the
# PR body.
#
# Resolves:
#   nginx mainline (odd minor) + stable (even minor)  -- nginx.org download page
#   Angie latest release                              -- GitHub API tag_name
#
# Angie is RESOLVED from the GitHub API (the only machine-readable index of
# Angie releases) but DOWNLOADED from download.angie.software, which is what
# ci/tools/ci-build.sh fetches. The two archives differ byte-for-byte, so the
# digest must come from the URL we actually build from -- hashing the GitHub
# tag archive here would pin a sha that never matches at build time.
#
# Run locally to preview a bump:  bash .github/scripts/compute-versions.sh
# (it rewrites versions.env; `git diff` to review, `git checkout` to discard).
#
# Requires: curl, jq, sha256sum. GITHUB_TOKEN honoured for API rate limits --
# unauthenticated api.github.com from a shared runner IP gets 403-throttled.
set -euo pipefail

VERSIONS_FILE=".github/versions.env"
FV=".github/scripts/fetch-verify.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

api() {
  local url="$1"
  # Same resilience budget as fetch-verify.sh: a transient blip or a stalled
  # connection must retry, not fail the weekly bump job or hang the runner.
  local -a opts=(-fsSL --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 300)
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl "${opts[@]}" -H "Authorization: Bearer $GITHUB_TOKEN" "$url"
  else
    curl "${opts[@]}" "$url"
  fi
}

# sha256 of a URL (download to scratch, hash). Fails the job on download error.
sha_of_url() {
  local url="$1" out="$tmp/dl.$RANDOM" sha
  # In "-" mode fetch-verify.sh sends progress text to stderr, so stdout is
  # exactly one "SHA  OUTFILE" line. Read the first field directly rather than
  # picking the last line out of mixed output -- an extra stdout line there
  # would otherwise be captured as a digest with no error.
  read -r sha _ < <(bash "$FV" "$url" - "$out")
  # Validate the shape rather than trusting position. Moving the progress text
  # to stderr fixes today's contamination; this catches the next one, because a
  # non-digest silently written into versions.env would pin every future build
  # to a value that can never match.
  if ! printf '%s' "$sha" | grep -qE '^[0-9a-f]{64}$'; then
    echo "::error::expected a sha256 from $FV for $url, got: ${sha:-<empty>}" >&2
    return 1
  fi
  printf '%s' "$sha"
}

echo "resolving nginx versions from nginx.org..."
dl_html="$(curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 300 \
  https://nginx.org/en/download.html)"
# nginx numbers mainline with an odd minor and stable with an even one. Take
# the highest of each rather than trusting page order.
NGX_MAINLINE="$(printf '%s' "$dl_html" | grep -oE 'nginx-1\.[0-9]+\.[0-9]+' \
  | awk -F. '$2%2==1' | sort -uV | tail -1 | sed 's/nginx-//')"
NGX_STABLE="$(printf '%s' "$dl_html" | grep -oE 'nginx-1\.[0-9]+\.[0-9]+' \
  | awk -F. '$2%2==0' | sort -uV | tail -1 | sed 's/nginx-//')"
[ -n "$NGX_MAINLINE" ] && [ -n "$NGX_STABLE" ] || { echo "::error::failed to resolve nginx versions" >&2; exit 1; }

echo "resolving Angie latest release..."
ANGIE_TAG="$(api 'https://api.github.com/repos/webserver-llc/angie/releases/latest' | jq -r '.tag_name')"
[ -n "$ANGIE_TAG" ] && [ "$ANGIE_TAG" != "null" ] || { echo "::error::failed to resolve Angie" >&2; exit 1; }
# Upstream tags releases "Angie-1.12.1"; ci-build.sh wants the bare version.
ANGIE="${ANGIE_TAG#Angie-}"
if ! printf '%s' "$ANGIE" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "::error::unexpected Angie tag format: $ANGIE_TAG" >&2
  exit 1
fi

echo "hashing archives..."
NGX_MAINLINE_SHA="$(sha_of_url "https://nginx.org/download/nginx-${NGX_MAINLINE}.tar.gz")"
NGX_STABLE_SHA="$(sha_of_url "https://nginx.org/download/nginx-${NGX_STABLE}.tar.gz")"
ANGIE_SHA="$(sha_of_url "https://download.angie.software/files/angie-${ANGIE}.tar.gz")"

cat > "$VERSIONS_FILE" <<EOF
# Central version + sha256 pins for all CI workflows.
#
# SINGLE SOURCE OF TRUTH. Every workflow loads this file into \$GITHUB_ENV as its
# first step (via .github/scripts/load-versions.sh); the weekly bump.yml job
# rewrites it and opens a PR. Tarballs are pinned by version string (release
# archives are immutable) AND verified against the sha256 recorded here, so a
# compromised or changed upstream archive fails the build instead of being
# compiled.
#
# Version and digest live on adjacent lines on purpose: they are bumped by one
# writer (compute-versions.sh) in one file, so a version can no longer move
# while its digest stays behind.
#
# Regenerate with .github/scripts/compute-versions.sh (bump.yml runs it weekly).
# Keep KEY=value, no spaces, no quotes -- this file is both \`source\`d by
# ci/tools/ci-build.sh and \`cat\`d into \$GITHUB_ENV.

# nginx mainline (odd minor) -- the default build everywhere; also the
# ci-deep "mainline" matrix cell.
NGINX_MAINLINE=${NGX_MAINLINE}
NGINX_MAINLINE_SHA256=${NGX_MAINLINE_SHA}

# nginx stable (even minor) -- ci-deep "stable" matrix cell only.
NGINX_STABLE=${NGX_STABLE}
NGINX_STABLE_SHA256=${NGX_STABLE_SHA}

# nginx version used by every single-version job (build-test, asan, valgrind,
# codeql, fuzzing, security-scanners, ci-deep memcheck). Tracks mainline.
NGINX_VERSION=${NGX_MAINLINE}
NGINX_VERSION_SHA256=${NGX_MAINLINE_SHA}

# Angie (webserver-llc) -- ci-deep "angie" matrix cell. Pinned to the tarball
# from download.angie.software, NOT the GitHub tag archive: different bytes,
# so this digest is not interchangeable with a github.com/webserver-llc one.
# ANGIE_VERSION is the bare version; the upstream release tag is "Angie-<ver>".
ANGIE_VERSION=${ANGIE}
ANGIE_SHA256=${ANGIE_SHA}
EOF

echo "----- resolved -----"
echo "nginx mainline: ${NGX_MAINLINE}"
echo "nginx stable:   ${NGX_STABLE}"
echo "angie:          ${ANGIE}"
