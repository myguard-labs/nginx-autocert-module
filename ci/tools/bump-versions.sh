#!/usr/bin/env bash
#
# Refresh the upstream version pins in .github/versions.env. Called by
# .github/workflows/bump.yml on a schedule; also runnable locally to preview a
# bump before it lands.
#
#   ci/tools/bump-versions.sh [--dry-run]
#
# One thing moves here:
#   - .github/versions.env  -- nginx mainline/stable + angie versions AND their
#                              sha256s, rewritten wholesale by
#                              .github/scripts/compute-versions.sh
#
# ADAPTED FROM THE SKELETON (nginx-skeleton-module, 2026-08-09). The reference
# version also bumps GitHub Action sha pins (ci/tools/bump-actions.sh), pinned
# linter versions (ci/tools/bump-tools.sh) and a vendored ci/vendor/nginx-tests
# submodule. This repo has none of those three: no bump-actions.sh, no
# bump-tools.sh, and no submodules at all (`git submodule status` is empty), so
# adopting those lanes would mean inventing tooling, not porting it. Each is a
# separate, independently reviewable change; they are recorded in the memory
# mirror's TODO.md rather than stubbed here. Keeping the script honest about
# what it actually does beats a copy with three dead branches in it.
#
# Version and digest are written on adjacent lines by one writer, so a version
# cannot move while its digest stays behind.
#
# --dry-run reports what WOULD change without writing anything: versions.env is
# regenerated into a scratch copy and diffed.
#
# Exit status is 0 whether or not anything changed; the caller decides what to
# do with a dirty tree. Prints CHANGED=0|1 as its last line.
#
# GH_TOKEN is honoured (passed through to compute-versions.sh as GITHUB_TOKEN):
# the runners share an egress IP, so unauthenticated api.github.com calls are
# routinely rate-limited to 403s.

set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

cd "$(dirname "$0")/../.."

# compute-versions.sh reads GITHUB_TOKEN; bump.yml sets GH_TOKEN.
export GITHUB_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

CHANGED=0
VERSIONS_FILE=".github/versions.env"

# --- version + sha256 pins -------------------------------------------------
if [ "$DRY_RUN" = 0 ]; then
    # Tolerate a missing file: compute-versions.sh creates it from scratch, so
    # bootstrapping (or regenerating after a delete) should report "changed"
    # rather than dying here under set -e.
    before="$(cat "$VERSIONS_FILE" 2>/dev/null || true)"
    bash .github/scripts/compute-versions.sh
    if [ "$before" != "$(cat "$VERSIONS_FILE")" ]; then
        echo "--- versions.env changed ---"
        git --no-pager diff -- "$VERSIONS_FILE" || true
        CHANGED=1
    else
        echo "versions.env already up to date"
    fi
else
    # Regenerate into a scratch copy so the working tree is untouched.
    scratch="$(mktemp -d)"
    trap 'rm -rf "$scratch"' EXIT
    cp -a .github "$scratch/.github"
    ( cd "$scratch" && bash .github/scripts/compute-versions.sh >/dev/null )
    if diff -u "$VERSIONS_FILE" "$scratch/$VERSIONS_FILE"; then
        echo "(dry-run: versions.env already up to date)"
    else
        echo "(dry-run: versions.env would change as shown above)"
        CHANGED=1
    fi
fi

if [ "$CHANGED" = 0 ]; then
    echo "everything up to date, nothing to bump"
fi

echo "CHANGED=$CHANGED"
