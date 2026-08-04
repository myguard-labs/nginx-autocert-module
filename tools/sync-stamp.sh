#!/usr/bin/env bash
# sync-stamp.sh -- content-hash stamp for the CI files copied from the skeleton.
#
# THE PROBLEM. This module's .github/ tree was adopted from
# labs/nginx-skeleton-module and then edited locally. Neither side has a cheap
# way to answer "is our copy of build-test.yml still the one the skeleton ships,
# or did we edit it / did the skeleton move?" -- short of diffing every file by
# hand. The stamps make that a sha comparison: `--list` on both repos, diff the
# two outputs, and every drifted file names itself.
#
# WHY A HASH, NOT A TIMESTAMP. A `# updated: 2026-08-04` header answers "when
# did someone touch this", which is not the question. It moves on no-op
# reformats, it does NOT move when a file is edited without discipline, and two
# repos with identical content can carry different dates -- so a human still has
# to diff to find out. A content hash answers the actual question, mechanically:
# equal sha means equal content, no judgement involved. It is the same reasoning
# .github/versions.env already applies to tarballs, and install-linters.sh to
# the actionlint binary: pin the CONTENT, not a label describing it.
#
# THE SELF-REFERENCE. A hash of a file cannot live in that file -- writing it
# changes the content it describes. So the stamp line itself is EXCLUDED from
# the digest: the hash covers the file with its `# sync-sha:` line removed. That
# makes it stable across re-stamping and lets `--check` recompute it in place.
#
# Usage:
#   tools/sync-stamp.sh            # rewrite every stamp (use after editing)
#   tools/sync-stamp.sh --check    # verify; exit 1 on any stale/missing stamp
#   tools/sync-stamp.sh --list     # print path<TAB>sha, for a consuming repo
#
# --check is what CI runs: it fails when a tracked file was edited without
# re-stamping, so the stamps cannot rot into decoration.
#
# SCOPE: the files actually shared with the skeleton -- workflows, the scripts
# they call, and composite actions. tools/ is NOT stamped; it is a much wider
# surface carrying this module's own name, paths and thresholds throughout, so
# it drifts from the skeleton by design and a stamp on it would report drift
# that is the intended state.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

MODE=stamp
case "${1:-}" in
    --check) MODE=check ;;
    --list) MODE=list ;;
    # Anchor to the end of the header block, not a line number: any edit to the
    # comments above would otherwise silently truncate this output.
    -h | --help)
        sed -n '2,/^set -/{/^set -/!p;}' "$0"
        exit 0
        ;;
    "") ;;
    *)
        echo "unknown argument: $1" >&2
        exit 2
        ;;
esac

# NUL-delimited: paths with spaces must not split. -print0/-d '' throughout.
#
# Sorted, and both YAML spellings. `--list` is documented above as a two-repo
# diff, so the order must not depend on directory order -- two checkouts holding
# identical files would otherwise produce a diff made entirely of moved lines.
# GitHub honours .yml and .yaml alike; matching only one lets a file be added
# under the other spelling and never enter the gate.
# Prints the NUL-delimited list on stdout, non-zero if any find failed. The
# caller redirects this to a file rather than capturing it: a command
# substitution would strip the NUL bytes that keep the paths apart.
#
# REQUIRED vs OPTIONAL. .github/workflows must exist -- it is where the gate
# itself lives, so a checkout without it is broken rather than differently
# shaped. .github/scripts and .github/actions are genuinely optional: a module
# with no composite action and no shell script under .github/ is a normal,
# complete layout. Five of this family's repos have neither.
#
# Absence is tested EXPLICITLY rather than inferred from find's exit status,
# because find cannot tell the cases apart -- a missing directory and an
# unreadable one both exit 1 (verified on GNU findutils and on bfs). Testing
# first means a directory that exists but cannot be scanned (permissions, I/O
# error) still fails hard and still trips the "refusing to report a partial
# result" guard below. That guard is the property that makes this variant
# canonical, and tolerating a missing path must not weaken it.
# Only "the path is simply not there" is tolerated.
#
# Four states, and only the last one is forgiven:
#   -L          any symlink, resolving or dangling  -> error
#   -d          a real directory                    -> scan it
#   -e, not -d  present but not a directory         -> error
#   none        genuinely absent                    -> contribute nothing
#
# The -L arm is not theoretical tidiness, and it is checked FIRST. `find "$d"`
# does not descend through a symlinked starting point, so a .github/scripts
# symlink pointing at a real directory passes -d and then matches zero files --
# --check reports success while gating nothing. A dangling symlink is just as
# bad in the other direction: -d and -e both follow, so it would read as
# "absent" and skip a directory somebody meant to be there, and `find` exits 0
# on it anyway. Rejecting every symlink covers both without an -H escape hatch
# that would then need its own containment check against the repo root.
optional_find() {
    local d="$1"
    shift
    # Symlinks are rejected BEFORE -d, dangling or not. `find "$d"` does not
    # descend through a symlinked starting point, so a `.github/scripts`
    # symlink pointing at a real directory passes -d and then yields NO files:
    # --check would report success while covering nothing. That is the exact
    # silent-shrink this gate exists to prevent, so a symlink is an error
    # rather than something to paper over with -H.
    if [ -L "$d" ]; then
        echo "sync-stamp: $d is a symlink; expected a real directory" >&2
        return 1
    fi
    if [ -d "$d" ]; then
        find "$d" "$@" -print0
        return
    fi
    # Present but not a directory: `find` over a regular file SUCCEEDS and
    # matches nothing, so an -e test alone would let a stray `.github/scripts`
    # file read as "no scripts here" and silently shrink the gate.
    if [ -e "$d" ]; then
        echo "sync-stamp: $d exists but is not a directory" >&2
        return 1
    fi
    return 0
}

targets() {
    find .github/workflows -maxdepth 1 \( -name '*.yml' -o -name '*.yaml' \) -print0 &&
        optional_find .github/scripts -maxdepth 1 -name '*.sh' &&
        optional_find .github/actions \( -name 'action.yml' -o -name 'action.yaml' \)
}

# The digest of a file with its own stamp line stripped -- see THE
# SELF-REFERENCE above.
content_sha() {
    grep -v '^# sync-sha: ' -- "$1" | sha256sum | cut -d' ' -f1
}

stamp_of() {
    sed -n 's/^# sync-sha: \([0-9a-f]\{64\}\)$/\1/p' -- "$1" | head -1
}

# A file must carry exactly one stamp. content_sha() strips EVERY stamp line
# while stamp_of() reads only the first, so a second line -- appended by a bad
# merge, or injected to launder an edit past the gate -- is invisible to both
# and --check would pass. Count them separately and reject more than one.
stamp_count() {
    grep -c '^# sync-sha: ' -- "$1" || true
}

# Insert the stamp as a LONE line, adding no blank line of its own.
#
# The blank line matters more than it looks. content_sha() strips only the
# `# sync-sha: ` line, so anything else this function adds becomes part of the
# content and changes the very digest just recorded -- every file then reads
# STALE the instant after it was stamped. (Observed: the first version printed
# a trailing "" and all 14 files failed --check immediately.) So: insert one
# line, remove one line, and the operation is exactly invertible.
#
# Placement: after a shebang if there is one (it must stay line 1), otherwise
# at the very top. Not "after the leading comment block" -- .github/workflows
# files start with `name:` and their comments come after it, so there is no
# single header shape to aim for, and the top is unambiguous for a reader
# looking to compare two repos' copies.
# Any existing stamp is dropped in the same awk pass, so re-stamping cannot
# accumulate lines and the strip filter is expressed in exactly one place.
insert_stamp() {
    local f="$1" sha="$2" tmp
    tmp="$(mktemp)"
    # RETURN, not EXIT: this runs per file, and an EXIT trap here would replace
    # the one guarding $raw_list.
    trap 'rm -f "$tmp"' RETURN
    # Keyed on the first SURVIVING line, not on NR == 1. Stripping an existing
    # stamp with `next` used to consume line 1 before the insert rule could
    # look at it, so `done` stayed 0 and the END block appended the stamp at the
    # BOTTOM of the file. --check still passed (stamp_of takes the first match
    # anywhere), so the stamp silently migrated to the end on every re-stamp
    # and the documented "top of the file" placement quietly stopped holding.
    awk -v sha="$sha" '
        /^# sync-sha: / { next }
        !done && /^#!/ { print; print "# sync-sha: " sha; done = 1; next }
        !done { print "# sync-sha: " sha; done = 1 }
        { print }
        END { if (!done) print "# sync-sha: " sha }
    ' "$f" >"$tmp"
    # Write back through the original file rather than mv'ing over it: the mode,
    # owner and inode are kept with no chmod --reference (GNU-only) and no
    # cross-filesystem mv. .github/scripts/*.sh must stay executable.
    cat "$tmp" >"$f"
}

# A process substitution discards the exit status of what runs inside it. With
# targets() piped straight into the loop, a find that aborts under `set -e`
# -- a renamed or removed .github/actions, say -- reaches the loop as a plain
# EOF: the files found BEFORE the failure are checked, `count` is non-zero, and
# --check reports "all N file(s) current" while silently covering fewer files
# than it should. Materialising the list first makes that failure catchable.
raw_list="$(mktemp)"
trap 'rm -f "$raw_list"' EXIT
if ! targets >"$raw_list"; then
    echo "sync-stamp: target discovery failed -- refusing to report a partial result" >&2
    exit 2
fi

targets_list=()
mapfile -t -d '' targets_list < <(LC_ALL=C sort -z -- "$raw_list")

rc=0
count=0
for f in "${targets_list[@]}"; do
    count=$((count + 1))
    want="$(content_sha "$f")"
    have="$(stamp_of "$f")"
    case "$MODE" in
        list)
            printf '%s\t%s\n' "$f" "$want"
            ;;
        check)
            if [ "$(stamp_count "$f")" -gt 1 ]; then
                echo "DUPLICATE stamp: $f" >&2
                echo "  a file must carry exactly one # sync-sha: line" >&2
                rc=1
            elif [ -z "$have" ]; then
                echo "MISSING stamp: $f" >&2
                rc=1
            elif [ "$have" != "$want" ]; then
                echo "STALE stamp:   $f" >&2
                echo "  recorded: $have" >&2
                echo "  actual:   $want" >&2
                rc=1
            fi
            ;;
        stamp)
            # The stamp_count test matters even when the sha matches: a file
            # carrying a duplicate line is not correctly stamped, and skipping
            # it here would leave --check permanently red.
            if [ "$have" = "$want" ] && [ "$(stamp_count "$f")" -eq 1 ]; then
                continue
            fi
            insert_stamp "$f" "$want"
            echo "stamped: $f"
            ;;
    esac
done

if [ "$count" -eq 0 ]; then
    # A selector that matches nothing must not report success -- that is how a
    # gate silently stops gating (same reasoning as ci/linter/selftest.sh).
    echo "sync-stamp: matched no files -- wrong working directory?" >&2
    exit 2
fi

if [ "$MODE" = check ]; then
    [ "$rc" -eq 0 ] && echo "sync-stamp: all $count file(s) current"
    [ "$rc" -ne 0 ] && echo "sync-stamp: re-run tools/sync-stamp.sh to fix" >&2
fi
exit "$rc"
