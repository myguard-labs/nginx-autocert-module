#!/usr/bin/env bash
# ci/linter/lint-ca-log-safety.sh -- CA-controlled data logging safety.
#
# Detects CA-controlled fields passed unwrapped to ngx_log_* at ERROR level or
# above, which risks log injection to high-integrity streams. DEBUG-level logs
# are intentionally excluded: ngx_log_debug* is runtime-gated (normally OFF) and
# lower-integrity, so an unwrapped CA-controlled field there is acceptable
# without per-request wrapping overhead.
#
# Safe-by-construction fields (validated before logging) are not checked.
#
# Usage: ci/linter/lint-ca-log-safety.sh [files...]     (no args => LINT_MODE)
# Env:   LINT_MODE=staged|all

# shellcheck source=ci/linter/lib.sh
. "$(git rev-parse --show-toplevel)/ci/linter/lib.sh"

FILES_LIST="$(lint_files '^src/.*\.[ch]$' "$@")" || exit 2
[ -n "$FILES_LIST" ] || {
	echo "lint-ca-log-safety: no C files to check"
	exit 0
}
mapfile -t FILES <<<"$FILES_LIST"

echo "lint-ca-log-safety: ${#FILES[@]}" file\(s\)
rc=0

# Scan for ngx_log_* calls (excluding ngx_log_debug*) that reference
# CA-controlled fields without wrapping. Join multi-line statements before
# checking so continuation-line arguments are visible.

# Statement accumulation is bounded so a pathological/unterminated statement
# (e.g. missing `;`) cannot make a single match run away and scan the rest of
# the file as one "statement".
awk '
/ngx_log_/ && !/ngx_log_debug/ {
    # This is an ERROR/WARN/NOTICE level log (non-debug).
    # Accumulate the statement until a line ends with `;`, optionally followed
    # by trailing whitespace and/or a trailing comment.
    stmt_start = FNR
    stmt = $0
    lines = 1

    while (stmt !~ /;[ \t]*(\/\*.*)?$/ && lines < 50 && getline > 0) {
        stmt = stmt " " $0
        lines++
    }

    # Normalize whitespace (POSIX-portable; no GNU-awk \s)
    gsub(/[ \t]+/, " ", stmt)

    # Collapse whitespace around `&` and `->` so `& r->url`, `&r -> url`,
    # `&r->  url` etc. normalize to the same spelling as `&r->url`. Applied
    # after the generic run-collapse above so only single spaces remain to
    # strip here.
    gsub(/& /, "\\&", stmt)
    gsub(/ ->/, "->", stmt)
    gsub(/-> /, "->", stmt)

    # Strip out ngx_autocert_acme_log_safe(...) calls before checking.
    # This prevents bypassing the check by having the helper name in a comment
    # while the raw &r->url is passed as an unwrapped argument.
    stmt_stripped = stmt
    pos = index(stmt_stripped, "ngx_autocert_acme_log_safe")
    while (pos > 0) {
        before = substr(stmt_stripped, 1, pos - 1)
        after_prefix = substr(stmt_stripped, pos + length("ngx_autocert_acme_log_safe"))
        # Find the opening paren
        if (substr(after_prefix, 1, 1) == "(") {
            # Find matching closing paren
            paren_count = 1
            i = 2
            while (i <= length(after_prefix) && paren_count > 0) {
                ch = substr(after_prefix, i, 1)
                if (ch == "(") paren_count++
                else if (ch == ")") paren_count--
                i++
            }
            after = substr(after_prefix, i)
            stmt_stripped = before after
        } else {
            break
        }
        pos = index(stmt_stripped, "ngx_autocert_acme_log_safe")
    }

    # Check for unwrapped &r->url (the unvalidated raw CA field)
    if (stmt_stripped ~ /&r->url/) {
        print FILENAME ":" stmt_start ": unwrapped &r->url in ngx_log_* (ERROR level)" \
              " (must wrap with ngx_autocert_acme_log_safe)"
        found = 1
    }
}
END {
    if (found) {
        exit 1
    }
}
' "${FILES[@]}" || rc=1

if [ "$rc" -eq 0 ]; then
	echo "lint-ca-log-safety: no unwrapped &r->url in ngx_log_* at ERROR+ levels"
fi

exit "$rc"
