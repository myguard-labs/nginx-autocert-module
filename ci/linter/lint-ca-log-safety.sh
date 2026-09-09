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
mapfile -t FILES <<<"$FILES_LIST"
[ "${#FILES[@]}" -gt 0 ] || {
	echo "lint-ca-log-safety: no C files to check"
	exit 0
}

echo "lint-ca-log-safety: ${#FILES[@]}" file\(s\)
rc=0

# Scan for ngx_log_* calls (excluding ngx_log_debug*) that reference
# CA-controlled fields without wrapping. Join multi-line statements before
# checking so continuation-line arguments are visible.

awk '
/ngx_log_/ && !/ngx_log_debug/ {
    # This is an ERROR/WARN/NOTICE level log (non-debug).
    # Accumulate the statement until it ends with `;`
    stmt_start = NR
    stmt = $0

    while (stmt !~ /;$/ && getline > 0) {
        stmt = stmt " " $0
    }

    # Normalize whitespace
    gsub(/\s+/, " ", stmt)

    # Check for unwrapped &r->url (the unvalidated raw CA field)
    if (stmt ~ /&r->url/) {
        if (stmt !~ /ngx_autocert_acme_log_safe/) {
            print FILENAME ":" stmt_start ": unwrapped &r->url in ngx_log_* (ERROR level)" \
                  " (must wrap with ngx_autocert_acme_log_safe)"
            exit 1
        }
    }
}
' "${FILES[@]}" || rc=1

if [ "$rc" -eq 0 ]; then
	echo "lint-ca-log-safety: CA-controlled fields are safe at ERROR+ levels"
fi

exit "$rc"
