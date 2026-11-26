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
function strip_c_comments(s,    out, start, end) {
    # Remove /* ... */ comments from an already-joined, whitespace-collapsed
    # single-line statement. Must run AFTER the statement is fully
    # accumulated and normalized, and BEFORE helper-call recognition and the
    # raw &r->url test -- otherwise a commented-out
    # "ngx_autocert_acme_log_safe(" can impersonate a real wrapper call and
    # its paren-balanced removal will delete a live, unwrapped argument along
    # with the comment (the very bypass this function exists to close).
    #
    # This statement was joined from possibly-multiple source lines into one
    # line before this point, so a multi-line /* ... */ comment now appears
    # as a single run within that line -- a plain non-greedy scan is enough;
    # no line-oriented state machine is needed. POSIX-portable index()/substr()
    # only, no GNU awk extensions.
    out = ""
    while (1) {
        start = index(s, "/*")
        if (start == 0) {
            out = out s
            break
        }
        out = out substr(s, 1, start - 1)
        rest = substr(s, start + 2)
        end = index(rest, "*/")
        if (end == 0) {
            # Unterminated comment: drop the remainder: it cannot hide a
            # real call site that awk would still need to see.
            s = ""
            break
        }
        # Replace the whole comment with a single space so tokens that were
        # separated only by the comment do not fuse together.
        out = out " "
        s = substr(rest, end + 2)
    }
    return out
}
function is_debug_call(line,    n, name) {
    # True only when the CALL SITE itself is an ngx_log_debug*(...) invocation
    # -- i.e. the matched function name immediately preceding "(" starts with
    # "ngx_log_debug". This must not be satisfied by the substring
    # "ngx_log_debug" occurring anywhere else on the line (e.g. inside a
    # comment), or a genuine ERROR/WARN/NOTICE call could be exempted by an
    # unrelated word.
    n = match(line, /ngx_log_[A-Za-z0-9_]*[ \t]*\(/)
    if (n == 0) return 0
    name = substr(line, n, RLENGTH)
    sub(/[ \t]*\($/, "", name)
    return (name ~ /^ngx_log_debug/)
}
/ngx_log_[A-Za-z0-9_]*[ \t]*\(/ && !is_debug_call($0) {
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

    # Strip C comments from the fully-joined, normalized statement BEFORE
    # recognizing helper calls and before the raw-&r->url test. Ordering
    # this after termination/normalization (above) but before helper
    # recognition (below) means: (1) the termination regex on line ~44 that
    # deliberately allows a trailing "; /* comment */" still sees the
    # unmodified stmt while accumulating, so a legitimate trailing comment
    # keeps terminating the statement normally; (2) is_debug_call() keys off
    # the ORIGINAL per-line text at the call site and is unaffected, since
    # comment-stripping only touches this fully-accumulated `stmt` used for
    # the helper/raw-argument checks below; (3) a helper name appearing only
    # inside a comment can no longer impersonate a real wrapper call, so its
    # paren-balanced removal can no longer delete a live, unwrapped argument
    # along with the commented-out text.
    stmt = strip_c_comments(stmt)

    # Strip out ngx_autocert_acme_log_safe(...) calls before checking.
    # This prevents bypassing the check by having the helper name in a comment
    # while the raw &r->url is passed as an unwrapped argument.
    stmt_stripped = stmt
    pos = index(stmt_stripped, "ngx_autocert_acme_log_safe")
    while (pos > 0) {
        before = substr(stmt_stripped, 1, pos - 1)
        after_prefix = substr(stmt_stripped, pos + length("ngx_autocert_acme_log_safe"))
        # Tolerate whitespace between the helper name and its opening paren.
        # The earlier generic run-collapse (line ~50) already reduces any
        # run of spaces/tabs -- including a joined-statement newline -- to a
        # single space, so at most one space can appear here.
        skip = 0
        if (substr(after_prefix, 1, 1) == " ") skip = 1
        # Find the opening paren
        if (substr(after_prefix, skip + 1, 1) == "(") {
            after_prefix = substr(after_prefix, skip + 1)
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
