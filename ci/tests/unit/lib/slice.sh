#!/usr/bin/env bash
#
# Shared brace-depth function slicer for extract_*.sh scripts (ci/tests/unit
# and ci/fuzz). Sourced, not executed: `source ".../lib/slice.sh"`.
#
# Extraction rule: a function body runs from its signature line (the caller
# locates that; see slice_find_start below) through the line where nested
# `{`/`}` depth first returns to zero after having gone positive. This is
# NOT "the first lone `}` in column 1" -- that rule silently over- or
# under-extracts whenever a trailing comment follows the real closer (e.g.
# `} /* foo */`) or the anchor drifts. See prior extract_*.sh history for the
# measured failures this replaced.
#
# Brace counting is lexical, not a real C tokenizer, but braces inside a
# /* comment */, a "string literal" or a character constant are stripped
# from a per-line copy before counting, so those three shapes no longer
# skew depth. What remains unhandled, because the strip is per-line:
#
#   - a MULTI-LINE comment body. Only a /* ... */ that closes on the same
#     line is removed, so an apostrophe in a continuation line ("the
#     caller's frame") is not stripped and can open a bogus character
#     constant that swallows to the next apostrophe. This bites only when
#     such a line ALSO carries an unbalanced brace. Measured on this tree:
#     661 continuation lines carry an odd apostrophe count, 2 of those
#     carry a brace, and both are the balanced "http{}" so they net zero.
#     Every one of the 339 function definitions in src/ slices correctly.
#     Re-run the sweep in test_h's spirit if that ever changes.
#   - a // comment and a multi-line string continuation (this tree has
#     neither), and any construct needing real parsing.
#
# Do NOT attempt full lexing in this helper.
#
# Strip the three together or not at all. Stripping only comments is worse
# than stripping nothing: in src/ngx_autocert_json.c a spurious `{` from a
# character constant was cancelled by one inside a comment, and removing
# just the comment half truncated the slice by 42 lines at exit 0.
#
# The depth<0 guard below remains, as a backstop for a stray `}` that the
# strip cannot reach: any point where cumulative closers outnumber
# cumulative openers so far exits non-zero rather than truncating. It does
# not catch a stray closer that lands depth exactly back on zero; that
# would need real parsing, which this helper deliberately does not do.
#
# slice_function SRC START_LINE ENTER_NAME
#   Prints the sliced function body (from START_LINE through its closing
#   brace) on stdout and exits 0, OR prints nothing and returns non-zero if:
#     - ENTER_NAME's definition line ("^ENTER_NAME(") is never matched
#       (source layout changed -- the "function never found" case) -- exits 1, or
#     - depth goes negative at any point (cumulative closers outnumber
#       cumulative openers so far -- see the LIMITATION note above for the
#       stray-`}` shape this does not catch) -- exits 2, or
#     - EOF is reached with the body still open -- exits 1, or
#     - SRC is missing or unreadable -- exits 4 (checked before awk ever
#       runs, so this is never confused with the depth<0 signal above).
#   ENTER_NAME is a literal function name (no regex metacharacters); the
#   match pattern is built inside awk to avoid shell/awk double-escaping.
slice_function() {
	local src="$1" start="$2" enter_name="$3"

	[ -r "$src" ] || return 4

	awk -v s="$start" -v name="$enter_name" '
        NR >= s {
            print
            if ($0 ~ ("^" name "\\(")) { entered = 1 }
            if (entered) {
                # Braces that are not code must not be counted: a comment
                # ("target_fn(void) /* {} */") would otherwise open and
                # close on the signature line and read as a one-line body,
                # and a character constant (case OPEN_BRACE_CHAR:) or a
                # string literal skews depth outright. Strip all three from
                # a copy and count on that, never on $0 itself.
                #
                # Stripping only comments is WORSE than stripping nothing:
                # in src/ngx_autocert_json.c the spurious "{" from a
                # character constant was cancelled by a spurious "{" inside
                # a comment, and removing just the comment half exposed the
                # imbalance and truncated the slice by 42 lines at exit 0.
                # Strip the set together or not at all.
                q = sprintf("%c", 39)
                code = $0
                gsub(/\/\*[^*]*\*+([^\/*][^*]*\*+)*\//, " ", code)
                # Character constants BEFORE string literals: a line may
                # hold a character constant whose value is a double quote
                # (case DQUOTE_CHAR:), and stripping strings first would
                # consume from that quote onward and mangle the line.
                gsub(q "(\\\\.|[^" q "\\\\])*" q, " ", code)
                gsub(/"(\\.|[^"\\])*"/, " ", code)
                # Track the parameter list. A brace can only open the BODY
                # once the closing ")" of the signature; before that, any
                # balanced "{...}" is a default argument or an initialiser,
                # not a one-line body. Without this, a wrapped parameter
                # list such as "struct s v = { 0 })" ends the slice at the
                # signature and returns a truncated stub at exit 0.
                n_lp = gsub(/\(/, "(", code)
                n_rp = gsub(/\)/, ")", code)
                # sig_was_closed is the state BEFORE this line. A line that
                # both closes the parameter list and carries balanced braces
                # ("struct s v = { 0 })") must not have those braces read as
                # a body, so the same-line-body test below uses the prior
                # state, not the state this line just produced.
                sig_was_closed = sig_closed
                if (n_lp > 0) { saw_lp = 1 }
                paren += n_lp - n_rp
                if (saw_lp && paren <= 0) { sig_closed = 1 }
                pre_depth = depth
                n_open = gsub(/{/, "{", code); depth += n_open
                n = gsub(/}/, "}", code); depth -= n
                if (depth < 0) { negative = 1; exit 2 }
                # A one-line body ("{ return 0; }") opens and closes on the
                # same line: depth is already back down to 0 by the time we
                # reach this check, so a lone (opened && depth == 0) test
                # (which only sees opened from a PRIOR line) never fires for
                # it. (pre_depth == 0 && n_open > 0) catches "this line
                # itself went positive", so the same-line close is not
                # missed.
                same_line = (sig_was_closed && pre_depth == 0 && n_open > 0)
                if ((opened || same_line) && depth == 0) {
                    closed = 1; exit
                }
                if (depth > 0) { opened = 1 }
            }
        }
        # awk always runs END after an in-block exit, and an unconditional
        # exit here would silently overwrite the depth<0 exit(2) above with
        # exit(1) -- skip entirely once that branch already fired.
        END {
            if (negative) { exit 2 }
            if (!closed) exit 1
        }
    ' "$src"
}

# slice_end_line SRC START_LINE ENTER_NAME
#   Prints the 1-based line number of the closing brace that ends the
#   function body starting at START_LINE (whose definition line matches
#   "^ENTER_NAME(") and returns 0, or prints nothing and returns non-zero:
#   exit 2 if depth ever goes negative (see slice_function), exit 1 if EOF is
#   reached with the body still open, exit 4 if SRC is missing or unreadable
#   (checked before awk ever runs, so this is never confused with the
#   depth<0 signal above).
slice_end_line() {
	local src="$1" start="$2" enter_name="$3"

	[ -r "$src" ] || return 4

	awk -v s="$start" -v name="$enter_name" '
        NR >= s {
            if ($0 ~ ("^" name "\\(")) { entered = 1 }
            if (entered) {
                # Braces that are not code must not be counted: a comment
                # ("target_fn(void) /* {} */") would otherwise open and
                # close on the signature line and read as a one-line body,
                # and a character constant (case OPEN_BRACE_CHAR:) or a
                # string literal skews depth outright. Strip all three from
                # a copy and count on that, never on $0 itself.
                #
                # Stripping only comments is WORSE than stripping nothing:
                # in src/ngx_autocert_json.c the spurious "{" from a
                # character constant was cancelled by a spurious "{" inside
                # a comment, and removing just the comment half exposed the
                # imbalance and truncated the slice by 42 lines at exit 0.
                # Strip the set together or not at all.
                q = sprintf("%c", 39)
                code = $0
                gsub(/\/\*[^*]*\*+([^\/*][^*]*\*+)*\//, " ", code)
                # Character constants BEFORE string literals: a line may
                # hold a character constant whose value is a double quote
                # (case DQUOTE_CHAR:), and stripping strings first would
                # consume from that quote onward and mangle the line.
                gsub(q "(\\\\.|[^" q "\\\\])*" q, " ", code)
                gsub(/"(\\.|[^"\\])*"/, " ", code)
                # Track the parameter list. A brace can only open the BODY
                # once the closing ")" of the signature; before that, any
                # balanced "{...}" is a default argument or an initialiser,
                # not a one-line body. Without this, a wrapped parameter
                # list such as "struct s v = { 0 })" ends the slice at the
                # signature and returns a truncated stub at exit 0.
                n_lp = gsub(/\(/, "(", code)
                n_rp = gsub(/\)/, ")", code)
                # sig_was_closed is the state BEFORE this line. A line that
                # both closes the parameter list and carries balanced braces
                # ("struct s v = { 0 })") must not have those braces read as
                # a body, so the same-line-body test below uses the prior
                # state, not the state this line just produced.
                sig_was_closed = sig_closed
                if (n_lp > 0) { saw_lp = 1 }
                paren += n_lp - n_rp
                if (saw_lp && paren <= 0) { sig_closed = 1 }
                pre_depth = depth
                n_open = gsub(/{/, "{", code); depth += n_open
                n = gsub(/}/, "}", code); depth -= n
                if (depth < 0) { negative = 1; exit 2 }
                # See slice_function matching comment above: a one-line body
                # opens and closes on the same line, so opened (only ever
                # set on a PRIOR line) misses it -- pre_depth==0 && n_open>0
                # detects "this line itself went positive".
                same_line = (sig_was_closed && pre_depth == 0 && n_open > 0)
                if ((opened || same_line) && depth == 0) {
                    print NR; closed = 1; exit
                }
                if (depth > 0) { opened = 1 }
            }
        }
        # awk always runs END after an in-block exit, and an unconditional
        # exit here would silently overwrite the depth<0 exit(2) above with
        # exit(1) -- skip entirely once that branch already fired.
        END {
            if (negative) { exit 2 }
            if (!closed) exit 1
        }
    ' "$src"
}

# slice_find_start SRC NAME
#   Prints the 1-based line number of the return-type line (one line above
#   the first line matching "^NAME(") on stdout and returns 0, or prints
#   nothing and returns 1 if that line never matches (source layout changed /
#   anchor renamed / function removed). NAME is a literal function name (no
#   regex metacharacters).
slice_find_start() {
	local src="$1" name="$2" line

	line=$(grep -nE "^${name}\\(" "$src" | head -1 | cut -d: -f1 || true)
	if [ -z "${line:-}" ]; then
		return 1
	fi
	echo $((line - 1))
}
