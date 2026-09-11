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
# _slice SRC START_LINE ENTER_NAME EMIT
#   Shared parser for slice_function and slice_end_line. EMIT is "body" to
#   print each candidate source line, or "end" to print only the closing line
#   number. Keep the lexical and malformed-source guards in this one program so
#   the two public interfaces cannot drift.
_slice() {
	local src="$1" start="$2" enter_name="$3" emit="$4"

	[ -r "$src" ] || return 4

	awk -v s="$start" -v name="$enter_name" -v emit="$emit" '
        NR >= s {
            if (emit == "body") print
            if ($0 ~ ("^" name "\\(")) { entered = 1 }
            if (entered) {
                # Braces that are not code must not be counted: a comment,
                # character constant, or string literal can otherwise skew
                # depth. Strip all three from a copy and count on that.
                q = sprintf("%c", 39)
                code = $0
                gsub(/\/\*[^*]*\*+([^\/*][^*]*\*+)*\//, " ", code)
                # Character constants must precede string literals: a
                # character constant may itself contain a double quote.
                gsub(q "(\\\\.|[^" q "\\\\])*" q, " ", code)
                gsub(/"(\\.|[^"\\])*"/, " ", code)
                # Braces before the parameter list closes are not the body.
                n_lp = gsub(/\(/, "(", code)
                n_rp = gsub(/\)/, ")", code)
                sig_was_closed = sig_closed
                if (n_lp > 0) { saw_lp = 1 }
                paren += n_lp - n_rp
                if (saw_lp && paren <= 0) { sig_closed = 1 }
                pre_depth = depth
                n_open = gsub(/{/, "{", code); depth += n_open
                n = gsub(/}/, "}", code); depth -= n
                if (depth < 0) { negative = 1; exit 2 }
                # opened covers bodies spanning lines; same_line covers a body
                # whose opening and closing braces occur on the same line.
                same_line = (sig_was_closed && pre_depth == 0 && n_open > 0)
                if ((opened || same_line) && depth == 0) {
                    if (emit == "end") print NR
                    closed = 1; exit
                }
                if (depth > 0) { opened = 1 }
            }
        }
        # awk runs END after exit; preserve the distinct negative-depth status.
        END {
            if (negative) { exit 2 }
            if (!closed) exit 1
        }
    ' "$src"
}

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
	_slice "$1" "$2" "$3" body
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
	_slice "$1" "$2" "$3" end
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
