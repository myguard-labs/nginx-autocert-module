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
# LIMITATION (documented, not solved here): brace counting is lexical, not a
# real C tokenizer. A `{` or `}` inside a string literal, a character
# constant, or a comment is counted like real code. This is a known,
# accepted gap -- do NOT attempt full lexing in this helper.
#
# The depth<0 guard below converts ONE shape of stray-`}` silent truncation
# into a loud, non-zero-exit error: any point where cumulative closers
# outnumber cumulative openers so far. It does NOT catch every stray `}`:
# an odd number of extra closers that lands the running depth exactly back
# on zero (e.g. a literal containing exactly one unmatched `}`, such as
# `"\"}"`) still reads as "the function just closed" and truncates silently
# at exit 0 -- full lexing would be required to catch that shape, and this
# helper deliberately does not attempt it. An extra unmatched `{` in a
# literal or comment overruns into the next function instead; that is
# usually caught by the "expected symbol missing" / structural checks
# callers layer on top, not by this helper.
#
# slice_function SRC START_LINE ENTER_NAME
#   Prints the sliced function body (from START_LINE through its closing
#   brace) on stdout and exits 0, OR prints nothing and returns non-zero if:
#     - ENTER_NAME's definition line ("^ENTER_NAME(") is never matched
#       (source layout changed -- the "function never found" case) -- exits 1, or
#     - depth goes negative at any point (cumulative closers outnumber
#       cumulative openers so far -- see the LIMITATION note above for the
#       stray-`}` shape this does not catch) -- exits 2, or
#     - EOF is reached with the body still open -- exits 1.
#   ENTER_NAME is a literal function name (no regex metacharacters); the
#   match pattern is built inside awk to avoid shell/awk double-escaping.
slice_function() {
	local src="$1" start="$2" enter_name="$3"

	awk -v s="$start" -v name="$enter_name" '
        NR >= s {
            print
            if ($0 ~ ("^" name "\\(")) { entered = 1 }
            if (entered) {
                n = gsub(/{/, "{"); depth += n
                n = gsub(/}/, "}"); depth -= n
                if (depth < 0) { negative = 1; exit 2 }
                if (opened && depth == 0) { closed = 1; exit }
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
#   reached with the body still open.
slice_end_line() {
	local src="$1" start="$2" enter_name="$3"

	awk -v s="$start" -v name="$enter_name" '
        NR >= s {
            if ($0 ~ ("^" name "\\(")) { entered = 1 }
            if (entered) {
                n = gsub(/{/, "{"); depth += n
                n = gsub(/}/, "}"); depth -= n
                if (depth < 0) { negative = 1; exit 2 }
                if (opened && depth == 0) { print NR; closed = 1; exit }
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
