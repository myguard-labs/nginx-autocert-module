#!/usr/bin/env bash
#
# Negative-control coverage for ci/tests/unit/lib/slice.sh (the shared
# brace-depth slicer every extract_*.sh in ci/tests/unit and ci/fuzz now
# calls). Operates ONLY on small synthetic fixtures generated below -- never
# on the real ngx_autocert_*.c sources -- so a change to production code
# cannot flip these assertions.
#
# Asserts:
#   (a) a closer followed by a trailing comment still yields the correct
#       sliced line count (the "reformatted function" case the brace-depth
#       rule exists for, replacing the old lone-`}`-in-column-1 rule).
#   (b) a missing closer (function body never returns to depth 0) exits 1.
#   (c) an unmatched `}` inside a string literal that drives depth negative
#       exits 2 (the new guard from review finding 2).
#   (d) an anchor that never matches in the source at all exits 1 (the new
#       guard from review finding 1 -- the "function never found" case,
#       which the deleted `if [ -z "${end:-}" ]; then exit 1; fi` used to
#       cover and the bare `END { if (opened && depth != 0) exit 1 }` form
#       did not).
#   (e) slice_function on a source with no matching anchor exits 1 via the
#       END-block `if (!closed) exit 1` guard (round-1's fix, distinct from
#       (d)'s slice_find_start guard -- this is the END anchor guard inside
#       slice_function itself).
#   (f) slice_end_line on the same no-anchor source exits 1 via its own
#       `if (!closed) exit 1` guard.
#   (g) a one-line function body ("{ return 0; }" on the signature's next
#       line) slices correctly instead of running to EOF: `{` and `}` both
#       land on the same line as the *first* positive depth, so an `opened`
#       flag set only AFTER the depth==0 check never sees depth==0 while
#       opened is true on that line -- MINOR from PR #263 round 3.
#
# Each assertion is proven to be a REAL negative control, not a vacuous one:
# this file also runs itself with the corresponding guard commented out via
# sed, and requires that variant to fail. See run_variant().

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_LIB="$DIR/lib/slice.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() {
	echo "✗ $1" >&2
	exit 1
}

pass() {
	echo "✓ $1"
}

# --- fixtures -----------------------------------------------------------
#
# Shared by the main run below and by run_variant's __run_single__
# re-invocation, so the four fixtures exist in exactly one place.

make_fixtures() {
	local dir="$1"

	cat >"$dir/fixture_reformatted.c" <<'EOF'
static ngx_int_t
target_fn(void)
{
    /* body */
    return 0;
} /* target_fn */
EOF

	cat >"$dir/fixture_unclosed.c" <<'EOF'
static ngx_int_t
target_fn(void)
{
    if (1) {
        return 0;
    /* missing closing brace for target_fn itself */
EOF

	cat >"$dir/fixture_stray_close.c" <<'EOF'
static ngx_int_t
target_fn(void)
{
    if (1) {
        return 0;
    }
    char *s = "}}";
    return 1;
}
EOF

	# A stray closer in real CODE, reached before the body opens, must
	# still drive depth negative and exit 2 -- that backstop is unchanged
	# and is the one stray-brace shape the literal strip cannot mask.
	cat >"$dir/fixture_stray_code.c" <<'EOF'
static ngx_int_t
target_fn(void)
}
{
    return 0;
}
EOF

	cat >"$dir/fixture_no_anchor.c" <<'EOF'
static ngx_int_t
some_other_function(void)
{
    return 0;
}
EOF

	cat >"$dir/fixture_one_line_body.c" <<'EOF'
static ngx_int_t
target_fn(void)
{ return 0; }
EOF

	# A wrapped parameter list carrying a balanced initialiser closes the
	# signature and the braces on the SAME line. Those braces are not a
	# body either -- reading them as one truncates the slice at exit 0.
	# Braces in a comment on its OWN line, after the signature has closed:
	# only the comment strip defends this one (the parameter-list gate has
	# already opened by then).
	cat >"$dir/fixture_comment_own_line.c" <<'EOF'
static ngx_int_t
target_fn(void)
    /* comment with { } braces */
{
    return 0;
}
EOF

	cat >"$dir/fixture_param_braces.c" <<'EOF'
static ngx_int_t
target_fn(ngx_int_t a,
    struct s v = { 0 })
{
    return 0;
}
EOF
}

make_fixtures "$TMP"

# --- (a) trailing comment on the real closer: correct line count --------

test_a() {
	# shellcheck source=ci/tests/unit/lib/slice.sh
	source "$SRC_LIB"
	rc=0
	body=$(slice_function "$TMP/fixture_reformatted.c" 1 target_fn) || rc=$?
	[ "$rc" -eq 0 ] || fail "(a) slice_function rc=$rc, expected 0"
	got=$(printf '%s\n' "$body" | wc -l)
	[ "$got" -eq 6 ] || fail "(a) expected 6 sliced lines (through the commented closer), got $got"
	printf '%s\n' "$body" | grep -qE '^\} /\* target_fn \*/$' \
		|| fail "(a) sliced body does not include the commented closer line"
	pass "(a) trailing-comment closer: correct 6-line slice, closer line present"
}

# --- (b) missing closer: exit 1 ------------------------------------------

test_b() {
	# shellcheck source=ci/tests/unit/lib/slice.sh
	source "$SRC_LIB"
	rc=0
	body=$(slice_function "$TMP/fixture_unclosed.c" 1 target_fn) || rc=$?
	[ "$rc" -eq 1 ] || fail "(b) expected rc=1 for a body that never closes, got rc=$rc"
	pass "(b) unclosed body: rc=1 as expected"
}

# --- (c) unmatched '}' in a string literal driving depth negative: exit 2

test_c() {
	# shellcheck source=ci/tests/unit/lib/slice.sh
	source "$SRC_LIB"
	rc=0
	body=$(slice_function "$TMP/fixture_stray_close.c" 1 target_fn) || rc=$?
	# Braces inside a string literal are stripped before counting, so this
	# no longer drives depth negative -- the slice is simply CORRECT.
	[ "$rc" -eq 0 ] || fail "(c) expected rc=0 for braces inside a string literal, got rc=$rc"
	got=$(printf '%s\n' "$body" | wc -l)
	[ "$got" -eq 9 ] \
		|| fail "(c) expected 9 sliced lines through the real closer, got $got"
	rc=0
	slice_function "$TMP/fixture_stray_code.c" 1 target_fn >/dev/null || rc=$?
	[ "$rc" -eq 2 ] \
		|| fail "(c) stray '}' in real code must exit 2 (depth<0 guard), got rc=$rc"
	pass "(c) braces in a literal ignored; a stray closer in code still exits 2"
}

# --- (d) anchor never matches: exit 1 (slice_find_start) ----------------

test_d() {
	# shellcheck source=ci/tests/unit/lib/slice.sh
	source "$SRC_LIB"
	rc=0
	slice_find_start "$TMP/fixture_no_anchor.c" target_fn >/dev/null || rc=$?
	[ "$rc" -eq 1 ] || fail "(d) expected rc=1 when the anchor never matches, got rc=$rc"
	pass "(d) anchor never matches: rc=1 as expected"
}

# --- (e) slice_function's OWN end-anchor guard: exit 1 when the source has
# no matching function at all (distinct from (d), which only exercises
# slice_find_start) ---------------------------------------------------

test_e() {
	# shellcheck source=ci/tests/unit/lib/slice.sh
	source "$SRC_LIB"
	rc=0
	slice_function "$TMP/fixture_no_anchor.c" 1 target_fn >/dev/null || rc=$?
	[ "$rc" -eq 1 ] || fail "(e) expected rc=1 from slice_function's END anchor guard, got rc=$rc"
	pass "(e) slice_function on a no-anchor source: rc=1 as expected"
}

# --- (f) slice_end_line's OWN end-anchor guard: exit 1 on the same
# no-anchor source -- slice_end_line has zero coverage otherwise ---------

test_f() {
	# shellcheck source=ci/tests/unit/lib/slice.sh
	source "$SRC_LIB"
	rc=0
	line=$(slice_end_line "$TMP/fixture_no_anchor.c" 1 target_fn) || rc=$?
	[ "$rc" -eq 1 ] || fail "(f) expected rc=1 from slice_end_line's END anchor guard, got rc=$rc"
	[ -z "$line" ] || fail "(f) expected no output on stdout, got: $line"
	pass "(f) slice_end_line on a no-anchor source: rc=1 as expected"
}

# --- (g) one-line function body: `{ ... }` on one line slices correctly -

test_g() {
	# shellcheck source=ci/tests/unit/lib/slice.sh
	source "$SRC_LIB"
	rc=0
	body=$(slice_function "$TMP/fixture_one_line_body.c" 1 target_fn) || rc=$?
	[ "$rc" -eq 0 ] || fail "(g) slice_function rc=$rc, expected 0 for a one-line body"
	got=$(printf '%s\n' "$body" | wc -l)
	[ "$got" -eq 3 ] || fail "(g) expected 3 sliced lines (through the one-line body), got $got"
	printf '%s\n' "$body" | grep -qE '^\{ return 0; \}$' \
		|| fail "(g) sliced body does not include the one-line open+close brace line"
	end=0
	got_end=$(slice_end_line "$TMP/fixture_one_line_body.c" 1 target_fn) || end=$?
	[ "$end" -eq 0 ] || fail "(g) slice_end_line rc=$end, expected 0 for a one-line body"
	[ "$got_end" -eq 3 ] || fail "(g) slice_end_line returned $got_end, expected 3"

	rc=0
	body=$(slice_function "$TMP/fixture_param_braces.c" 1 target_fn) || rc=$?
	[ "$rc" -eq 0 ] || fail "(g) param-brace fixture: slice_function rc=$rc, expected 0"
	got=$(printf '%s\n' "$body" | wc -l)
	[ "$got" -eq 6 ] \
		|| fail "(g) param-brace fixture: expected 6 sliced lines through the real body, got $got (slice truncated at the parameter list)"
	rc=0
	body=$(slice_function "$TMP/fixture_comment_own_line.c" 1 target_fn) || rc=$?
	[ "$rc" -eq 0 ] || fail "(g) own-line-comment fixture: slice_function rc=$rc, expected 0"
	got=$(printf '%s\n' "$body" | wc -l)
	[ "$got" -eq 6 ] \
		|| fail "(g) own-line-comment fixture: expected 6 sliced lines through the real body, got $got (slice truncated at the comment)"
	pass "(g) one-line body + comment and parameter braces: correct slices"
}

# --- (h) the in-tree proof: real source, not a synthetic fixture --------
#
# src/ngx_autocert_json.c is where the literal/comment miscount actually
# bit. json_value holds `case DQUOTE:` and `case OPEN_BRACE:` character
# constants; json_object holds a `/* consume { */` comment. Counting any
# of those as code moves the end line, so pin both against the real file.

test_h() {
	# shellcheck source=ci/tests/unit/lib/slice.sh
	source "$SRC_LIB"
	local src="$DIR/../../../src/ngx_autocert_json.c"
	[ -r "$src" ] || fail "(h) $src is not readable"

	rc=0
	got=$(slice_end_line "$src" 1 ngx_autocert_json_value) || rc=$?
	[ "$rc" -eq 0 ] || fail "(h) slice_end_line(json_value) rc=$rc, expected 0"
	[ "$got" -eq 156 ] \
		|| fail "(h) json_value ends at 156 (verified against the file), slicer said $got"

	rc=0
	got=$(slice_end_line "$src" 1 ngx_autocert_json_object) || rc=$?
	[ "$rc" -eq 0 ] || fail "(h) slice_end_line(json_object) rc=$rc, expected 0"
	[ "$got" -eq 228 ] \
		|| fail "(h) json_object ends at 228 (verified against the file), slicer said $got"

	pass "(h) real src/ngx_autocert_json.c: both function ends exact"
}

# --- prove each control is real: remove the guard, require red ----------
#
# A control that was never observed red proves nothing (test-evidence.md).
# For each assertion, run this same test file in a subshell against a COPY
# of lib/slice.sh with the relevant guard line deleted, and require that
# copy to fail its own assertion.

run_variant() {
	local label="$1" sed_expr="$2" test_fn="$3" rc=0
	local variant_lib="$TMP/slice_${label}.sh"
	sed "$sed_expr" "$SRC_LIB" >"$variant_lib"

	# A sed expression that no longer matches anything in the real lib
	# (e.g. a guard line got reworded) silently yields an unmutated copy,
	# and the "expecting failure" check below would then pass for the
	# wrong reason -- the assertion never actually ran against a mutant.
	# Require the variant to differ from the real lib before trusting it.
	if cmp -s "$SRC_LIB" "$variant_lib"; then
		fail "MUTATION CONTROL FAILED: $label — sed expression matched nothing; variant is byte-identical to $SRC_LIB"
	fi

	# Run test_fn in a FRESH bash process against the MUTATED lib (exported
	# via env, not sourced by re-parsing this file), expecting failure.
	# Require exit 1 specifically -- the status `fail` produces. Any other
	# non-zero (127 from a typo'd $test_fn, 2 from a broken __run_single__)
	# means the harness broke, NOT that the assertion went red, and must not
	# be credited as a passing control.
	rc=0
	MUTATED_SRC_LIB="$variant_lib" bash "$0" __run_single__ "$test_fn" || rc=$?
	if [ "$rc" -eq 0 ]; then
		fail "MUTATION CONTROL FAILED: $label — removing the guard did NOT turn $test_fn() red (still exit 0)"
	elif [ "$rc" -ne 1 ]; then
		fail "MUTATION CONTROL FAILED: $label — $test_fn() child exited $rc, expected 1 (assertion red); the harness is broken"
	fi
	pass "mutation control: removing '$label' guard turns $test_fn() red, as required"
}

if [ "${1:-}" = "__run_single__" ]; then
	# Re-invoked by run_variant: point SRC_LIB at the mutated copy before
	# running the single named assertion function.
	# Exit 2, NOT the 1 that `:?` would produce -- run_variant credits a
	# child exit of 1 as "the assertion went red", so harness breakage must
	# use a distinct status or it re-opens the false-pass hole this file
	# exists to close.
	[ -n "${MUTATED_SRC_LIB:-}" ] \
		|| { echo "__run_single__ requires MUTATED_SRC_LIB set by run_variant" >&2; exit 2; }
	SRC_LIB="$MUTATED_SRC_LIB"
	declare -F "$2" >/dev/null \
		|| { echo "__run_single__: no such test function: $2" >&2; exit 2; }
	TMP="$(mktemp -d)"
	trap 'rm -rf "$TMP"' EXIT
	make_fixtures "$TMP"
	"$2"
	exit $?
fi

echo "== ci/tests/unit/test_slicer_guards.sh =="

test_a
test_b
test_c
test_d
test_e
test_f
test_g
test_h

# (c)'s guard is the `if (depth < 0) { exit 2 }` line -- remove it and rerun
# test_c, which must now fail (rc will be 0 instead of 2: the stray '}'
# silently truncates the slice at the "if (1) { ... }" closer instead of
# being caught).
run_variant "finding2_depth_guard" '/if (depth < 0) { negative = 1; exit 2 }/d' test_c

# (d)'s guard is slice_find_start returning 1 when grep finds nothing --
# replace that branch with a no-op "always succeed" so the anchor-missing
# case is silently accepted, and rerun test_d, which must now fail.
# shellcheck disable=SC2016  # sed script: no shell expansion wanted here
run_variant "finding1_anchor_guard" \
	's/if \[ -z "\${line:-}" \]; then/if false; then/' test_d

# (e)/(f)'s guard is the END-block `if (!closed) exit 1` in BOTH
# slice_function and slice_end_line -- this is round 1's MAJOR 1 fix
# itself. Revert it to the pre-fix shape (round 1's exact bug) and rerun
# both (e) and (f), which must now fail: a no-anchor source never sets
# `opened`, so `opened && depth != 0` is false and the mutated guard
# silently accepts what should be an error.
run_variant "major1_end_anchor_guard" \
	's/if (!closed) exit 1/if (opened \&\& depth != 0) exit 1/' test_e
run_variant "major1_end_anchor_guard" \
	's/if (!closed) exit 1/if (opened \&\& depth != 0) exit 1/' test_f
# (g)'s guard is the `pre_depth == 0 && n_open > 0` disjunct that lets a line
# which both opens and closes the body terminate the slice. Remove it and the
# one-line body is never recognised as closed, so test_g must go red.
run_variant "one_line_body_disjunct" \
	's/same_line = (sig_was_closed \&\& pre_depth == 0 \&\& n_open > 0)/same_line = 0/g' test_g
# The comment strip and the parameter-list gate each defend one truncation
# shape in test_g's fixtures; remove either and test_g must go red.
run_variant "comment_strip" \
	'/, " ", code)$/d' test_g
run_variant "param_list_gate" \
	's/sig_was_closed = sig_closed/sig_was_closed = 1/g' test_g
# The char-constant strip is what the real src/ngx_autocert_json.c needs:
# remove it and json_value's end moves 156 -> 227 (the cancelling-error
# shape that made a comment-only strip worse than none).
run_variant "char_constant_strip" \
	'/gsub(q "/d' test_h

echo "✓ all slicer guard assertions passed, including mutation controls"
