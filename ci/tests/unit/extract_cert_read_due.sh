#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/tests/unit/lib/slice.sh
source "$DIR/lib/slice.sh"
SRC="$DIR/../../../src/ngx_autocert_driver.c"
CRYPTO_SRC="$DIR/../../../src/ngx_http_autocert_crypto.c"
OUT="$DIR/generated_cert_read_due.inc"
FN="ngx_autocert_cert_read_due"

rtype=$(slice_find_start "$SRC" "$FN") || {
	echo "x could not locate ${FN}() in $SRC" >&2
	exit 1
}
body=$(slice_function "$SRC" "$rtype" "$FN") || {
	echo "x could not extract ${FN}() from $SRC" >&2
	exit 1
}
printf '%s\n' "$body" >"$OUT"
grep -qE "^${FN}\\(" "$OUT" || {
	echo "x ${FN} missing from generated output" >&2
	exit 1
}

# Windows maps a rejected reparse point to ELOOP too. Keep the persistent
# symlink verdict platform-neutral instead of compiling it out on NGX_WIN32.
cert_rtype=$(slice_find_start "$CRYPTO_SRC" \
	"ngx_http_autocert_cert_not_after") || exit 1
cert_body=$(slice_function "$CRYPTO_SRC" "$cert_rtype" \
	"ngx_http_autocert_cert_not_after") || exit 1
key_rtype=$(slice_find_start "$CRYPTO_SRC" \
	"ngx_http_autocert_key_pairs_with") || exit 1
key_body=$(slice_function "$CRYPTO_SRC" "$key_rtype" \
	"ngx_http_autocert_key_pairs_with") || exit 1

# Let the C preprocessor resolve complete conditional groups. This naturally
# covers nested groups, continued directives, #else, and mutually-exclusive
# #elif arms without reimplementing preprocessor state in awk.
eloop_preprocess_status() {
	local function_body="$1" windows_body nonwindows_body

	windows_body=$(printf '%s\n' "$function_body" \
		| cc -E -P -x c -DNGX_WIN32=1 -) || return 3
	nonwindows_body=$(printf '%s\n' "$function_body" \
		| cc -E -P -x c -UNGX_WIN32 -) || return 3

	grep -qE 'errno[[:space:]]*==[[:space:]]*ELOOP' \
		<<<"$windows_body" || return 1
	grep -qE 'errno[[:space:]]*==[[:space:]]*ELOOP' \
		<<<"$nonwindows_body" || return 2
}

check_eloop_scope() {
	local label="$1" function_body="$2" probe_rc

	if eloop_preprocess_status "$function_body"; then
		return
	fi
	probe_rc=$?
	case $probe_rc in
	1) echo "x $label excludes the ELOOP verdict on Windows" >&2 ;;
	2) echo "x $label excludes the ELOOP verdict outside Windows" >&2 ;;
	3) echo "x could not preprocess $label for the ELOOP scope probe" >&2 ;;
	esac
	exit 1
}

check_eloop_scope "certificate reader" "$cert_body"
check_eloop_scope "private-key reader" "$key_body"

# Earlier-arm negative control: Windows selects the first arm, so an ELOOP in
# the later arm must not fool the probe into treating the mapping as portable.
earlier_arm_control='\
#if NGX_WIN32
return NGX_ERROR;
#else
if (errno == ELOOP) {
    return NGX_ABORT;
}
#endif
'
if eloop_preprocess_status "$earlier_arm_control"; then
	echo "x ELOOP probe ignored the selected earlier Windows arm" >&2
	exit 1
else
	control_rc=$?
	if [ "$control_rc" -ne 1 ]; then
		echo "x earlier-arm ELOOP negative control was malformed" >&2
		exit 1
	fi
fi

# Later-elif negative control: the undefined first condition reaches the
# Windows elif, whose selected body deliberately lacks the ELOOP mapping.
later_elif_control='\
#if TEST_EARLIER_ARM
if (errno == ELOOP) {
    return NGX_ABORT;
}
#elif NGX_WIN32
return NGX_ERROR;
#else
if (errno == ELOOP) {
    return NGX_ABORT;
}
#endif
'
if eloop_preprocess_status "$later_elif_control"; then
	echo "x ELOOP probe ignored the selected later #elif NGX_WIN32 arm" >&2
	exit 1
else
	control_rc=$?
	if [ "$control_rc" -ne 1 ]; then
		echo "x later-elif ELOOP negative control was malformed" >&2
		exit 1
	fi
fi
