#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ci/tests/unit/lib/slice.sh
source "$DIR/lib/slice.sh"
SRC="$DIR/../../../src/ngx_autocert_driver.c"
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
