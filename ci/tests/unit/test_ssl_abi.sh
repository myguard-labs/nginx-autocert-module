#!/usr/bin/env bash
# Exercise the production preconfiguration guard against real core types.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="${WORKSPACE:-$(cd "$DIR/../../.." && pwd)}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:?set NGX_BUILD_DIR to a configured nginx/angie tree}"
# shellcheck source=ci/tests/unit/lib/slice.sh
source "$DIR/lib/slice.sh"
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT
SRC="$WORKSPACE/src/ngx_http_autocert_module.c"
FN=ngx_http_autocert_preconfig
start=$(slice_find_start "$SRC" "$FN")
slice_function "$SRC" "$start" "$FN" >"$BUILD/ssl_abi.inc"
# The callback must run before directives can access the SSL srv_conf.
grep -Eq 'ngx_http_autocert_preconfig, +/\* preconfiguration \*/' "$SRC"
flags=(-O2 -g -Wall -Wextra -Werror)
if [ -n "${SANITIZE:-}" ]; then
	flags+=("-fsanitize=address,undefined" -fno-sanitize-recover=all)
fi
"${CC:-cc}" "${flags[@]}" -I"$BUILD" -I"$NGX_BUILD_DIR/objs" \
	-I"$NGX_BUILD_DIR/src/core" -I"$NGX_BUILD_DIR/src/event" \
	-I"$NGX_BUILD_DIR/src/event/modules" -I"$NGX_BUILD_DIR/src/os/unix" \
	-I"$NGX_BUILD_DIR/src/http" -I"$NGX_BUILD_DIR/src/http/modules" \
	-I"$NGX_BUILD_DIR/src/http/v2" -I"$NGX_BUILD_DIR/src/http/v3" \
	"$DIR/test_ssl_abi.c" -o "$BUILD/test_ssl_abi"
stat -c 'test_ssl_abi binary: bytes=%s mtime=%y' "$BUILD/test_ssl_abi"
sha256sum "$BUILD/ssl_abi.inc" "$BUILD/test_ssl_abi"
"$BUILD/test_ssl_abi"
