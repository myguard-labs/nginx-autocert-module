#!/bin/bash
set -euo pipefail

# Unit test runner for nginx-autocert-module with ASan+UBSan.
# Builds all unit tests with -fsanitize=address,undefined to catch buffer
# overflows, use-after-free, and undefined behavior that static compilation
# with -Wall -Wextra might miss.
#
# Required environment: NGX_BUILD_DIR must point to a built nginx tree
# (with objs/src/core/*.o and other object files intact).
#
# Optional: WORKSPACE overrides the repo root (defaults to this script's parent dir).

# Derive workspace from script location if not set
if [ -z "${WORKSPACE:-}" ]; then
	WORKSPACE="$(cd "$(dirname "$0")/../../.." && pwd)"
fi

# Require NGX_BUILD_DIR
if [ -z "${NGX_BUILD_DIR:-}" ]; then
	echo "Usage: NGX_BUILD_DIR=<built nginx tree> $0"
	echo "  where <built nginx tree> is a path to a configured+built nginx source,"
	echo "  with object files at objs/src/core/*.o"
	exit 2
fi

# Absolutize paths (same idiom as run.sh)
if ! _abs="$(cd "$WORKSPACE" 2>/dev/null && pwd)"; then
	echo "✗ WORKSPACE is not a readable directory: ${WORKSPACE}" >&2
	exit 2
fi
WORKSPACE="$_abs"
if ! _abs="$(cd "$NGX_BUILD_DIR" 2>/dev/null && pwd)"; then
	echo "✗ NGX_BUILD_DIR is not a readable directory: ${NGX_BUILD_DIR}" >&2
	exit 2
fi
NGX_BUILD_DIR="$_abs"
unset _abs

# Build directory for binaries
BUILD_DIR="${WORKSPACE}/.build/unit-asan"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

NGX="$NGX_BUILD_DIR"
CORE_INC="-I$NGX/src/core -I$NGX/src/event -I$NGX/src/os/unix -I$NGX/objs"

# ASan+UBSan flags: detect buffer overflows, use-after-free, and undefined behavior.
ASAN_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all"

# Test the ngx_autocert_account_log_safe function under ASan+UBSan.
# This test verifies that the escaping logic cannot overflow the output buffer
# or read past bounds of the input buffer, even with adversarial input.
echo "Building test_account_jsonsafe with ASan+UBSan..."
bash "$WORKSPACE/ci/tests/unit/extract_jsonsafe.sh"
# shellcheck disable=SC2086
gcc $ASAN_FLAGS -Wall -Wextra -Werror -Ici/tests/unit $CORE_INC \
	-o "$BUILD_DIR/test_account_jsonsafe_asan" \
	"$WORKSPACE/ci/tests/unit/test_account_jsonsafe.c" \
	"$NGX/objs/src/core/ngx_string.o" \
	"$NGX/objs/src/core/ngx_palloc.o" \
	"$NGX/objs/src/os/unix/ngx_alloc.o" \
	-lasan -lubsan
echo "Running test_account_jsonsafe with ASan+UBSan..."
"$BUILD_DIR/test_account_jsonsafe_asan"

echo "all sanitizer tests passed"
exit 0
