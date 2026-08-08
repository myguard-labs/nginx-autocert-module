#!/bin/bash
set -euo pipefail

# Unit test runner for nginx-autocert-module.
# Extracts and compiles all 12 unit tests against a pre-built nginx tree.
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

# Both are baked into -I/-o/object arguments below, and this script cd's into
# $BUILD_DIR before using them. A RELATIVE value would then re-resolve against
# .build/unit and every path would miss -- so absolutize both here, while the
# cwd is still the caller's. Failing loudly beats a confusing gcc error:
# `NGX_BUILD_DIR=../nginx-1.31.3 ci/tests/unit/run.sh` is the natural local
# invocation and used to break silently.
# Assign via a temp: `X="$(cd "$X")" || echo "$X"` reports an EMPTY value,
# because the failed substitution has already clobbered X by the time the
# handler runs.
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

# Build directory for binaries (use scratch under repo root)
BUILD_DIR="${WORKSPACE}/.build/unit"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

NGX="$NGX_BUILD_DIR"
CORE_INC="-I$NGX/src/core -I$NGX/src/event -I$NGX/src/os/unix -I$NGX/objs"
BASE_OBJS="$NGX/objs/src/core/ngx_palloc.o $NGX/objs/src/core/ngx_string.o \
      $NGX/objs/src/os/unix/ngx_time.o $NGX/objs/src/core/ngx_times.o \
      $NGX/objs/src/os/unix/ngx_alloc.o"
INET_OBJS="$BASE_OBJS $NGX/objs/src/core/ngx_inet.o"
# ngx_array.o: A3.1 drain uses ngx_array_push; its test uses ngx_array_create.
STORE_OBJS="$BASE_OBJS $NGX/objs/src/core/ngx_slab.o \
      $NGX/objs/src/core/ngx_rbtree.o $NGX/objs/src/core/ngx_crc32.o \
      $NGX/objs/src/core/ngx_shmtx.o $NGX/objs/src/core/ngx_array.o"

# INC and OBJS are flag/object lists that must word-split.
# ngx_inet.o: crypto.c now pulls ngx_autocert_str_is_ip (IP-cert arc),
# which references ngx_inet_addr / ngx_inet6_addr.
# shellcheck disable=SC2086
gcc -Wall -Wextra -Werror $CORE_INC -o test_crypto \
	"$WORKSPACE/ci/tests/unit/test_crypto.c" \
	"$WORKSPACE/src/ngx_http_autocert_crypto.c" \
	$INET_OBJS -lssl -lcrypto
./test_crypto

# shellcheck disable=SC2086
gcc -Wall -Wextra -Werror $CORE_INC -o test_json \
	"$WORKSPACE/ci/tests/unit/test_json.c" \
	"$WORKSPACE/src/ngx_autocert_json.c" \
	$BASE_OBJS
./test_json

HTTP_INC="-I$NGX/src/core -I$NGX/src/event -I$NGX/src/event/modules \
     -I$NGX/src/event/quic -I$NGX/src/os/unix -I$NGX/objs \
     -I$NGX/src/http -I$NGX/src/http/modules"
IPIDENT_OBJS="$NGX/objs/src/core/ngx_string.o $NGX/objs/src/core/ngx_inet.o \
      $NGX/objs/src/core/ngx_palloc.o $NGX/objs/src/os/unix/ngx_alloc.o"
# shellcheck disable=SC2086
gcc -Wall -Wextra -Werror $HTTP_INC -o test_ipident \
	"$WORKSPACE/ci/tests/unit/test_ipident.c" \
	$IPIDENT_OBJS -lssl -lcrypto
./test_ipident

# Self-contained: the parser bodies are sliced from the shipped
# ngx_autocert_acme.c by extract_http.sh and compiled against the
# fuzz shim — no nginx objects needed (the rest of that TU is
# event/SSL/resolver machinery the parser does not touch).
bash "$WORKSPACE/ci/fuzz/extract_http.sh"
gcc -Wall -Wextra -Werror -I"$WORKSPACE" \
	-o test_http "$WORKSPACE/ci/tests/unit/test_http.c"
./test_http

# The store source carries an (intentional) unused init-zone `data`
# param, so compile it with nginx's own -Wall (no -Wextra), and keep
# -Wextra -Werror on the test TU.
# shellcheck disable=SC2086
gcc -Wall -Werror $CORE_INC -c \
	"$WORKSPACE/src/ngx_autocert_challenge.c" -o challenge.o
# shellcheck disable=SC2086
gcc -Wall -Wextra -Werror $CORE_INC -c \
	"$WORKSPACE/ci/tests/unit/test_challenge.c" \
	-o test_challenge_tu.o
# shellcheck disable=SC2086
gcc -o test_challenge test_challenge_tu.o challenge.o $STORE_OBJS
./test_challenge

# autolabel A1: runtime cert-request registry. Owner/consumer is
# selected by which init callback runs; the `data` param carries the
# OLD cycle's shm header on nginx's zone-reuse (reload) path and is
# adopted, which the reload tests here exercise.
# shellcheck disable=SC2086
gcc -Wall -Wextra -Werror $CORE_INC -c \
	"$WORKSPACE/src/ngx_autocert_requests.c" -o requests.o
# shellcheck disable=SC2086
gcc -Wall -Wextra -Werror $CORE_INC -c \
	"$WORKSPACE/ci/tests/unit/test_requests.c" \
	-o test_requests_tu.o
# shellcheck disable=SC2086
gcc -o test_requests test_requests_tu.o requests.o $STORE_OBJS
./test_requests

# autolabel A3.4: pure rate-cap + wildcard-cover primitives
# (ngx_autocert_ratecap.h). Header-only; the test provides link stubs
# for the ngx_string.o refs it never calls (ngx_alloc/ngx_pnalloc/
# ngx_log_error_core/ngx_cycle), so it links against ONLY ngx_string.o
# (NOT $STORE_OBJS — ngx_palloc.o there would clash with the stubs).
# shellcheck disable=SC2086
gcc -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_ratecap.c" \
	"$NGX/objs/src/core/ngx_string.o" -o test_ratecap
./test_ratecap

# A6 runtime-marker open semantics. Pure syscall-contract test (no nginx
# objects): plants a FIFO / symlink at <store>/<seg>/.autocert-runtime and
# asserts the driver's open flags refuse them WITHOUT blocking. A FIFO
# opened O_WRONLY without O_NONBLOCK blocks in openat() until a reader
# appears, which wedged the sole ACME driver loop (and its worker) after a
# successful runtime issuance; O_NOFOLLOW does not stop it.
gcc -Wall -Wextra -Werror \
	"$WORKSPACE/ci/tests/unit/test_marker_open.c" \
	-o test_marker_open
./test_marker_open

# Store cert retrieval: ngx_autocert_open_file_path (ngx_autocert_shared.h)
# is the fd-pinned open the serve path uses to read a leaf out of the
# store at handshake. Plants real symlinks / traversal in a temp store
# and asserts the happy read plus that a symlinked leaf OR ancestor is
# refused (per-component O_NOFOLLOW). Header-only: needs the nginx
# include path but no nginx objects.
# shellcheck disable=SC2086
gcc -D_GNU_SOURCE -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_store_open.c" \
	-o test_store_open
./test_store_open

# shellcheck disable=SC2086
gcc -Wall -Werror $CORE_INC -c \
	"$WORKSPACE/src/ngx_autocert_alpn.c" -o alpn.o
# shellcheck disable=SC2086
gcc -Wall -Wextra -Werror $CORE_INC -c \
	"$WORKSPACE/ci/tests/unit/test_alpn.c" -o test_alpn_tu.o
# shellcheck disable=SC2086
gcc -o test_alpn test_alpn_tu.o alpn.o $STORE_OBJS
./test_alpn

# ngx_inet.o: crypto.c (include-shimmed here) now pulls
# ngx_autocert_str_is_ip, which references ngx_inet_addr/ngx_inet6_addr.
# _GNU_SOURCE: the test cross-checks ngx_autocert_timegm against libc
# timegm(3). The test include-shims the crypto .c to reach the static
# ngx_autocert_timegm, so run it from the repo root (relative fixture
# path ci/tests/unit/fixture_leaf.pem).
cd "$WORKSPACE"
# shellcheck disable=SC2086
gcc -D_GNU_SOURCE -Wall -Wextra -Werror $CORE_INC -o "$BUILD_DIR/test_cert_time" \
	"$WORKSPACE/ci/tests/unit/test_cert_time.c" \
	$INET_OBJS -lssl -lcrypto
"$BUILD_DIR/test_cert_time"

# Slice just ngx_autocert_account_json_safe from the shipped account
# source — the function depends only on ngx_str_t, so no nginx objects
# are linked.
bash ci/tests/unit/extract_jsonsafe.sh
# shellcheck disable=SC2086
gcc -Wall -Wextra -Werror -Ici/tests/unit $CORE_INC \
	-o "$BUILD_DIR/test_account_jsonsafe" \
	"$WORKSPACE/ci/tests/unit/test_account_jsonsafe.c"
"$BUILD_DIR/test_account_jsonsafe"
