#!/bin/bash
set -euo pipefail

# Unit test runner for nginx-autocert-module.
# Extracts and compiles all unit tests against a pre-built nginx tree.
#
# Required environment: NGX_BUILD_DIR must point to a built nginx tree
# (with objs/src/core/*.o and other object files intact).
#
# Optional: WORKSPACE overrides the repo root (defaults to this script's parent dir).

# Derive workspace from script location if not set
if [ -z "${WORKSPACE:-}" ]; then
	WORKSPACE="$(cd "$(dirname "$0")/../../.." && pwd)"
fi

# Compiler + optional sanitizer instrumentation. Default (CC unset, SANITIZE
# unset) is byte-identical to the historical hardcoded `gcc` invocation: CC
# resolves to plain "gcc" and both flag/lib additions are empty strings, so
# every gcc line below compiles and links exactly as before.
#
# SANITIZE=1 (or any non-empty value) turns on ASan+UBSan for the WHOLE suite
# (same flags ci/tests/unit/run-asan.sh already uses for its one test), so the
# same 12-binary suite this script runs by default can also run instrumented,
# rather than maintaining a second parallel script per binary.
CC="${CC:-gcc}"
SANITIZE_CFLAGS=""
SANITIZE_LIBS=""
if [ -n "${SANITIZE:-}" ]; then
	SANITIZE_CFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all"
	SANITIZE_LIBS="-lasan -lubsan"
fi
# EXTRA_CFLAGS: free-form additional compiler flags (e.g. -O1 -g3), applied to
# every compile/link invocation alongside SANITIZE_CFLAGS. Empty by default.
EXTRA_CFLAGS="${EXTRA_CFLAGS:-}"

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
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror -DNGX_AUTOCERT_TEST_FAULTS $CORE_INC -o test_crypto \
	"$WORKSPACE/ci/tests/unit/test_crypto.c" \
	"$WORKSPACE/src/ngx_http_autocert_crypto.c" \
	$INET_OBJS -lssl -lcrypto $SANITIZE_LIBS
./test_crypto

# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror $CORE_INC -o test_json \
	"$WORKSPACE/ci/tests/unit/test_json.c" \
	"$WORKSPACE/src/ngx_autocert_json.c" \
	$BASE_OBJS $SANITIZE_LIBS
./test_json

HTTP_INC="-I$NGX/src/core -I$NGX/src/event -I$NGX/src/event/modules \
     -I$NGX/src/event/quic -I$NGX/src/os/unix -I$NGX/objs \
     -I$NGX/src/http -I$NGX/src/http/modules -I$NGX/src/http/v2"
IPIDENT_OBJS="$NGX/objs/src/core/ngx_string.o $NGX/objs/src/core/ngx_inet.o \
      $NGX/objs/src/core/ngx_palloc.o $NGX/objs/src/os/unix/ngx_alloc.o"
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror $HTTP_INC -o test_ipident \
	"$WORKSPACE/ci/tests/unit/test_ipident.c" \
	$IPIDENT_OBJS -lssl -lcrypto $SANITIZE_LIBS
./test_ipident

# Self-contained: the parser bodies are sliced from the shipped
# ngx_autocert_acme.c by extract_http.sh and compiled against the
# fuzz shim — no nginx objects needed (the rest of that TU is
# event/SSL/resolver machinery the parser does not touch).
bash "$WORKSPACE/ci/fuzz/extract_http.sh"
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror -I"$WORKSPACE" \
	-o test_http "$WORKSPACE/ci/tests/unit/test_http.c" $SANITIZE_LIBS
./test_http

# The store source carries an (intentional) unused init-zone `data`
# param, so compile it with nginx's own -Wall (no -Wextra), and keep
# -Wextra -Werror on the test TU.
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Werror $CORE_INC -c \
	"$WORKSPACE/src/ngx_autocert_challenge.c" -o challenge.o
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror $CORE_INC -c \
	"$WORKSPACE/ci/tests/unit/test_challenge.c" \
	-o test_challenge_tu.o
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -o test_challenge test_challenge_tu.o challenge.o $STORE_OBJS $SANITIZE_LIBS
./test_challenge

# autolabel A1: runtime cert-request registry. Owner/consumer is
# selected by which init callback runs; the `data` param carries the
# OLD cycle's shm header on nginx's zone-reuse (reload) path and is
# adopted, which the reload tests here exercise.
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror $CORE_INC -c \
	"$WORKSPACE/src/ngx_autocert_requests.c" -o requests.o
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror $CORE_INC -c \
	"$WORKSPACE/ci/tests/unit/test_requests.c" \
	-o test_requests_tu.o
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -o test_requests test_requests_tu.o requests.o $STORE_OBJS $SANITIZE_LIBS
./test_requests

# autolabel A3.4: pure rate-cap + wildcard-cover primitives
# (ngx_autocert_ratecap.h). Header-only; the test provides link stubs
# for the ngx_string.o refs it never calls (ngx_alloc/ngx_pnalloc/
# ngx_log_error_core/ngx_cycle), so it links against ONLY ngx_string.o
# (NOT $STORE_OBJS — ngx_palloc.o there would clash with the stubs).
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_ratecap.c" \
	"$NGX/objs/src/core/ngx_string.o" -o test_ratecap $SANITIZE_LIBS
./test_ratecap

# F4: pure seconds->ms clamp used for resolver_timeout (and matching the
# dns-01 hook/propagation-delay clamp style) (ngx_autocert_timeconv.h).
# Header-only static-inline touching no nginx runtime state; links against
# ONLY ngx_string.o, same idiom as test_ratecap.c above (a plain `ngx_cycle`
# stub covers the one extern ref ngx_core.h's headers pull in).
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_timeconv.c" \
	"$NGX/objs/src/core/ngx_string.o" -o test_timeconv $SANITIZE_LIBS
./test_timeconv

# A6 runtime-marker open semantics. Pure syscall-contract test (no nginx
# objects): plants a FIFO / symlink at <store>/<seg>/.autocert-runtime and
# asserts the driver's open flags refuse them WITHOUT blocking. A FIFO
# opened O_WRONLY without O_NONBLOCK blocks in openat() until a reader
# appears, which wedged the sole ACME driver loop (and its worker) after a
# successful runtime issuance; O_NOFOLLOW does not stop it.
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_marker_open.c" \
	-o test_marker_open $SANITIZE_LIBS
./test_marker_open

# Store cert retrieval: ngx_autocert_open_file_path (ngx_autocert_shared.h)
# is the fd-pinned open the serve path uses to read a leaf out of the
# store at handshake. Plants real symlinks / traversal in a temp store
# and asserts the happy read plus that a symlinked leaf OR ancestor is
# refused (per-component O_NOFOLLOW), plus (W5g-gap) that win32-spelled
# paths ('\'-separated, mixed, and a '..\' leaf) resolve identically to
# their '/'-spelled form. Needs ngx_string.o for ngx_snprintf/ngx_strlchr,
# now that open_file_path routes through ngx_autocert_win32_classify_root
# (same as test_win32_split_root.c below); not $STORE_OBJS -- its
# ngx_palloc.o would clash with this file's own trivial stubs.
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_store_open.c" \
	"$NGX/objs/src/core/ngx_string.o" -o test_store_open $SANITIZE_LIBS
./test_store_open

# Store-directory / serving-key ownership guard (ngx_autocert_check_owner_mode,
# ngx_autocert_shared.h): driver.c's trylock and serve.c's cache reload both
# adopt filesystem state (a store directory, a serving key) that a hostile
# co-tenant could have pre-created or substituted. open_dir_path()/open_file_
# path() pin every ancestor against a planted symlink, but say nothing about
# who owns the inode or what it is writable by -- this guard closes that gap.
# Exercises real owner-only / group-writable / world-readable dirs and files
# in a temp tree.
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_owner_mode.c" \
	"$NGX/objs/src/core/ngx_string.o" -o test_owner_mode $SANITIZE_LIBS
./test_owner_mode

# win32 root-splitting classifier (ngx_autocert_win32_classify_root, W5g):
# drive-absolute / UNC / relative root recognition, both \ and / separators,
# and the two drive-relative EINVAL rejects. Compiled unconditionally in
# ngx_autocert_shared.h (no win32-header dependency) so this runs the real
# production function on Linux -- the only platform this suite can run on.
# Needs ngx_string.o for ngx_snprintf/ngx_strlchr; not $STORE_OBJS (its
# ngx_palloc.o pulls in symbols this header-only test never defines stubs for).
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_win32_split_root.c" \
	"$NGX/objs/src/core/ngx_string.o" -o test_win32_split_root $SANITIZE_LIBS
./test_win32_split_root

# win32 command-line quoting (ngx_autocert_win32_quote_arg, W8): the
# CreateProcessW lpCommandLine builder the dns-01 operator hook spawn uses on
# win32 -- plain args, spaces, embedded quotes, trailing/interior backslashes,
# concatenation and overflow. Compiled unconditionally in ngx_autocert_shared.h
# (no win32-header dependency), same reasoning as test_win32_split_root.c
# above: this runs the real production function on Linux.
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_win32_quote_arg.c" \
	"$NGX/objs/src/core/ngx_string.o" -o test_win32_quote_arg $SANITIZE_LIBS
./test_win32_quote_arg

# dns-01 hooks share one order across add/remove invocations.  The timeout
# verdict is per-hook state, so keep the source-level control-flow invariant
# pinned: a timed-out add hook must not poison a successful remove hook.
bash "$WORKSPACE/ci/tests/unit/assert_dns_hook_timeout_reset.sh"

# win32 named-mutex singleton NAME construction
# (ngx_autocert_win32_singleton_name, W9): "Global\ngx_autocert_singleton_<hash>"
# from a (caller-canonicalized) store path -- same path -> same name, different
# paths -> different names, oversized output rejected, empty path handled.
# Compiled unconditionally in ngx_autocert_shared.h (no win32-header
# dependency), same reasoning as test_win32_quote_arg.c above: this runs the
# real production function on Linux.
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_win32_singleton_name.c" \
	"$NGX/objs/src/core/ngx_string.o" -o test_win32_singleton_name $SANITIZE_LIBS
./test_win32_singleton_name

# win32 WaitForSingleObject() result -> singleton-acquisition VERDICT mapping
# (ngx_autocert_win32_mutex_wait_verdict, W9): the decision core of the
# named-mutex gate. Pins the rule a plausible port gets backwards --
# WAIT_ABANDONED means ownership transferred to us and is a SUCCESS, not an
# error -- plus WAIT_OBJECT_0 (acquired), WAIT_TIMEOUT (-> NGX_AGAIN, same
# retry path as POSIX EAGAIN), WAIT_FAILED and an unrecognised code
# (-> NGX_ERROR, fail closed). No win32-header dependency (takes a plain
# uint32_t), so this runs the real production function on Linux.
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_win32_mutex_verdict.c" \
	-o test_win32_mutex_verdict $SANITIZE_LIBS
./test_win32_mutex_verdict

# win32 DACL-ACE-tuple -> POSIX group/other permission-bit decision core
# (ngx_autocert_win32_dacl_mode, W11): the security decision behind the
# account-key permission guard (ngx_autocert_account.c:276-283) becoming
# real on win32 instead of a tautology -- before W11 the fabricated st_mode
# was a constant S_IFREG|0600 regardless of the file's actual DACL, so a
# world-readable account key always passed the guard on win32. Given the
# caller's (is_owner, is_allow, is_tolerated, is_write) walk of a file's
# real DACL, this decides whether the group/other bits that guard checks should be set.
# No win32-header dependency (plain ngx_int_t arrays), same reasoning as
# test_win32_mutex_verdict.c above: this runs the real production function
# on Linux.
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_win32_dacl_mode.c" \
	-o test_win32_dacl_mode $SANITIZE_LIBS
./test_win32_dacl_mode

# FILE_RENAME_INFORMATION / FILE_LINK_INFORMATION variable-length-buffer
# layout arithmetic used by ngx_autocert_renameat2() and
# ngx_autocert_linkat() in src/ngx_autocert_win32.h (W18b): pins that the
# trailing FileName[] array starts at offsetof(FileNameLength)+sizeof(ULONG)
# ON THE WIRE, which is NOT the same as sizeof(the hand-laid header struct)
# once HANDLE's 8-byte alignment pads the struct's overall size. The offset
# arithmetic is factored into NGX_AUTOCERT_FILE_NAME_INFO_OFF() in
# ngx_autocert_shared.h (the SAME macro both win32.h callers use), with a
# POSIX-arm ABI-matched stand-in struct alongside it -- so this test binds to
# and asserts the PRODUCTION macro/struct rather than a hand-copied
# reimplementation. Needs ngx_string.o for the same reason
# test_win32_split_root.c does (shared.h pulls in ngx_core.h).
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror $CORE_INC \
	"$WORKSPACE/ci/tests/unit/test_win32_rename_info_layout.c" \
	"$NGX/objs/src/core/ngx_string.o" -o test_win32_rename_info_layout $SANITIZE_LIBS
./test_win32_rename_info_layout

# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Werror $CORE_INC -c \
	"$WORKSPACE/src/ngx_autocert_alpn.c" -o alpn.o
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror $CORE_INC -c \
	"$WORKSPACE/ci/tests/unit/test_alpn.c" -o test_alpn_tu.o
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -o test_alpn test_alpn_tu.o alpn.o $STORE_OBJS $SANITIZE_LIBS
./test_alpn

# ngx_inet.o: crypto.c (include-shimmed here) now pulls
# ngx_autocert_str_is_ip, which references ngx_inet_addr/ngx_inet6_addr.
# _GNU_SOURCE: the test cross-checks ngx_autocert_timegm against libc
# timegm(3). The test include-shims the crypto .c to reach the static
# ngx_autocert_timegm, so run it from the repo root (relative fixture
# path ci/tests/unit/fixture_leaf.pem).
cd "$WORKSPACE"
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror $CORE_INC -o "$BUILD_DIR/test_cert_time" \
	"$WORKSPACE/ci/tests/unit/test_cert_time.c" \
	$INET_OBJS -lssl -lcrypto $SANITIZE_LIBS
"$BUILD_DIR/test_cert_time"

# Slice ngx_autocert_account_json_safe + ngx_autocert_account_log_safe from
# the shipped account source. json_safe depends only on ngx_str_t; log_safe
# calls nginx core's ngx_escape_json (ngx_string.o) but never touches a pool
# or ngx_cycle itself — those are only pulled in because ngx_string.o is
# linked as a whole object and OTHER functions in it reference ngx_cycle /
# ngx_log_error_core / ngx_pnalloc. Same stub-link idiom as test_ratecap.c.
bash ci/tests/unit/extract_jsonsafe.sh
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror -Ici/tests/unit $CORE_INC \
	-o "$BUILD_DIR/test_account_jsonsafe" \
	"$WORKSPACE/ci/tests/unit/test_account_jsonsafe.c" \
	"$NGX/objs/src/core/ngx_string.o" \
	"$NGX/objs/src/core/ngx_palloc.o" \
	"$NGX/objs/src/os/unix/ngx_alloc.o" $SANITIZE_LIBS
"$BUILD_DIR/test_account_jsonsafe"

# Cert-cache freshness key (audit MINOR): mtime alone is whole-second
# resolution and blind to an atomic rename landing a different file with a
# coincidentally equal mtime, or two renewals inside one second. Slices the
# slot struct + sentinel + ngx_autocert_slot_fresh() from the shipped
# ngx_autocert_serve.c (too heavy to include-shim whole: SSL cert_cb + PEM
# parse + ngx_http_ssl_module.h/v2/v3) and drives it against real temp files
# via ngx_autocert_fstat, so the mtime/size/inode values are genuine kernel
# output, not hand-built fixtures.
bash "$WORKSPACE/ci/tests/unit/extract_slotfresh.sh"
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror -Ici/tests/unit -I"$WORKSPACE" \
	$CORE_INC \
	-o "$BUILD_DIR/test_slot_fresh" \
	"$WORKSPACE/ci/tests/unit/test_slot_fresh.c" $SANITIZE_LIBS
"$BUILD_DIR/test_slot_fresh"

# dns-01 orphan-reap table (audit MAJOR/Robustness): ngx_autocert_order_free()
# used to reap the SIGKILLed dns-01 hook child with a BLOCKING waitpid(), which
# parks the worker event loop when the child is wedged in uninterruptible
# kernel I/O (hung NFS/FUSE under the hook binary) and SIGKILL does not land.
# The pid is now handed to a module-scoped table reaped by a standalone
# WNOHANG timer. The table is static inside ngx_autocert_order.c -- the ACME
# order state machine, far too heavy to include-shim -- so extract_orphan.sh
# slices just the table, add() and reap() out of the shipped source. waitpid is
# injected, so "child that never exits" is modelled exactly, and the fake
# waitpid FAILS the run if the reaper ever asks for a blocking wait. No nginx
# objects: the slice touches only ngx_str/ngx_log declarations, and this TU
# stubs ngx_log_error_core/ngx_cycle itself (same idiom as test_ratecap.c).
bash "$WORKSPACE/ci/tests/unit/extract_orphan.sh"
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror -Ici/tests/unit -I"$WORKSPACE" \
	$CORE_INC \
	-o "$BUILD_DIR/test_orphan_reap" \
	"$WORKSPACE/ci/tests/unit/test_orphan_reap.c" $SANITIZE_LIBS
"$BUILD_DIR/test_orphan_reap"

# A6 chunked runtime-marker store walk (audit MINOR/Performance):
# ngx_autocert_runtime_seed() used to readdir() the whole store top level
# synchronously on worker 0's event loop, from BOTH init_process and the
# relock handler -- a reload-time stall proportional to tenant count. The walk
# is now bounded to NGX_AUTOCERT_SEED_CHUNK entries per tick and resumes from
# the live DIR* cursor. This test plants a real store LARGER than one chunk and
# pins that the chunked walk recovers exactly the one-shot walk's host set, at
# every chunk size (no boundary is special), that skipped entry kinds
# (dotfile/marker-less/plain file/empty/oversized/symlink/FIFO) behave as
# before, and that a mid-walk abort releases the DIR* and its container fd.
# It carries its own negative control: a variant that drops the resume cursor
# must recover a DIFFERENT set. extract_seedchunk.sh slices the chunk constant
# and the per-entry marker read out of the shipped driver source (the whole .c
# is the ACME driver -- order state machine, shm zones, OpenSSL, event loop --
# far too heavy to include-shim), so the test stays locked to production code.
bash "$WORKSPACE/ci/tests/unit/extract_seedchunk.sh"
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -D_GNU_SOURCE -Wall -Wextra -Werror -Ici/tests/unit -I"$WORKSPACE" \
	$CORE_INC \
	-o "$BUILD_DIR/test_seed_chunk" \
	"$WORKSPACE/ci/tests/unit/test_seed_chunk.c" \
	"$NGX/objs/src/core/ngx_string.o" $SANITIZE_LIBS
"$BUILD_DIR/test_seed_chunk"

# Config-time name/contact validation (audit MINOR): server_name/
# autocert_wildcard values land verbatim, unescaped, in the ACME newOrder
# JSON and as a filesystem path segment; autocert_contact's email is
# json_safe-checked today only at ACME-bootstrap time. Both gates now run at
# `nginx -t` (ngx_http_autocert_add_name / ngx_http_autocert_contact in
# ngx_http_autocert_module.c). ngx_autocert_dns_name_valid is header-only
# (ngx_autocert_ident.h, same file test_ipident.c already exercises this
# way); ngx_autocert_account_json_safe is sliced by the same
# extract_jsonsafe.sh test_account_jsonsafe uses above. A wildcard
# ("*.example.com") and a punycode label ("xn--...") MUST still be accepted
# -- an over-strict gate here breaks a working config, which is worse than
# the bug this closes.
# shellcheck disable=SC2086
"$CC" $SANITIZE_CFLAGS $EXTRA_CFLAGS -Wall -Wextra -Werror -Ici/tests/unit -I"$WORKSPACE" $HTTP_INC \
	-o "$BUILD_DIR/test_name_valid" \
	"$WORKSPACE/ci/tests/unit/test_name_valid.c" -lssl -lcrypto $SANITIZE_LIBS
"$BUILD_DIR/test_name_valid"
