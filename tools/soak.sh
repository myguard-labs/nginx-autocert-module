#!/usr/bin/env bash
#
# Sustained mixed-load soak for the autocert HTTP-01 challenge serve path.
# Drives a real nginx (ideally an ASAN/UBSAN build, optionally under valgrind
# memcheck or helgrind) with concurrent, varied requests against the
# content-phase challenge handler for a fixed duration, then asserts the worker
# survived cleanly: no sanitizer report, no crash, no leak, no error-log
# [alert]/[emerg]. This is the "survives production-shaped load" check that the
# synthetic single-shot e2e tests do not give.
#
# The ACME order/network flow is NOT exercised (it needs a live CA). Instead the
# soak uses the test-only autocert_test_challenge directive (compiled in with
# AUTOCERT_TEST=1) to seed a known token->keyauth into the shared challenge
# store, then hammers /.well-known/acme-challenge/<token> across the handler's
# hit / miss / nested-path / wrong-method / body-carrying branches.
#
# Usage:
#   tools/soak.sh <nginx-binary> [duration_seconds] [concurrency]
#   USE_VALGRIND=1 tools/soak.sh <nginx-binary> 300 4
#   USE_HELGRIND=1 tools/soak.sh <nginx-binary> 300 4
#
# The module .so is looked up next to the binary (../objs or objs). Override
# with NGX_BUILD_DIR.
#
# Exit non-zero on ANY of: sanitizer error, valgrind/helgrind error,
# nginx crash/non-clean exit, error-log alert/emerg, or a wrong response.

set -euo pipefail

NGINX="${1:?usage: soak.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-60}"
CONC="${3:-8}"

NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$NGINX")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "FAIL: missing module .so: $HTTP_SO"; exit 1; }

PORT="${AC_SOAK_PORT:-18288}"
TOKEN="evaGxfADs6pSRb2LMJ7rzMrXXX0123456789abcdefg"
KEYAUTH="$TOKEN.9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/store"

cat > "$WORK/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
daemon off;
master_process on;
worker_processes 2;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 256; }
http {
    access_log off;
    autocert_store_path $WORK/store;
    autocert_test_challenge $TOKEN "$KEYAUTH";
    server {
        listen 127.0.0.1:$PORT;
        server_name a.example.com;
        autocert on;
    }
}
EOF

ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=1:abort_on_error=1:exitcode=42:log_path=$WORK/logs/asan"
export ASAN_OPTIONS
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-}:print_stacktrace=1:halt_on_error=1"

SUPP="$(cd "$(dirname "$0")" && pwd)/valgrind.supp"
RUN=("$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf")
if [ "${USE_VALGRIND:-0}" = "1" ]; then
    RUN=(valgrind --error-exitcode=99 --leak-check=full
         --errors-for-leak-kinds=definite
         --suppressions="$SUPP" --log-file="$WORK/logs/valgrind.%p"
         "${RUN[@]}")
elif [ "${USE_HELGRIND:-0}" = "1" ]; then
    # Data-race / lock-order checking (challenge store rbtree + shared memory).
    # Reuses the same suppression file; --error-exitcode=99 so a detected race
    # fails the job rather than relying on grep-of-log alone.
    RUN=(valgrind --tool=helgrind --error-exitcode=99
         --suppressions="$SUPP" --log-file="$WORK/logs/helgrind.%p"
         "${RUN[@]}")
fi

echo "== config test =="
"$NGINX" -t -p "$WORK" -c "$WORK/conf/nginx.conf"

"${RUN[@]}" &
NGINX_PID=$!

# Wait for the worker-0 driver to seed the test challenge token.
for _ in $(seq 1 100); do
    grep -q 'seeded test challenge token' "$WORK/logs/error.log" 2>/dev/null && break
    curl -fsS -o /dev/null "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN" 2>/dev/null && break
    sleep 0.2
done

echo "soak: ${DURATION}s, concurrency ${CONC}$( [ "${USE_VALGRIND:-0}" = 1 ] && echo ' (valgrind)'; [ "${USE_HELGRIND:-0}" = 1 ] && echo ' (helgrind)')"
END=$(( $(date +%s) + DURATION ))
fail=0

worker() {
    local wid="$1"
    local i=0
    while [ "$(date +%s)" -lt "$END" ]; do
        i=$((i + 1))
        local r=$((RANDOM % 6))
        case "$r" in
        0)  # valid token -> must return exact keyauth
            got=$(curl -fsS "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN" 2>/dev/null || true)
            [ "$got" = "$KEYAUTH" ] || { echo "BAD keyauth: '$got'"; return 1; } ;;
        1)  # HEAD on valid token
            curl -fsS -I -o /dev/null "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN" 2>/dev/null || true ;;
        2)  # unknown token -> 404
            code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/.well-known/acme-challenge/nope-$wid-$i" 2>/dev/null || echo 000)
            [ "$code" = "404" ] || { echo "BAD miss code $code"; return 1; } ;;
        3)  # nested path -> 404
            code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN/extra" 2>/dev/null || echo 000)
            [ "$code" = "404" ] || { echo "BAD nested code $code"; return 1; } ;;
        4)  # wrong method -> 405 with Allow (drain path)
            code=$(curl -s -X POST -o /dev/null -w '%{http_code}' -d 'body=1' "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN" 2>/dev/null || echo 000)
            [ "$code" = "405" ] || { echo "BAD method code $code"; return 1; } ;;
        5)  # GET carrying a body on the valid token (discard_request_body path)
            got=$(curl -fsS --data-binary 'ignored-body' -X GET "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN" 2>/dev/null || true)
            [ "$got" = "$KEYAUTH" ] || { echo "BAD body-GET keyauth"; return 1; } ;;
        esac
    done
}

pids=()
for w in $(seq 1 "$CONC"); do worker "$w" & pids+=($!); done
for pid in "${pids[@]}"; do wait "$pid" || fail=1; done

# Clean shutdown so all pool + shared-zone cleanups run.
kill -QUIT "$NGINX_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null; rc=$?

problems=0
if ls "$WORK"/logs/asan* >/dev/null 2>&1; then
    echo "FAIL: ASAN/UBSAN report:"; cat "$WORK"/logs/asan*; problems=1
fi
if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
    if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null; then
        echo "FAIL: valgrind/helgrind errors:"
        grep -E 'ERROR SUMMARY|definitely lost' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null
        problems=1
    fi
fi
if grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null; then
    echo "FAIL: alert/emerg in error.log"; problems=1
fi
if [ "$fail" -ne 0 ]; then
    echo "FAIL: a worker reported a wrong response"; problems=1
fi
# QUIT is a clean exit; valgrind uses 99, ASAN 42 on error.
if [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ]; then
    echo "FAIL: nginx exited $rc"; tail -40 "$WORK/logs/error.log" || true
    problems=1
fi

[ "$problems" -ne 0 ] && exit 1
echo "✓ soak clean: ${DURATION}s @ ${CONC} concurrent, no sanitizer/leak/crash"
