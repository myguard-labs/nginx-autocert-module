#!/usr/bin/env bash
# Regression controls for ci/tools/soak.sh.
#
# Usage: bash ci/tools/soak-selftest.sh <asan-nginx-binary>

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
NGINX="${1:?usage: soak-selftest.sh <asan-nginx-binary>}"
REAL_CURL="$(command -v curl)"
CC_BIN="${CC:-cc}"
WORK="$(mktemp -d)"

cleanup() {
    rm -rf "${WORK:?}"
}
trap cleanup EXIT

mkdir -p "$WORK/bin" "$WORK/logs" "$WORK/valgrind-bin"

# Strip the bypass in a controlled wrapper. With a dead ambient proxy and an
# empty NO_PROXY, this models a regression that removes --noproxy from soak.sh.
cat > "$WORK/bin/curl" <<EOF
#!/usr/bin/env bash
set -euo pipefail
args=()
while [ "\$#" -gt 0 ]; do
    if [ "\$1" = "--noproxy" ]; then
        shift 2
        continue
    fi
    args+=("\$1")
    shift
done
exec "$REAL_CURL" "\${args[@]}"
EOF
chmod +x "$WORK/bin/curl"

proxy_env=(
    http_proxy=http://127.0.0.1:9
    https_proxy=http://127.0.0.1:9
    all_proxy=http://127.0.0.1:9
    HTTP_PROXY=http://127.0.0.1:9
    HTTPS_PROXY=http://127.0.0.1:9
    ALL_PROXY=http://127.0.0.1:9
    no_proxy=
    NO_PROXY=
)

if env "${proxy_env[@]}" PATH="$WORK/bin:$PATH" \
        bash "$ROOT/ci/tools/soak.sh" "$NGINX" 1 1 \
        > "$WORK/proxy-negative.log" 2>&1; then
    echo "FAIL: proxy negative control survived after --noproxy was stripped" >&2
    exit 1
fi
if ! grep -qE 'BAD |wrong response' "$WORK/proxy-negative.log"; then
    echo "FAIL: proxy negative control failed for an unexpected reason" >&2
    sed -n '1,120p' "$WORK/proxy-negative.log" >&2
    exit 1
fi
echo "ok   proxy negative control fails without --noproxy"

positive_rc=0
env "${proxy_env[@]}" \
    bash "$ROOT/ci/tools/soak.sh" "$NGINX" 1 1 \
    > "$WORK/proxy-positive.log" 2>&1 || positive_rc=$?
if [ "$positive_rc" -ne 0 ]; then
    echo "FAIL: forced proxy environment captured a loopback soak request" >&2
    sed -n '1,160p' "$WORK/proxy-positive.log" >&2
    exit "$positive_rc"
fi
echo "ok   forced proxy environment cannot capture loopback soak requests"

# Model Memcheck finding a definite leak while the nginx master still exits 0.
# Valgrind and Helgrind are mutually exclusive modes, so only one report glob
# exists in a real run. The soak must inspect that one log and fail.
cat > "$WORK/valgrind-bin/valgrind" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
log_file=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --log-file=*) log_file="${1#*=}"; shift ;;
        --*) shift ;;
        *) break ;;
    esac
done
log_file="${log_file//%p/$$}"
case "${FAKE_VALGRIND_REPORT:?}" in
    clean) printf 'ERROR SUMMARY: 0 errors\n' > "$log_file" ;;
    error) printf 'ERROR SUMMARY: 1 errors\n' > "$log_file" ;;
    leak)  printf 'definitely lost: 8 bytes\nERROR SUMMARY: 1 errors\n' > "$log_file" ;;
    *) exit 64 ;;
esac
exec "$@"
EOF
chmod +x "$WORK/valgrind-bin/valgrind"

run_valgrind_control() {
    local mode_var="$1" report="$2" expected="$3" label="$4"
    local output="$WORK/${mode_var}-${report}.log" control_rc=0

    env "${proxy_env[@]}" PATH="$WORK/valgrind-bin:$PATH" \
        FAKE_VALGRIND_REPORT="$report" "$mode_var=1" \
        bash "$ROOT/ci/tools/soak.sh" "$NGINX" 1 1 \
        > "$output" 2>&1 || control_rc=$?
    if [ "$expected" = fail ]; then
        if [ "$control_rc" -eq 0 ] ||
                ! grep -q 'FAIL: valgrind/helgrind errors' "$output"; then
            echo "FAIL: $label did not fail through its report log" >&2
            sed -n '1,160p' "$output" >&2
            exit 1
        fi
    elif [ "$control_rc" -ne 0 ]; then
        echo "FAIL: $label did not stay clean" >&2
        sed -n '1,160p' "$output" >&2
        exit 1
    fi
    echo "ok   $label"
}

run_valgrind_control USE_VALGRIND leak fail \
    "sole Valgrind report log fails on a definite leak"
run_valgrind_control USE_HELGRIND error fail \
    "sole Helgrind report log fails on an error"
run_valgrind_control USE_VALGRIND clean pass \
    "clean Valgrind report log passes"

cat > "$WORK/canary.c" <<'EOF'
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
    volatile char *p = malloc(8);
    volatile size_t redzone = 8;

    if (p == NULL) {
        return 2;
    }
    p[0] = 1;
    if (argc == 2 && strcmp(argv[1], "leak") == 0) {
        return 0;
    }
    p[redzone] = 1;
    free((void *) p);
    return 0;
}
EOF
"$CC_BIN" -O0 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
    "$WORK/canary.c" -o "$WORK/canary"

# shellcheck source=ci/tools/sanitizer-env.sh
source "$ROOT/ci/tools/sanitizer-env.sh"
autocert_sanitizer_env "$WORK/logs"

"$WORK/canary" leak
if compgen -G "$WORK/logs/asan*" > /dev/null; then
    echo "FAIL: intentional leak produced a report although LSan is disabled" >&2
    sed -n '1,160p' "$WORK"/logs/asan* >&2
    exit 1
fi
echo "ok   intentional leak is delegated to Valgrind"

canary_rc=0
"$WORK/canary" redzone >/dev/null 2>&1 || canary_rc=$?
if [ "$canary_rc" -eq 0 ]; then
    echo "FAIL: ASan redzone canary did not fail" >&2
    exit 1
fi
if ! grep -q 'AddressSanitizer' "$WORK"/logs/asan* 2>/dev/null; then
    echo "FAIL: ASan redzone canary failed without a sanitizer report" >&2
    exit 1
fi
echo "ok   ASan redzone canary fails and reports"
