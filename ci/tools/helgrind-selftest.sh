#!/usr/bin/env bash
# Verify the cross-process semaphore suppression without hiding thread races.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK:?}"' EXIT

"${CC:-cc}" -g -O0 -Wall -Wextra -Werror -pthread \
    "$ROOT/ci/tests/unit/test_helgrind_sem.c" -o "$WORK/control"

check() {
    local mode="$1" expected="$2" suppression="$3" rc=0
    local log="$WORK/$mode-$expected"
    valgrind --tool=helgrind --error-exitcode=99 \
        --suppressions="$suppression" --log-file="$log.%p" \
        "$WORK/control" "$mode" || rc=$?
    if [ "$rc" -ne "$expected" ]; then
        echo "FAIL: $mode returned $rc, expected $expected" >&2
        cat "$log".* >&2
        exit 1
    fi
    if [ "$expected" -eq 99 ]; then
        grep -qE 'ERROR SUMMARY: [1-9][0-9]* errors' "$log".*
    else
        if grep -qE 'ERROR SUMMARY: [1-9][0-9]* errors' "$log".*; then
            echo "FAIL: $mode left an unsuppressed child-process error" >&2
            exit 1
        fi
        grep -q 'suppressed: 1 from 1' "$log".*
    fi
    echo "ok   $mode returned $expected"
}

touch "$WORK/empty.supp"
check ipc 99 "$WORK/empty.supp"
check ipc 0 "$ROOT/ci/tools/valgrind.supp"
check outside 99 "$ROOT/ci/tools/valgrind.supp"
check race 99 "$ROOT/ci/tools/valgrind.supp"
