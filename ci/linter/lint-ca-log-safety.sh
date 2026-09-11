#!/usr/bin/env bash
# ci/linter/lint-ca-log-safety.sh -- CA-controlled data logging safety.
#
# Reject CA-controlled fields passed unwrapped to non-debug ngx_log_* calls.
# DEBUG logs remain exempt because they are runtime-gated and lower-integrity.
# The C-aware lexer lives in ca_log_safety.py; do not replace it with a
# line/statement regex, which cannot distinguish C comments and literals.
#
# Usage: ci/linter/lint-ca-log-safety.sh [files...]     (no args => LINT_MODE)
# Env:   LINT_MODE=staged|all

set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)"
# shellcheck source=ci/linter/lib.sh
. "$ROOT/ci/linter/lib.sh"

FILES_LIST="$(lint_files '^src/.*\.[ch]$' "$@")" || exit 2
if [ -z "$FILES_LIST" ]; then
	echo "lint-ca-log-safety: no C files to check"
	exit 0
fi
mapfile -t FILES <<<"$FILES_LIST"

echo "lint-ca-log-safety: ${#FILES[@]} file(s)"
python3 "$ROOT/ci/linter/ca_log_safety.py" "${FILES[@]}"
rc=$?
if [ "$rc" -eq 0 ]; then
	echo "lint-ca-log-safety: no unwrapped CA-controlled fields in non-debug ngx_log_* calls"
fi
exit "$rc"
