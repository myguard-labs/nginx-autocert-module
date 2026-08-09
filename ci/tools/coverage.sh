#!/usr/bin/env bash
# coverage.sh -- build the module with gcov instrumentation, run the unit
# suite, and print a per-file line-coverage summary for the module's own
# sources under src/ (NOT nginx's sources).
#
# WHY. ci/tests/unit/run.sh compiles several module .c files directly
# (ngx_http_autocert_crypto.c, ngx_autocert_json.c, ngx_autocert_challenge.c,
# ngx_autocert_requests.c, ngx_autocert_alpn.c, plus extracted slices of
# ngx_autocert_acme.c / ngx_autocert_account.c) against a small set of nginx
# core objects, rather than through nginx's own build. run.sh calls `gcc`
# literally (no $CC hook), and it is also the file PR #165 is actively
# editing, so this script does not touch run.sh. Instead it shadows `gcc`
# on PATH with a thin wrapper that appends `--coverage` to every invocation
# and DELETES any pre-existing non-instrumented .build/unit cache first, so
# every module TU run.sh compiles is rebuilt with -fprofile-arcs
# -ftest-coverage this run. .gcno/.gcda then land next to the .o the way gcc
# does by default (compile cwd == .build/unit, see run.sh) -- no GCOV_PREFIX
# juggling needed.
#
# USAGE:
#   ci/tools/coverage.sh
#
# ENV:
#   NGINX_VERSION      pre-resolved version; skips nginx.org lookup when set
#                       (same knob as ci-build.sh).
#   GITHUB_WORKSPACE   module checkout root; falls back to repo root locally
#                      (same as ci-build.sh).
#
# OUTPUT: a per-file line-coverage table for src/*.c to stdout, exit 0 on
# success. This script REPORTS coverage, it does not gate on a threshold --
# repo policy is "coverage high as practical", not a %% gate.
#
# TOOLING: prefers gcovr, falls back to lcov+genhtml, falls back to raw gcov
# (terse per-file %% only, no HTML). Install whichever is missing via the
# normal package route; this script does not install anything itself.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace="${GITHUB_WORKSPACE:-$(cd "$script_dir/../.." && pwd)}"

echo "== coverage.sh =="
echo "workspace: $workspace"

# ---- 1. instrumented build via ci-build.sh's "coverage" profile -----------
AC_BUILD_PROFILE=coverage "$script_dir/ci-build.sh"

# Locate the build dir ci-build.sh just produced: nginx-$NGINX_VERSION under
# $workspace. NGINX_VERSION may have been resolved inside ci-build.sh (not
# exported back to us unless GITHUB_ENV was set), so discover it instead of
# re-resolving against nginx.org a second time.
build_dir="$(find "$workspace" -maxdepth 1 -type d -name 'nginx-*' | sort -V | tail -1)"
if [ -z "$build_dir" ] || [ ! -d "$build_dir/objs" ]; then
  echo "::error::no built nginx-* tree found under $workspace after ci-build.sh coverage" >&2
  exit 1
fi
echo "build dir: $build_dir"

# ---- 2. gcc wrapper: shadow PATH so run.sh's literal `gcc` calls pick up
#         --coverage without editing run.sh (PR #165 is live on those files) --
cov_bin_dir="$(mktemp -d)"
trap 'rm -rf "$cov_bin_dir"' EXIT

real_gcc="$(command -v gcc)"
cat >"$cov_bin_dir/gcc" <<EOF
#!/usr/bin/env bash
exec "$real_gcc" --coverage "\$@"
EOF
chmod +x "$cov_bin_dir/gcc"

# Force a clean recompile of every module TU under coverage instrumentation
# -- a stale non-instrumented .o/.gcno from a prior plain run.sh invocation
# would otherwise link fine and silently produce zero coverage data.
unit_build="$workspace/.build/unit"
rm -rf "$unit_build"

# ---- 3. run the unit suite with gcc shadowed -------------------------------
# Not `set -e`-fatal here: a test binary that crashes mid-suite still leaves
# every .gcda file from tests that ran BEFORE it, and this script's job is to
# report coverage of whatever executed, not to re-judge pass/fail (that is
# run.sh's own contract, already enforced by its own `set -e`). A suite
# failure is surfaced loudly below, never swallowed.
echo "== running unit suite under coverage instrumentation =="
suite_rc=0
PATH="$cov_bin_dir:$PATH" \
  NGX_BUILD_DIR="$build_dir" \
  WORKSPACE="$workspace" \
  bash "$workspace/ci/tests/unit/run.sh" || suite_rc=$?

if [ "$suite_rc" -ne 0 ]; then
  echo "::warning::unit suite exited $suite_rc -- coverage below reflects only the tests that ran before the failure" >&2
fi

gcno_count="$(find "$unit_build" -name '*.gcno' 2>/dev/null | wc -l)"
gcda_count="$(find "$unit_build" -name '*.gcda' 2>/dev/null | wc -l)"
echo "instrumented objects: $gcno_count .gcno, $gcda_count .gcda"
if [ "$gcda_count" -eq 0 ]; then
  echo "::error::no .gcda files produced -- unit suite did not exercise any instrumented binary" >&2
  exit 1
fi

echo "== generating coverage report (src/ only) =="

report_ok=0

if command -v gcovr >/dev/null 2>&1; then
  echo "-- using gcovr --"
  gcovr --root "$workspace" \
    --filter "$workspace/src/" \
    --object-directory "$unit_build" \
    --print-summary \
    "$unit_build" \
    && report_ok=1
elif command -v lcov >/dev/null 2>&1; then
  echo "-- using lcov --"
  info="$unit_build/coverage.info"
  lcov --capture --directory "$unit_build" --base-directory "$workspace" \
    --output-file "$info" --rc branch_coverage=0 \
    --ignore-errors gcov,source,empty,unused,negative,mismatch
  lcov --extract "$info" "$workspace/src/*" --output-file "$info.src" \
    --ignore-errors unused
  lcov --list "$info.src" && report_ok=1
  if command -v genhtml >/dev/null 2>&1; then
    genhtml "$info.src" --output-directory "$unit_build/html" >/dev/null 2>&1 \
      && echo "HTML report: $unit_build/html/index.html"
  fi
else
  echo "-- using raw gcov (no gcovr/lcov found) --"
  for src in "$workspace"/src/*.c; do
    base="$(basename "$src" .c)"
    gcno="$(find "$unit_build" -name "${base}.gcno" | head -1)"
    [ -z "$gcno" ] && continue
    (cd "$(dirname "$gcno")" && gcov -r "$base" 2>/dev/null | grep -A1 "File.*${base}\.c") || true
    report_ok=1
  done
fi

if [ "$report_ok" -ne 1 ]; then
  echo "::error::no coverage tool (gcovr/lcov/gcov) produced a report" >&2
  exit 1
fi

echo "== coverage.sh done =="
