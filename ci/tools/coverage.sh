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
# OUTPUT: a per-file line-coverage table for every tracked production src/*.c
# translation unit.  The script fails if an expected TU has no instrumentation
# data, and preserves a unit-suite failure after writing the report.  It does
# not gate on a percentage -- repo policy is "coverage high as practical", not
# a %% gate.
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
server_prefix=""
trap 'rm -rf "$cov_bin_dir" "$server_prefix"' EXIT

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
module_build="$build_dir/objs/addon/src"
rm -rf "$unit_build"

# The module is linked into nginx as a dynamic module, so the unit binaries
# cannot exercise the main config, worker lifecycle, driver or serve TUs.
# Start and immediately quit one local worker after the unit suite.  This
# bounded workload makes the worker-0 driver init/arm/exit state machine emit
# gcda data without fetching an ACME directory or sending an HTTP request.
run_server_workload() {
  local prefix module binary

  prefix="$(mktemp -d "$workspace/.build/coverage-server.XXXXXX")"
  server_prefix="$prefix"
  module="$build_dir/objs/ngx_http_autocert_module.so"
  binary="$build_dir/objs/nginx"

  if [ ! -f "$module" ] || [ ! -x "$binary" ]; then
    echo "::error::coverage server workload needs $module and $binary" >&2
    return 1
  fi

  mkdir -p "$prefix/conf" "$prefix/logs"
  cat >"$prefix/conf/nginx.conf" <<EOF
load_module $module;
worker_processes 1;
error_log $prefix/logs/error.log notice;
pid $prefix/logs/nginx.pid;
events {}
http {
    autocert on;
    autocert_contact coverage@example.test;
    autocert_store_path $prefix/store;
    server {
        # A Unix socket keeps this workload entirely local and avoids a shared
        # TCP test-port collision with other CI jobs.
        listen unix:$prefix/coverage.sock;
        server_name coverage.example.test;
        autocert on;
    }
}
EOF

  echo "== running bounded no-network server workload =="
  "$binary" -p "$prefix" -c "$prefix/conf/nginx.conf"
  # The initial ACME kick is delayed 500ms.  Four 100ms observations give the
  # synchronous worker-init log time to flush, then quit before that timer can
  # enter any ACME client code.
  for _ in $(seq 1 4); do
    grep -q 'autocert: ACME driver armed on worker 0' "$prefix/logs/error.log" \
      && break
    sleep 0.1
  done
  "$binary" -p "$prefix" -c "$prefix/conf/nginx.conf" -s quit
  if ! grep -q 'autocert: ACME driver armed on worker 0' "$prefix/logs/error.log"; then
    echo "::error::coverage server workload did not reach ngx_autocert_driver_init_process" >&2
    cat "$prefix/logs/error.log" >&2
    return 1
  fi
  echo "server evidence: ngx_autocert_driver_init_process armed worker 0"
}

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

run_server_workload

gcno_count="$(find "$unit_build" "$module_build" -name '*.gcno' 2>/dev/null | wc -l)"
gcda_count="$(find "$unit_build" "$module_build" -name '*.gcda' 2>/dev/null | wc -l)"
echo "instrumented objects: $gcno_count .gcno, $gcda_count .gcda"
if [ "$gcda_count" -eq 0 ]; then
  echo "::error::no .gcda files produced -- unit suite did not exercise any instrumented binary" >&2
  exit 1
fi

# A report over whichever objects happened to run is not a module report.
# Every production TU must have both build-time notes and runtime data.  The
# unit suite owns a small subset; the server workload above owns the dynamic
# module's lifecycle/state-machine objects.  List every missing source rather
# than letting a coverage frontend silently omit it from its aggregate.
missing_inventory=0
for src in "$workspace"/src/*.c; do
  base="$(basename "$src" .c)"
  gcno="$(find "$unit_build" "$module_build" -name "${base}.gcno" -print -quit 2>/dev/null || true)"
  gcda="$(find "$unit_build" "$module_build" -name "${base}.gcda" -print -quit 2>/dev/null || true)"
  if [ -z "$gcno" ] || [ -z "$gcda" ]; then
    echo "::error::coverage inventory missing ${base}.c (gcno=${gcno:-absent}, gcda=${gcda:-absent})" >&2
    missing_inventory=1
  fi
done
if [ "$missing_inventory" -ne 0 ]; then
  exit 1
fi

echo "== generating coverage report (src/ only) =="

report_ok=0

if command -v gcovr >/dev/null 2>&1; then
  echo "-- using gcovr --"
  gcovr --root "$workspace" \
    --filter "$workspace/src/" \
    --print-summary \
    "$unit_build" "$module_build" \
    && report_ok=1
elif command -v lcov >/dev/null 2>&1; then
  echo "-- using lcov --"
  info="$unit_build/coverage.info"
  lcov --capture --directory "$unit_build" --base-directory "$workspace" \
    --output-file "$info.unit" --rc branch_coverage=0 \
    --ignore-errors gcov,source,empty,unused,negative,mismatch
  lcov --capture --directory "$module_build" --base-directory "$workspace" \
    --output-file "$info.server" --rc branch_coverage=0 \
    --ignore-errors gcov,source,empty,unused,negative,mismatch
  lcov --add-tracefile "$info.unit" --add-tracefile "$info.server" \
    --output-file "$info"
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
    gcno="$(find "$unit_build" "$module_build" -name "${base}.gcno" | head -1)"
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

# Do this last: partial data is useful for diagnosis, but a coverage report
# must never turn a late unit failure into a passing command.
exit "$suite_rc"
