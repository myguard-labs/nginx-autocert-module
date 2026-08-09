#!/usr/bin/env bash
# ci-build.sh -- single chokepoint for building a mainline nginx + the
# autocert dynamic module under a given CI profile.
#
# WHY. Every sanitizer/debug lane (asan.yml, valgrind.yml, and eventually
# codeql.yml) inlined the same shape: resolve latest mainline nginx from
# nginx.org -> wget+untar -> AUTOCERT_TEST=1 ./configure --with-compat
# --with-debug --with-threads --with-http_ssl_module <profile cc/ld opts>
# --add-dynamic-module="$GITHUB_WORKSPACE" -> make -j"$(nproc)" [target]. The
# only thing that ever varied between callers was the cc-opt/ld-opt profile
# and the make target. Centralizing it here means a build-flag or configure
# fix lands once instead of N times across workflows.
#
# USAGE:
#   ci/tools/ci-build.sh <profile> [make-target]
#   AC_BUILD_PROFILE=<profile> ci/tools/ci-build.sh [make-target]
#
#   make-target "none" runs configure only and skips make entirely -- for a
#   scanner-setup lane (security-scanners.yml) that only needs a configured
#   nginx source tree (e.g. for clang-tidy headers), never a build.
#
# PROFILES:
#   asan      -fsanitize=address,undefined + UBSan, no recover, -O1 -g3
#   valgrind  -DNGX_DEBUG_PALLOC=1, -O0 -g3, unwind tables
#   debug     --with-debug plain, -O0 -g3 (no sanitizer)
#   release   -O2, no debug symbols beyond what --with-debug already adds
#   codeql    like debug, but intended to be paired with `make-target=modules`
#             so CodeQL only traces the module build, not the whole of nginx
#   coverage  gcov/gcda instrumented build (-g -O0 --coverage), consumed by
#             ci/tools/coverage.sh for a module-only line-coverage report
#
# ENV:
#   NGINX_VERSION   pre-set (non-empty) skips version resolution entirely.
#                    Always exported to $GITHUB_ENV when that var is set, so
#                    existing downstream steps that read env.NGINX_VERSION or
#                    $NGINX_VERSION keep working unmodified.
#   GITHUB_WORKSPACE used as --add-dynamic-module path when set; otherwise
#                    falls back to the directory this script's repo root is
#                    checked out in, so it also works outside Actions.
#
# OUTPUT LAYOUT (unchanged from the pre-existing inline blocks):
#   tarball:    $PWD/nginx-$NGINX_VERSION.tar.gz
#   build dir:  $GITHUB_WORKSPACE/nginx-$NGINX_VERSION  (or $PWD/... locally)
#   nginx bin:  <build dir>/objs/nginx
#
# BUG CLASS THIS SCRIPT MUST NEVER REINTRODUCE: `if ! cmd; then rc=$?; fi`
# captures the NEGATION's exit status, which is always 0/1 for the `if`, not
# cmd's real code. Any place this script needs a command's real status uses
# `rc=0; cmd || rc=$?` instead.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ci-build.sh <profile> [make-target]
       AC_BUILD_PROFILE=<profile> ci-build.sh [make-target]

Build mainline nginx + the autocert dynamic module for a CI profile.

Profiles:
  asan      ASan+UBSan instrumented build (asan.yml)
  valgrind  NGX_DEBUG_PALLOC debug build for memcheck (valgrind.yml)
  debug     plain --with-debug build, no sanitizer
  release   optimized build, no debug cc-opts
  codeql    debug-shaped build; pair with make-target "modules"
  coverage  gcov/gcda instrumented build (ci/tools/coverage.sh)

Env:
  NGINX_VERSION      pre-resolved version; skips nginx.org lookup when set
  AC_BUILD_PROFILE    alternate way to select the profile; when set, arg1
                       (if any) is taken as the make target instead
  GITHUB_WORKSPACE    module checkout root used for --add-dynamic-module
  GITHUB_ENV          when set, NGINX_VERSION is appended to it

Examples:
  ci/tools/ci-build.sh asan
  ci/tools/ci-build.sh valgrind
  AC_BUILD_PROFILE=codeql ci/tools/ci-build.sh modules
  ci/tools/ci-build.sh debug none   # configure only, no make (scanner setup)
EOF
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
esac

# Profile selection: if AC_BUILD_PROFILE is already set, arg1 (if any) is the
# make target, not the profile -- that's how a codeql-shaped caller does
# `AC_BUILD_PROFILE=codeql ci-build.sh modules`. Otherwise arg1 is the
# profile and arg2 is the make target.
if [ -n "${AC_BUILD_PROFILE:-}" ]; then
  profile="$AC_BUILD_PROFILE"
  make_target="${1:-}"
else
  profile="${1:-}"
  make_target="${2:-}"
fi

if [ -z "$profile" ]; then
  echo "::error::no profile given (arg1 or AC_BUILD_PROFILE)" >&2
  usage >&2
  exit 1
fi

cc_opt=""
ld_opt=""
case "$profile" in
  asan)
    san="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g3 -O1"
    cc_opt="$san"
    ld_opt="-fsanitize=address,undefined"
    ;;
  valgrind)
    cc_opt="-DNGX_DEBUG_PALLOC=1 -g3 -O0 -fno-omit-frame-pointer -funwind-tables"
    ;;
  debug | codeql)
    cc_opt="-g3 -O0 -fno-omit-frame-pointer -funwind-tables"
    ;;
  release)
    cc_opt="-O2"
    ;;
  coverage)
    cc_opt="-g -O0 --coverage"
    ld_opt="--coverage"
    ;;
  *)
    echo "::error::unknown build profile '$profile' (want: asan, valgrind, debug, release, codeql, coverage)" >&2
    exit 1
    ;;
esac

# ---- resolve nginx version -------------------------------------------------
if [ -z "${NGINX_VERSION:-}" ]; then
  ver=$(curl -fsSL https://nginx.org/en/download.html \
    | grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.gz)' \
    | sort -V | tail -1)
  if [ -z "$ver" ]; then
    echo "::error::cannot resolve nginx version from nginx.org" >&2
    exit 1
  fi
  NGINX_VERSION="$ver"
fi

if [ -n "${GITHUB_ENV:-}" ]; then
  echo "NGINX_VERSION=$NGINX_VERSION" >>"$GITHUB_ENV"
fi

workspace="${GITHUB_WORKSPACE:-$PWD}"

echo "== ci-build.sh =="
echo "profile:       $profile"
echo "nginx version: $NGINX_VERSION"
echo "make target:   ${make_target:-<default>}"

# ---- idempotent tarball fetch + extract ------------------------------------
tarball="nginx-${NGINX_VERSION}.tar.gz"
test -f "$tarball" \
  || wget -q -O "$tarball" "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"

build_dir="nginx-${NGINX_VERSION}"
if [ ! -d "$build_dir" ]; then
  tar -xzf "$tarball"
fi

(
  cd "$build_dir"

  configure_args=(
    --with-compat --with-debug --with-threads --with-http_ssl_module
    --with-cc="ccache cc"
  )
  [ -n "$cc_opt" ] && configure_args+=(--with-cc-opt="$cc_opt")
  [ -n "$ld_opt" ] && configure_args+=(--with-ld-opt="$ld_opt")
  configure_args+=(--add-dynamic-module="$workspace")

  echo "configure: AUTOCERT_TEST=1 ./configure ${configure_args[*]}"
  AUTOCERT_TEST=1 ./configure "${configure_args[@]}"

  if [ "$make_target" = "none" ]; then
    echo "make target is 'none' -- configure only, skipping make"
  elif [ -n "$make_target" ]; then
    make -j"$(nproc)" "$make_target"
  else
    make -j"$(nproc)"
  fi
)

echo "build dir:     ${workspace}/${build_dir}"
echo "nginx binary:  ${workspace}/${build_dir}/objs/nginx"
