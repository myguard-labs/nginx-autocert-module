#!/usr/bin/env bash
#
# run-all.sh — batched Pebble e2e runner for ONE flavor.
#
# CI used to spawn one job per (script × flavor): 33 scripts × 2 flavors = 66
# jobs, each paying the full checkout + download-artifact + apt boilerplate
# before running a single ~60-90s test. With only ~2 self-hosted runner lanes
# that serialized into a very long queue. This driver runs the whole e2e suite
# for one flavor in a SINGLE job: the build artifact is downloaded once, then
# every script runs sequentially against it. Two jobs (nginx + angie) then run
# in parallel on the two lanes.
#
# Each e2e script owns its own /tmp/ac-<name> prefix with a `trap cleanup EXIT`,
# so sequential execution is safe — no shared state, no cross-test leakage.
#
# Env (same contract as .github/actions/run-e2e):
#   SERVER_BIN     path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR  unpacked build dir (required; scripts read it too)
#   FLAVOR         nginx | angie (default: basename of SERVER_BIN)
#
# Exit non-zero if ANY script fails; runs them all first (fail-fast off, matching
# the old matrix `fail-fast: false`) and prints a summary table at the end.

set -uo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:?set NGX_BUILD_DIR to the unpacked build dir}"
FLAVOR="${FLAVOR:-$(basename "$SERVER_BIN")}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The Pebble e2e suite, in a sensible order (cheap config/lint first, heavy
# issuance later). Keep in sync with build-test.yml's e2e set: a script here but
# not built into the module, or vice versa, is the drift to catch. Each entry:
#   <script>[:sudo]
# sudo means the test binds a privileged port (:80) or needs root for the store
# and the unprivileged runner must elevate. Harmless to over-request; scripts
# that don't need it ignore it.
SCRIPTS=(
  config-rejects.sh
  coexist-native-acme.sh:sudo     # angie-only; self-detects + skips on nginx; binds :80
  acme-directory.sh
  eab-account.sh
  ipv4-directory.sh
  ipv6-directory.sh
  account-migration.sh
  dns01-order.sh
  dns01-exec-hook.sh
  wildcard-issue.sh
  wildcard-shared.sh
  multi-ca-grouping.sh
  multi-ca-srv-scope.sh
  multi-ca.sh:sudo
  multi-ca-contact.sh:sudo
  single-process-reload.sh
  reload-inflight.sh
  tls-alpn-issue.sh
  rsa-issue.sh
  dual-cert-serve.sh
  dual-cert-issue.sh:sudo
  order-authz.sh:sudo
  renewal.sh:sudo
  backoff.sh:sudo
  retry-after.sh:sudo
  mock-400-repoll.sh:sudo
  mock-finalize-ready.sh:sudo
  mock-download-400-retry.sh:sudo
  mock-order-poll-retry.sh:sudo
  mock-freshness-wrong-domain.sh:sudo
  mock-origin-pin.sh:sudo
  store-certbot.sh:sudo
  store-symlink-swap.sh:sudo
)

# cert-validate-reject.sh exercises one rejection fixture per CERT_CASE; run all
# four (matches the old per-case matrix). Always sudo (root-owned store).
CERT_CASES=(key-mismatch expired future wrong-san)

PASS=(); FAIL=(); SKIP=()

run_one() {
    local label="$1"; shift
    echo "::group::e2e ${FLAVOR}: ${label}"
    local rc=0
    "$@" || rc=$?
    echo "::endgroup::"
    if [ "$rc" -eq 0 ]; then
        echo "✓ ${label}"
        PASS+=("$label")
    else
        echo "::error::e2e ${FLAVOR}: ${label} failed (exit ${rc})"
        FAIL+=("$label")
    fi
}

invoke() {   # invoke <use_sudo> <script-abs> [extra env KEY=VAL ...]
    local use_sudo="$1" script="$2"; shift 2
    local env_kv=("SERVER_BIN=$SERVER_BIN" "NGX_BUILD_DIR=$NGX_BUILD_DIR" "$@")
    if [ "$use_sudo" = sudo ]; then
        sudo env "${env_kv[@]}" bash "$script"
    else
        env "${env_kv[@]}" bash "$script"
    fi
}

chmod +x "$SERVER_BIN" 2>/dev/null || true

for entry in "${SCRIPTS[@]}"; do
    script="${entry%%:*}"
    mode="${entry#"$script"}"; mode="${mode#:}"   # "sudo" or ""
    path="$HERE/$script"
    if [ ! -f "$path" ]; then
        echo "::warning::missing e2e script $script — skipping"
        SKIP+=("$script (missing)")
        continue
    fi
    run_one "$script" invoke "${mode:-nosudo}" "$path"
done

# cert-validate-reject: one run per fixture case.
cvr="$HERE/cert-validate-reject.sh"
if [ -f "$cvr" ]; then
    for case in "${CERT_CASES[@]}"; do
        run_one "cert-validate-reject.sh [$case]" \
            invoke sudo "$cvr" "CERT_CASE=$case"
    done
else
    echo "::warning::cert-validate-reject.sh missing — skipping"
    SKIP+=("cert-validate-reject.sh (missing)")
fi

echo
echo "==================== e2e summary (${FLAVOR}) ===================="
printf 'passed:  %d\n' "${#PASS[@]}"
printf 'failed:  %d\n' "${#FAIL[@]}"
printf 'skipped: %d\n' "${#SKIP[@]}"
if [ "${#FAIL[@]}" -gt 0 ]; then
    printf '  FAIL: %s\n' "${FAIL[@]}"
fi
if [ "${#SKIP[@]}" -gt 0 ]; then
    printf '  SKIP: %s\n' "${SKIP[@]}"
fi
echo "================================================================"

[ "${#FAIL[@]}" -eq 0 ]
