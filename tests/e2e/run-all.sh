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
#   AC_PORT_OFFSET optional integer added to host-bound test ports; defaults by
#                  FLAVOR (nginx=0, angie=1000) so flavor jobs can run in parallel.
#
# Exit non-zero if ANY script fails; runs them all first (fail-fast off, matching
# the old matrix `fail-fast: false`) and prints a summary table at the end.

set -uo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:?set NGX_BUILD_DIR to the unpacked build dir}"
FLAVOR="${FLAVOR:-$(basename "$SERVER_BIN")}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "${AC_PORT_OFFSET:-}" ]; then
    case "$FLAVOR" in
        angie) AC_PORT_OFFSET=1000 ;;
        *)     AC_PORT_OFFSET=0 ;;
    esac
fi

PORT_BASES=(
    5001 5002 5021 5998 5999
    8055 8056 8057 8080 8081 8082 8083 8084 8085 8086 8087 8088 8089
    8443 8444 8463 8466 8543
    14000 14001 14011 14013 14014 14021 14031 14037 14041 14042
    14066 14071 14072 14081 14443 14444
    15000 15001 15353 15354 15355 15356 15357 15358
    15453 15455 15463 15465 15466 15473 15475 15483 15487 15489
    15493 15571 15581 18089 18090 18185 18190
)

set_port() {
    local base="$1"
    export "AC_PORT_${base}=$((base + AC_EFFECTIVE_PORT_OFFSET))"
}

set_ports() {
    local extra_offset="$1"
    AC_EFFECTIVE_PORT_OFFSET=$((AC_PORT_OFFSET + extra_offset))
    export AC_EFFECTIVE_PORT_OFFSET
    local base
    for base in "${PORT_BASES[@]}"; do
        set_port "$base"
    done
}

export AC_PORT_OFFSET

set_ports 0
echo "e2e ${FLAVOR}: AC_PORT_OFFSET=${AC_PORT_OFFSET} AC_PORT_14000=${AC_PORT_14000} AC_PORT_15000=${AC_PORT_15000}"

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
  ipv4-issue.sh
  ipv6-directory.sh
  account-migration.sh
  dns01-order.sh
  dns01-exec-hook.sh
  wildcard-issue.sh
  wildcard-shared.sh
  runtime-issue.sh
  runtime-zero-static-names.sh
  runtime-ttl-gc.sh
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

# max-port.sh sources this file purely to reuse PORT_BASES/SCRIPTS/CERT_CASES so
# its port-budget ceiling can never drift from the real suite. Hand control back
# before we touch docker or run a single test.
if [ -n "${AC_E2E_MAX_PORT_ONLY:-}" ]; then
    return 0
fi

PASS=(); FAIL=(); SKIP=()

# Per-script wall-clock, as "<seconds>\t<label>" rows. Recorded for every script
# including failures: a script that fails slowly is exactly the one worth seeing.
# Written to $AC_E2E_TIMINGS as a TSV when that is set, so CI can keep it as an
# artifact instead of making the next reader re-derive it from a log.
DURATIONS=()

run_one() {
    local label="$1"; shift
    local slot="$1"; shift
    local safe_label="${label//[^A-Za-z0-9_.-]/-}"
    set_ports "$((slot * 100))"
    AC_E2E_PREFIX="/tmp/ac-${FLAVOR}-${GITHUB_RUN_ID:-local}-$(printf '%02d' "$slot")-${safe_label}"
    export AC_E2E_PREFIX
    echo "e2e ${FLAVOR}: ${label}: AC_EFFECTIVE_PORT_OFFSET=${AC_EFFECTIVE_PORT_OFFSET} AC_PORT_8080=${AC_PORT_8080} AC_PORT_14000=${AC_PORT_14000} AC_PORT_15000=${AC_PORT_15000}"
    echo "e2e ${FLAVOR}: ${label}: PREFIX=${AC_E2E_PREFIX}"
    echo "::group::e2e ${FLAVOR}: ${label}"
    local rc=0 started=$SECONDS
    "$@" || rc=$?
    local elapsed=$((SECONDS - started))
    echo "::endgroup::"
    DURATIONS+=("${elapsed}	${label}")
    if [ "$rc" -eq 0 ]; then
        echo "✓ ${label} (${elapsed}s)"
        PASS+=("$label")
    else
        echo "::error::e2e ${FLAVOR}: ${label} failed (exit ${rc}, ${elapsed}s)"
        FAIL+=("$label")
    fi
}

invoke() {   # invoke <use_sudo> <script-abs> [extra env KEY=VAL ...]
    local use_sudo="$1" script="$2"; shift 2
    local env_kv=("SERVER_BIN=$SERVER_BIN" "NGX_BUILD_DIR=$NGX_BUILD_DIR" \
                  "AC_PORT_OFFSET=$AC_PORT_OFFSET" \
                  "AC_EFFECTIVE_PORT_OFFSET=$AC_EFFECTIVE_PORT_OFFSET" \
                  "PREFIX=$AC_E2E_PREFIX" "$@")
    local name
    while IFS='=' read -r name _; do
        case "$name" in
            AC_PORT_*) env_kv+=("$name=${!name}") ;;
        esac
    done < <(env)
    if [ "$use_sudo" = sudo ]; then
        sudo env "${env_kv[@]}" bash "$script"
    else
        env "${env_kv[@]}" bash "$script"
    fi
}

# Self-hosted runners persist Docker state across job runs. A prior job
# killed mid-e2e (runner OOM, workflow cancel) can leave an ac-* container
# holding a UDP port binding; docker-proxy for that stale container then
# collides with the next run's `-p ...:53/udp` and fails the whole script
# with "address already in use" on an unrelated ephemeral port. Reap any
# leftovers from a previous run before starting ours.
for pat in 'ac-dns-' 'ac-pebble-'; do
    docker ps -aq --filter "name=${pat}" | xargs -r docker rm -f >/dev/null 2>&1 || true
done
docker network ls -q --filter 'name=ac-net-' | xargs -r docker network rm >/dev/null 2>&1 || true

chmod +x "$SERVER_BIN" 2>/dev/null || true

slot=0
for entry in "${SCRIPTS[@]}"; do
    script="${entry%%:*}"
    mode="${entry#"$script"}"; mode="${mode#:}"   # "sudo" or ""
    path="$HERE/$script"
    if [ ! -f "$path" ]; then
        echo "::warning::missing e2e script $script — skipping"
        SKIP+=("$script (missing)")
        continue
    fi
    run_one "$script" "$slot" invoke "${mode:-nosudo}" "$path"
    slot=$((slot + 1))
done

# cert-validate-reject: one run per fixture case.
cvr="$HERE/cert-validate-reject.sh"
if [ -f "$cvr" ]; then
    for case in "${CERT_CASES[@]}"; do
        run_one "cert-validate-reject.sh [$case]" \
            "$slot" invoke sudo "$cvr" "CERT_CASE=$case"
        slot=$((slot + 1))
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

# Slowest-first, because the only actionable question here is "what is the long
# pole". Sequential total is the current wall-clock floor for this job; any
# sharding or concurrency work is measured against it.
if [ "${#DURATIONS[@]}" -gt 0 ]; then
    echo
    echo "---- per-script wall-clock (${FLAVOR}), slowest first ----"
    printf '%s\n' "${DURATIONS[@]}" | sort -rn | awk -F'\t' '
        { total += $1; printf "  %5ds  %s\n", $1, $2 }
        END { printf "  ------\n  %5ds  TOTAL (%d scripts, sequential)\n", total, NR }'
    if [ -n "${AC_E2E_TIMINGS:-}" ]; then
        printf '%s\n' "${DURATIONS[@]}" | sort -rn > "$AC_E2E_TIMINGS"
        echo "  timings TSV: $AC_E2E_TIMINGS"
    fi
fi
echo "================================================================"

[ "${#FAIL[@]}" -eq 0 ]
