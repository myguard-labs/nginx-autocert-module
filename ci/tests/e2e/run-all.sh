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

# Run tag: identifies this job to distinguish it from concurrent sibling jobs
# sharing a self-hosted runner. Used in container/network names to prevent one
# job's cleanup from killing another job's live resources. Format: GITHUB_RUN_ID
# (set by GitHub Actions) or local+PID for local test runs.
AC_E2E_RUN_TAG="${GITHUB_RUN_ID:-local$$}"
export AC_E2E_RUN_TAG

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
CERT_CASES=(key-mismatch expired future wrong-san untrusted-chain)

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
                  "AC_E2E_RUN_TAG=$AC_E2E_RUN_TAG" \
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
#
# This runs ONCE, before the first task starts, so intra-job concurrency
# (AC_E2E_JOBS>1) is unaffected - no task of ours is alive yet.
#
# Container names are scoped by AC_E2E_RUN_TAG to distinguish concurrent e2e
# jobs on the same self-hosted runner. We reap only containers that DON'T match
# our tag, preserving live sibling jobs' resources while cleaning up stale
# containers from previous runs.
for pat in 'ac-dns-' 'ac-pebble-'; do
    # Find all ac-* containers with this pattern, filter those that don't match our tag.
    # Name format: ac-dns-${AC_E2E_RUN_TAG}-$$, ac-pebble-${AC_E2E_RUN_TAG}-$$, etc.
    docker ps -a --filter "name=${pat}" --format "{{.Names}}" | \
        grep -v -- "-${AC_E2E_RUN_TAG}-" | \
        xargs -r docker rm -f >/dev/null 2>&1 || true
done
# Reap networks that don't match our tag (format: ac-net-${AC_E2E_RUN_TAG}-$$).
docker network ls --filter 'name=ac-net-' --format "{{.Name}}" | \
    grep -v -- "-${AC_E2E_RUN_TAG}-" | \
    xargs -r docker network rm >/dev/null 2>&1 || true

chmod +x "$SERVER_BIN" 2>/dev/null || true

# Build the task list first (label, sudo mode, path, extra env), so the runner
# below can be a plain pool over a flat array instead of two near-identical
# loops. Skips are decided here, before any slot is spent on them.
TASK_LABEL=(); TASK_MODE=(); TASK_PATH=(); TASK_ENV=()

for entry in "${SCRIPTS[@]}"; do
    script="${entry%%:*}"
    mode="${entry#"$script"}"; mode="${mode#:}"   # "sudo" or ""
    path="$HERE/$script"
    if [ ! -f "$path" ]; then
        echo "::warning::missing e2e script $script — skipping"
        SKIP+=("$script (missing)")
        continue
    fi
    TASK_LABEL+=("$script"); TASK_MODE+=("${mode:-nosudo}")
    TASK_PATH+=("$path");    TASK_ENV+=("")
done

# cert-validate-reject: one run per fixture case.
cvr="$HERE/cert-validate-reject.sh"
if [ -f "$cvr" ]; then
    for case in "${CERT_CASES[@]}"; do
        TASK_LABEL+=("cert-validate-reject.sh [$case]"); TASK_MODE+=("sudo")
        TASK_PATH+=("$cvr");                             TASK_ENV+=("CERT_CASE=$case")
    done
else
    echo "::warning::cert-validate-reject.sh missing — skipping"
    SKIP+=("cert-validate-reject.sh (missing)")
fi

# Concurrency. Default 1 = the historical sequential behaviour, so this is inert
# until a caller opts in.
#
# !! NOT SAFE ABOVE 1 YET - the port scheme has to be fixed first. !!
#
# AC_E2E_PREFIX and the $$-named containers/networks (acip4-pebble-$$,
# ac-wc-net-$$) really are per-task. Ports are NOT:
#
#   - set_ports strides 100 per slot, but PORT_BASES spans 5001..18190 = 13189
#     ports, so slot N's high bases land on slot N+1's low bases. AC_PORT_15353
#     at slot 1 IS AC_PORT_15453 at slot 0.
#   - AC_PORT_15456 (ipv4-issue.sh) is not in PORT_BASES at all, so it is never
#     offset and every concurrent task publishes the same literal 15456.
#   - Bases are shared across scripts by design (21 scripts use AC_PORT_5002,
#     17 use AC_PORT_14000). Harmless sequentially, a collision when they
#     overlap: tls-alpn-issue.sh and retry-after.sh both take AC_PORT_15453.
#
# Observed in CI at AC_E2E_JOBS=4: "Bind for 0.0.0.0:17053 failed: port is
# already allocated", plus backoff.sh (nginx) and tls-alpn-issue.sh +
# retry-after.sh (angie) failing together.
#
# A stride wider than the span would have to exceed 13189 per slot, which blows
# past the ephemeral floor at 4 slots. The fix is dynamic port allocation per
# task (or a container-network-only scheme with no host publishing), not a
# bigger stride. Until then this stays at 1.
#
# Slots are RECYCLED from a free list of size AC_E2E_JOBS rather than handed out
# one per task. The port ceiling is max(PORT_BASES) + offset + slot*100 and it
# has to stay under the ephemeral floor (max-port.sh enforces this); consuming a
# fresh slot per task would make that ceiling grow with the suite instead of with
# the concurrency.
JOBS="${AC_E2E_JOBS:-1}"
case "$JOBS" in ''|*[!0-9]*|0) JOBS=1 ;; esac
[ "$JOBS" -gt "${#TASK_LABEL[@]}" ] && JOBS="${#TASK_LABEL[@]}"

# PASS/FAIL/DURATIONS are appended by run_one. Under `&` that runs in a subshell,
# where those appends are invisible to the parent - a lost FAIL would turn a red
# suite green. Each task therefore writes its own result file and the parent
# folds them in after wait.
RESULT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ac-e2e-results-XXXXXX")"
trap 'rm -rf "$RESULT_DIR"' EXIT

echo "e2e ${FLAVOR}: ${#TASK_LABEL[@]} tasks, AC_E2E_JOBS=${JOBS}"

if [ "$JOBS" -eq 1 ]; then
    # Sequential: no subshell, so run_one's arrays are the real ones. Kept as a
    # distinct path so the default behaviour is exactly what it always was.
    slot=0
    for i in "${!TASK_LABEL[@]}"; do
        run_one "${TASK_LABEL[$i]}" "$slot" \
            invoke "${TASK_MODE[$i]}" "${TASK_PATH[$i]}" ${TASK_ENV[$i]:+"${TASK_ENV[$i]}"}
        slot=$((slot + 1))
    done
else
    # Worker pool: at most JOBS live tasks, each pinned to a recycled slot.
    declare -A SLOT_OF_PID=()
    free_slots=(); for ((s = 0; s < JOBS; s++)); do free_slots+=("$s"); done

    reap_one() {
        local pid
        wait -n -p pid 2>/dev/null || true
        [ -n "${pid:-}" ] || return 0
        free_slots+=("${SLOT_OF_PID[$pid]}")
        unset "SLOT_OF_PID[$pid]"
    }

    for i in "${!TASK_LABEL[@]}"; do
        while [ "${#free_slots[@]}" -eq 0 ]; do reap_one; done
        slot="${free_slots[0]}"; free_slots=("${free_slots[@]:1}")
        (
            run_one "${TASK_LABEL[$i]}" "$slot" \
                invoke "${TASK_MODE[$i]}" "${TASK_PATH[$i]}" ${TASK_ENV[$i]:+"${TASK_ENV[$i]}"}
            # Subshell: report the verdict through the filesystem.
            printf '%s\t%s\t%s\n' "${#FAIL[@]}" "${DURATIONS[0]%%	*}" "${TASK_LABEL[$i]}" \
                > "$RESULT_DIR/$i"
        ) &
        SLOT_OF_PID[$!]="$slot"
    done
    while [ "${#SLOT_OF_PID[@]}" -gt 0 ]; do reap_one; done

    # Fold the per-task verdicts back into the parent's arrays. A task whose
    # result file is missing (killed, disk full, subshell died before the write)
    # counts as a FAILURE, never as a pass - silence must not read as success.
    PASS=(); FAIL=(); DURATIONS=()
    for i in "${!TASK_LABEL[@]}"; do
        if [ ! -s "$RESULT_DIR/$i" ]; then
            echo "::error::e2e ${FLAVOR}: ${TASK_LABEL[$i]} produced no result (worker died?)"
            FAIL+=("${TASK_LABEL[$i]} (no result)")
            continue
        fi
        IFS=$'\t' read -r nfail secs label < "$RESULT_DIR/$i"
        DURATIONS+=("${secs}	${label}")
        if [ "$nfail" -eq 0 ]; then PASS+=("$label"); else FAIL+=("$label"); fi
    done
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
