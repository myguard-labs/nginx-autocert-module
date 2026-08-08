#!/usr/bin/env bash
#
# Per-name failure backoff test (M9b).
#
# Two names share one helper:
#   - good.example.com  -> a real server{} block; Pebble validates http-01 and
#                          the cert issues exactly once.
#   - bad.example.com   -> DNS points it at an unroutable address, so Pebble's
#                          VA can never fetch the http-01 token; its order fails
#                          every attempt.
#
# The scheduler must NOT re-order the failing name every sweep: after a failure
# it holds the name off for an exponential backoff (5s, then 10s, then 20s...
# BASE=5, NGX_AUTOCERT_TEST build). The oracle only works if the sweep period is
# SHORTER than the backoff step being measured -- otherwise the sweep, not the
# backoff, sets the spacing between failures and a build with backoff deleted
# would still pass. autocert_renew_before is set here to floor the sweep at the
# 5s NGX_AUTOCERT_SCHED_FLOOR.
#
# Each failed order attempt against the unroutable BAD name also takes a fixed
# ~15-20s (Pebble's own VA retry/give-up cadence, outside this module's
# control) BEFORE the "ACME order failed" log line, so an absolute gap
# threshold between two failures cannot discriminate: it is dominated by that
# fixed order duration, not the backoff hold, and does not fall low enough to
# fail even with backoff sabotaged to a no-op (measured: sabotaged gap ~21s,
# clean gap ~21s for the FIRST retry -- indistinguishable). What DOES
# discriminate is GROWTH: the backoff step doubles (5s -> 10s) between the
# first and second retry, so the inter-attempt-START gap must grow by
# approximately one backoff step across three attempts, while a no-op backoff
# holds it flat. We therefore compare the two inter-start gaps (1st->2nd vs
# 2nd->3rd) and require the second to exceed the first by a margin only the
# growing backoff explains. The good name issued once and is not re-ordered.
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-backoff}"
AC_E2E_RUN_TAG="${AC_E2E_RUN_TAG:-local$$}"
NET_NAME="ac-net-${AC_E2E_RUN_TAG}-$$"
PEBBLE_NAME="ac-pebble-${AC_E2E_RUN_TAG}-$$"
DNS_NAME="ac-dns-${AC_E2E_RUN_TAG}-$$"
GOOD="good.example.com"
BAD="bad.example.com"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    docker rm -f "$PEBBLE_NAME" "$DNS_NAME" >/dev/null 2>&1 || true
    docker network rm "$NET_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

docker network create "$NET_NAME" >/dev/null
HOST_IP=$(docker network inspect "$NET_NAME" \
    -f '{{ (index .IPAM.Config 0).Gateway }}')
echo "== host IP reachable from containers: $HOST_IP =="

DNS_PORT="${DNS_PORT:-${AC_PORT_15353:-15353}}"
MGMT_PORT=$((DNS_PORT + 1))
# good -> host (VA can fetch); bad -> 192.0.2.1 (TEST-NET-1, unroutable) so the
# VA never reaches a token responder and the order keeps failing.
docker run -d --name "$DNS_NAME" --network "$NET_NAME" \
    -p "${DNS_PORT}":53/udp -p "${DNS_PORT}":53/tcp \
    -p "${MGMT_PORT}":8055 \
    ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    -dnsserver :53 -management :8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -defaultIPv4 "" -defaultIPv6 "" >/dev/null
DNS_CONTAINER_IP=$(docker inspect -f \
    '{{ (index .NetworkSettings.Networks "'"$NET_NAME"'").IPAddress }}' "$DNS_NAME")

# challtestsrv mgmt readiness, then republish the A records challtestsrv must serve
for i in $(seq 1 30); do
    if curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/clear-txt" \
            -d '{"host":"_probe.invalid."}' >/dev/null 2>&1; then break; fi
    sleep 1
    [ "$i" = 30 ] && { echo "challtestsrv mgmt did not come up"; docker logs "$DNS_NAME"; exit 1; }
done
curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/add-a" \
    -d "{\"host\":\"pebble.\",\"addresses\":[\"127.0.0.1\"]}" >/dev/null
curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/add-a" \
    -d "{\"host\":\"${GOOD}.\",\"addresses\":[\"${HOST_IP}\"]}" >/dev/null
curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/add-a" \
    -d "{\"host\":\"${BAD}.\",\"addresses\":[\"192.0.2.1\"]}" >/dev/null

cat > "$PREFIX/pebble-config.json" <<EOF
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": ${AC_PORT_5002:-5002},
    "tlsPort": ${AC_PORT_5001:-5001},
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}
EOF

echo "== starting Pebble =="
docker run -d --name "$PEBBLE_NAME" --network "$NET_NAME" \
    -p "${AC_PORT_14000:-14000}":14000 -p "${AC_PORT_15000:-15000}":15000 \
    -e PEBBLE_VA_NOSLEEP=1 \
    -e PEBBLE_WFE_NONCEREJECT=0 \
    -v "$PREFIX/pebble-config.json:/test/config/pebble-config.json:ro" \
    ghcr.io/letsencrypt/pebble:latest \
    -config /test/config/pebble-config.json \
    -dnsserver "${DNS_CONTAINER_IP}:53" -strict >/dev/null

for i in $(seq 1 30); do
    if curl -ksf "https://127.0.0.1:${AC_PORT_14000:-14000}/dir" >/dev/null 2>&1; then break; fi
    sleep 1
    [ "$i" = 30 ] && { echo "Pebble did not come up"; docker logs "$PEBBLE_NAME"; exit 1; }
done

docker cp "$PEBBLE_NAME:/test/certs/pebble.minica.pem" "$PREFIX/ca.pem"

# renew_before 10s => sweep period = renew_before/2 = 5s, clamped at the 5s
# NGX_AUTOCERT_TEST NGX_AUTOCERT_SCHED_FLOOR -- deliberately shorter than the
# backoff step under measurement below (10s), so the backoff, not the sweep,
# is what spaces out the failing name's retries.
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;   # worker-0 ACME driver writes the store; keep worker uid able to
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on;
    autocert_contact admin@example.com;
    autocert_ca https://pebble:${AC_PORT_14000:-14000}/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_resolver_timeout 5s;
    autocert_ca_trusted_certificate $PREFIX/ca.pem;
    autocert_store_path $PREFIX/store;
    autocert_renew_before 10s;
    server { listen ${AC_PORT_5002:-5002}; server_name ${GOOD}; }
    server { listen ${AC_PORT_5002:-5002}; server_name ${BAD}; }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

LOG="$PREFIX/logs/error.log"

# good must provision (once).
for i in $(seq 1 120); do
    [ -f "$PREFIX/store/${GOOD}/fullchain.pem" ] && break
    sleep 0.5
    [ "$i" = 120 ] && { echo "::error::${GOOD} not provisioned"; grep autocert "$LOG" | tail -30; exit 1; }
done
echo "✓ ${GOOD} provisioned"

# Wait for THREE order attempts (starts, not failures) of the bad name, so we
# can measure two consecutive inter-attempt gaps and check they GROW -- see
# the rationale above for why an absolute-threshold gap is not discriminating
# here.
echo "== watching bad-name order attempts for backoff growth (up to ~90s) =="
deadline=$(( $(date +%s) + 90 ))
while :; do
    n=$(grep -c "starting ACME order for \"${BAD}\"" "$LOG" || true)
    [ "$n" -ge 3 ] && break
    [ "$(date +%s)" -ge "$deadline" ] && { echo "::error::did not observe 3 order attempts for ${BAD} (got $n)"; grep autocert "$LOG" | tail -40; exit 1; }
    sleep 2
done

# Extract epoch seconds of the first three attempt starts (nginx log ts: YYYY/MM/DD HH:MM:SS).
mapfile -t TS < <(grep "starting ACME order for \"${BAD}\"" "$LOG" \
    | sed -E 's#^([0-9]{4})/([0-9]{2})/([0-9]{2}) ([0-9:]{8}).*#\1-\2-\3 \4#' \
    | head -3)
t1=$(date -d "${TS[0]}" +%s)
t2=$(date -d "${TS[1]}" +%s)
t3=$(date -d "${TS[2]}" +%s)
gap1=$(( t2 - t1 ))
gap2=$(( t3 - t2 ))
growth=$(( gap2 - gap1 ))
echo "== bad-name inter-attempt gaps: 1st->2nd=${gap1}s, 2nd->3rd=${gap2}s (growth ${growth}s) =="

# BASE=5, MAXSHIFT>=1: the backoff step doubles from 5s (fails=1) to 10s
# (fails=2), so the second gap must exceed the first by a margin only that
# +5s step explains. A build with the backoff hold deleted retries on the
# same fixed cadence every time (measured flat at ~21s in the negative
# control), so growth stays near 0 and this fails.
if [ "$growth" -lt 3 ]; then
    echo "::error::inter-attempt gap did not grow (${gap1}s -> ${gap2}s, growth ${growth}s < 3s); backoff step-up not observed -- a flat retry cadence would explain this"
    grep autocert "$LOG" | tail -40
    exit 1
fi
echo "✓ inter-attempt gap grew ${gap1}s -> ${gap2}s (backoff step-up working, not a flat retry cadence)"

# good must not have been re-ordered (single issuance, no churn).
good_orders=$(grep -c "starting ACME order for \"${GOOD}\"" "$LOG" || true)
[ "$good_orders" -le 1 ] || { echo "::error::${GOOD} ordered ${good_orders}x (should be 1)"; exit 1; }
echo "✓ ${GOOD} ordered once (no re-issue churn)"

echo "✓✓ M9b per-name backoff verified"
