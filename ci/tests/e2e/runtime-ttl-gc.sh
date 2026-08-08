#!/usr/bin/env bash
#
# Idle-TTL GC e2e test (autolabel GC / autocert_runtime_ttl).
#
# The runtime registry is a bounded shm table (NGX_AUTOCERT_REQUESTS_MAX):
# without eviction, a long-lived gateway churning distinct runtime hosts
# wedges at the cap. This test proves the eviction arc end to end against a
# real CA:
#   1. a runtime host is seeded (autocert_test_runtime_request), drained,
#      ordered under Pebble and flipped to ISSUED — with its A6 marker on disk
#      and its cert served on SNI (same arc as runtime-issue.sh);
#   2. autocert_runtime_ttl is set to seconds-scale, and the test seed is
#      one-shot (the driver's once-only kick seed), so nothing refreshes the
#      node's last_seen after issuance;
#   3. the next sched tick (the rearm interval is clamped to the TTL, floored
#      at 60s) GC-evicts the idle node: the eviction is logged, the A6 marker
#      is REMOVED (else a restart would resurrect the node the GC just
#      removed), and the SNI serve gate (A4) no longer presents the runtime
#      cert — the registry node is genuinely gone, not just flagged;
#   4. the config-name vhost is untouched throughout (GC only sweeps the
#      runtime registry, never config names).
#
# DNS mock: same pattern as runtime-issue.sh — challtestsrv publishes an A
# record for the runtime host pointing at the docker network gateway so
# Pebble's http-01 validator can reach this process's listener.
#
# Inputs (env):
#   SERVER_BIN    - built nginx/angie binary (required)
#   NGX_BUILD_DIR - dir holding objs/*.so (defaults to two levels up from BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-runtime-ttl-gc}"
NET_NAME="ac-gc-net-$$"
PEBBLE_NAME="ac-gc-pebble-$$"
DNS_NAME="ac-gc-dns-$$"

CONFIG_DOMAIN="cfg.example.com"        # ordinary config name (creates requests_zone)
RUNTIME_HOST="gcme.example.com"        # seeded ONLY via the test directive
HTTP_PORT="${AC_PORT_5002:-5002}"      # Pebble's httpPort = http-01 validation target
TLS_PORT="${AC_PORT_8443:-8443}"       # TLS SNI serve probe

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    local pid
    pid=$(ss -ltnp 2>/dev/null | grep ":$TLS_PORT " | grep -oP 'pid=\K[0-9]+') || true
    if [ -n "${pid:-}" ]; then kill -9 "$pid" 2>/dev/null || true; fi
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
docker run -d --name "$DNS_NAME" --network "$NET_NAME" \
    -p "${DNS_PORT}":53/udp -p "${DNS_PORT}":53/tcp \
    -p "${MGMT_PORT}":8055 \
    ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    -dnsserver :53 -management :8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -defaultIPv4 "" -defaultIPv6 "" >/dev/null
DNS_CONTAINER_IP=$(docker inspect -f \
    '{{ (index .NetworkSettings.Networks "'"$NET_NAME"'").IPAddress }}' "$DNS_NAME")

for i in $(seq 1 30); do
    if curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/clear-txt" \
            -d '{"host":"_probe.invalid."}' >/dev/null 2>&1; then break; fi
    sleep 1
    [ "$i" = 30 ] && { echo "challtestsrv mgmt did not come up"; docker logs "$DNS_NAME"; exit 1; }
done
curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/add-a" \
    -d "{\"host\":\"pebble.\",\"addresses\":[\"127.0.0.1\"]}" >/dev/null
curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/add-a" \
    -d "{\"host\":\"${CONFIG_DOMAIN}.\",\"addresses\":[\"${HOST_IP}\"]}" >/dev/null
curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/add-a" \
    -d "{\"host\":\"${RUNTIME_HOST}.\",\"addresses\":[\"${HOST_IP}\"]}" >/dev/null

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

# autocert_runtime_ttl 5s: production-meaningless, but the test seed is
# one-shot and nothing else refreshes the node after issuance, so any TTL
# comfortably under the sched floor (5s under NGX_AUTOCERT_TEST, 60s in
# production) makes the FIRST post-issuance tick evict it. The eviction wait
# below is bounded by that floor, not the TTL.
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on;
    autocert_contact admin@example.com;
    autocert_ca https://pebble:${AC_PORT_14000:-14000}/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_ca_trusted_certificate $PREFIX/ca.pem;
    autocert_store_path $PREFIX/store;
    autocert_challenge http-01;
    autocert_runtime_ttl 5s;
    autocert_test_runtime_request ${RUNTIME_HOST};
    server {
        # server_name is CONFIG_DOMAIN only — RUNTIME_HOST must exist ONLY in
        # the runtime registry (same rationale as runtime-issue.sh), or the GC
        # under test would never own its lifecycle.
        listen ${HTTP_PORT};
        server_name ${CONFIG_DOMAIN};
        autocert on;
    }
    server {
        listen ${TLS_PORT} ssl;
        server_name ${CONFIG_DOMAIN};
        autocert on;
    }
}
EOF

echo "== config accepts autocert_runtime_ttl =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
echo "✓ config accepted"

echo "== start =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== wait: runtime cert provisioned (drain -> order -> ISSUED) =="
issued_rt=
for i in $(seq 1 180); do
    grep -q "certificate provisioned for \"${RUNTIME_HOST}\"" "$PREFIX/logs/error.log" && issued_rt=1
    [ -n "$issued_rt" ] && break
    if grep -Eq 'autocert: (ACME order failed|finalize failed|order poll timed out|authorization did not become valid)' \
            "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done
[ -n "$issued_rt" ] || { echo "::error::${RUNTIME_HOST} (runtime) not provisioned"; \
    grep autocert "$PREFIX/logs/error.log" | tail -30; docker logs "$PEBBLE_NAME" 2>&1 | tail -40; exit 1; }
echo "✓ runtime ${RUNTIME_HOST} provisioned"

MARKER="$PREFIX/store/${RUNTIME_HOST}/.autocert-runtime"
[ -f "$MARKER" ] || { echo "::error::missing A6 marker $MARKER"; ls -la "$PREFIX/store" 2>&1; exit 1; }
echo "✓ A6 runtime marker present on disk"

echo "== serve: SNI presents the issued cert BEFORE eviction =="
san=$(echo | openssl s_client -connect "127.0.0.1:${TLS_PORT}" \
        -servername "$RUNTIME_HOST" 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)
echo "$san" | grep -qF "DNS:${RUNTIME_HOST}" \
    || { echo "::error::SNI ${RUNTIME_HOST} did not serve the issued cert pre-eviction (SAN: $san)"; exit 1; }
echo "✓ ${RUNTIME_HOST} served pre-eviction (A4 gate open)"

# The sched rearm interval is clamped to the TTL but floored at 5s under
# NGX_AUTOCERT_TEST (60s in production), so the evicting tick lands ~5s after
# the last pump. Keep a generous ceiling for flake margin.
echo "== wait: idle-TTL GC evicts the node (next sched tick, ~5s) =="
for i in $(seq 1 360); do
    grep -q "runtime request \"${RUNTIME_HOST}\" evicted" "$PREFIX/logs/error.log" && break
    sleep 0.5
    [ "$i" = 360 ] && { echo "::error::runtime host never evicted"; \
        grep autocert "$PREFIX/logs/error.log" | tail -30; exit 1; }
done
echo "✓ eviction logged"

# A6 marker must be gone WITH the node — a surviving marker would resurrect
# the evicted host as ISSUED on the next true restart, un-doing the GC.
for i in $(seq 1 20); do
    [ ! -f "$MARKER" ] && break
    sleep 0.5
    [ "$i" = 20 ] && { echo "::error::A6 marker survived the eviction: $MARKER"; exit 1; }
done
echo "✓ A6 marker removed with the eviction"

echo "== serve: SNI must NOT present the runtime cert AFTER eviction =="
san=$(echo | openssl s_client -connect "127.0.0.1:${TLS_PORT}" \
        -servername "$RUNTIME_HOST" 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)
if echo "$san" | grep -qF "DNS:${RUNTIME_HOST}"; then
    echo "::error::evicted ${RUNTIME_HOST} still served its cert (A4 gate should be closed; SAN: $san)"
    exit 1
fi
echo "✓ evicted ${RUNTIME_HOST} no longer served (A4 gate closed)"

echo "== config name unaffected by the GC =="
san=$(echo | openssl s_client -connect "127.0.0.1:${TLS_PORT}" \
        -servername "$CONFIG_DOMAIN" 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)
echo "$san" | grep -qF "DNS:${CONFIG_DOMAIN}" \
    || { echo "::error::config name ${CONFIG_DOMAIN} broken after GC (SAN: $san)"; exit 1; }
echo "✓ ${CONFIG_DOMAIN} still served (GC only sweeps the runtime registry)"

echo "PASS: idle-TTL GC evicted the runtime node, removed its A6 marker, closed the serve gate"
