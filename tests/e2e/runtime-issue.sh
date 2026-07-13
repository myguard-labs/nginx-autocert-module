#!/usr/bin/env bash
#
# Runtime-issuance full lifecycle e2e test (autolabel C).
#
# Proves the A1-A6 arc end to end WITHOUT a real consumer module (label-
# autoconf): a test-only directive seeds a host into the requests_zone as
# REQUESTED (the exact insertion path a real consumer would use), then:
#   1. the driver pump (A3) drains it, orders it under Pebble (http-01, A5
#      forces http-01 for runtime names), and flips it to ISSUED;
#   2. the serve gate (A4) presents that issued cert on the runtime host's
#      SNI, sourced from requests_zone (NOT the config-time `names` set —
#      the host is deliberately absent from any `server_name`/`autocert on;`
#      block, so this is genuinely runtime-only);
#   3. a TRUE RESTART: stop the master outright, so the shm segment it owns is
#      destroyed and the runtime registry genuinely ceases to exist (killing a
#      worker is NOT enough — the master survives, owns the segment, and the
#      respawned worker inherits the still-populated mapping, so A6 would pass
#      without ever reading disk). The test seed directive is stripped from the
#      config first, so nothing but the marker can repopulate the registry;
#   4. a fresh master boots over the retained store and its
#      ngx_autocert_runtime_seed() (A6) restores the ISSUED state from the
#      on-disk `.autocert-runtime` marker, so the host is re-served immediately
#      WITHOUT a new ACME order (asserted against a rotated log: any provision
#      line after the restart is by definition a new order).
#
# DNS mock: same pattern as renewal.sh / wildcard-issue.sh — challtestsrv's
# management API publishes an A record for the runtime host pointing at the
# docker network gateway (the host), so Pebble's http-01 validator (running
# in its own container) can reach this process's :80-equivalent listener.
#
# Inputs (env):
#   SERVER_BIN    - built nginx/angie binary (required)
#   NGX_BUILD_DIR - dir holding objs/*.so (defaults to two levels up from BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-runtime-issue}"
NET_NAME="ac-rt-net-$$"
PEBBLE_NAME="ac-rt-pebble-$$"
DNS_NAME="ac-rt-dns-$$"

CONFIG_DOMAIN="cfg.example.com"        # ordinary config name (creates requests_zone)
RUNTIME_HOST="runtime.example.com"     # seeded ONLY via the test directive
# Pebble's httpPort (below) is what it actually GETs for http-01 validation
# (matches renewal.sh's convention) -- this MUST be the port nginx listens on.
HTTP_PORT="${AC_PORT_5002:-5002}"
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

# HTTP_PORT must be reachable from the Pebble container at HOST_IP:HTTP_PORT for
# the http-01 validation GET (autocert forces http-01 for runtime names, A5).
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;   # worker-0 ACME driver writes the store; keep worker uid able to
error_log $PREFIX/logs/error.log notice;
# Explicit pid path: this script is the only one in the suite that reads the
# master pidfile back (the true-restart assertions below compare the pre- and
# post-restart master pids to prove the master really died and a fresh one came
# up over the retained store). angie's compiled-in default pidfile name is
# logs/angie.pid, not logs/nginx.pid like nginx/mainline -- without an
# explicit \`pid\` directive the master starts fine (config test passes, certs
# get issued) but $PREFIX/logs/nginx.pid never appears on an angie build, so
# the wait loop below always times out with "no master pidfile" after 30s.
# Every other e2e script in this suite never reads the pidfile back, so they
# never hit this nginx/angie default-name divergence.
pid $PREFIX/logs/nginx.pid;
events {}
http {
    autocert on;
    autocert_contact admin@example.com;
    autocert_ca https://pebble:${AC_PORT_14000:-14000}/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_ca_trusted_certificate $PREFIX/ca.pem;
    autocert_store_path $PREFIX/store;
    autocert_challenge http-01;
    autocert_test_runtime_request ${RUNTIME_HOST};
    server {
        # server_name is CONFIG_DOMAIN only: the http-01 challenge handler
        # matches purely on the token path (/.well-known/acme-challenge/<token>
        # against challenge_zone), not on server_name/Host -- it doesn't need
        # RUNTIME_HOST here. Listing RUNTIME_HOST in server_name on an
        # "autocert on;" block would collect it into amcf->names too (every
        # server_name of an enabled vhost is collected), defeating the point of
        # this test: RUNTIME_HOST must be seeded ONLY via
        # autocert_test_runtime_request / requests_zone, never a config name.
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

echo "== config accepts autocert_test_runtime_request =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
echo "✓ config accepted"

echo "== start =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
for _ in $(seq 1 30); do [ -s "$PREFIX/logs/nginx.pid" ] && break; sleep 1; done
MASTER=$(cat "$PREFIX/logs/nginx.pid" 2>/dev/null) || { echo "::error::no master pidfile"; exit 1; }

echo "== wait: test host seeded into requests_zone =="
for i in $(seq 1 60); do
    grep -q "seeded test runtime request \"${RUNTIME_HOST}\"" "$PREFIX/logs/error.log" && break
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::runtime host never seeded"; grep autocert "$PREFIX/logs/error.log" | tail -30; exit 1; }
done
echo "✓ ${RUNTIME_HOST} seeded as REQUESTED"

echo "== wait: config-name cert AND runtime-name cert both provisioned =="
issued_cfg=; issued_rt=
for i in $(seq 1 180); do
    grep -q "certificate provisioned for \"${CONFIG_DOMAIN}\"" "$PREFIX/logs/error.log" && issued_cfg=1
    grep -q "certificate provisioned for \"${RUNTIME_HOST}\"" "$PREFIX/logs/error.log" && issued_rt=1
    [ -n "$issued_cfg" ] && [ -n "$issued_rt" ] && break
    if grep -Eq 'autocert: (ACME order failed|finalize failed|order poll timed out|authorization did not become valid)' \
            "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done
grep autocert "$PREFIX/logs/error.log" | tail -40 || true
[ -n "$issued_cfg" ] || { echo "::error::${CONFIG_DOMAIN} not provisioned"; docker logs "$PEBBLE_NAME" 2>&1 | tail -40; exit 1; }
[ -n "$issued_rt" ]  || { echo "::error::${RUNTIME_HOST} (runtime) not provisioned"; docker logs "$PEBBLE_NAME" 2>&1 | tail -40; exit 1; }
echo "✓ both ${CONFIG_DOMAIN} and runtime ${RUNTIME_HOST} provisioned"

# A6 marker on disk (write side) — same segment naming as the store writer.
MARKER="$PREFIX/store/${RUNTIME_HOST}/.autocert-runtime"
[ -f "$MARKER" ] || { echo "::error::missing A6 marker $MARKER"; ls -la "$PREFIX/store" 2>&1; exit 1; }
echo "✓ A6 runtime marker present on disk"

echo "== serve: TLS SNI for ${RUNTIME_HOST} presents the issued (non-dummy) cert =="
san=$(echo | openssl s_client -connect "127.0.0.1:${TLS_PORT}" \
        -servername "$RUNTIME_HOST" 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)
echo "$san" | grep -qF "DNS:${RUNTIME_HOST}" \
    || { echo "::error::SNI ${RUNTIME_HOST} did not serve the issued cert (SAN: $san)"; exit 1; }
cn=$(echo | openssl s_client -connect "127.0.0.1:${TLS_PORT}" \
        -servername "$RUNTIME_HOST" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null || true)
echo "$cn" | grep -q "M7 dummy" && { echo "::error::runtime SNI served the M7 dummy cert, not the issued one"; exit 1; }
echo "✓ ${RUNTIME_HOST} served the ACME-issued cert via cert_cb SNI fallback (A4)"

#
# TRUE RESTART (not a worker crash).
#
# Killing only a worker leaves the master alive, and the master owns the shm
# segment: the respawned worker inherits the SAME mapping, with the runtime
# registry still fully populated. A6 would then "pass" without ever reading the
# disk marker -- the state it claims to restore was never lost. To actually
# exercise A6, the shm segment must be destroyed, which only happens when the
# master itself is gone. So: stop the whole master, prove nothing is left
# holding the ports, then boot a fresh master over the retained store.
#
alive() { kill -0 "$1" 2>/dev/null; }

echo "== true restart: stop the master (destroys the shm segment) =="
# The test directive would re-seed RUNTIME_HOST as REQUESTED on the new master
# and mask the A6 restore entirely, so strip it: after the restart the ONLY
# thing that can put RUNTIME_HOST back into the registry is the disk marker.
sed -i "/autocert_test_runtime_request/d" "$PREFIX/conf/nginx.conf"
grep -q autocert_test_runtime_request "$PREFIX/conf/nginx.conf" \
    && { echo "::error::failed to strip the test seed directive"; exit 1; }
echo "✓ test seed directive stripped from the restart config"

"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop
for _ in $(seq 1 100); do alive "$MASTER" || break; sleep 0.2; done
alive "$MASTER" && { echo "::error::master $MASTER did not exit on -s stop"; exit 1; }

# Nothing may still hold the shm/ports: any surviving process would keep the
# old mapping alive and invalidate the whole point of this restart.
for _ in $(seq 1 50); do
    ss -ltn 2>/dev/null | grep -q ":$TLS_PORT " || break
    sleep 0.2
done
ss -ltn 2>/dev/null | grep -q ":$TLS_PORT " \
    && { echo "::error::something still listens on :$TLS_PORT after stop"; ss -ltnp; exit 1; }
echo "✓ master gone, no listener left: shm segment destroyed"

# Everything the new master learns about RUNTIME_HOST must come off disk. The
# marker + the issued cert are all that survive.
[ -f "$MARKER" ] || { echo "::error::A6 marker vanished across the restart"; exit 1; }

# Rotate the log so every post-restart assertion below reads ONLY new lines --
# otherwise the pre-restart "provisioned"/"restored" lines would satisfy the
# greps and the restart would prove nothing.
mv "$PREFIX/logs/error.log" "$PREFIX/logs/error.pre-restart.log"
: > "$PREFIX/logs/error.log"

echo "== start a FRESH master over the retained store =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
for _ in $(seq 1 30); do
    NEW_MASTER=$(cat "$PREFIX/logs/nginx.pid" 2>/dev/null) || true
    [ -n "${NEW_MASTER:-}" ] && [ "$NEW_MASTER" != "$MASTER" ] && break
    sleep 1
done
[ -n "${NEW_MASTER:-}" ] || { echo "::error::fresh master never wrote a pidfile"; exit 1; }
[ "$NEW_MASTER" != "$MASTER" ] \
    || { echo "::error::pid unchanged ($MASTER) -- the master never actually restarted"; exit 1; }
echo "✓ fresh master $NEW_MASTER (was $MASTER)"

echo "== A6 restores runtime state from the disk marker into the NEW shm =="
for i in $(seq 1 60); do
    grep -q "A6 restored runtime name \"${RUNTIME_HOST}\"" "$PREFIX/logs/error.log" && break
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::A6 restore never logged on the fresh master"; grep autocert "$PREFIX/logs/error.log" | tail -30; exit 1; }
done
echo "✓ A6 restored ${RUNTIME_HOST} into the new shm segment from the disk marker"

echo "== re-served on the fresh master WITHOUT a new ACME order =="
for i in $(seq 1 60); do
    san=$(echo | openssl s_client -connect "127.0.0.1:${TLS_PORT}" \
            -servername "$RUNTIME_HOST" 2>/dev/null \
            | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)
    echo "$san" | grep -qF "DNS:${RUNTIME_HOST}" && break
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::${RUNTIME_HOST} not served after the restart"; exit 1; }
done
cn=$(echo | openssl s_client -connect "127.0.0.1:${TLS_PORT}" \
        -servername "$RUNTIME_HOST" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null || true)
echo "$cn" | grep -q "M7 dummy" \
    && { echo "::error::post-restart SNI served the M7 dummy cert, not the restored one"; exit 1; }
echo "✓ ${RUNTIME_HOST} re-served from the restored state"

# The pre-restart log was rotated away, so ANY provision line here is a new
# order -- the restored ISSUED state must make the driver skip it entirely.
orders_after=$(grep -c "certificate provisioned for \"${RUNTIME_HOST}\"" "$PREFIX/logs/error.log" || true)
[ "$orders_after" -eq 0 ] \
    || { echo "::error::a NEW ACME order was placed for ${RUNTIME_HOST} after the restart ($orders_after) -- A6 restore did not suppress it"; exit 1; }
echo "✓ no new ACME order placed for ${RUNTIME_HOST} across the true restart"

echo "✓✓ autolabel C: runtime issuance lifecycle (seed -> drain/order -> serve -> TRUE RESTART -> A6 restore from disk -> re-serve, no re-order) verified end-to-end"
