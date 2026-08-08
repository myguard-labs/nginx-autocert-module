#!/usr/bin/env bash
#
# Runtime issuance with ZERO static config names (autolabel C).
#
# The deployment this proves out is the one nginx-label-autoconf exists to
# serve: a gateway that matches every host with a regex/catch-all server_name
# and learns the real hostnames at runtime from container labels. Such a config
# contributes NO issuable name at config time -- amcf->names is empty.
#
# Before the autolabel-C fix, three things were gated on names->nelts != 0:
#   - the requests_zone (the runtime registry a consumer attaches by name),
#   - the challenge_zone + the :80 http-01 handler,
#   - the ACME account bootstrap (via a ca_list that is only ever populated
#     lazily, per added config name).
# So a runtime-only gateway got no registry to attach, no surface to answer the
# CA's validation GET on, and no account to order under -- and it failed
# SILENTLY: the consumer's zone init stamped api_version 0 and every
# ngx_autocert_requests_* helper fail-safed to inert. No cert was ever
# requested and nothing said why.
#
# This test asserts the whole arc works with no config name anywhere:
#   1. the requests_zone exists at all (the test directive can seed into it);
#   2. an ACME account is bootstrapped despite zero config names;
#   3. the http-01 challenge surface answers for a name that was never in the
#      config, so the order validates;
#   4. the cert is issued and served on that host's SNI;
#   5. no order is ever placed for a config name (there are none -- this guards
#      against "fixing" the gate by fabricating a dummy config-name order).
#
# Inputs (env):
#   SERVER_BIN    - built nginx/angie binary (required)
#   NGX_BUILD_DIR - dir holding objs/*.so (defaults to two levels up from BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-runtime-zero}"
NET_NAME="ac-z-net-$$"
PEBBLE_NAME="ac-z-pebble-$$"
DNS_NAME="ac-z-dns-$$"

# The ONLY hostname in this test. It appears in NO server_name, in NO
# autocert_wildcard -- it exists solely as a runtime request.
RUNTIME_HOST="runtime-only.example.com"

HTTP_PORT="${AC_PORT_5002:-5002}"
TLS_PORT="${AC_PORT_8443:-8443}"

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

#
# The whole point: NO concrete server_name anywhere.
#
# Both vhosts match by regex (`~^.+$`), exactly as a label-driven gateway does.
# nginx strips the leading '~' and sets sn->regex, so postconfig's name sweep
# skips them -- amcf->names ends up EMPTY. The runtime host is injected only via
# autocert_test_runtime_request, standing in for a consumer module's
# ngx_autocert_requests_ensure() call.
#
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;
error_log $PREFIX/logs/error.log notice;
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

    # http-01 validation surface. Regex server_name => contributes NO issuable
    # name; the challenge handler matches on the token path, not on Host.
    server {
        listen ${HTTP_PORT};
        server_name ~^.+\$;
        autocert on;
    }

    # TLS listener. Also regex-only: the cert is selected in cert_cb from the
    # runtime registry (A4), never from a config-time name.
    server {
        listen ${TLS_PORT} ssl;
        server_name ~^.+\$;
        autocert on;
    }
}
EOF

echo "== config accepted with zero concrete server_names =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
echo "✓ config accepted"

echo "== start =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
for _ in $(seq 1 30); do [ -s "$PREFIX/logs/nginx.pid" ] && break; sleep 1; done
[ -s "$PREFIX/logs/nginx.pid" ] || { echo "::error::no master pidfile"; exit 1; }

# Guard the premise: if this ever logs a nonzero name count, the config grew a
# concrete name and the test is no longer testing what it claims to.
echo "== premise: autocert collected ZERO config names =="
for i in $(seq 1 30); do
    grep -q "name(s) enabled for issuance" "$PREFIX/logs/error.log" && break
    sleep 0.5
    [ "$i" = 30 ] && { echo "::error::autocert never logged its name count"; exit 1; }
done
if ! grep -q "autocert: 0 name(s) enabled for issuance" "$PREFIX/logs/error.log"; then
    echo "::error::premise broken -- autocert collected config names, so this is NOT a zero-static-name test"
    grep "name(s) enabled for issuance" "$PREFIX/logs/error.log"
    exit 1
fi
echo "✓ 0 config names (regex-only vhosts), as intended"

# The registry must exist despite zero config names, or the seed can't land.
echo "== requests_zone exists: the runtime seed lands =="
for i in $(seq 1 60); do
    grep -q "seeded test runtime request \"${RUNTIME_HOST}\"" "$PREFIX/logs/error.log" && break
    sleep 0.5
    [ "$i" = 60 ] && {
        echo "::error::runtime host never seeded -- requests_zone was not provisioned with 0 config names"
        grep autocert "$PREFIX/logs/error.log" | tail -30
        exit 1
    }
done
echo "✓ ${RUNTIME_HOST} seeded as REQUESTED into requests_zone"

# The account must bootstrap despite zero config names (empty ca_list => the
# driver used to log "no issuable names; driver idle (no account)" and stop).
echo "== ACME account bootstrapped despite zero config names =="
for i in $(seq 1 60); do
    grep -q "autocert: ACME account registered" "$PREFIX/logs/error.log" && break
    if grep -q "driver idle (no account)" "$PREFIX/logs/error.log"; then
        echo "::error::driver went idle -- no ACME account was bootstrapped with 0 config names"
        grep autocert "$PREFIX/logs/error.log" | tail -20
        exit 1
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::ACME account never registered"; grep autocert "$PREFIX/logs/error.log" | tail -30; exit 1; }
done
echo "✓ ACME account registered (runtime-only CA group provisioned)"

echo "== the runtime-only host is ordered, validated (http-01) and issued =="
for i in $(seq 1 180); do
    grep -q "certificate provisioned for \"${RUNTIME_HOST}\"" "$PREFIX/logs/error.log" && break
    if grep -Eq 'autocert: (ACME order failed|finalize failed|order poll timed out|authorization did not become valid)' \
            "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done
grep autocert "$PREFIX/logs/error.log" | tail -30 || true
grep -q "certificate provisioned for \"${RUNTIME_HOST}\"" "$PREFIX/logs/error.log" \
    || { echo "::error::${RUNTIME_HOST} never provisioned"; docker logs "$PEBBLE_NAME" 2>&1 | tail -40; exit 1; }
echo "✓ ${RUNTIME_HOST} issued -- the :80 challenge surface answered for a name that is not in the config"

echo "== serve: TLS SNI presents the issued (non-dummy) cert =="
san=$(echo | openssl s_client -connect "127.0.0.1:${TLS_PORT}" \
        -servername "$RUNTIME_HOST" 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)
echo "$san" | grep -qF "DNS:${RUNTIME_HOST}" \
    || { echo "::error::SNI ${RUNTIME_HOST} did not serve the issued cert (SAN: $san)"; exit 1; }
cn=$(echo | openssl s_client -connect "127.0.0.1:${TLS_PORT}" \
        -servername "$RUNTIME_HOST" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null || true)
echo "$cn" | grep -q "M7 dummy" \
    && { echo "::error::served the M7 dummy cert, not the issued one"; exit 1; }
echo "✓ ${RUNTIME_HOST} served the ACME-issued cert (A4 cert_cb, from requests_zone)"

# Guard against a "fix" that fabricates a config-name order to force the CA
# group into existence: the ONLY identifier Pebble should ever have seen is the
# runtime host.
echo "== no order was placed for anything but the runtime host =="
others=$(grep -oP 'autocert: starting ACME order for "\K[^"]+' "$PREFIX/logs/error.log" \
         | grep -vFx "$RUNTIME_HOST" || true)
[ -z "$others" ] \
    || { echo "::error::an order was placed for a non-runtime identifier: $others"; exit 1; }
echo "✓ ${RUNTIME_HOST} is the only identifier ever ordered (no dummy config-name order)"

echo "✓✓ autolabel C: runtime issuance works with ZERO static config names (registry + challenge surface + ACME account all provisioned from \"autocert on\", not from the name count)"
