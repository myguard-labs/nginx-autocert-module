#!/usr/bin/env bash
#
# IPv4-literal certificate issuance e2e (RFC 8738) — the full round trip.
#
# Distinct from ipv4-directory.sh, which only proves the *ACME client* mechanics
# when the CA's own URL is an IP literal (Host authority, no SNI) against a mock.
# Here the ORDERED IDENTIFIER is the IP: nginx has `server_name <host-ip>;`, the
# module must POST newOrder with {"type":"ip"} (not "dns"), build a CSR carrying
# an iPAddress SAN, satisfy http-01 at that literal address, and store the leaf.
#
# Also distinct from the runtime IP-literal *rejection* (#133): that forbids
# learning an IP from a runtime request. Config-time IP issuance is supported.
#
# http-01 is used deliberately: for an IP identifier the Pebble VA dials the
# literal address directly, which is exactly how a real CA validates an IP cert
# (no DNS record for the identifier exists, or can exist). Only the CA's own
# "pebble" hostname needs resolving, which challtestsrv provides.
#
# Asserts: the order carries type "ip"; authorization valid; cert provisioned;
# the store segment is the verbatim IPv4 literal; the leaf's SAN is an
# *iPAddress* (NOT a DNS name); and cert pubkey == stored privkey.
#
# IPv6 store round-trip is deliberately NOT covered here — the IPv6 store
# segment is mangled (`_ip6_` + zero-padded groups) and deserves its own test.
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-ipv4-issue}"
NET_NAME="acip4-net-$$"
PEBBLE_NAME="acip4-pebble-$$"
DNS_NAME="acip4-dns-$$"

# The VA dials http-01 at <identifier>:<httpPort>. The identifier IS the host's
# gateway IP, so nginx must listen on that same port for the challenge to land.
HTTP_PORT="${HTTP_PORT:-${AC_PORT_5002:-5002}}"

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
echo "== ordering a certificate for the IP literal: $HOST_IP =="

# challtestsrv resolves only "pebble" (the CA's own hostname) for the module's
# ACME client. The ordered identifier is an IP and needs no DNS record at all —
# that asymmetry is the point of the test.
echo "== starting challtestsrv (resolves 'pebble' only) =="
DNS_PORT="${DNS_PORT:-${AC_PORT_15456:-15456}}"
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

# tlsPort points at a closed port to prove tls-alpn-01 is never used: the VA
# only dials httpPort for this challenge.
cat > "$PREFIX/pebble-config.json" <<EOF
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": ${HTTP_PORT},
    "tlsPort": ${AC_PORT_5998:-5998},
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}
EOF

echo "== starting Pebble (VA -> http-01 at ${HOST_IP}:${HTTP_PORT}) =="
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

# The IP literal is the server_name. The listener must bind the gateway address
# on the VA's httpPort so the http-01 GET from Pebble reaches this worker.
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;   # worker-0 ACME driver writes the store; keep worker uid able to
error_log $PREFIX/logs/error.log info;
events {}
http {
    autocert on;
    autocert_contact admin@example.com;
    autocert_ca https://pebble:${AC_PORT_14000:-14000}/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_ca_trusted_certificate $PREFIX/ca.pem;
    autocert_store_path $PREFIX/store;
    autocert_challenge http-01;
    server {
        listen ${HTTP_PORT};
        server_name ${HOST_IP};
        autocert on;
    }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start: register account, then run the http-01 order for ${HOST_IP} =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

ok=
for i in $(seq 1 60); do
    if grep -q 'autocert: authorization for .* is valid' "$PREFIX/logs/error.log"; then
        ok=1; break
    fi
    if grep -Eq 'autocert: ACME order failed|authorization poll timed out|authorization did not become valid' \
            "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done

echo "== helper log =="
grep autocert "$PREFIX/logs/error.log" || true

if [ -z "$ok" ]; then
    echo "::error::authorization did not reach valid for the IP identifier"
    echo "== pebble log =="
    docker logs "$PEBBLE_NAME" 2>&1 | tail -40 || true
    exit 1
fi
echo "✓ authorization reached valid (http-01 served at the IP literal)"

issued=
for i in $(seq 1 60); do
    if grep -q 'autocert: certificate provisioned for' "$PREFIX/logs/error.log"; then
        issued=1; break
    fi
    if grep -Eq 'autocert: (finalize failed|order poll timed out|order did not become valid|certificate download failed|ACME order failed)' \
            "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done

if [ -z "$issued" ]; then
    echo "::error::certificate was not provisioned for the IP identifier"
    docker logs "$PEBBLE_NAME" 2>&1 | tail -40 || true
    exit 1
fi
echo "✓ certificate provisioned (finalize -> poll -> download -> store)"

# Pebble echoes the identifier back on the order. Seeing type "ip" in its log
# proves the module sent {"type":"ip"}, not {"type":"dns"} — a "dns" identifier
# holding a dotted quad would be a silent spec violation that still issues.
if docker logs "$PEBBLE_NAME" 2>&1 | grep -q '"type":"dns","value":"'"${HOST_IP}"'"'; then
    echo "::error::module ordered the IP as a dns identifier (RFC 8738 violation)"
    exit 1
fi
echo "✓ the IP was ordered as an 'ip' identifier, not 'dns'"

# An IPv4 literal is stored verbatim (only IPv6 segments get mangled).
KEY="$PREFIX/store/${HOST_IP}/privkey.pem"
CHAIN="$PREFIX/store/${HOST_IP}/fullchain.pem"
[ -f "$KEY" ]   || { echo "::error::missing $KEY"; exit 1; }
[ -f "$CHAIN" ] || { echo "::error::missing $CHAIN"; exit 1; }
echo "✓ store segment is the verbatim IPv4 literal (${HOST_IP})"

# The SAN must be an iPAddress, NOT a DNS name. X509_check_host never matches an
# iPAddress SAN, so a cert that carried "DNS:1.2.3.4" would fail to serve even
# though it looks right by eye — assert the SAN *type* explicitly.
SAN=$(openssl x509 -in "$CHAIN" -noout -ext subjectAltName 2>/dev/null)
echo "$SAN" | grep -q "IP Address:${HOST_IP}" \
    || { echo "::error::leaf SAN has no iPAddress:${HOST_IP} (got: $SAN)"; exit 1; }
echo "$SAN" | grep -q "DNS:" \
    && { echo "::error::leaf SAN carries a DNS name for an IP identifier (got: $SAN)"; exit 1; }
echo "✓ leaf SAN is an iPAddress (RFC 8738), with no DNS SAN"

CERT_PUB=$(openssl x509 -in "$CHAIN" -noout -pubkey 2>/dev/null | openssl md5)
KEY_PUB=$(openssl pkey -in "$KEY" -pubout 2>/dev/null | openssl md5)
[ "$CERT_PUB" = "$KEY_PUB" ] || { echo "::error::cert pubkey != stored privkey"; exit 1; }
echo "✓ issued certificate public key matches the stored private key"

echo "✓✓ full IPv4-literal issuance verified end-to-end (RFC 8738, http-01)"
