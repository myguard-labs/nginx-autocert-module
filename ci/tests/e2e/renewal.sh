#!/usr/bin/env bash
#
# ACME renewal + multi-name scheduler e2e test (M8).
#
# Builds on order-authz.sh. Two things M8 adds over M6:
#   1. The helper provisions EVERY collected server_name, not just the first.
#   2. A periodic scheduler reissues a certificate once it is inside its
#      renew_before window (now >= notAfter - renew_before).
#
# We drive both:
#   - Two server{} blocks (two domains) -> assert BOTH get a cert on first run.
#   - Pebble issues 1h certs (certificateValidityPeriod: 3600). At provisioning,
#     autocert_renew_before is 60s (< lifetime) so stored certs are NOT
#     immediately due; later we switch renew_before higher for renewal. A
#     reload spawns a fresh helper whose initial scan then reissues both
#     domains. We capture each leaf's serial before the switch and assert it
#     changes after the reload — i.e. a genuine reissue landed atomically in
#     the store and the per-SNI serve path would hot-reload it (M7).
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

# shellcheck source=ci/tests/e2e/image-pins.sh
. "$(dirname "${BASH_SOURCE[0]}")/image-pins.sh"

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-renewal}"
AC_E2E_RUN_TAG="${AC_E2E_RUN_TAG:-local$$}"
NET_NAME="ac-net-${AC_E2E_RUN_TAG}-$$"
PEBBLE_NAME="ac-pebble-${AC_E2E_RUN_TAG}-$$"
DNS_NAME="ac-dns-${AC_E2E_RUN_TAG}-$$"
DOMAIN_A="a.example.com"
DOMAIN_B="b.example.com"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    docker rm -f "$PEBBLE_NAME" "$DNS_NAME" >/dev/null 2>&1 || true
    docker network rm "$NET_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"
# store mode must not depend on the caller's umask (the driver refuses a
# group/other-writable store, and mkdir's mode is umask-filtered).
chmod 0700 "$PREFIX/store"

docker network create "$NET_NAME" >/dev/null
HOST_IP=$(docker network inspect "$NET_NAME" \
    -f '{{ (index .IPAM.Config 0).Gateway }}')
echo "== host IP reachable from containers: $HOST_IP =="

DNS_PORT="${DNS_PORT:-${AC_PORT_15353:-15353}}"
MGMT_PORT=$((DNS_PORT + 1))
docker run -d --name "$DNS_NAME" --network "$NET_NAME" \
    -p "${DNS_PORT}":53/udp -p "${DNS_PORT}":53/tcp \
    -p "${MGMT_PORT}":8055 \
    "$CHALLTESTSRV_IMAGE" \
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
    -d "{\"host\":\"${DOMAIN_A}.\",\"addresses\":[\"${HOST_IP}\"]}" >/dev/null
curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/add-a" \
    -d "{\"host\":\"${DOMAIN_B}.\",\"addresses\":[\"${HOST_IP}\"]}" >/dev/null

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
    "externalAccountBindingRequired": false,
    "profiles": {
      "default": {
        "description": "short-lived certs so renew_before <= 89d forces a renewal",
        "validityPeriod": 3600
      }
    }
  }
}
EOF

echo "== starting Pebble =="
docker run -d --name "$PEBBLE_NAME" --network "$NET_NAME" \
    -p "${AC_PORT_14000:-14000}":14000 -p "${AC_PORT_15000:-15000}":15000 \
    -e PEBBLE_VA_NOSLEEP=1 \
    -e PEBBLE_WFE_NONCEREJECT=0 \
    -v "$PREFIX/pebble-config.json:/test/config/pebble-config.json:ro" \
    "$PEBBLE_IMAGE" \
    -config /test/config/pebble-config.json \
    -dnsserver "${DNS_CONTAINER_IP}:53" -strict >/dev/null

for i in $(seq 1 30); do
    if curl -ksf "https://127.0.0.1:${AC_PORT_14000:-14000}/dir" >/dev/null 2>&1; then break; fi
    sleep 1
    [ "$i" = 30 ] && { echo "Pebble did not come up"; docker logs "$PEBBLE_NAME"; exit 1; }
done

docker cp "$PEBBLE_NAME:/test/certs/pebble.minica.pem" "$PREFIX/ca.pem"

# Pebble issues 1h certs here (certificateValidityPeriod: 3600). We provision with
# a small renew_before (60s) so pass-1 certs are NOT inside their renew window and
# the background scheduler cannot renew them during baseline capture.
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
    autocert_ca_trusted_certificate $PREFIX/ca.pem;
    autocert_store_path $PREFIX/store;
    autocert_renew_before 60s;
    server { listen ${AC_PORT_5002:-5002}; server_name ${DOMAIN_A}; }
    server { listen ${AC_PORT_5002:-5002}; server_name ${DOMAIN_B}; }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

CHAIN_A="$PREFIX/store/${DOMAIN_A}/fullchain.pem"
CHAIN_B="$PREFIX/store/${DOMAIN_B}/fullchain.pem"

wait_for_cert() {
    local f="$1" i
    for i in $(seq 1 120); do
        [ -f "$f" ] && openssl x509 -in "$f" -noout -serial 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}

# require_renew_before_token <value> <tag>
#
# <value> is interpolated into an ERE and a sed replacement, so it is
# restricted to a positive integer plus an s/m/h/d unit. That is not a grammar
# check -- the "nginx -t" that follows a rewrite is the real gate -- it only
# keeps ERE and delimiter metacharacters, "|" above all, out of the patterns.
# The unit is required because a bare assertion has no "nginx -t" behind it, so
# a unitless caller typo would surface as a config-state failure instead.
require_renew_before_token() {
    # RHS unquoted on purpose: quoting makes bash match it literally.
    [[ $1 =~ ^[1-9][0-9]*[smhd]$ ]] \
        || { echo "::error::unsafe autocert_renew_before token '$1' [${2}]"; exit 1; }
}

# The match is anchored to a whole line, so a commented-out directive can
# neither satisfy an assertion nor be rewritten in place of the active one. The
# regex is ERE, so -E is required on both the grep and the sed below, and the
# \1 capture restores the original indentation.
renew_before_re() {
    printf '^([[:space:]]*)autocert_renew_before[[:space:]]+%s;[[:space:]]*$' "$1"
}

# Assert that $PREFIX/conf/nginx.conf carries "autocert_renew_before <value>;"
# exactly once as an active directive. <tag> names the call site in the error
# text. Aborts with exit, so call it as a plain statement.
#
# The count is asserted, not just the presence: the lane's timing reasoning
# assumes one active instance value, so a config that grew a second server
# block with its own directive must fail here rather than be half-rewritten.
assert_renew_before() {
    local value="$1" tag="$2" n
    require_renew_before_token "$value" "$tag"
    # grep exits 1 for no match and 2 for a read error; only the former is an
    # assertion failure, and conflating them would report a blank count.
    n=$(grep -Ec "$(renew_before_re "$value")" "$PREFIX/conf/nginx.conf") \
        || [[ $? == 1 ]] \
        || { echo "::error::cannot read $PREFIX/conf/nginx.conf [${tag}]"; exit 1; }
    # String compare: also rejects an empty count rather than erroring on it.
    [[ $n == 1 ]] \
        || { echo "::error::nginx.conf has ${n} active autocert_renew_before ${value} lines, want 1 [${tag}]"; exit 1; }
}

# Rewrite autocert_renew_before <from> -> <to> in $PREFIX/conf/nginx.conf,
# asserting the value before and after. <tag> names the call site in the error
# text. Aborts with exit, so call it as a plain statement.
#
# The trailing [[:space:]]* is consumed by the substitution, so a rewrite also
# normalises away trailing whitespace.
switch_renew_before() {
    local from="$1" to="$2" tag="$3"
    require_renew_before_token "$from" "$tag"
    require_renew_before_token "$to" "$tag"
    # A no-op switch would pass both assertions over a file that never changed.
    [[ $from != "$to" ]] \
        || { echo "::error::switch_renew_before: from == to ('${from}') [${tag}]"; exit 1; }
    assert_renew_before "$from" "$tag"
    sed -Ei "s|$(renew_before_re "$from")|\\1autocert_renew_before ${to};|" \
        "$PREFIX/conf/nginx.conf"
    assert_renew_before "$to" "$tag"
}

echo "== start: provision BOTH domains =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

SERIAL_A1=$(wait_for_cert "$CHAIN_A") || { echo "::error::${DOMAIN_A} not provisioned"; grep autocert "$PREFIX/logs/error.log" || true; docker logs "$PEBBLE_NAME" 2>&1 | tail -40; exit 1; }
SERIAL_B1=$(wait_for_cert "$CHAIN_B") || { echo "::error::${DOMAIN_B} not provisioned"; grep autocert "$PREFIX/logs/error.log" || true; docker logs "$PEBBLE_NAME" 2>&1 | tail -40; exit 1; }
echo "✓ both domains provisioned (multi-name): A=$SERIAL_A1 B=$SERIAL_B1"

# Now switch the config file to renew_before 2h (> the 1h cert lifetime,
# under the 89d config clamp). The running instance keeps renew_before 60s
# until the reload below, so the first moment either cert can read as due is
# the fresh helper's initial scan — any serial change after the reload is
# attributable to it and not to a background scheduler race.
echo "== updating config: autocert_renew_before 60s -> 2h =="
switch_renew_before 60s 2h "pass-2 switch"
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

# Reload -> fresh helper -> initial scan finds both inside the renew window
# (renew_before 2h > 1h cert lifetime) -> reissues both. New serials prove it.
echo "== reload: force renewal scan =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s reload

renewed() {
    local f="$1" old="$2" i cur
    for i in $(seq 1 120); do
        cur=$(openssl x509 -in "$f" -noout -serial 2>/dev/null || true)
        [ -n "$cur" ] && [ "$cur" != "$old" ] && { echo "$cur"; return 0; }
        sleep 0.5
    done
    return 1
}

SERIAL_A2=$(renewed "$CHAIN_A" "$SERIAL_A1") || { echo "::error::${DOMAIN_A} not renewed (serial unchanged)"; grep autocert "$PREFIX/logs/error.log" | tail -30; exit 1; }
SERIAL_B2=$(renewed "$CHAIN_B" "$SERIAL_B1") || { echo "::error::${DOMAIN_B} not renewed (serial unchanged)"; grep autocert "$PREFIX/logs/error.log" | tail -30; exit 1; }
echo "✓ both domains reissued inside renew window: A=$SERIAL_A2 B=$SERIAL_B2"

# The running instance still holds renew_before 2h against 1h Pebble certs, so
# every stored cert reads as permanently due and the scheduler will keep
# reissuing (driven by the 1s initial scan and order completion pumping the
# scan forward -- at 2h the rearm is min(12h, 1h) = 1h, so the 5s floor never
# binds here). Bring the store back to a not-due, quiescent
# state before reading it, or the consistency checks below can sample across a
# live reissue's atomic swap.
echo "== restart with small renew_before (quiesce store before verification) =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop
# `-s stop` signals the master and returns; it does not wait. A fixed sleep is
# both too long on an idle runner and too short on a loaded one, and what it
# hides is the old master still holding the store (or its listening socket)
# when the new instance starts below -- which would let the 2h instance's
# scheduler reissue into the store the consistency checks are about to read,
# i.e. exactly the race this test exists to close. Poll for real exit instead.
NGINX_PID_FILE="$PREFIX/logs/nginx.pid"
for _ in $(seq 1 100); do
    [ -e "$NGINX_PID_FILE" ] || break
    old_pid=$(cat "$NGINX_PID_FILE" 2>/dev/null || true)
    [ -n "$old_pid" ] || break
    kill -0 "$old_pid" 2>/dev/null || break
    sleep 0.1
done
if [ -e "$NGINX_PID_FILE" ] \
   && old_pid=$(cat "$NGINX_PID_FILE" 2>/dev/null) \
   && [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
    echo "::error::nginx master $old_pid still alive 10s after -s stop"
    exit 1
fi
switch_renew_before 2h 60s "quiesce"
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

# Renewed cert must still be a valid leaf that certifies its domain and whose
# pubkey matches the (freshly issued) stored key — i.e. the atomic swap kept the
# key/chain pair consistent. The store is quiescent now (60s, not due), so these
# reads cannot race a live reissue.
for d in "$DOMAIN_A" "$DOMAIN_B"; do
    key="$PREFIX/store/$d/privkey.pem"
    chain="$PREFIX/store/$d/fullchain.pem"
    openssl x509 -in "$chain" -noout -ext subjectAltName 2>/dev/null \
        | grep -q "DNS:${d}" || { echo "::error::renewed cert SAN missing $d"; exit 1; }
    cpub=$(openssl x509 -in "$chain" -noout -pubkey 2>/dev/null | openssl md5)
    kpub=$(openssl pkey -in "$key" -pubout 2>/dev/null | openssl md5)
    [ "$cpub" = "$kpub" ] || { echo "::error::renewed cert pubkey != stored key for $d"; exit 1; }
    # The atomic-swap commit (renameat2 RENAME_EXCHANGE) must leave no staging dir.
    [ ! -e "$PREFIX/store/$d.tmp" ] || { echo "::error::staging $d.tmp left after renewal swap"; ls -la "$PREFIX/store/$d.tmp"; exit 1; }
done
echo "✓ renewed key/chain pairs are consistent, no staging leftover (atomic swap)"

# --- Negative cases (M9): staleness detection -------------------------------
# The instance is already running under the small renew_before from the quiesce
# restart above, so healthy stored certs are NOT due — that lets us prove the
# scheduler reissues ONLY when the stored fullchain is unusable (corrupt /
# missing / a symlink), and leaves a healthy cert untouched.

# Healthy certs must survive a REAL sweep unchanged (control).
#
# The observation window must be longer than one scheduler period, or the
# control proves nothing: it would pass even against a module whose due-ness
# gate was deleted entirely, simply because no sweep landed inside it.
# A healthy sweep logs nothing at notice level (only the reissue path does,
# ngx_autocert_driver.c), so there is no positive "a sweep ran" marker to
# assert on without a debug build. The window is therefore sized to make a
# missed sweep impossible rather than merely unlikely: THREE sweeps fall
# inside 65s -- the restart's NGX_AUTOCERT_SCHED_INITIAL scan at t~1s (the
# reads above are a handful of openssl calls, so it has NOT fired yet at
# capture time), plus rearms at t~31s and t~61s. The rearm is
# min(12h, renew_before/2) floored by NGX_AUTOCERT_SCHED_FLOOR: under a 60s
# renew_before that is 30s, NOT the 5s test floor -- which is why the
# previous 6s window observed no sweep at all and could not fail.
assert_renew_before 60s "M9 negatives"
SERIAL_A3=$(openssl x509 -in "$CHAIN_A" -noout -serial)
SERIAL_B3=$(openssl x509 -in "$CHAIN_B" -noout -serial)
if [ -z "$SERIAL_A3" ] || [ -z "$SERIAL_B3" ]; then
    echo "::error::could not read baseline serials for the M9 control"
    exit 1
fi
sleep 65
[ "$(openssl x509 -in "$CHAIN_A" -noout -serial)" = "$SERIAL_A3" ] \
    || { echo "::error::healthy ${DOMAIN_A} reissued though not due"; exit 1; }
[ "$(openssl x509 -in "$CHAIN_B" -noout -serial)" = "$SERIAL_B3" ] \
    || { echo "::error::healthy ${DOMAIN_B} reissued though not due"; exit 1; }
echo "✓ healthy certs not reissued under small renew_before (control)"

# Corrupt A's fullchain, remove B's entirely, then reload (fresh helper scans
# at once). A: parse fails -> NGX_ERROR -> due. B: open ENOENT -> NGX_DECLINED
# -> due. Both must be reissued into a fresh, valid cert.
echo "== corrupt A + remove B, reload =="
printf '%s\n' '-----BEGIN CERTIFICATE-----' 'not a real cert' '-----END CERTIFICATE-----' \
    > "$CHAIN_A"
rm -rf "$PREFIX/store/${DOMAIN_B}"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s reload

SERIAL_A4=$(renewed "$CHAIN_A" "$SERIAL_A3") \
    || { echo "::error::corrupt ${DOMAIN_A} not reissued"; grep autocert "$PREFIX/logs/error.log" | tail -20; exit 1; }
SERIAL_B4=$(wait_for_cert "$CHAIN_B") \
    || { echo "::error::missing ${DOMAIN_B} not re-provisioned"; grep autocert "$PREFIX/logs/error.log" | tail -20; exit 1; }
openssl x509 -in "$CHAIN_A" -noout -ext subjectAltName 2>/dev/null \
    | grep -q "DNS:${DOMAIN_A}" || { echo "::error::reissued ${DOMAIN_A} invalid"; exit 1; }
echo "✓ corrupt + missing fullchain both trigger reissue: A=$SERIAL_A4 B=$SERIAL_B4"

# Replace A's fullchain with a symlink: the O_NOFOLLOW open must refuse to
# follow it (NGX_ERROR -> due) and reissue a real regular file in its place.
echo "== symlink A's fullchain, reload =="
SERIAL_A5=$(openssl x509 -in "$CHAIN_A" -noout -serial)
if [ -z "$SERIAL_A5" ]; then
    echo "::error::could not read baseline serial before the symlink case"
    exit 1
fi
rm -f "$CHAIN_A"
ln -s /etc/hostname "$CHAIN_A"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s reload
for i in $(seq 1 120); do
    if [ ! -L "$CHAIN_A" ] && cur=$(openssl x509 -in "$CHAIN_A" -noout -serial 2>/dev/null) \
       && [ -n "$cur" ] && [ "$cur" != "$SERIAL_A5" ]; then
        break
    fi
    sleep 0.5
    [ "$i" = 120 ] && { echo "::error::symlinked ${DOMAIN_A} not reissued as a regular file"; grep autocert "$PREFIX/logs/error.log" | tail -20; exit 1; }
done
[ -L "$CHAIN_A" ] && { echo "::error::${DOMAIN_A} fullchain still a symlink"; exit 1; }
echo "✓ symlinked fullchain refused (O_NOFOLLOW) and reissued as a regular file"

echo "✓✓ M8 renewal + multi-name + M9 staleness negatives verified end-to-end"
