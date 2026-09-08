#!/usr/bin/env bash
#
# HTTP-01 authority parity (h1 Host / h2 :authority) coverage.
#
# The content-phase challenge handler (ngx_http_autocert_challenge_handler)
# keys its token lookup on the shared, global challenge zone alone -- it never
# reads Host or :authority. But it also calls
# ngx_http_get_module_srv_conf(r, ngx_http_autocert_module) and declines
# (NGX_DECLINED) unless that server's `autocert on` is set, and *virtual host
# selection* is driven by Host/:authority. So the authority is the real parity
# surface: it gates whether the handler runs at all, not which token it looks
# up.
#
# IMPORTANT established fact (verified by hand while writing this script,
# reading nginx's ngx_http_core_content_phase()): the module registers itself
# as a plain NGX_HTTP_CONTENT_PHASE array handler, and nginx's content phase
# dispatcher skips the whole array whenever the matched location already set
# r->content_handler (e.g. `return`, `proxy_pass`, or any other handler
# directive):
#
#     if (r->content_handler) {
#         ngx_http_finalize_request(r, r->content_handler(r));
#         return NGX_OK;
#     }
#
# So a vhost whose matched location has its own content handler NEVER reaches
# ngx_http_autocert_challenge_handler at all, regardless of `autocert on/off`
# on that server -- confirmed by hand: with `location / { return 200
# "b-plain"; }` on server b, flipping `autocert on` on b did NOT change its
# response (still "b-plain", never the keyauth). That is a real fall-through
# gap orthogonal to the authority question this item covers (it means an
# operator with a catch-all `return`/`proxy_pass` on `/` unintentionally
# shadows ACME HTTP-01 solving on that vhost); it is ledgered in TODO.md as
# its own item rather than fixed here. This script therefore avoids a
# location content handler on the comparison vhost, so `autocert on/off` is
# the only thing distinguishing the two servers, and asserts against the
# actual content-phase dispatch this item's acceptance criterion is about.
#
# This script pins the following established behavior:
#
#   (a) Host matching an autocert-enabled server              -> 200 + keyauth
#   (b) Host matching a DIFFERENT, autocert-DISABLED server on
#       the same listen port, no location content handler      -> falls
#       through to nginx's core/static handler (404: no file, autoindex off);
#       the keyauth is NEVER present in that response body.
#   (c) Unknown/absent Host falling to the default server
#       (also autocert-disabled)                                -> same 404;
#       no keyauth leak.
#   (d) U-label vs A-label: the module rejects a raw U-label `server_name` at
#       config time ("not a valid DNS name or IP address"), so the only
#       reachable config declares the A-label. Requesting that A-label server
#       with a mismatched/U-label-shaped Host does NOT match (nginx does no
#       IDNA) and falls through to the default server, same as (c).
#   (e) HTTP/2 h2c :authority reproduces (a) and (b) exactly -- the gate is on
#       server selection, not on the h1-specific Host header parsing.
#
# Negative control (AC_AUTHORITY_AUTOCERT_ON=1, not run by CI): flips
# `autocert on` onto the comparison vhost too, so it is no longer a
# different/disabled authority -- (b)/(e)'s "must not leak" assertions must
# then flip to "must equal the keyauth", proving they are wired to something
# real rather than vacuously true. See PR description for the exact command
# and the specific assertion that goes red without the flip's own branch.
#
# Inputs (env):
#   SERVER_BIN    - built nginx/angie binary (required)
#   NGX_BUILD_DIR - dir holding objs/*.so (defaults to two levels up from BIN)
#   AC_AUTHORITY_AUTOCERT_ON - if "1", enable autocert on the comparison vhost
#                              too (negative control, see above).

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

HAS_HTTP2=0
"$SERVER_BIN" -V 2>&1 | grep -q -- '--with-http_v2_module' && HAS_HTTP2=1

PREFIX="${PREFIX:-/tmp/ac-http01-authority}"
PORT="${AC_TEST_PORT:-${AC_PORT_18396:-18396}}"
TOKEN="autHtok0123456789ABCDEFGHIJKLMNOPQ"
KEYAUTH="$TOKEN.authorityParityThumbprintXYZ"

B_AUTOCERT_LINE="# autocert intentionally OFF on this server"
CONTROL=0
if [ "${AC_AUTHORITY_AUTOCERT_ON:-0}" = "1" ]; then
    CONTROL=1
    B_AUTOCERT_LINE="autocert on;"
fi

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"
chmod 0700 "$PREFIX/store"

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert_store_path $PREFIX/store;
    autocert_test_challenge $TOKEN "$KEYAUTH";

    server {
        listen $PORT;
        http2 on;
        server_name a.example.com;
        autocert on;
    }
    server {
        listen $PORT default_server;
        http2 on;
        server_name b.example.com;
        $B_AUTOCERT_LINE
        # deliberately no location block: any content-handler directive here
        # (return/proxy_pass/...) would short-circuit nginx's content phase
        # before the autocert array handler ever runs -- see header comment.
    }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

for _ in $(seq 1 30); do
    grep -q 'seeded test challenge token' "$PREFIX/logs/error.log" && break
    sleep 0.3
done

fetch_h1() {
    local host="$1"
    curl -s -H "Host: $host" \
        "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN"
}
fetch_h1_code() {
    local host="$1"
    curl -s -o /dev/null -w '%{http_code}' -H "Host: $host" \
        "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN"
}
assert_no_leak() {
    local label="$1" body="$2"
    case "$body" in
        *"$KEYAUTH"*)
            echo "::error::($label) TOKEN LEAK: wrong authority returned the keyauth (body='$body')"
            exit 1
            ;;
    esac
}

echo "== (a) h1 Host: a.example.com (enabled) -> keyauth =="
got=$(fetch_h1 a.example.com)
if [ "$got" != "$KEYAUTH" ]; then
    echo "::error::(a) wrong body for enabled authority: got '$got' want '$KEYAUTH'"
    exit 1
fi
echo "✓ (a) enabled authority served exact key authorization"

echo "== (b) h1 Host: b.example.com (different vhost, same port) =="
got=$(fetch_h1 b.example.com)
code=$(fetch_h1_code b.example.com)
if [ "$CONTROL" = 1 ]; then
    if [ "$got" != "$KEYAUTH" ]; then
        echo "::error::(b) [CONTROL] did not flip to keyauth with autocert enabled on b: got '$got'"
        exit 1
    fi
    echo "✓ (b) [CONTROL] with autocert enabled on b, it now serves the keyauth like a"
else
    assert_no_leak "b" "$got"
    if [ "$code" != "404" ]; then
        echo "::error::(b) disabled authority did not fall through to the expected 404: code=$code body='$got'"
        exit 1
    fi
    echo "✓ (b) disabled authority falls through (404); keyauth never present"
fi

echo "== (c) h1 Host: unknown.example.com (falls to default server = b) =="
got=$(fetch_h1 unknown.example.com)
if [ "$CONTROL" = 1 ]; then
    # b is default_server and now has autocert on too, so an unknown Host
    # legitimately lands on an enabled server and gets the keyauth.
    if [ "$got" != "$KEYAUTH" ]; then
        echo "::error::(c) [CONTROL] unknown Host on now-enabled default server did not get keyauth: got '$got'"
        exit 1
    fi
    echo "✓ (c) [CONTROL] unknown Host on now-enabled default server serves keyauth"
else
    assert_no_leak "c" "$got"
    echo "✓ (c) unknown authority falls to disabled default server; keyauth never present"
fi

echo "== (d) mismatched/A-vs-U-label authority (no IDNA in nginx) =="
# The module rejects a raw U-label server_name at config time (verified by
# hand: "autocert: \"...\" is not a valid DNS name or IP address"), so only
# the A-label form is a reachable config. Requesting the A-label server with a
# non-matching authority shaped like a U-label/punycode mismatch is exactly
# the "unknown Host" case from (c): nginx does no Unicode/IDNA normalization
# on Host, so it cannot match and falls through to default.
got=$(fetch_h1 xn--fsq.example.net)
if [ "$CONTROL" = 1 ]; then
    # same default-server propagation as (c) under the control.
    if [ "$got" != "$KEYAUTH" ]; then
        echo "::error::(d) [CONTROL] mismatched-authority fallback to now-enabled default did not get keyauth: got '$got'"
        exit 1
    fi
    echo "✓ (d) [CONTROL] mismatched authority falls to now-enabled default; serves keyauth"
else
    assert_no_leak "d" "$got"
    echo "✓ (d) mismatched authority (no IDNA folding) never receives the keyauth"
fi

if [ "$HAS_HTTP2" = 1 ]; then
    echo "== (e) HTTP/2 h2c :authority parity =="
    got=$(curl -s --http2-prior-knowledge --resolve a.example.com:"$PORT":127.0.0.1 \
        "http://a.example.com:$PORT/.well-known/acme-challenge/$TOKEN")
    if [ "$got" != "$KEYAUTH" ]; then
        echo "::error::(e) h2 :authority a.example.com (enabled) wrong body: got '$got'"
        exit 1
    fi
    echo "✓ (e) h2 :authority enabled authority served exact key authorization"

    got=$(curl -s --http2-prior-knowledge --resolve b.example.com:"$PORT":127.0.0.1 \
        "http://b.example.com:$PORT/.well-known/acme-challenge/$TOKEN")
    if [ "$CONTROL" = 1 ]; then
        if [ "$got" != "$KEYAUTH" ]; then
            echo "::error::(e) [CONTROL] h2 :authority b did not flip to keyauth: got '$got'"
            exit 1
        fi
        echo "✓ (e) [CONTROL] h2 :authority b now serves keyauth with autocert enabled"
    else
        assert_no_leak "e" "$got"
        echo "✓ (e) h2c :authority parity: disabled authority never leaks the keyauth"
    fi
else
    echo "-- (e) SKIPPED: binary was not built with --with-http_v2_module (scoped gap, h1 fully covered) --"
fi

echo "✓ HTTP-01 authority parity verified"
