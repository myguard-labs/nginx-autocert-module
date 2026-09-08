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
# Caveat: the module registers as a plain NGX_HTTP_CONTENT_PHASE array
# handler, and nginx's content-phase dispatcher skips the whole array whenever
# the matched location already set r->content_handler (`return`, `proxy_pass`,
# ...). Such a vhost never reaches the challenge handler at all, regardless of
# `autocert on/off`. That is a separate fall-through gap, ledgered in
# issues.md, not fixed here. This script therefore gives the comparison vhosts
# no location content handler, so `autocert on/off` is the only difference
# between them.
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
#   (d) U-label vs canonical A-label of the SAME name. The module rejects a
#       raw U-label `server_name` at config time ("not a valid DNS name or IP
#       address"), so an IDN vhost can only be declared as its A-label; here
#       `xn--fsq.example.com` with `autocert on`. The canonical A-label Host
#       MUST get the keyauth (200); the raw U-label Host must NOT -- nginx
#       performs no IDNA folding and rejects the non-ASCII header outright
#       (400), before vhost selection runs at all. Measured, not assumed.
#   (e) HTTP/2 h2c :authority reproduces (a) and (b) exactly -- the gate is on
#       server selection, not on the h1-specific Host header parsing.
#
# Negative control (AC_AUTHORITY_AUTOCERT_ON=1, RUN BY CI as its own step so
# it is a gate rather than a claim): flips
# `autocert on` onto the comparison vhost too, so it is no longer a
# different/disabled authority -- (b)/(e)'s "must not leak" assertions must
# then flip to "must equal the keyauth", proving they are wired to something
# real rather than vacuously true.
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

# Qualify by flavor: the nginx and angie jobs run this concurrently on a shared
# self-hosted runner, and each one starts by rm -rf'ing its prefix. An
# unqualified default lets the second job delete the first job's pidfile out
# from under its running master process.
PREFIX="${PREFIX:-${AC_E2E_PREFIX:-/tmp/ac-http01-authority-${FLAVOR:-nginx}}}"
PORT="${AC_TEST_PORT:-${AC_PORT_18396:-18396}}"
TOKEN="autHtok0123456789ABCDEFGHIJKLMNOPQ"
KEYAUTH="$TOKEN.authorityParityThumbprintXYZ"
# U-label (raw UTF-8) form of xn--fsq.example.com.
U_LABEL=$(printf '\344\276\213.example.com')

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

rm -rf "${PREFIX:?PREFIX must not be empty}"
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
    # xn--fsq.example.com is the A-label (punycode) form of the IDN
    # 例.example.com. It is autocert-ENABLED, so it is the case (d) probe for
    # whether nginx folds a U-label Host onto its A-label server_name.
    server {
        listen $PORT;
        http2 on;
        server_name xn--fsq.example.com;
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

# This wait MUST be fatal. If the seed line never appears the token was never
# planted, and every no-leak case below would then pass for the wrong reason:
# a missing token produces exactly the same 404 they assert. A silent
# fall-through here makes the whole no-leak half of the suite vacuous.
seeded=0
for _ in $(seq 1 30); do
    if grep -q 'seeded test challenge token' "$PREFIX/logs/error.log"; then
        seeded=1
        break
    fi
    sleep 0.3
done
if [ "$seeded" != 1 ]; then
    echo "::error::challenge token was never seeded after 9s; error.log follows"
    sed -n '1,50p' "$PREFIX/logs/error.log" >&2 || true
    exit 1
fi

# The CI runners export http_proxy/https_proxy pointing at a caching proxy.
# curl would then hand the whole URL to that proxy -- which resolves the
# hostname itself and ignores --resolve -- so a request meant for the local
# nginx comes back as the proxy's DNS-failure error page instead. Every curl
# here must talk to 127.0.0.1 directly.
fetch_h1() {
    local host="$1"
    curl -s --noproxy '*' -H "Host: $host" \
        "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN"
}
# One request, body and status from the SAME exchange -- fetching them
# separately characterises two different responses as though they were one.
# Sets the globals `got` and `code`.
fetch_h1_both() {
    local host="$1" resp
    resp=$(curl -s --noproxy '*' -w '\n%{http_code}' -H "Host: $host" \
        "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN")
    code=${resp##*$'\n'}
    got=${resp%$'\n'*}
}
# A no-leak assertion on the body alone passes vacuously whenever the request
# never reached nginx at all (connection refused, a proxy error page, an empty
# body). The status check below is a LIVENESS guard against exactly that: only
# nginx answers 404 here, whereas a proxy page or a refused connection gives
# 000. It is deliberately NOT a discriminator for the enable gate -- autocert
# itself also returns 404 for an unknown token, byte-identically, so the code
# alone cannot say which path declined.
# $4 = the status the case expects (default 404, the disabled-vhost
# fall-through). Case (d) passes 400 instead: nginx rejects a raw U-label Host
# as a malformed header before vhost selection ever runs.
assert_no_leak() {
    local label="$1" body="$2" code="$3" want="${4:-404}"
    case "$body" in
        *"$KEYAUTH"*)
            echo "::error::($label) TOKEN LEAK: wrong authority returned the keyauth (body='$body')"
            exit 1
            ;;
    esac
    if [ "$code" != "$want" ]; then
        echo "::error::($label) expected $want, got code=$code body='$body' -- the request did not reach nginx, or the rejection path changed"
        exit 1
    fi
}

echo "== (a) h1 Host: a.example.com (enabled) -> keyauth =="
got=$(fetch_h1 a.example.com)
if [ "$got" != "$KEYAUTH" ]; then
    echo "::error::(a) wrong body for enabled authority: got '$got' want '$KEYAUTH'"
    exit 1
fi
echo "✓ (a) enabled authority served exact key authorization"

echo "== (b) h1 Host: b.example.com (different vhost, same port) =="
fetch_h1_both b.example.com
if [ "$CONTROL" = 1 ]; then
    if [ "$got" != "$KEYAUTH" ]; then
        echo "::error::(b) [CONTROL] did not flip to keyauth with autocert enabled on b: got '$got'"
        exit 1
    fi
    echo "✓ (b) [CONTROL] with autocert enabled on b, it now serves the keyauth like a"
else
    assert_no_leak "b" "$got" "$code"
    echo "✓ (b) disabled authority falls through (404); keyauth never present"
fi

echo "== (c) h1 Host: unknown.example.com (falls to default server = b) =="
fetch_h1_both unknown.example.com
if [ "$CONTROL" = 1 ]; then
    # b is default_server and now has autocert on too, so an unknown Host
    # legitimately lands on an enabled server and gets the keyauth.
    if [ "$got" != "$KEYAUTH" ]; then
        echo "::error::(c) [CONTROL] unknown Host on now-enabled default server did not get keyauth: got '$got'"
        exit 1
    fi
    echo "✓ (c) [CONTROL] unknown Host on now-enabled default server serves keyauth"
else
    assert_no_leak "c" "$got" "$code"
    echo "✓ (c) unknown authority falls to disabled default server; keyauth never present"
fi

echo "== (d) U-label vs canonical A-label authority (no IDNA folding) =="
# Both forms of the SAME name, against a server declaring only the A-label
# xn--fsq.example.com with autocert on. nginx performs no IDNA/Unicode
# normalization on Host. Measured against nginx 1.31.4: the raw U-label is
# rejected as a malformed header with 400, before vhost selection runs, while
# the canonical A-label gets 200 + the keyauth. (The module rejects a raw
# U-label server_name at config time, so the A-label is the only reachable
# spelling of an IDN vhost; that is what makes this a real pair rather than
# two spellings of "unknown host".)
fetch_h1_both "$U_LABEL"
# The 400 is independent of CONTROL: a malformed Host is rejected before vhost
# selection, so flipping `autocert on` onto the default server cannot reach it.
assert_no_leak "d" "$got" "$code" 400
echo "✓ (d) raw U-label authority is rejected (400), never folded onto the A-label vhost"

# The canonical A-label form of the same name MUST work, in both modes --
# otherwise (d) would pass merely because the vhost is unreachable, which is
# the exact way a U-label test can be vacuous.
got=$(fetch_h1 xn--fsq.example.com)
if [ "$got" != "$KEYAUTH" ]; then
    echo "::error::(d) canonical A-label authority did not receive the keyauth: got '$got'"
    exit 1
fi
echo "✓ (d) canonical A-label authority served exact key authorization"

if [ "$HAS_HTTP2" = 1 ]; then
    echo "== (e) HTTP/2 h2c :authority parity =="
    got=$(curl -s --noproxy '*' --http2-prior-knowledge --resolve a.example.com:"$PORT":127.0.0.1 \
        "http://a.example.com:$PORT/.well-known/acme-challenge/$TOKEN")
    if [ "$got" != "$KEYAUTH" ]; then
        echo "::error::(e) h2 :authority a.example.com (enabled) wrong body: got '$got'"
        exit 1
    fi
    echo "✓ (e) h2 :authority enabled authority served exact key authorization"

    got=$(curl -s --noproxy '*' --http2-prior-knowledge --resolve b.example.com:"$PORT":127.0.0.1 \
        "http://b.example.com:$PORT/.well-known/acme-challenge/$TOKEN")
    code=$(curl -s --noproxy '*' --http2-prior-knowledge --resolve b.example.com:"$PORT":127.0.0.1 \
        -o /dev/null -w '%{http_code}' \
        "http://b.example.com:$PORT/.well-known/acme-challenge/$TOKEN")
    if [ "$CONTROL" = 1 ]; then
        if [ "$got" != "$KEYAUTH" ]; then
            echo "::error::(e) [CONTROL] h2 :authority b did not flip to keyauth: got '$got'"
            exit 1
        fi
        echo "✓ (e) [CONTROL] h2 :authority b now serves keyauth with autocert enabled"
    else
        assert_no_leak "e" "$got" "$code"
        echo "✓ (e) h2c :authority parity: disabled authority never leaks the keyauth"
    fi
else
    echo "-- (e) SKIPPED: binary was not built with --with-http_v2_module (scoped gap, h1 fully covered) --"
fi

echo "✓ HTTP-01 authority parity verified"
