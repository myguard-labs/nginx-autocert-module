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
#   (d) A-label (IDN) authority matching. The module rejects a raw U-label
#       `server_name` at config time ("not a valid DNS name or IP address"),
#       so an IDN vhost can only be declared as its A-label; here
#       `xn--fsq.example.com` with `autocert on`. Three probes, all of which
#       reach nginx's name matching:
#         canonical A-label            -> 200 + keyauth
#         same A-label, upper-cased    -> 200 + keyauth (nginx case-folds)
#         same A-label, different TLD  -> 404, no keyauth
#       A raw U-label Host is deliberately NOT used as the negative: nginx
#       rejects any non-ASCII byte in Host with 400 inside
#       ngx_http_validate_host(), BEFORE vhost selection runs, so such a probe
#       would pass identically with no IDN vhost configured at all and would
#       prove nothing about name matching.
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

# The nginx and angie jobs share one self-hosted runner pool with no
# concurrency group, and this script starts by rm -rf'ing its prefix -- so two
# jobs sharing a prefix means the second deletes the first's pidfile and store
# out from under its running master. action.yml therefore passes a
# flavor-qualified PREFIX on both steps; the default below is for manual runs.
PREFIX="${PREFIX:-${AC_E2E_PREFIX:-/tmp/ac-http01-authority}}"
# action.yml passes AC_TEST_PORT explicitly. This script is not in run-all.sh's
# SCRIPTS list, so run-all.sh never dispatches it and never exports a per-slot
# AC_PORT_* for it; its ports are registered in PORT_BASES only so max-port.sh's
# budget ceiling stays honest.
PORT="${AC_TEST_PORT:-18396}"
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
# Same single-exchange discipline as fetch_h1_both, over h2c. The URL must
# carry the real hostname so it becomes the :authority pseudo-header, hence
# --resolve; --noproxy is what keeps --resolve effective (see above).
fetch_h2_both() {
    local host="$1" resp
    resp=$(curl -s --noproxy '*' --http2-prior-knowledge \
        --resolve "$host:$PORT:127.0.0.1" -w '\n%{http_code}' \
        "http://$host:$PORT/.well-known/acme-challenge/$TOKEN")
    code=${resp##*$'\n'}
    got=${resp%$'\n'*}
}
# A no-leak assertion on the body alone passes vacuously whenever the request
# was answered by something other than nginx. The status check below guards
# that: the reachable case is an intercepting proxy, which returns its own
# error page with a 200/502 and a body that trivially lacks the keyauth. (A
# refused connection does not reach here at all -- `set -e` aborts on curl's
# exit 7 inside fetch_h1_both.) It is deliberately NOT a discriminator for the
# enable gate: autocert itself also returns 404 for an unknown token,
# byte-identically, so the code alone cannot say which path declined.
# $4 = the expected status; every current call site wants the 404
# fall-through, so state it explicitly rather than defaulting.
assert_no_leak() {
    local label="$1" body="$2" code="$3" want="$4"
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
    assert_no_leak "b" "$got" "$code" 404
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
    assert_no_leak "c" "$got" "$code" 404
    echo "✓ (c) unknown authority falls to disabled default server; keyauth never present"
fi

echo "== (d) A-label (IDN) authority matching =="
# All three probes are pure ASCII, so all three reach nginx's virtual-host
# name matching -- which is the thing under test. A raw U-label probe would
# not: nginx rejects any non-ASCII Host byte with 400 in
# ngx_http_validate_host() before selection runs, so it returns 400 whether or
# not the IDN vhost exists and discriminates nothing. Verified by probing a
# config with the vhost deleted.
got=$(fetch_h1 xn--fsq.example.com)
if [ "$got" != "$KEYAUTH" ]; then
    echo "::error::(d) canonical A-label authority did not receive the keyauth: got '$got'"
    exit 1
fi
echo "✓ (d) canonical A-label authority served exact key authorization"

got=$(fetch_h1 XN--FSQ.EXAMPLE.COM)
if [ "$got" != "$KEYAUTH" ]; then
    echo "::error::(d) upper-cased A-label authority did not receive the keyauth: got '$got'"
    exit 1
fi
echo "✓ (d) A-label authority matches case-insensitively"

# Same A-label, different registrable domain: parsed fine, reaches matching,
# matches nothing, falls to the disabled default server.
fetch_h1_both xn--fsq.example.net
if [ "$CONTROL" = 1 ]; then
    if [ "$got" != "$KEYAUTH" ]; then
        echo "::error::(d) [CONTROL] non-matching A-label did not fall to the now-enabled default: got '$got'"
        exit 1
    fi
    echo "✓ (d) [CONTROL] non-matching A-label falls to now-enabled default; serves keyauth"
else
    assert_no_leak "d" "$got" "$code" 404
    echo "✓ (d) non-matching A-label never receives another vhost's keyauth"
fi

if [ "$HAS_HTTP2" = 1 ]; then
    echo "== (e) HTTP/2 h2c :authority parity =="
    got=$(curl -s --noproxy '*' --http2-prior-knowledge --resolve a.example.com:"$PORT":127.0.0.1 \
        "http://a.example.com:$PORT/.well-known/acme-challenge/$TOKEN")
    if [ "$got" != "$KEYAUTH" ]; then
        echo "::error::(e) h2 :authority a.example.com (enabled) wrong body: got '$got'"
        exit 1
    fi
    echo "✓ (e) h2 :authority enabled authority served exact key authorization"

    fetch_h2_both b.example.com
    if [ "$CONTROL" = 1 ]; then
        if [ "$got" != "$KEYAUTH" ]; then
            echo "::error::(e) [CONTROL] h2 :authority b did not flip to keyauth: got '$got'"
            exit 1
        fi
        echo "✓ (e) [CONTROL] h2 :authority b now serves keyauth with autocert enabled"
    else
        assert_no_leak "e" "$got" "$code" 404
        echo "✓ (e) h2c :authority parity: disabled authority never leaks the keyauth"
    fi
else
    echo "-- (e) SKIPPED: binary was not built with --with-http_v2_module (scoped gap, h1 fully covered) --"
fi

echo "✓ HTTP-01 authority parity verified"
