#!/usr/bin/env bash
#
# Config-time rejection tests (nginx -t only, no network/docker). Asserts the
# module fails configuration — rather than misbehaving at runtime — for invalid
# directive values.
#
# Cases:
#   - autocert_dns_hook_timeout 0;  (and negative) must be rejected: a
#     non-positive timeout otherwise reaches the driver as 0 and SIGKILLs every
#     dns-01 hook on the first poll tick, silently breaking all dns-01 issuance.
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-cfgreject}"
rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

# Port 8443 avoids the privileged-bind failure that would make every `-t` fail
# regardless of the directive under test (the reason we grep for the SPECIFIC
# rejection message below, not just a non-zero exit).
PORT=8443

# Asserts `nginx -t` rejects the body AND logs the expected reason substring.
expect_reject() {
    local label="$1" body="$2" want="$3"
    cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log;
events {}
http {
    autocert on;
    autocert_contact a@b.com;
    autocert_store_path $PREFIX/store;
$body
    server { listen $PORT; server_name x.example.com; }
}
EOF
    # Detect rejection by `-t` exit status, not by the absence of the
    # "syntax is ok" line: angie prints "syntax is ok" for the *parse* phase
    # and only then fails the init test (init_main_conf), so the string-based
    # heuristic wrongly read a rejected angie config as accepted. The high
    # PORT above means no privileged bind can make `-t` fail spuriously, so a
    # non-zero exit reliably means "config rejected" on both nginx and angie.
    local out rc=0
    out=$("$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" 2>&1) || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "::error::$label: config was ACCEPTED (-t exit 0) but should be rejected"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    if ! printf '%s' "$out" | grep -q "$want"; then
        echo "::error::$label: rejected, but not for the expected reason ($want)"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "✓ $label rejected at config time"
}

# 0 is the value ngx_conf_set_sec_slot accepts but the driver cannot use; our
# explicit post-parse check rejects it with this message. (A negative value is
# already rejected by the sec parser itself, with a generic "invalid value".)
expect_reject "autocert_dns_hook_timeout 0" "    autocert_dns_hook_timeout 0;" \
    "autocert_dns_hook_timeout must be greater than 0"
expect_reject "autocert_dns_hook_timeout -1" "    autocert_dns_hook_timeout -1;" \
    "invalid value"

# D5 (#16): autocert_wildcard must be a sole leading-label wildcard. A concrete
# name (or any non "*." form) is rejected at parse by the directive setter.
expect_reject "autocert_wildcard non-wildcard arg" \
    "    autocert_wildcard example.com;" \
    "is not a leading-label wildcard"
expect_reject "autocert_wildcard embedded star" \
    "    autocert_wildcard *.ex*ple.com;" \
    "is not a leading-label wildcard"
# Codex LOW: an empty label ("*..example.com") or trailing dot must be rejected
# at config time, not silently suppress a concrete name then fail at issuance.
expect_reject "autocert_wildcard empty label" \
    "    autocert_wildcard *..example.com;" \
    "is not a leading-label wildcard"
expect_reject "autocert_wildcard trailing dot" \
    "    autocert_wildcard *.example.com.;" \
    "is not a leading-label wildcard"

# D5: a wildcard cert is unissuable over http-01 / tls-alpn-01, so an
# autocert_wildcard with a non-dns-01 challenge is rejected at postconfig. The
# template's default challenge is http-01, so just declaring one trips the gate.
expect_reject "autocert_wildcard under http-01" \
    "    autocert_wildcard *.example.com;" \
    "autocert_wildcard requires \"autocert_challenge dns-01\""

# Sanity: a positive timeout is accepted (config syntax ok).
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log;
events {}
http {
    autocert on;
    autocert_contact a@b.com;
    autocert_store_path $PREFIX/store;
    autocert_dns_hook_timeout 15s;
    server { listen $PORT; server_name x.example.com; }
}
EOF
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" 2>&1 | grep -q "syntax is ok" \
    || { echo "::error::a valid autocert_dns_hook_timeout was rejected"; exit 1; }
echo "✓ valid autocert_dns_hook_timeout accepted"

# Phase B dual-cert: autocert_key_type is a 1-4 element list. Two ECDSA types
# collide on the flat privkey.pem/fullchain.pem name; two RSA types collide on
# the .rsa. name; a repeated value and >4 are rejected.
expect_reject "autocert_key_type two ECDSA" \
    "    autocert_key_type p256 p384;" \
    "more than one ECDSA"
expect_reject "autocert_key_type two RSA" \
    "    autocert_key_type rsa2048 rsa4096;" \
    "more than one RSA"
expect_reject "autocert_key_type duplicate value" \
    "    autocert_key_type rsa3072 rsa3072;" \
    "duplicate key type"
expect_reject "autocert_key_type over cap" \
    "    autocert_key_type p256 p384 rsa2048 rsa3072 rsa4096;" \
    "at most 4 key types"

# renew_before is subtracted from a cert's notAfter to pick the renew instant; a
# value at/above the cert lifetime makes "now >= notAfter - renew_before" always
# true, so every sweep reissues -> CA hammering / ACME rate-limit self-DoS. Clamp
# to <= 89d at config time (LE certs live 90d) rather than fail mysteriously.
expect_reject "autocert_renew_before over 89d" \
    "    autocert_renew_before 90d;" \
    "autocert_renew_before must be > 0 and <= 89d"
expect_reject "autocert_renew_before absurd" \
    "    autocert_renew_before 999999999;" \
    "autocert_renew_before must be > 0 and <= 89d"

# Sanity: a normal renew_before window is accepted.
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log;
events {}
http {
    autocert on;
    autocert_contact a@b.com;
    autocert_store_path $PREFIX/store;
    autocert_renew_before 30d;
    server { listen $PORT; server_name x.example.com; }
}
EOF
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" 2>&1 | grep -q "syntax is ok" \
    || { echo "::error::a valid autocert_renew_before was rejected"; exit 1; }
echo "✓ valid autocert_renew_before accepted"

# --- IP-address certs (RFC 8738) ---------------------------------------------

# An IP identifier can only be validated over http-01 / tls-alpn-01; dns-01 is
# meaningless for an address (no zone to place a TXT under). The name loop
# rejects an IP server_name under dns-01 at postconfig. The reject template
# hardcodes a dns server_name, so these use a bespoke config with an IP name.
expect_reject_ip() {
    local label="$1" name="$2" chal="$3" want="$4"
    cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log;
events {}
http {
    autocert on;
    autocert_contact a@b.com;
    autocert_store_path $PREFIX/store;
    autocert_challenge $chal;
    autocert_dns_hook_add /bin/true;
    autocert_dns_hook_remove /bin/true;
    server { listen $PORT; server_name $name; }
}
EOF
    local out rc=0
    out=$("$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" 2>&1) || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "::error::$label: config ACCEPTED but should be rejected"
        printf '%s\n' "$out" | sed 's/^/    /'; return 1
    fi
    printf '%s' "$out" | grep -q "$want" || {
        echo "::error::$label: rejected, but not for expected reason ($want)"
        printf '%s\n' "$out" | sed 's/^/    /'; return 1; }
    echo "✓ $label rejected at config time"
}

expect_reject_ip "IPv4 server_name under dns-01" "192.0.2.1" "dns-01" \
    "cannot issue a certificate for IP address"
# nginx stores an IPv6 server_name unbracketed, e.g. "2001:db8::1".
expect_reject_ip "IPv6 server_name under dns-01" "2001:db8::1" "dns-01" \
    "cannot issue a certificate for IP address"

# autocert_profile is emitted verbatim into the newOrder JSON, so a value with a
# JSON-special / out-of-charset byte is rejected at config load. Use a quoted
# value so the out-of-charset byte reaches our check rather than tripping the
# nginx tokenizer first (a bare '"' or '{' is a config metacharacter).
expect_reject "autocert_profile with slash" \
    '    autocert_profile "a/b";' \
    "autocert_profile .* contains an invalid character"
expect_reject "autocert_profile with space" \
    '    autocert_profile "a b";' \
    "autocert_profile .* contains an invalid character"

# Sanity: an IP server_name under http-01 and a valid profile are accepted.
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log;
events {}
http {
    autocert on;
    autocert_contact a@b.com;
    autocert_store_path $PREFIX/store;
    autocert_challenge http-01;
    autocert_profile shortlived;
    server { listen $PORT; server_name 192.0.2.1; }
    server { listen $PORT; server_name 2001:db8::1; }
}
EOF
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" 2>&1 | grep -q "syntax is ok" \
    || { echo "::error::a valid IP-cert + profile config was rejected"; exit 1; }
echo "✓ IP server_names + autocert_profile accepted under http-01"

echo "✓✓ config-time rejection checks verified"
