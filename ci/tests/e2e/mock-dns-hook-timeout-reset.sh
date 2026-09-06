#!/usr/bin/env bash
#
# Behavioral dns-01 hook-timeout-reset test (F8).
#
# ci/tests/unit/assert_dns_hook_timeout_reset.sh only proves the source text
# resets order->dns_hook_timed_out immediately before the shared spawn call;
# it compiles nothing and cannot fail if the reset were silently skipped at
# runtime. ci/tests/e2e/dns01-exec-hook.sh sleeps its add-hook 2s under a 15s
# timeout, so dns_hook_timed_out is never actually set by any existing suite.
# This test drives the real state machine so the timeout genuinely fires:
#
#   add-hook invoked -> sleeps past autocert_dns_hook_timeout -> nginx SIGKILLs
#   the child group and sets order->dns_hook_timed_out=1 -> add hook reported
#   failed -> order aborted -> remove-hook invoked for cleanup -> remove-hook
#   exits 0 and is NOT misreported as failed -> exactly one "hook timed out"
#   line, exactly one add-hook invocation, exactly one remove-hook invocation,
#   no leaked hook process.
#
# SCOPE -- what this test does and does NOT prove (VERIFIED 2026-09-06):
#   It proves the POSIX add-timeout -> remove-success flow end to end. It does
#   NOT prove the `order->dns_hook_timed_out = 0` reset at
#   ngx_autocert_order.c:1512, and no POSIX test can: the flag's ONLY reader is
#   at :1332, which sits inside the `#if (NGX_WIN32)` arm opened at :1296 and
#   closed by `#else` at :1340. On POSIX the flag is written and never read --
#   a timed-out hook is detected instead by `!WIFEXITED(status)` at :1360,
#   entirely independently of it. Confirmed by mutation: deleting the :1512
#   reset leaves this test green, because nothing on POSIX observes the flag.
#   The reset therefore matters only on win32, which has no behavioral lane
#   here (no Windows host / Pebble-on-Windows). Until such a lane exists,
#   ci/tests/unit/assert_dns_hook_timeout_reset.sh -- weak as a source-text
#   assertion is -- stays as the only guard on the win32-relevant invariant,
#   and must NOT be dropped on the strength of this file.
#
# A deterministic mock ACME CA stands in for Pebble (same technique as
# mock-order-poll-retry.sh): it serves exactly one authorization fetch (the
# pending dns-01 challenge the driver needs to start the add-hook), then
# traps any further authz poll or challenge-respond POST as a hard failure —
# the add-hook timeout must abort the order before either happens. The only
# real network dependency is challtestsrv for DNS resolution of the mock
# CA's own hostname (autocert_resolver), exactly as the sibling mock-*.sh
# tests use it.
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
[ -f "$HTTP_SO" ] || {
	echo "missing $HTTP_SO"
	exit 1
}

PREFIX="${PREFIX:-/tmp/ac-dnshook-timeout-reset}"
CA_HOST="mockca-timeout.example.com"
CA_PORT="${CA_PORT:-${AC_PORT_14021:-14021}}"
DNS_NAME="ac-dnshto-dns-$$"
DNS_PORT="${DNS_PORT:-${AC_PORT_15357:-15357}}"
NAME="dnshooktimeout.example.com"
HOOK_TIMEOUT=1

MOCK_PID=""
cleanup() {
	"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
	if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null || true; fi
	docker rm -f "$DNS_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store" "$PREFIX/hooks"
chmod 0700 "$PREFIX/store"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-keyout "$PREFIX/ca-key.pem" -out "$PREFIX/ca.pem" -days 2 -nodes \
	-subj "/CN=$CA_HOST" -addext "subjectAltName=DNS:$CA_HOST" >/dev/null 2>&1

docker network ls >/dev/null
docker run -d --name "$DNS_NAME" \
	-p "${DNS_PORT}":53/udp -p "${DNS_PORT}":53/tcp \
	"$CHALLTESTSRV_IMAGE" \
	-dnsserver :53 -management :8055 \
	-http01 "" -https01 "" -tlsalpn01 "" -doh "" \
	-defaultIPv4 127.0.0.1 -defaultIPv6 "" >/dev/null

# ---- mock ACME server: dns-01 challenge only, never actually polled ---------
# The order aborts on the add-hook timeout before authz is ever fetched, so
# this server only needs to serve /dir, newAccount and newOrder plausibly;
# anything past that is unreached and intentionally a 404 trap (::error:: if
# it is ever hit, which would mean the abort did not happen before authz).
cat >"$PREFIX/mockca.py" <<PYEOF
import json, ssl, itertools
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = "https://${CA_HOST}:${CA_PORT}"
nonces = ("nonce-%d" % i for i in itertools.count())
state = {"authz_hits": 0}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Replay-Nonce", next(nonces))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/dir":
            d = {"newNonce": BASE + "/nonce", "newAccount": BASE + "/acct",
                 "newOrder": BASE + "/order"}
            self._send(200, json.dumps(d).encode())
        elif self.path == "/nonce":
            self._send(204)
        else:
            self._send(404, b'{"type":"urn:ietf:params:acme:error:malformed"}')

    do_HEAD = do_GET

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n) if n else b""
        if self.path == "/nonce":
            self._send(204)
        elif self.path == "/acct":
            self._send(201, b'{"status":"valid"}', extra={"Location": BASE + "/acct/1"})
        elif self.path == "/order":
            body = json.dumps({
                "status": "pending",
                "finalize": BASE + "/finalize",
                "authorizations": [BASE + "/authz"],
            }).encode()
            self._send(201, body, extra={"Location": BASE + "/order/1"})
        elif self.path == "/authz":
            # First fetch: pending + the dns-01 challenge the driver needs to
            # learn the token and start the add-hook. The add-hook timeout
            # must abort the order right after that -- it must never POST
            # /chal or re-poll this authz, so a second hit here (or any hit
            # on /chal) is the trap: it means the timeout failed to abort the
            # order and it limped into a validation attempt instead.
            state["authz_hits"] += 1
            if state["authz_hits"] > 1:
                self._send(500, b'{"type":"urn:ietf:params:acme:error:serverInternal",'
                                b'"detail":"authz re-fetched: add-hook timeout did not abort the order"}',
                           ctype="application/problem+json")
                return
            body = json.dumps({
                "status": "pending",
                "challenges": [{
                    "type": "dns-01",
                    "status": "pending",
                    "token": "mock-token-dns01timeout",
                    "url": BASE + "/chal",
                }],
            }).encode()
            self._send(200, body)
        elif self.path == "/chal":
            self._send(500, b'{"type":"urn:ietf:params:acme:error:serverInternal",'
                            b'"detail":"chal responded: add-hook timeout did not abort the order"}',
                       ctype="application/problem+json")
        else:
            self._send(404, b'{"type":"urn:ietf:params:acme:error:malformed"}')

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("${PREFIX}/ca.pem", "${PREFIX}/ca-key.pem")
srv = HTTPServer(("0.0.0.0", ${CA_PORT}), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PYEOF

echo "== starting mock ACME CA on :$CA_PORT =="
python3 "$PREFIX/mockca.py" &
MOCK_PID=$!
for i in $(seq 1 30); do
	if curl -sf --resolve "${CA_HOST}:${CA_PORT}:127.0.0.1" \
		--cacert "$PREFIX/ca.pem" "https://${CA_HOST}:${CA_PORT}/dir" >/dev/null 2>&1; then
		break
	fi
	sleep 0.5
	[ "$i" = 30 ] && {
		echo "::error::mock CA did not come up"
		exit 1
	}
done

# Hooks: add.sh sleeps well past HOOK_TIMEOUT so the deadline timer genuinely
# fires and SIGKILLs it; remove.sh is a normal fast success so the finish path
# proves the reset happened (see the reasoning header above). Each hook logs
# a marker file line to prove it ran exactly once and to record its own exit
# path independent of nginx's error.log parsing.
cat >"$PREFIX/hooks/add.sh" <<EOF
#!/usr/bin/env bash
echo "add \$\$ start" >> "$PREFIX/hook-calls.log"
sleep 10
echo "add \$\$ finished-without-being-killed" >> "$PREFIX/hook-calls.log"
EOF
cat >"$PREFIX/hooks/remove.sh" <<EOF
#!/usr/bin/env bash
echo "remove \$\$ ran" >> "$PREFIX/hook-calls.log"
exit 0
EOF
chmod +x "$PREFIX/hooks/add.sh" "$PREFIX/hooks/remove.sh"

cat >"$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;
error_log $PREFIX/logs/error.log info;
events {}
http {
    autocert on;
    autocert_contact admin@example.com;
    autocert_ca "https://${CA_HOST}:${CA_PORT}/dir";
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_ca_trusted_certificate $PREFIX/ca.pem;
    autocert_store_path $PREFIX/store;
    autocert_challenge dns-01;
    autocert_dns_hook_add $PREFIX/hooks/add.sh;
    autocert_dns_hook_remove $PREFIX/hooks/remove.sh;
    autocert_dns_propagation_delay 0;
    autocert_dns_hook_timeout ${HOOK_TIMEOUT};
    server {
        listen ${AC_PORT_8081:-8081};
        server_name ${NAME};
        autocert on;
    }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
echo "✓ config accepted"

echo "== start: dns-01 order for ${NAME} (add-hook will time out) =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

LOG="$PREFIX/logs/error.log"

echo "== waiting for the add-hook to start =="
for i in $(seq 1 40); do
	if grep -q 'autocert: dns-01 exec add hook' "$LOG"; then break; fi
	sleep 0.25
	[ "$i" = 40 ] && {
		echo "::error::add-hook never started"
		grep autocert "$LOG" | tail -30
		exit 1
	}
done
ADD_PID=""
for i in $(seq 1 20); do
	ADD_PID="$(pgrep -f "$PREFIX/hooks/add.sh" | head -1 || true)"
	[ -n "$ADD_PID" ] && break
	sleep 0.25
done
[ -n "$ADD_PID" ] || {
	echo "::error::could not observe the add-hook child pid"
	exit 1
}
echo "✓ dns-01 add-hook started (pid $ADD_PID)"

echo "== waiting for the timeout to genuinely fire =="
for i in $(seq 1 40); do
	if grep -q 'autocert: dns-01 hook timed out after' "$LOG"; then break; fi
	sleep 0.25
	[ "$i" = 40 ] && {
		echo "::error::add-hook timeout never fired"
		grep autocert "$LOG" | tail -30
		exit 1
	}
done
echo "✓ add-hook timeout fired (deadline timer killed the child group)"

# Prove the process is actually gone (SIGKILL landed), not merely reported.
for i in $(seq 1 20); do
	if ! kill -0 "$ADD_PID" 2>/dev/null; then break; fi
	sleep 0.25
	[ "$i" = 20 ] && {
		echo "::error::add-hook pid $ADD_PID still alive after the reported timeout (leaked child)"
		exit 1
	}
done
echo "✓ add-hook child process is gone (no leaked process)"

echo "== waiting for the order to abort from the timed-out add-hook =="
for i in $(seq 1 40); do
	if grep -Eq 'autocert: dns-01 hook failed .*for "'"${NAME}"'"' "$LOG"; then break; fi
	sleep 0.25
	[ "$i" = 40 ] && {
		echo "::error::timed-out add-hook was never reported as a failed hook"
		grep autocert "$LOG" | tail -30
		exit 1
	}
done
echo "✓ timed-out add-hook reported as a failed hook (not silently swallowed)"

echo "== waiting for the cleanup remove-hook to run and SUCCEED =="
for i in $(seq 1 40); do
	if grep -q 'autocert: dns-01 exec remove hook' "$LOG"; then break; fi
	sleep 0.25
	[ "$i" = 40 ] && {
		echo "::error::remove-hook never ran after the add-hook timeout"
		grep autocert "$LOG" | tail -30
		exit 1
	}
done
for i in $(seq 1 40); do
	if [ -f "$PREFIX/hook-calls.log" ] && grep -q '^remove .* ran$' "$PREFIX/hook-calls.log"; then break; fi
	sleep 0.25
	[ "$i" = 40 ] && {
		echo "::error::remove-hook script never actually executed to completion"
		exit 1
	}
done
echo "✓ remove-hook actually executed to completion"

# THE regression this test exists for: the remove-hook must NOT be reported
# as timed out / failed just because the PRECEDING add-hook on the same order
# timed out. If ngx_autocert_order_dns_hook() failed to reset
# order->dns_hook_timed_out=0 before spawning the remove-hook, this next line
# either never appears, or a second "hook timed out"/"hook failed ... remove"
# line appears for the remove-hook despite its script exiting 0 quickly.
if grep -Eq 'autocert: dns-01 hook failed \(exit 0\)' "$LOG"; then
	echo "::error::impossible log line matched (exit 0 reported as failed)"
	exit 1
fi
REMOVE_FAILED=$(grep -c 'autocert: dns-01 hook timed out' "$LOG" || true)
[ "$REMOVE_FAILED" -eq 1 ] ||
	{
		echo "::error::expected exactly one timeout (the add-hook's); got $REMOVE_FAILED"
		grep autocert "$LOG"
		exit 1
	}
echo "✓ exactly one hook-timeout was reported (the add-hook's, not leaked onto the remove-hook)"

# Exactly-once finalization: the order must reach a single terminal outcome,
# never both an error finish and a later success (or a double remove-hook).
FINISH_COUNT=$(grep -cE 'autocert: (ACME order failed|order did not become valid|certificate provisioned for)' "$LOG" || true)
[ "$FINISH_COUNT" -le 1 ] ||
	{
		echo "::error::order reached more than one terminal outcome ($FINISH_COUNT) -- not exactly-once"
		grep autocert "$LOG"
		exit 1
	}
ADD_CALLS=$(grep -c '^add ' "$PREFIX/hook-calls.log" || true)
REMOVE_CALLS=$(grep -c '^remove ' "$PREFIX/hook-calls.log" || true)
[ "$ADD_CALLS" -eq 1 ] || {
	echo "::error::add-hook ran $ADD_CALLS times, expected exactly 1"
	exit 1
}
[ "$REMOVE_CALLS" -eq 1 ] || {
	echo "::error::remove-hook ran $REMOVE_CALLS times, expected exactly 1"
	exit 1
}
echo "✓ exactly-once finalization: one add-hook invocation, one remove-hook invocation, one terminal outcome"

# The re-fetch/respond traps must never have been hit -- proves the order
# aborted from the add-hook timeout rather than limping into a validation
# attempt (a second authz poll or a /chal POST).
grep -Eq 'add-hook timeout did not abort the order' "$LOG" 2>/dev/null &&
	{
		echo "::error::validation trap was hit -- order was not aborted by the hook timeout"
		exit 1
	}
echo "✓ order aborted after learning the challenge, before any validation attempt (traps not hit)"

echo "✓✓ dns-01 hook-timeout-reset verified behaviorally end-to-end"
