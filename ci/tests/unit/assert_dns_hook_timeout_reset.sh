#!/usr/bin/env bash
#
# Verify the per-invocation dns-hook timeout state cannot leak from one hook
# into the next.  This is a source invariant rather than a runnable unit of
# ngx_autocert_order_dns_hook(): the function is an nginx event-loop state
# machine with static process-spawn arms for both POSIX and win32, so extracting
# it would test a copy instead of the shipped control flow.
#
# Usage: assert_dns_hook_timeout_reset.sh [path/to/ngx_autocert_order.c]

set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_file="${1:-$dir/../../../src/ngx_autocert_order.c}"

if [ ! -f "$source_file" ]; then
    echo "FAIL: cannot find $source_file" >&2
    exit 1
fi

# The next function starts immediately after the dns-hook implementation in
# the module's one-function-per-block style.  Keeping the search inside this
# function prevents the order-initialization reset from satisfying this check.
hook_body="$(awk '
    /^ngx_autocert_order_dns_hook\(/ { in_hook = 1 }
    /^ngx_autocert_order_publish_dns\(/ { exit }
    in_hook { print }
' "$source_file")"

if [ -z "$hook_body" ]; then
    echo "FAIL: could not locate ngx_autocert_order_dns_hook()" >&2
    exit 1
fi

# The reset must be the final state transition before the shared spawn call.
# A timed-out add hook otherwise makes a successful remove hook report failure.
if ! printf '%s\n' "$hook_body" | perl -0777 -ne '
    exit 0 if /order->dns_hook_timed_out = 0;\s*\n\s*return ngx_autocert_dns_hook_spawn\(/s;
    exit 1;
'; then
    echo "FAIL: dns-hook timeout state is not reset immediately before spawn" >&2
    exit 1
fi

echo "ok: dns-hook timeout state resets before each spawn"
