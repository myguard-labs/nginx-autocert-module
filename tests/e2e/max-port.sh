#!/usr/bin/env bash
#
# Print the highest host port the e2e suite can publish for a given
# AC_PORT_OFFSET, so CI can prove the whole suite stays BELOW the ephemeral
# range before it starts binding anything.
#
# Why this exists: a published port that lands inside the kernel's ephemeral
# range (/proc/sys/net/ipv4/ip_local_port_range, 32768 by default) races the
# kernel's own outbound allocations. Docker then refuses the container with
# "Bind for 0.0.0.0:<p> failed: port is already allocated" on a RANDOM test,
# and a rerun appears to fix it. Cheaper to assert the budget up front.
#
# The ceiling is derived from the SAME data run-all.sh uses -- it sources
# run-all.sh with AC_E2E_MAX_PORT_ONLY=1, which makes it define PORT_BASES and
# SCRIPTS and then hand control back here instead of running any test. Anything
# else (a hardcoded 18190, a second copy of the list) would silently drift the
# moment someone adds a port base or a test.
#
# Inputs (env):
#   AC_PORT_OFFSET - the offset CI intends to use (default 0)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Sourced, not executed: run-all.sh returns early on this flag, leaving
# PORT_BASES + SCRIPTS + CERT_CASES defined in our shell.
AC_E2E_MAX_PORT_ONLY=1
export AC_E2E_MAX_PORT_ONLY
# run-all.sh insists on these two even when it is only being probed.
SERVER_BIN="${SERVER_BIN:-/nonexistent}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-/nonexistent}"
export SERVER_BIN NGX_BUILD_DIR
# run-all.sh echoes a banner as it sets up; swallow it so stdout carries ONLY the
# number (CI reads this in a command substitution).
# shellcheck source=/dev/null
. "$HERE/run-all.sh" >/dev/null

offset="${AC_PORT_OFFSET:-0}"

# Highest port base.
max_base=0
for b in "${PORT_BASES[@]}"; do
    [ "$b" -gt "$max_base" ] && max_base="$b"
done

# Highest slot term. run_one() sets the per-test offset to slot*100; slots are
# handed out in SCRIPTS order, then one per CERT_CASE (see run-all.sh), so the
# last slot is (#SCRIPTS + #CERT_CASES - 1).
slots=$(( ${#SCRIPTS[@]} + ${#CERT_CASES[@]} ))
max_slot_term=$(( (slots - 1) * 100 ))

echo $(( max_base + offset + max_slot_term ))
