#!/usr/bin/env bash
#
# Drift gate for ci/fuzz/fuzz.dict.
#
# Extracts the literal tokens the JSON (src/ngx_autocert_json.c),
# order/ACME response (src/ngx_autocert_order.c) and HTTP framing
# (src/ngx_autocert_acme.c) parsers actually compare input against, then
# checks each one appears as a quoted libFuzzer dictionary entry in
# ci/fuzz/fuzz.dict. Exits non-zero and lists the gap when the parser has
# grown a recognized literal the dictionary doesn't carry yet.
#
# Run from anywhere; paths are resolved relative to this script.
#
# Usage: ci/fuzz/check-dict-drift.sh

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "$FUZZ_DIR/../../src" && pwd)"
DICT="$FUZZ_DIR/fuzz.dict"

if [ ! -f "$DICT" ]; then
  echo "❌ missing dictionary: $DICT" >&2
  exit 1
fi

# Tokens the dictionary is required to carry, one per line, no quotes.
# Sources, by category:
#
#  - JSON literal table (ngx_autocert_json_literal, ngx_autocert_json.c)
#  - object_get()/object_str() key lookups (ngx_autocert_order.c)
#  - ngx_strncmp/ngx_strncasecmp fixed-string comparisons against parsed
#    JSON string values and HTTP header/status-line text
#    (ngx_autocert_order.c, ngx_autocert_acme.c)
tokens="$(
  {
    # JSON true/false/null literal table.
    grep -oE '"\s*[a-z]+\s*",\s*[0-9]+,\s*NGX_AUTOCERT_JSON_(BOOL|NULL)' \
      "$SRC_DIR/ngx_autocert_json.c" \
      | grep -oE '"[a-z]+"' | tr -d '"'

    # object_get(...) / object_str(...) literal key arguments.
    grep -ohE 'object_(get|str)\([^,]+,\s*"[A-Za-z_-]+"' "$SRC_DIR"/*.c \
      | grep -oE '"[A-Za-z_-]+"$' | tr -d '"'

    # ngx_strncmp/ngx_strncasecmp fixed-string comparisons.
    grep -ohE 'ngx_strn(case)?cmp\([^,]+,\s*(\(u_char \*\)\s*)?"[A-Za-z0-9:._/-]+"' \
      "$SRC_DIR"/*.c \
      | grep -oE '"[A-Za-z0-9:._/-]+"$' | tr -d '"'
  } | sort -u
)"

missing=""
while IFS= read -r tok; do
  [ -z "$tok" ] && continue
  # Dictionary entries are quoted C-string literals; a bare substring
  # match on the quoted form is sufficient and avoids re-implementing
  # libFuzzer's escape parsing.
  if ! grep -qF "\"$tok\"" "$DICT"; then
    missing="${missing}${tok}\n"
  fi
done <<<"$tokens"

if [ -n "$missing" ]; then
  echo "❌ fuzz.dict is missing tokens the parser now recognizes:" >&2
  printf '%b' "$missing" | sed 's/^/    - /' >&2
  echo "Add each to $DICT (or confirm it is genuinely non-security-relevant" >&2
  echo "and drop it from this script's extraction patterns with a comment)." >&2
  exit 1
fi

echo "✓ fuzz.dict covers all $(printf '%b' "$tokens" | grep -c .) extracted parser literals"
