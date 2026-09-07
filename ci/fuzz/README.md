# Fuzzing

Coverage-guided (libFuzzer) fuzzing of the parsers that read attacker-
influenceable ACME server bytes: the JSON parser, the HTTP-response parser,
and the base64url decoder. All three targets are built from the SHIPPED
parser source by their `extract_*.sh` slicers — no hand-maintained copy and
no nginx build tree required. `fuzz/build.sh` builds all three (`fuzz_json`,
`fuzz_http`, `fuzz_b64`).

## Targets

### `fuzz_json`

Exercises the JSON parser over arbitrary byte sequences with ASan and UBSan.
It covers:

- `ngx_autocert_json_parse()` — recursive-descent over arbitrary input
- `ngx_autocert_json_object_get()` / `ngx_autocert_json_object_str()` —
  member lookup and string extraction
- `ngx_autocert_json_array_count()` / `ngx_autocert_json_array_item()` —
  array traversal
- `ngx_autocert_json_number_int()` — integer conversion with overflow guard

### `fuzz_http`

Exercises the ACME HTTP-response parser over arbitrary byte sequences:

- `ngx_autocert_acme_parse_response()` — status line (`HTTP/1.x` + 3-digit
  code), header scan, `Content-Length` / `Transfer-Encoding: chunked` framing
- `ngx_autocert_acme_dechunk()` — chunked-body decode (size arithmetic,
  overflow guard, CRLF framing), reached via `parse_response`

The harness builds a minimal `ngx_autocert_acme_request_t` in the shim and
feeds the whole input as the receive buffer in one shot — the way the read
handler hands accumulated bytes to `parse_response`, which internally
dispatches to `dechunk` for a chunked body, so one call exercises both. A
fully decoded chunked body is read back byte-by-byte so ASAN validates the
freshly allocated output region too. (A clean libFuzzer target over
`parse_response` alone is practical here precisely because these functions take
only the buffer + a handful of plain fields — no live connection — so no
fallback to fuzzing `dechunk` in isolation was needed.)

### `fuzz_b64`

Exercises `ngx_http_autocert_base64url_decode()` — the strict RFC 4648 §5
URL-safe-alphabet decoder that layers a hand-written validation loop and a
size-arithmetic overflow guard on top of nginx's own (permissive)
`ngx_decode_base64url()`. nginx's decoder accepts `=` padding and silently
stops at the first non-alphabet byte; this wrapper must reject any such input
outright rather than let a hostile/MITM'd ACME response silently truncate a
decoded field. Only the wrapper's own validation logic is sliced from
production source (`extract_b64.sh`); `ngx_decode_base64url()` itself is
reproduced verbatim from nginx core in `ngx_b64_shim.h` as a fixed
nginx-version dependency, not module code.

Currently the only in-tree caller passes an operator-configured EAB HMAC key
(not ACME-response bytes), but the function is the module's general-purpose
base64url decoder — the highest-value target for any future ACME-response-
derived base64url field, and worth fuzzing defensively regardless of caller.

Why these targets: both parsers read ACME server response bytes
— bytes that arrive over a verified-TLS channel but are still attacker-
influenceable (compromised CA, hostile redirect, buggy server). A single
off-by-one in the string escape decoder, surrogate-pair branch, or
number/literal scanner would be a worker-crashing OOB read. The parser is
written defensively (bounded nesting at 32 levels, length-delimited, no NUL
reliance) but coverage-guided fuzzing catches that bug class more reliably than
the ACME integration tests.

## No copy drift

None of the three targets contains a copy of its parser. `extract_parser.sh`
slices the JSON parser (types from `ngx_autocert_json.h` + bodies from
`ngx_autocert_json.c`) into `generated_json.inc`, compiled against `ngx_shim.h`.
`extract_http.sh` slices the six self-contained HTTP parser functions
(`url_part_safe`, `parse_url`, `memmem`, `header`, `parse_response`, `dechunk`)
out of `ngx_autocert_acme.c` into `generated_http.inc`, compiled against
`ngx_http_shim.h`. (The rest of `ngx_autocert_acme.c` is the event-driven TLS
client — DNS / connect / handshake — which the parser functions never touch, so
slicing avoids linking the whole nginx event/SSL/resolver tree just to fuzz the
byte crunchers.) `extract_b64.sh` slices `ngx_http_autocert_base64url_decode()`
out of `ngx_http_autocert_crypto.c` into `generated_b64.inc`, compiled against
`ngx_b64_shim.h` (avoiding a link against OpenSSL, which the rest of that file
needs but the decode wrapper does not). If a signature or body changes
upstream, the next build picks it up — or fails loudly rather than fuzz stale
code.

`ngx_http_shim.h` mirrors the reduced `ngx_autocert_acme_request_t` surface the
parser reads (pool, url/host/port/uri, recv `ngx_buf_t`, headers array, the
`headers_done` / `chunked` / `content_length` / `body_offset` framing fields)
plus the `ngx_string` / `ngx_array` / `ngx_atoi` / `ngx_atoof` helpers, with
identical semantics. The same shim + slice also back the standalone unit test
`ci/tests/unit/test_http.c`.

`ngx_shim.h` supplies the minimal nginx surface the JSON parser touches:
`ngx_pool_t` with a malloc-backed allocator, `ngx_pcalloc` / `ngx_pnalloc`,
`ngx_strlen` / `ngx_strncmp`, a stub `ngx_log_debug1` macro, and the core
types (`u_char`, `ngx_int_t`, `ngx_uint_t`, `ngx_str_t`, `NGX_OK`,
`NGX_ERROR`, `NGX_DECLINED`).

The harness allocates a buffer sized **exactly** to `size` bytes with **no**
trailing NUL, so ASAN turns any read at or past the end into an immediate
heap-buffer-overflow.

### Allocation-budget oracle

ASAN cannot see a *pool*-allocated overflow — pool allocations carry no
per-allocation redzone — and it has nothing to say about a parser that merely
allocates far too much. Both the JSON and HTTP shims therefore assert the
allocation invariant directly.

The shims previously registered allocations in a fixed 4096-entry array and
returned `NULL` once it filled. That made blowup **invisible**: a document
asking for a million nodes hit the cap, got `NULL`, and the parser's own
out-of-memory path produced a clean rejection — indistinguishable from correct
behaviour. The registry now grows geometrically (`realloc`), so it is never the
thing that fails; only the budget assertion stops a parse.

Both parsers allocate `O(N)` in the document length, because every allocation
site is charged to input bytes that are consumed once and never revisited. The
shims assert:

```
allocs <= 2 * input_len + 8
bytes  <= 64 * input_len + 4096
```

Measured worst-case densities the bounds are derived from (per input byte):

| document | allocs/byte | bytes/byte |
|---|---|---|
| `[[[[...` (32 deep) | 2.00 | 40.0 |
| `[0,0,0,...]` | 1.00 | 20.0 |
| `["","",...]` | 1.00 | 13.3 |
| `{"":0,"":0,...}` | 0.60 | 11.2 |
| `"aaaa...a"` | ~0 | 1.0 |
| `a:b\r\n` x N (HTTP) | 0.40 | 21.4 |

A linear bound catches superlinear growth whatever its slack, since superlinear
growth exceeds *any* linear bound once the document is long enough — slack only
decides how long "long enough" is.

The two bounds are not equally slack. `K2 = 64` bytes/len has real headroom over
the 40.0 bytes/byte worst case above. `K1 = 2` allocs/len is **exact**:
`[[[[[[` saturates it at 2.00 allocs per byte, and stays under budget only
because `C1 = 8` absorbs it and `NGX_AUTOCERT_JSON_MAX_DEPTH` (32) truncates
the family at 64 allocations. A parser change adding an allocation per value on the array path
must re-derive `K1`, not raise it.

A violation prints `ALLOCATION BUDGET EXCEEDED` and `abort()`s, so libFuzzer
records it as a crash with the offending input saved.

`fuzz_b64` has no such oracle and needs none: it performs exactly one
allocation per input, sized directly from the input length.

Because the oracle can only fire on a document long enough to exceed its bound,
both CI lanes run with `-max_len=32768` rather than libFuzzer's 4096-byte
default.

## Build & run locally

```bash
# needs clang with libFuzzer (clang >= 6) — no nginx build tree needed
CC=clang bash ci/fuzz/build.sh    # -> ci/fuzz/fuzz_json + ci/fuzz/fuzz_http + ci/fuzz/fuzz_b64
cd ci/fuzz
./fuzz_json -max_total_time=120 -print_final_stats=1 corpus/
./fuzz_http -max_total_time=120 -print_final_stats=1 corpus_http/
./fuzz_b64  -max_total_time=120 -print_final_stats=1 corpus_b64/
```

The valgrind-replay path (plain compile, no sanitizers):

```bash
CC=clang CFLAGS='-g -O1' bash ci/fuzz/build.sh
```

A crash drops a `crash-*` reproducer; re-run with `./fuzz_json crash-<id>` to
reproduce. Add the reproducer to `corpus/` (named `regress_*`) so it becomes a
permanent regression seed.

## Corpus

`corpus/` contains 10 seed inputs covering the main ACME response shapes:

| file | covers |
| --- | --- |
| `directory.json` | ACME directory object |
| `order.json` | order with identifiers + authorizations arrays |
| `account.json` | newAccount response |
| `authz.json` | authorization + challenges array |
| `escapes.json` | all JSON string escape types incl. surrogate pairs |
| `numbers.json` | integer, negative, float, exponent edge cases |
| `unicode.json` | UTF-8 multibyte strings in array |
| `deep_nest.json` | 9-level object nesting |
| `truncated.json` | mid-string truncation (parse error path) |
| `empty_obj.json` | minimal valid input |

`corpus_http/` seeds the HTTP target with valid, chunked and malformed
responses:

| file | covers |
| --- | --- |
| `cl_ok` | 200 with a `Content-Length` body |
| `created` | 201 with a `Location` header (account register) |
| `chunked` | `Transfer-Encoding: chunked` multi-chunk body |
| `notfound` | `HTTP/1.0` 404, zero-length body |
| `bad_ver` | non-`HTTP/1.x` version (reject path) |
| `bad_code` | non-numeric status code (reject path) |
| `big_chunk` | oversized chunk-size line (framing arithmetic) |
| `junk` | no CRLF at all (header-incomplete path) |

`corpus_b64/` seeds the base64url target with JOSE/JWS-shaped tokens and the
alphabet-boundary cases the strict decoder must reject:

| file | covers |
| --- | --- |
| `jws_protected_header` | a realistic JWS protected-header segment |
| `jws_payload_order` / `jws_payload_empty` | JWS payload segment, incl. empty |
| `jws_signature_ecdsa` | 64-byte raw ECDSA signature, base64url-encoded |
| `eab_hmac_key_32` | the current in-tree caller's shape (EAB HMAC key) |
| `short_1char` .. `exact_4char`, `empty` | length-boundary inputs |
| `has_padding_equals` | `=` padding — must be rejected (std base64, not url) |
| `has_std_b64_plus` / `_slash` | std base64 alphabet chars — not url-safe |
| `has_space` / `has_newline` / `has_null_byte` | non-alphabet bytes mid-token |
| `all_dash_underscore` | pure url-safe-substitute alphabet |
| `mixed_valid_invalid` | valid prefix, invalid tail (early-reject path) |
| `len_mod4_eq1` | length ≡ 1 mod 4 (internal decoder's own reject case) |
| `very_long_valid` | 4096-byte decode (size-arithmetic guard, non-overflow) |
| `high_byte_0x80` / `utf8_multibyte` | non-ASCII bytes |

## CI

`.github/workflows/ci-deep.yml` runs all three targets long (14400s each)
monthly (1st of the month) and on manual dispatch, alongside the
memcheck/helgrind soaks and the security scanners. `.github/workflows/fuzzing.yml`
runs a 30s/target regression on manual dispatch (with `fuzz.dict`);
`valgrind.yml` (60s memcheck soak) and `security-scanners.yml` gate PR/push
events. The per-change build gate is the ASan+UBSan build-test suite in
`build-test.yml`.
