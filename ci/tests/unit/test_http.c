/*
 * Unit tests for the autocert ACME HTTP-response / URL parser (M4b):
 *   ngx_autocert_acme_parse_url       absolute-https URL splitter
 *   ngx_autocert_acme_parse_response  status-line + header validation
 *
 * DESIGN NOTE — why this is shim+slice, not include+link:
 * ngx_autocert_acme.c is an event-driven TLS client; the parser functions are
 * self-contained byte crunchers, but the rest of the TU references
 * ngx_event_connect / ngx_resolver / ngx_ssl, which would have to be linked
 * (with their transitive deps) just to satisfy the linker for an include-shim
 * build. So we reuse the fuzz infrastructure: fuzz/extract_http.sh slices the
 * parser bodies into fuzz/generated_http.inc, compiled here against
 * fuzz/ngx_http_shim.h — same idiom as fuzz/fuzz_json.c, and the SAME shipped
 * code the fuzzer exercises, with no copy drift. (Reported as a deliberate
 * deviation from the include+link route in the PR.)
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include "../../fuzz/ngx_http_shim.h"

static size_t  ngx_autocert_test_memmem_visits;

#undef NGX_AUTOCERT_TEST_MEMMEM_VISIT
#define NGX_AUTOCERT_TEST_MEMMEM_VISIT()  ngx_autocert_test_memmem_visits++

#include "../../fuzz/generated_http.inc"

#include <stdio.h>
#include <assert.h>


static int          failures;
static ngx_pool_t   pool;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


static void
req_init(ngx_autocert_acme_request_t *r)
{
    memset(r, 0, sizeof(*r));
    r->pool = &pool;
    r->content_length = -1;
}

static int
streq(ngx_str_t *s, const char *lit)
{
    return s->len == strlen(lit) && memcmp(s->data, lit, s->len) == 0;
}


/* ---- parse_url ---- */

static void
url_ok(const char *url, const char *host, int port, const char *uri,
    ngx_uint_t ipv6)
{
    ngx_autocert_acme_request_t  r;
    char  msg[160];

    req_init(&r);
    r.url.data = (u_char *) url;
    r.url.len = strlen(url);

    snprintf(msg, sizeof(msg), "parse_url ok \"%s\"", url);
    if (ngx_autocert_acme_parse_url(&r) != NGX_OK) {
        CHECK(0, msg);
        return;
    }
    CHECK(streq(&r.host, host) && r.port == port && streq(&r.uri, uri)
          && r.host_is_ipv6 == ipv6, msg);
    ngx_http_fuzz_pool_reset(&pool);
}

static void
url_bad(const char *url)
{
    ngx_autocert_acme_request_t  r;
    char  msg[160];

    req_init(&r);
    r.url.data = (u_char *) url;
    r.url.len = strlen(url);

    snprintf(msg, sizeof(msg), "parse_url reject \"%s\"", url);
    CHECK(ngx_autocert_acme_parse_url(&r) == NGX_ERROR, msg);
    ngx_http_fuzz_pool_reset(&pool);
}

/* parse_url over an explicit (data,len) so we can embed NUL/control bytes. */
static void
url_bad_n(const u_char *data, size_t len, const char *label)
{
    ngx_autocert_acme_request_t  r;

    req_init(&r);
    r.url.data = (u_char *) data;
    r.url.len = len;
    CHECK(ngx_autocert_acme_parse_url(&r) == NGX_ERROR, label);
    ngx_http_fuzz_pool_reset(&pool);
}

static void
test_parse_url(void)
{
    /* scheme / host / port / uri split */
    url_ok("https://acme.example.com/dir", "acme.example.com", 443, "/dir", 0);
    url_ok("https://acme.example.com", "acme.example.com", 443, "/", 0);
    url_ok("https://acme.example.com:8443/x", "acme.example.com", 8443, "/x", 0);
    url_ok("https://acme.example.com:443/", "acme.example.com", 443, "/", 0);
    url_ok("https://[2001:db8::1]/p", "2001:db8::1", 443, "/p", 1);
    url_ok("https://[2001:db8::1]:8443/p", "2001:db8::1", 8443, "/p", 1);
    url_ok("https://h/a/b?c=d&e=f", "h", 443, "/a/b?c=d&e=f", 0);

    /* scheme is case-insensitive */
    url_ok("HTTPS://h/x", "h", 443, "/x", 0);

    /* missing / wrong scheme */
    url_bad("http://acme.example.com/dir");   /* TLS-only: http rejected */
    url_bad("ftp://h/x");
    url_bad("acme.example.com/dir");           /* no scheme */
    url_bad("https://");                       /* empty everything */
    url_bad("https:///path");                  /* empty host */

    /* port edge cases */
    url_bad("https://h:/x");                    /* empty port */
    url_bad("https://h:0/x");                   /* port 0 out of range */
    url_bad("https://h:65536/x");               /* port overflow */
    url_bad("https://h:99999999999/x");         /* huge port */
    url_bad("https://h:8a43/x");                /* non-numeric port */

    /* IPv6 without closing bracket */
    url_bad("https://[2001:db8::1/x");

    /* relative / junk between host and uri */
    url_bad("https://h x/y");                   /* space (control) in host */

    /* control / NUL bytes in host or uri are rejected (url_part_safe) */
    {
        static const u_char nul_host[]  = "https://h\x00x/y";
        static const u_char ctrl_host[] = "https://h\x01x/y";
        static const u_char ctrl_uri[]  = "https://h/a\x01b";
        static const u_char cr_uri[]    = "https://h/a\rb";
        static const u_char lf_uri[]    = "https://h/a\nb";
        url_bad_n(nul_host,  sizeof(nul_host) - 1,  "parse_url reject NUL in host");
        url_bad_n(ctrl_host, sizeof(ctrl_host) - 1, "parse_url reject ctrl in host");
        url_bad_n(ctrl_uri,  sizeof(ctrl_uri) - 1,  "parse_url reject ctrl in uri");
        url_bad_n(cr_uri,    sizeof(cr_uri) - 1,     "parse_url reject CR in uri");
        url_bad_n(lf_uri,    sizeof(lf_uri) - 1,     "parse_url reject LF in uri");
    }

    /* url_part_safe exact boundary: 0x20 (space) is rejected, 0x21 ('!') is
     * the first PRINTABLE byte and must be accepted -- "ch < 0x21" must not
     * become "ch <= 0x21". */
    url_ok("https://h/a!b", "h", 443, "/a!b", 0);
}


/* ---- parse_response: drive it over a fixed response buffer ---- */

static ngx_int_t
parse_resp(const char *resp, size_t len, ngx_autocert_acme_request_t *r)
{
    ngx_buf_t  *b;

    req_init(r);
    b = ngx_pnalloc(&pool, sizeof(ngx_buf_t));
    b->start = ngx_pnalloc(&pool, len ? len : 1);
    memcpy(b->start, resp, len);
    b->pos = b->start;
    b->last = b->start + len;
    b->end = b->last;
    r->recv = b;

    return ngx_autocert_acme_parse_response(r);
}

#define RESP(s)  (s), (sizeof(s) - 1)

static void
test_status_line(void)
{
    ngx_autocert_acme_request_t  r;
    ngx_int_t  rc;

    /* valid 200 with a Content-Length-0 body completes */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_DONE && r.status == 200,
          "status line: HTTP/1.1 200 accepted, status captured");
    ngx_http_fuzz_pool_reset(&pool);

    /* HTTP/1.0 is also accepted */
    rc = parse_resp(RESP("HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
                    &r);
    CHECK(rc == NGX_DONE && r.status == 404, "status line: HTTP/1.0 accepted");
    ngx_http_fuzz_pool_reset(&pool);

    /* non-HTTP/1.x version rejected */
    rc = parse_resp(RESP("HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: HTTP/2.0 rejected");
    ngx_http_fuzz_pool_reset(&pool);

    rc = parse_resp(RESP("XTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: non-HTTP prefix rejected");
    ngx_http_fuzz_pool_reset(&pool);

    /* non-3-digit / non-numeric code rejected */
    rc = parse_resp(RESP("HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: 2-digit code rejected");
    ngx_http_fuzz_pool_reset(&pool);

    rc = parse_resp(RESP("HTTP/1.1 2zz OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: non-numeric code rejected");
    ngx_http_fuzz_pool_reset(&pool);

    /* out-of-range code (< 100 or > 599) rejected */
    rc = parse_resp(RESP("HTTP/1.1 099 X\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: code 099 rejected");
    ngx_http_fuzz_pool_reset(&pool);

    rc = parse_resp(RESP("HTTP/1.1 600 X\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: code 600 rejected");
    ngx_http_fuzz_pool_reset(&pool);

    /* missing space after version rejected */
    rc = parse_resp(RESP("HTTP/1.1x200 OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: missing space after version rejected");
    ngx_http_fuzz_pool_reset(&pool);
}


static void
test_body_framing(void)
{
    ngx_autocert_acme_request_t  r;
    ngx_int_t  rc;

    /* Content-Length body */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
                    &r);
    CHECK(rc == NGX_DONE && r.body_out.len == 5
          && memcmp(r.body_out.data, "hello", 5) == 0,
          "body: Content-Length body captured");
    ngx_http_fuzz_pool_reset(&pool);

    /* partial body -> NGX_AGAIN */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel"), &r);
    CHECK(rc == NGX_AGAIN, "body: short Content-Length body -> AGAIN");
    ngx_http_fuzz_pool_reset(&pool);

    /* chunked body decode */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                         "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"), &r);
    CHECK(rc == NGX_DONE && r.body_out.len == 11
          && memcmp(r.body_out.data, "hello world", 11) == 0,
          "body: chunked decode concatenates chunks");
    ngx_http_fuzz_pool_reset(&pool);

    /* both Content-Length and chunked -> reject */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                         "Transfer-Encoding: chunked\r\n\r\nhello"), &r);
    CHECK(rc == NGX_ERROR, "body: CL + TE rejected");
    ngx_http_fuzz_pool_reset(&pool);

    /* unsupported transfer-encoding rejected */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n"
                         "x"), &r);
    CHECK(rc == NGX_ERROR, "body: unsupported Transfer-Encoding rejected");
    ngx_http_fuzz_pool_reset(&pool);

    /* header capture: ngx_autocert_acme_header finds a value */
    rc = parse_resp(RESP("HTTP/1.1 201 Created\r\nLocation: https://acct/1\r\n"
                         "Content-Length: 0\r\n\r\n"), &r);
    {
        ngx_str_t  *loc = ngx_autocert_acme_header(&r, "Location");
        CHECK(rc == NGX_DONE && loc != NULL
              && streq(loc, "https://acct/1"),
              "header: Location captured + case-insensitive lookup");
    }
    ngx_http_fuzz_pool_reset(&pool);

    /* incomplete headers (no CRLFCRLF) -> AGAIN, no over-read */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"), &r);
    CHECK(rc == NGX_AGAIN, "headers: incomplete header block -> AGAIN");
    ngx_http_fuzz_pool_reset(&pool);

    /* chunk-size overflow guard, exact boundary, called directly since
     * ngx_autocert_acme_chunk_size is sliced into THIS TU by
     * extract_http.sh (unlike json.c's hex4, which lives in a separately
     * compiled object). NGX_MAX_SIZE_T_VALUE here is 0x7fff...f (signed
     * max, per the shim), so bound = (0x7fff...f >> 4) = 0x7ff...f (15 hex
     * digits: "7ffffffffffffff"). Feeding exactly that 15-digit prefix makes
     * the accumulated size equal the bound precisely; a 16th digit then
     * checks "size > bound", which is FALSE (they're equal) so the real
     * guard lets it through -- but a mutation to "size >= bound" rejects it.
     * This is the one input where "> " and ">=" actually diverge (any pure
     * run of 'f' digits hits the guard at the same digit count either way,
     * since size strictly exceeds bound the moment it does at all). */
    {
        u_char      at_bound[]  = "7ffffffffffffff";      /* 15 digits == bound */
        u_char      one_over[]  = "7fffffffffffffff";     /* 16 digits, one more 'f' */
        size_t      out;

        CHECK(ngx_autocert_acme_chunk_size(at_bound, at_bound + 15, &out) == NGX_OK
              && out == 0x7ffffffffffffffULL,
              "chunk_size: 15 hex digits forming exactly the overflow bound accepted");
        CHECK(ngx_autocert_acme_chunk_size(one_over, one_over + 16, &out) == NGX_OK,
              "chunk_size: bound followed by one more digit still accepted "
              "(guard is strictly '>', not '>=')");
    }

    /* chunk-size line with no hex digits at all (e.g. an extension with no
     * leading size) must be rejected, not treated as a 0-size terminator. */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                         ";ext\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR,
          "body: digit-less chunk-size line rejected");
    ngx_http_fuzz_pool_reset(&pool);

    /* chunked body with a genuine trailer field, correctly terminated by an
     * empty line, is accepted and the trailer is not mistaken for the body
     * terminator. */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                         "5\r\nhello\r\n0\r\nFoo: x\r\n\r\n"), &r);
    CHECK(rc == NGX_DONE && r.body_out.len == 5
          && memcmp(r.body_out.data, "hello", 5) == 0,
          "body: last chunk with a genuine trailer field + empty line "
          "terminator accepted");
    ngx_http_fuzz_pool_reset(&pool);

    /* last chunk followed by a trailer field's CRLF but NO further empty
     * line is an INCOMPLETE message, not a complete one: "0\r\nFoo: x\r\n" is
     * merely the end of the trailer field's own line, not the empty line
     * that closes trailers per RFC 7230 SS4.1.2. The pre-fix parser searched
     * for "any following CRLF" and stopped at the trailer field's CRLF,
     * misreading this as a complete body. */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                         "5\r\nhello\r\n0\r\nFoo: x\r\n"), &r);
    CHECK(rc == NGX_AGAIN,
          "body: last chunk + trailer field with no closing empty line is "
          "incomplete, not a complete body (regression for the "
          "any-following-CRLF trailer bug)");
    ngx_http_fuzz_pool_reset(&pool);
}


/*
 * ---- hdr_scan_pos: incremental header-boundary scan ----
 *
 * Drives parse_response over a response delivered in pieces (as the real
 * read handler does across NGX_AGAIN events) instead of one shot, so the
 * persisted scan cursor (r->hdr_scan_pos) is actually exercised: each call
 * appends more bytes to the same buffer and re-invokes the parser, exactly
 * like ngx_autocert_acme_read_handler's loop. feed_sizes gives the number of
 * bytes visible to the buffer after each call (cumulative, not a delta).
 */
static ngx_int_t
parse_resp_incremental(const char *resp, const size_t *feed_sizes,
    size_t nfeeds, ngx_autocert_acme_request_t *r)
{
    ngx_buf_t  *b;
    size_t      total = strlen(resp);
    size_t      i;
    ngx_int_t   rc = NGX_AGAIN;

    req_init(r);
    b = ngx_pnalloc(&pool, sizeof(ngx_buf_t));
    b->start = ngx_pnalloc(&pool, total ? total : 1);
    b->pos = b->start;
    b->last = b->start;
    b->end = b->start + total;
    r->recv = b;

    for (i = 0; i < nfeeds; i++) {
        size_t  upto = feed_sizes[i];

        assert(upto <= total);   /* harness invariant; see parse_resp_grow */
        memcpy(b->start, resp, upto);
        b->last = b->start + upto;

        rc = ngx_autocert_acme_parse_response(r);
        if (rc != NGX_AGAIN) {
            break;
        }
    }

    return rc;
}


static void
test_hdr_scan_cursor(void)
{
    ngx_autocert_acme_request_t  r;
    ngx_int_t                    rc;

    /*
     * The CRLFCRLF boundary is split across two feeds: the first feed ends
     * right after the lone CR that starts it ("...0\r\n\r"), the second
     * delivers the final "\n". A cursor that fails to back off by (marker
     * length - 1) before resuming the scan would start searching AFTER the
     * split "\r", never see the completed "\r\n\r\n", and wrongly report
     * AGAIN forever instead of DONE.
     */
    {
        static const char  resp[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        size_t              split = sizeof(resp) - 1 - 1;  /* stop before \n */
        size_t              feeds[2];

        feeds[0] = split;
        feeds[1] = sizeof(resp) - 1;

        rc = parse_resp_incremental(resp, feeds, 2, &r);
        CHECK(rc == NGX_DONE && r.status == 200,
              "hdr_scan_pos: CRLFCRLF split across two reads still found");
        ngx_http_fuzz_pool_reset(&pool);
    }

    /*
     * Same split, but one byte earlier: first feed ends after "...0\r\n\r\n"
     * minus the LAST TWO bytes ("...0\r\n"), second feed delivers the
     * trailing "\r\n". This is the case a too-small backoff (e.g. only 1
     * byte instead of marker_len - 1 == 3) would miss, since the boundary's
     * first byte ('\r') already sits before the (wrongly small) resume
     * point.
     */
    {
        static const char  resp[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        size_t              feeds[2];

        feeds[0] = sizeof(resp) - 1 - 2;   /* "...Length: 0\r\n" */
        feeds[1] = sizeof(resp) - 1;       /* + trailing "\r\n" */

        rc = parse_resp_incremental(resp, feeds, 2, &r);
        CHECK(rc == NGX_DONE && r.status == 200,
              "hdr_scan_pos: boundary split one byte earlier still found");
        ngx_http_fuzz_pool_reset(&pool);
    }

    /*
     * A byte sequence that LOOKS like a false-start of the boundary just
     * before the real split point must not desync the cursor: "\r\n\r" (3
     * of the 4 marker bytes) appears mid-header-value here, followed by
     * ordinary header bytes, then the real terminator arrives in a later
     * feed. The cursor must still find the REAL CRLFCRLF, not stop early or
     * skip past it.
     */
    {
        static const char  resp[] =
            "HTTP/1.1 200 OK\r\n"
            "X-Odd: a\r\n\rX-Next: b\r\n" /* false delimiter: CRLF + CR */
            "Content-Length: 0\r\n"
            "\r\n";
        size_t              feeds[3];

        feeds[0] = sizeof("HTTP/1.1 200 OK\r\nX-Odd: a\r\n\r") - 1;
                                                /* stop on false CRLF + CR */
        feeds[1] = sizeof(resp) - 1 - 4;    /* just before final CRLFCRLF */
        feeds[2] = sizeof(resp) - 1;

        rc = parse_resp_incremental(resp, feeds, 3, &r);
        CHECK(rc == NGX_DONE && r.status == 200,
              "hdr_scan_pos: multi-feed scan finds boundary delivered last");
        ngx_http_fuzz_pool_reset(&pool);
    }

    /* Sanity: many tiny 1-byte-at-a-time feeds (worst case for a resume
     * cursor) still finds the boundary and parses headers correctly. */
    {
        static const char  resp[] =
            "HTTP/1.1 201 Created\r\nLocation: https://x/1\r\n"
            "Content-Length: 0\r\n\r\n";
        size_t              feeds[sizeof(resp)];
        size_t              n = sizeof(resp) - 1;
        size_t              i;

        for (i = 0; i < n; i++) {
            feeds[i] = i + 1;
        }

        rc = parse_resp_incremental(resp, feeds, n, &r);
        CHECK(rc == NGX_DONE && r.status == 201,
              "hdr_scan_pos: byte-at-a-time feed finds boundary");
        if (rc == NGX_DONE) {
            ngx_str_t  *loc = ngx_autocert_acme_header(&r, "Location");
            CHECK(loc != NULL && streq(loc, "https://x/1"),
                  "hdr_scan_pos: header captured correctly after "
                  "byte-at-a-time scan");
        }
        ngx_http_fuzz_pool_reset(&pool);
    }
}


static void
test_chunked_trailer_cursor(void)
{
    static const char  prefix[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n";
    ngx_autocert_acme_request_t  r;
    ngx_buf_t                   *b;
    u_char                       resp[512];
    size_t                       visible, i, fail_i = 0, fail_cursor = 0;
    size_t                       fail_visits = 0, fail_visible = 0;
    ngx_int_t                    rc;
    ngx_int_t                    fail_rc = NGX_OK;
    ngx_uint_t                   fail_state = 0;
    const char                  *fail_phase = "none";
    int                          bounded = 1;

#define TRAILER_STEP_OK(condition, phase_name)                                \
    do {                                                                      \
        size_t  trailer_bytes = visible - (sizeof(prefix) - 1);               \
        if (bounded                                                           \
            && (!(condition)                                                  \
                || ngx_autocert_test_memmem_visits > 2 * trailer_bytes + 2))  \
        {                                                                     \
            bounded = 0;                                                      \
            fail_i = i;                                                       \
            fail_phase = phase_name;                                          \
            fail_rc = rc;                                                     \
            fail_cursor = r.dechunk_pos;                                      \
            fail_state = r.dechunk_state;                                     \
            fail_visits = ngx_autocert_test_memmem_visits;                    \
            fail_visible = visible;                                           \
        }                                                                     \
    } while (0)

    req_init(&r);
    b = ngx_pnalloc(&pool, sizeof(ngx_buf_t));
    memcpy(resp, prefix, sizeof(prefix) - 1);
    visible = sizeof(prefix) - 1;
    b->start = resp;
    b->pos = resp;
    b->last = resp + visible;
    b->end = resp + sizeof(resp);
    r.recv = b;

    rc = ngx_autocert_acme_parse_response(&r);
    if (rc != NGX_AGAIN
        || r.dechunk_state != NGX_AUTOCERT_DECHUNK_TRAILER_START
        || r.dechunk_pos != visible)
    {
        bounded = 0;
        fail_phase = "zero-chunk";
        fail_rc = rc;
        fail_cursor = r.dechunk_pos;
        fail_state = r.dechunk_state;
        fail_visits = ngx_autocert_test_memmem_visits;
        fail_visible = visible;
    }
    ngx_autocert_test_memmem_visits = 0;

    /* Feed 64 one-byte trailer fields one byte at a time. After every parse,
     * all but at most a trailing CR must be behind the persisted scan cursor.
     * This is the executable linear-work invariant: 195 parser calls cover
     * 194 incrementally exposed trailer bytes and retain at most one byte of
     * delimiter overlap. */
    for (i = 0; i < 64; i++) {
        resp[visible++] = 'X';
        b->last = resp + visible;
        rc = ngx_autocert_acme_parse_response(&r);
        TRAILER_STEP_OK(rc == NGX_AGAIN && visible - r.dechunk_pos <= 1,
                        "field-byte");

        resp[visible++] = '\r';
        b->last = resp + visible;
        rc = ngx_autocert_acme_parse_response(&r);
        TRAILER_STEP_OK(rc == NGX_AGAIN && visible - r.dechunk_pos <= 1,
                        "field-cr");

        resp[visible++] = '\n';
        b->last = resp + visible;
        rc = ngx_autocert_acme_parse_response(&r);
        TRAILER_STEP_OK(rc == NGX_AGAIN && r.dechunk_pos == visible
                        && r.dechunk_state
                           == NGX_AUTOCERT_DECHUNK_TRAILER_START,
                        "field-lf");
    }

    resp[visible++] = '\r';
    b->last = resp + visible;
    rc = ngx_autocert_acme_parse_response(&r);
    TRAILER_STEP_OK(rc == NGX_AGAIN && visible - r.dechunk_pos == 1,
                    "terminator-cr");

    resp[visible++] = '\n';
    b->last = resp + visible;
    rc = ngx_autocert_acme_parse_response(&r);
    TRAILER_STEP_OK(rc == NGX_DONE && r.body_out.len == 0,
                    "terminator-lf");

    if (!bounded) {
        fprintf(stderr,
                "diag: trailer step=%zu phase=%s rc=%ld cursor=%zu "
                "state=%lu memmem_visits=%zu visible=%zu\n",
                fail_i, fail_phase, (long) fail_rc, fail_cursor,
                (unsigned long) fail_state, fail_visits, fail_visible);
    }

    fprintf(stderr, "metric: trailer_bytes=194 parser_calls=195 "
            "memmem_visits=%zu\n", ngx_autocert_test_memmem_visits);

    CHECK(bounded,
          "dechunk: 195 byte-split trailer reads stay within linear "
          "memmem/cursor bound");
#undef TRAILER_STEP_OK
    ngx_http_fuzz_pool_reset(&pool);
}


/*
 * ---- fragmentation-parity harness ----
 *
 * For one response, the WHOLE-parse result (rc, status, every captured
 * header name/value, content_length, decoded body) is the reference. Every
 * split delivery of the SAME bytes -- at every offset 1..len-1 as a two-feed
 * delivery, plus one byte at a time -- must reach an IDENTICAL result. This
 * tests invariance under fragmentation, not what the parser should decide:
 * whatever the whole-parse verdict is (accept or reject) is also the
 * required split verdict.
 *
 * Captured header names/values ARE pool copies (see the "Copy into the pool"
 * comment in ngx_autocert_acme_parse_response), but the non-chunked body is
 * NOT: parse_response sets body_out.data = b->start + body_offset, a raw
 * alias into the recv buffer. So the reference must be deep-copied out of
 * BOTH the pool and the recv buffer before either is reset or reallocated --
 * which is what snapshot_result does with malloc'd storage.
 *
 * That aliasing is also precisely the hazard the grow variant probes: a
 * grown-and-copied recv buffer abandons the old allocation, so an aliased
 * body pointer captured before the growth dangles into freed memory, and the
 * byte comparison here reads whatever now occupies it.
 */

/*
 * Header-array bound for a captured result. Asserted, never silently
 * clamped -- see snapshot_result.
 */
#define PARITY_MAX_HDRS  32


/*
 * malloc that aborts instead of dereferencing NULL. Abort, not CHECK: this
 * runs once per captured header per delivery (thousands of times), so a
 * CHECK here would bury the parser's own assertions under harness noise --
 * and an OOM in a fixture-sized test is an environment failure, not a
 * parser result worth counting.
 */
static void *
parity_dup(const void *src, size_t len)
{
    void  *p = malloc(len);

    if (p == NULL) {
        fprintf(stderr, "FATAL: parity snapshot allocation failed\n");
        abort();
    }
    memcpy(p, src, len);
    return p;
}

typedef struct {
    ngx_int_t   rc;
    ngx_uint_t  status;
    ngx_uint_t  nheaders;
    ngx_str_t   hnames[PARITY_MAX_HDRS];
    ngx_str_t   hvalues[PARITY_MAX_HDRS];
    off_t       content_length;
    ngx_str_t   body;
} parse_result_t;

/* Deep-copy r's observable result out of the pool before ngx_http_fuzz_pool_reset
 * frees it, so a reference captured from the whole-parse run survives long
 * enough to be compared against later split runs. */
static void
snapshot_result(ngx_int_t rc, ngx_autocert_acme_request_t *r,
    parse_result_t *out)
{
    ngx_uint_t  i, n;

    memset(out, 0, sizeof(*out));
    out->rc = rc;
    out->status = r->status;
    out->content_length = r->content_length;

    if (rc == NGX_DONE) {
        out->body.len = r->body_out.len;
        if (out->body.len) {
            out->body.data = parity_dup(r->body_out.data, out->body.len);
        }
    }

    if (r->headers != NULL) {
        n = r->headers->nelts;

        /*
         * Assert the bound rather than clamping to it. A silent clamp would
         * leave nheaders unclamped while comparing only the first
         * PARITY_MAX_HDRS entries, so a parser that dropped header 33 on a
         * split delivery would match on count and never be compared past the
         * bound -- a divergence the harness exists to catch, reported as a
         * pass. Raise PARITY_MAX_HDRS if a corpus case ever needs more.
         */
        if (n > PARITY_MAX_HDRS) {
            CHECK(0, "parity: header count within PARITY_MAX_HDRS");
            n = PARITY_MAX_HDRS;
        }

        out->nheaders = n;
        for (i = 0; i < n; i++) {
            ngx_autocert_acme_header_t  *h =
                &((ngx_autocert_acme_header_t *) r->headers->elts)[i];

            /*
             * A zero-length name/value is copied as NULL rather than a
             * 1-byte allocation: dup'ing one byte of a zero-length source
             * reads an uninitialized byte (ASan does not see it, MSan
             * would). free(NULL) and memcmp(..., 0) are both safe on the
             * paths that touch these, so NULL is the honest representation.
             */
            out->hnames[i].len = h->name.len;
            out->hnames[i].data = h->name.len
                                  ? parity_dup(h->name.data, h->name.len)
                                  : NULL;

            out->hvalues[i].len = h->value.len;
            out->hvalues[i].data = h->value.len
                                   ? parity_dup(h->value.data, h->value.len)
                                   : NULL;
        }
    }
}

static void
free_result(parse_result_t *res)
{
    ngx_uint_t  i, n;

    n = res->nheaders > PARITY_MAX_HDRS ? PARITY_MAX_HDRS : res->nheaders;
    for (i = 0; i < n; i++) {
        free(res->hnames[i].data);
        free(res->hvalues[i].data);
    }
    free(res->body.data);
}

/* Feed resp[0,len) into parse_response via 'feeds' cumulative sizes, starting
 * the recv buffer at buf_init bytes and growing it (copy old->new, exactly
 * like ngx_autocert_acme_read_handler's single jump-to-ceiling realloc) the
 * moment a feed needs more than the buffer currently holds. Returns the final
 * rc and leaves *r populated for snapshotting. */
static ngx_int_t
parse_resp_grow(const char *resp, size_t len, const size_t *feeds,
    size_t nfeeds, size_t buf_init, ngx_autocert_acme_request_t *r)
{
    ngx_buf_t  *b;
    size_t      cap = buf_init;
    size_t      i;
    ngx_int_t   rc = NGX_AGAIN;

    req_init(r);
    b = ngx_pnalloc(&pool, sizeof(ngx_buf_t));
    b->start = ngx_pnalloc(&pool, cap ? cap : 1);
    b->pos = b->start;
    b->last = b->start;
    b->end = b->start + cap;
    r->recv = b;

    for (i = 0; i < nfeeds; i++) {
        size_t  upto = feeds[i];
        size_t  used = b->last - b->start;

        /* Harness invariant on a caller-computed constant, not a parser
         * constraint: assert it without inflating the assertion count
         * (it would otherwise fire once per feed, thousands of times). */
        assert(upto <= len);

        if (upto > cap) {
            /* grow: fresh allocation, copy live bytes, abandon the old one --
             * mirrors the real read handler's realloc-and-copy exactly. */
            u_char  *nb;

            cap = len > cap * 2 ? len : cap * 2;
            nb = ngx_pnalloc(&pool, cap);
            memcpy(nb, b->start, used);
            b->start = nb;
            b->pos = nb;
            b->last = nb + used;
            b->end = nb + cap;
        }

        memcpy((void *) (b->start + used), resp + used, upto - used);
        b->last = b->start + upto;

        rc = ngx_autocert_acme_parse_response(r);
        if (rc != NGX_AGAIN) {
            break;
        }
    }

    return rc;
}

static int  parity_failures;

/* Compare a split/grown run's result against the whole-parse reference.
 * Names the case and the split offset in the failure message so a
 * regression is diagnosable, per the item's done criterion. */
static void
assert_parity(const parse_result_t *ref, ngx_int_t rc,
    ngx_autocert_acme_request_t *r, const char *case_label, long split)
{
    parse_result_t  got;
    char            msg[256];
    int             ok = 1;
    ngx_uint_t      i, n;

    snapshot_result(rc, r, &got);

    /*
     * status, content_length and the header array are populated on the
     * NGX_AGAIN and NGX_ERROR paths too, so they are compared for EVERY
     * verdict -- a split delivery that rejects with a different status, or
     * having captured half the headers, is a parity failure even though the
     * rc matches. Only the body is gated on NGX_DONE, since that is the only
     * verdict that produces one.
     */
    if (got.rc != ref->rc) {
        ok = 0;
    } else {
        if (got.status != ref->status
            || got.content_length != ref->content_length
            || got.nheaders != ref->nheaders
            || (ref->rc == NGX_DONE
                && (got.body.len != ref->body.len
                    || (got.body.len
                        && memcmp(got.body.data, ref->body.data,
                                  got.body.len) != 0))))
        {
            ok = 0;
        } else {
            n = ref->nheaders > PARITY_MAX_HDRS
                ? PARITY_MAX_HDRS : ref->nheaders;
            for (i = 0; i < n; i++) {
                /*
                 * Length first, and bytes only when there ARE bytes: a
                 * zero-length field is snapshotted as NULL, and
                 * memcmp(NULL, NULL, 0) is undefined (UBSan rejects a NULL
                 * argument to a nonnull parameter even with n == 0).
                 */
                if (got.hnames[i].len != ref->hnames[i].len
                    || (got.hnames[i].len
                        && memcmp(got.hnames[i].data, ref->hnames[i].data,
                                  got.hnames[i].len) != 0)
                    || got.hvalues[i].len != ref->hvalues[i].len
                    || (got.hvalues[i].len
                        && memcmp(got.hvalues[i].data, ref->hvalues[i].data,
                                  got.hvalues[i].len) != 0))
                {
                    ok = 0;
                    break;
                }
            }
        }
    }

    snprintf(msg, sizeof(msg),
             "parity[%s]: split@%ld matches whole-parse reference "
             "(rc=%ld vs ref rc=%ld)",
             case_label, split, (long) got.rc, (long) ref->rc);
    CHECK(ok, msg);
    if (!ok) {
        parity_failures++;
    }
    free_result(&got);
}

/*
 * Drive one response case through: (a) whole-shot reference, (b) every
 * two-feed split point i in 1..len-1, (c) byte-at-a-time, (d) a grown-buffer
 * variant that starts small (below the response length, forcing at least one
 * realloc) split at a hand-picked interior point. All must match (a).
 */
static void
parity_case(const char *label, const char *resp)
{
    ngx_autocert_acme_request_t  r;
    parse_result_t                ref;
    ngx_int_t                     rc;
    size_t                        len = strlen(resp);
    size_t                        i;

    /* (a) whole-shot reference */
    rc = parse_resp(resp, len, &r);
    snapshot_result(rc, &r, &ref);
    ngx_http_fuzz_pool_reset(&pool);

    /* (b) every two-feed split point */
    for (i = 1; i < len; i++) {
        size_t  feeds[2];

        feeds[0] = i;
        feeds[1] = len;
        rc = parse_resp_incremental(resp, feeds, 2, &r);
        assert_parity(&ref, rc, &r, label, (long) i);
        ngx_http_fuzz_pool_reset(&pool);
    }

    /* (c) byte-at-a-time (worst-case fragmentation) */
    {
        size_t  *feeds = malloc(len * sizeof(size_t));

        if (feeds == NULL) {
            fprintf(stderr, "FATAL: parity byte-at-a-time feed table "
                    "allocation failed\n");
            abort();
        }
        for (i = 0; i < len; i++) {
            feeds[i] = i + 1;
        }
        rc = parse_resp_incremental(resp, feeds, len, &r);
        assert_parity(&ref, rc, &r, label, -1);
        ngx_http_fuzz_pool_reset(&pool);
        free(feeds);
    }

    /*
     * (d) forced buffer growth. The ORDERING is the point: the first feed must
     * FIT the initial buffer so the first parse_response runs against the old
     * allocation, and the second feed must then exceed it so the realloc
     * lands BETWEEN the two parses. Sizing the buffer below the first feed
     * instead would grow before any parse had run, and the case would prove
     * nothing. Verified by instrumentation: the growth branch executes for
     * every corpus case, always one byte before the end.
     *
     * SCOPE, honestly stated: this is a REGRESSION GUARD, not a test that
     * currently discriminates. Today parse_response recomputes
     * body_out.data = b->start + body_offset on the parse that returns
     * NGX_DONE, so no pointer captured by an earlier parse survives the
     * growth, and poisoning the abandoned buffer changes no result (measured).
     * It would catch a future change that CACHED a recv-buffer pointer across
     * NGX_AGAIN returns -- but only once a case exists whose body completes
     * across the growth boundary rather than on the final feed. Adding one is
     * TODO; do not read this case as already covering that hazard.
     */
    {
        size_t  buf_init;
        size_t  feeds[2];

        /*
         * The first feed must also be LATE enough for the first parse to get
         * past the header boundary and populate the body/state that a later
         * growth could invalidate. len-1 is the latest feed that still leaves
         * a second one, so it maximises what the pre-growth parse has done;
         * len/2 would return NGX_AGAIN in the header scan for most cases and
         * the growth would invalidate nothing.
         */
        feeds[0] = len > 1 ? len - 1 : 1;
        feeds[1] = len;

        buf_init = feeds[0];

        rc = parse_resp_grow(resp, len, feeds, 2, buf_init, &r);
        assert_parity(&ref, rc, &r, label, -2);
        ngx_http_fuzz_pool_reset(&pool);
    }

    free_result(&ref);
}

static void
test_hdr_split_parity(void)
{
    /* status line variants (both accepted and rejected whole-parse) */
    parity_case("status HTTP/1.1 200",
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    parity_case("status HTTP/1.0 404",
                "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    parity_case("status HTTP/2.0 rejected",
                "HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    parity_case("status out-of-range 600 rejected",
                "HTTP/1.1 600 X\r\nContent-Length: 0\r\n\r\n");
    parity_case("status non-numeric rejected",
                "HTTP/1.1 2zz OK\r\nContent-Length: 0\r\n\r\n");

    /* CRLF placement: a lone CR / bare LF inside header content is not a
     * line terminator (only CRLF is) -- both must still parse consistently
     * (as whatever the whole-parse decides) under fragmentation. */
    parity_case("lone CR in header value",
                "HTTP/1.1 200 OK\r\nX-Odd: a\rb\r\nContent-Length: 0\r\n\r\n");
    parity_case("bare LF in header value",
                "HTTP/1.1 200 OK\r\nX-Odd: a\nb\r\nContent-Length: 0\r\n\r\n");

    /* multiple headers, duplicate header names, empty header value */
    parity_case("multiple + duplicate + empty-value headers",
                "HTTP/1.1 200 OK\r\n"
                "X-A: 1\r\n"
                "X-B: 2\r\n"
                "X-A: 3\r\n"
                "X-Empty:\r\n"
                "Content-Length: 0\r\n\r\n");

    /* "obs-fold" (leading-whitespace continuation line): this parser has no
     * defined folding behavior -- it splits strictly on CRLF and ":", so a
     * folded continuation is just another line. It has no colon, so the
     * generic "skip a line with no colon" path applies and the continuation
     * contributes nothing to the preceding header's value. That is the
     * whole-parse verdict under test here, not a claim it is RFC-correct. */
    parity_case("obs-fold-shaped continuation (no colon on cont. line)",
                "HTTP/1.1 200 OK\r\n"
                "X-Folded: start\r\n"
                " continued\r\n"
                "Content-Length: 0\r\n\r\n");

    /* chunk extensions on a non-final chunk */
    parity_case("chunk extension on data chunk",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "5;ext=1\r\nhello\r\n0\r\n\r\n");
    parity_case("chunk extension with quoted-ish value",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "a;name=value\r\n0123456789\r\n0\r\n\r\n");

    /* multi-chunk body */
    parity_case("multi-chunk body",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "4\r\nWiki\r\n5\r\npedia\r\n"
                "E\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n");

    /* trailer WITH closing empty line (accepted) */
    parity_case("trailer with closing empty line",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "5\r\nhello\r\n0\r\nFoo: x\r\n\r\n");

    /* trailer WITHOUT closing empty line (incomplete, AGAIN whole-parse) */
    parity_case("trailer without closing empty line",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                "5\r\nhello\r\n0\r\nFoo: x\r\n");

    /* Content-Length vs chunked conflict (rejected) */
    parity_case("Content-Length + chunked conflict",
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                "Transfer-Encoding: chunked\r\n\r\nhello");

    /* Content-Length body, exact and short (AGAIN) */
    parity_case("Content-Length exact body",
                "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world");
    parity_case("Content-Length short body stays AGAIN",
                "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello");

    CHECK(parity_failures == 0,
          "hdr_split_parity: no split/grow delivery diverged from any "
          "whole-parse reference");
}


int
main(void)
{
    /* The unit suite drives fixed fixtures, not sized fuzz inputs, so it opts
     * out of the shim's allocation budget while keeping its tracked registry. */
    ngx_http_fuzz_pool_init(&pool, NULL, NGX_HTTP_FUZZ_NO_BUDGET);

    test_parse_url();
    test_status_line();
    test_body_framing();
    test_hdr_scan_cursor();
    test_chunked_trailer_cursor();
    test_hdr_split_parity();

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
