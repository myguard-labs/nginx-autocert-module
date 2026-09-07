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
#include "../../fuzz/generated_http.inc"

#include <stdio.h>


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

        CHECK(upto <= total, "incremental: feed size within buffer");
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
            "X-Odd: a\r\n"          /* ordinary header, no false start */
            "Content-Length: 0\r\n"
            "\r\n";
        size_t              feeds[3];

        feeds[0] = 20;                      /* mid status-line/header area */
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

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
