/*
 * Unit test for ngx_autocert_account_json_safe() (M4d) — the guard that rejects
 * bytes which would break the protected JWS JSON header (control chars < 0x20,
 * double-quote, backslash). The kid/nonce/url values it screens come straight
 * from ACME response headers, so a hostile/buggy server must not be able to
 * inject a field or corrupt the header.
 *
 * The function is static, so this TU slices JUST it from the shipped
 * src/ngx_autocert_account.c via tests/unit/extract_jsonsafe.sh (the whole .c is the
 * account state machine and would drag in the acme client + json + crypto TUs
 * to link). Locked to production code, no copy drift.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "generated_jsonsafe.inc"

#include <stdio.h>
#include <string.h>


static int  failures;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


static ngx_uint_t
safe_lit(const char *lit)
{
    ngx_str_t s;
    s.data = (u_char *) lit;
    s.len = ngx_strlen(lit);
    return ngx_autocert_account_json_safe(&s);
}

static ngx_uint_t
safe_n(const u_char *data, size_t len)
{
    ngx_str_t s;
    s.data = (u_char *) data;
    s.len = len;
    return ngx_autocert_account_json_safe(&s);
}


int
main(void)
{
    ngx_uint_t  c;

    /* ordinary ACME tokens / URLs / nonces accepted */
    CHECK(safe_lit("https://acme.example/acme/acct/12345") == 1,
          "accepts an ordinary URL");
    CHECK(safe_lit("0123456789abcdef-_.~") == 1,
          "accepts a base64url-ish token");
    CHECK(safe_lit("") == 1, "accepts the empty string");
    CHECK(safe_lit("space and ~tilde!") == 1,
          "accepts spaces and printable punctuation");

    /* every control byte 0x00..0x1f rejected (one embedded in a token) */
    for (c = 0x00; c <= 0x1f; c++) {
        u_char  buf[5] = { 'a', 'b', (u_char) c, 'c', 'd' };
        char    msg[48];
        snprintf(msg, sizeof(msg), "rejects control byte 0x%02x", (unsigned) c);
        CHECK(safe_n(buf, sizeof(buf)) == 0, msg);
    }

    /* the two JSON-structural bytes rejected */
    CHECK(safe_lit("has\"quote") == 0, "rejects a double quote");
    CHECK(safe_lit("has\\backslash") == 0, "rejects a backslash");

    /* 0x7f (DEL) and high bytes are NOT rejected by this guard (only < 0x20,
     * '"' and '\\' are) — pin the exact contract so a future change is noticed. */
    {
        u_char  del[3] = { 'a', 0x7f, 'b' };
        u_char  hi[3]  = { 'a', 0xff, 'b' };
        CHECK(safe_n(del, sizeof(del)) == 1,
              "accepts 0x7f (DEL) — guard only screens <0x20, quote, backslash");
        CHECK(safe_n(hi, sizeof(hi)) == 1, "accepts a high byte (>= 0x80)");
    }

    /*
     * ngx_autocert_account_log_safe: bound + escape server-controlled bytes
     * (an ACME problem-document body) before they reach the error log.
     */
    {
        u_char     buf[256];
        ngx_str_t  src;
        ngx_str_t  out;

        /* ordinary printable body with no bytes needing escaping (no
         * quote, backslash or control byte) passes through unchanged */
        src.data = (u_char *) "type: badNonce";
        src.len = ngx_strlen((char *) src.data);
        out = ngx_autocert_account_log_safe(&src, buf, sizeof(buf));
        CHECK(out.len == src.len
              && memcmp(out.data, src.data, src.len) == 0,
              "log_safe: ordinary printable body passes through unchanged");

        /* CRLF is escaped, not passed through raw -- a hostile server must
         * not be able to forge a second log line via an embedded newline. */
        {
            u_char  raw[] = "line1\r\nautocert: FORGED line\r\n";
            src.data = raw;
            src.len = sizeof(raw) - 1;
            out = ngx_autocert_account_log_safe(&src, buf, sizeof(buf));
            CHECK(memchr(out.data, '\r', out.len) == NULL
                  && memchr(out.data, '\n', out.len) == NULL,
                  "log_safe: raw CR and LF bytes never appear in the output");
            CHECK(out.len > src.len,
                  "log_safe: CRLF escaping strictly grows the output "
                  "(\\r\\n each become 2 output bytes)");
        }

        /* a NUL and other control bytes are escaped, not passed through
         * raw or silently dropped. */
        {
            u_char  raw[] = { 'a', 0x00, 0x01, 0x1f, 'b' };
            src.data = raw;
            src.len = sizeof(raw);
            out = ngx_autocert_account_log_safe(&src, buf, sizeof(buf));
            CHECK(memchr(out.data, 0x00, out.len) == NULL
                  && memchr(out.data, 0x01, out.len) == NULL
                  && memchr(out.data, 0x1f, out.len) == NULL,
                  "log_safe: raw control bytes never appear in the output");
        }

        /* over-long input is truncated to the buffer's capacity (a hostile
         * server sending a multi-megabyte body must not flood the log or
         * overrun the caller's fixed buffer). Feed a body of all '\r' so
         * WORST-CASE escaping (2 bytes per input byte, "\\r") is what the
         * cap has to survive -- this is the case that would overrun a naive
         * "cap = buf_size" (rather than buf_size / 6) implementation. */
        {
            static u_char  big[4096];
            size_t         i;

            for (i = 0; i < sizeof(big); i++) {
                big[i] = '\r';
            }
            src.data = big;
            src.len = sizeof(big);
            out = ngx_autocert_account_log_safe(&src, buf, sizeof(buf));
            CHECK(out.len <= sizeof(buf),
                  "log_safe: escaped output never exceeds the caller's "
                  "buffer capacity, even under worst-case 2x-per-byte "
                  "escaping");
            CHECK(out.len < sizeof(buf),
                  "log_safe: an over-long body is truncated (bounded), "
                  "not merely happening to fit");
        }
    }

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}


/*
 * Minimal ngx_log stub so the TU links: ngx_string.o / ngx_palloc.o are
 * linked whole-object for ngx_escape_json / ngx_pnalloc, and drag in
 * references to ngx_cycle / ngx_log_error_core from OTHER functions in
 * those objects that this test never calls. Same idiom as test_json.c and
 * test_ratecap.c.
 */
volatile ngx_cycle_t  *ngx_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}
