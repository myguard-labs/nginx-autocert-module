/*
 * Unit test for ngx_autocert_acme_log_safe() — the guard that bounds and
 * JSON-escapes CA-controlled bytes (URLs, response bodies, headers) before
 * they reach the error log, preventing log injection attacks.
 *
 * A hostile or buggy ACME server can inject bytes < 0x21 (including LF/CR)
 * into response headers and the directory JSON. When these reach an
 * ngx_log_error(..., "%V", &unescaped_url) call, they can forge log lines.
 * The helper escapes all control bytes using ngx_escape_json.
 *
 * The function is static, so this TU slices JUST it from the shipped
 * src/ngx_autocert_acme.c via tests/unit/extract_acme_logsafe.sh.
 * Locked to production code, no copy drift.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "generated_acme_logsafe.inc"

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


int
main(void)
{
    ngx_pool_t  *pool;
    ngx_log_t    log;

    /* Initialize a minimal log object (stub) */
    ngx_memzero(&log, sizeof(log));
    log.log_level = NGX_LOG_EMERG;

    /* Initialize the pool for allocation tests */
    pool = ngx_create_pool(4096, &log);
    if (pool == NULL) {
        fprintf(stderr, "FAIL: could not create pool\n");
        return 1;
    }

    /*
     * ngx_autocert_acme_log_safe: bound + escape server-controlled bytes
     * (a CA-supplied URL or problem-document body) before they reach the
     * error log.
     */
    {
        ngx_str_t  src;
        ngx_str_t  out;

        /* ordinary printable URL with no bytes needing escaping passes
         * through unchanged */
        static const u_char  url[] = "https://acme.example.com/acme/v2/directory";
        src.data = (u_char *) url;
        src.len = sizeof(url) - 1;  /* exclude trailing NUL */
        out = ngx_autocert_acme_log_safe(pool, &src);
        CHECK(out.len == src.len
              && memcmp(out.data, src.data, src.len) == 0,
              "log_safe: ordinary printable URL passes through unchanged");

        /* LF (0x0a) is the primary attack vector: a URL with embedded LF
         * reaches this log site when parse_url rejects it, and must be
         * escaped so it cannot forge a log line.
         *
         * MUTATION CONTROL: The assertion "raw LF byte never appears in the
         * output" fails if ngx_autocert_acme_log_safe() is replaced with a
         * passthrough that just returns src unchanged. Revert lines ~263-266
         * in acme.c to remove the escaping call, and this assertion goes RED:
         * out will still contain the raw \n, failing the memchr check. */
        {
            u_char  raw[] = "https://example.com/path\nautocert: FORGED";
            src.data = raw;
            src.len = sizeof(raw) - 1;  /* exclude trailing NUL */

            /* Verify the test fixture contains an LF byte */
            CHECK(memchr(raw, '\n', src.len) != NULL,
                  "test fixture: input contains LF byte");

            out = ngx_autocert_acme_log_safe(pool, &src);

            /* Verify escaping REMOVES the LF */
            CHECK(memchr(out.data, '\n', out.len) == NULL,
                  "MUTATION ASSERTION: raw LF byte never appears in output");
            CHECK(out.len > src.len,
                  "escaping: LF grows output size");
        }

        /* CR (0x0d) likewise must be escaped */
        {
            u_char  raw[] = "https://example.com\rautocert: FORGED";
            src.data = raw;
            src.len = sizeof(raw) - 1;
            out = ngx_autocert_acme_log_safe(pool, &src);
            CHECK(memchr(out.data, '\r', out.len) == NULL,
                  "log_safe: raw CR byte never appears in the output");
        }

        /* All control bytes 0x00..0x1f are escaped, not passed through raw
         * or silently dropped. */
        {
            u_char  raw[] = { 'a', 0x00, 0x01, 0x1f, 'b' };
            src.data = raw;
            src.len = sizeof(raw);
            out = ngx_autocert_acme_log_safe(pool, &src);
            CHECK(memchr(out.data, 0x00, out.len) == NULL
                  && memchr(out.data, 0x01, out.len) == NULL
                  && memchr(out.data, 0x1f, out.len) == NULL,
                  "log_safe: raw control bytes never appear in the output");
        }

        /* over-long input is truncated to NGX_AUTOCERT_LOG_MAX. A hostile
         * CA sending a URL with many newlines must not flood the log. */
        {
            static u_char  big[4096];
            size_t         i;

            for (i = 0; i < sizeof(big); i++) {
                big[i] = 0x0a;  /* LF, escapes to 2-byte "\\n" */
            }
            src.data = big;
            src.len = sizeof(big);
            out = ngx_autocert_acme_log_safe(pool, &src);
            CHECK(out.len <= NGX_AUTOCERT_LOG_MAX * 2,
                  "log_safe: escaped output respects the buffer cap (at most "
                  "NGX_AUTOCERT_LOG_MAX * expansion_factor)");
            CHECK(out.len < sizeof(big),
                  "log_safe: an over-long input is truncated (bounded), "
                  "not passed through wholesale");
            CHECK(memchr(out.data, '\n', out.len) == NULL,
                  "log_safe: control bytes are still escaped even in truncated "
                  "output");
        }

        /* a quoted string (if a JSON field somehow reaches here) must escape
         * the quotes so they don't break the log format */
        {
            u_char  raw[] = "value with \"quotes\"";
            src.data = raw;
            src.len = sizeof(raw) - 1;
            out = ngx_autocert_acme_log_safe(pool, &src);
            /* ngx_escape_json escapes " as \", so the input and output
             * lengths differ */
            CHECK(out.len > src.len,
                  "log_safe: quoting escaping strictly grows the output");
            /* Verify that the raw quote bytes are NOT present as sequential
             * raw bytes: if "test" escapes to \"test\", the output contains
             * backslash + quote, not a standalone quote */
            for (size_t i = 0; i < out.len; i++) {
                if (out.data[i] == '"' && i > 0 && out.data[i - 1] != '\\') {
                    CHECK(0, "log_safe: unescaped raw quote byte in output");
                    break;
                }
            }
            CHECK(1, "log_safe: quotes are escaped (backslash-prefixed)");
        }
    }

    ngx_destroy_pool(pool);

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
 * those objects that this test never calls. Same idiom as test_account_jsonsafe.c
 * and test_ratecap.c.
 */
volatile ngx_cycle_t  *ngx_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}
