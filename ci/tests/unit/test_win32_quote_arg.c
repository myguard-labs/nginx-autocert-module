/*
 * Unit tests for the win32 COMMAND-LINE QUOTING function
 * (src/ngx_autocert_shared.h: ngx_autocert_win32_quote_arg()), which W8 uses
 * to build the CreateProcessW lpCommandLine string for the dns-01 operator
 * hook. CreateProcessW takes one flat command-line string, not an argv array
 * (unlike execve), so quoting is the injection surface: getting it wrong
 * lets a crafted domain/TXT value break out of its argument.
 *
 * The function implements the CommandLineToArgvW quoting rules (the same
 * parser the CRT/CreateProcessW child uses to split the string back apart):
 *   - wrap each argument in double quotes
 *   - a run of backslashes doubles ONLY when immediately followed by a
 *     quote (an embedded '"' or the closing quote this function appends);
 *     otherwise backslashes pass through literally
 *   - an embedded '"' becomes '\"'
 *
 * It has no win32-header dependency (pure ngx_strlen + byte loop), so it is
 * compiled unconditionally in ngx_autocert_shared.h and this suite calls the
 * REAL production function on Linux -- the only host these tests can run on
 * -- rather than a hand-copied stand-in that could silently drift from it.
 *
 * Exit 0 = all pass; non-zero on first failure count.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../../../src/ngx_autocert_shared.h"


/*
 * Link stubs: ngx_string.o (for ngx_strlen, what the function under test
 * actually calls) drags in refs this test never exercises. Same pattern as
 * test_win32_split_root.c.
 */
volatile ngx_cycle_t  *ngx_cycle;

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...);
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{ (void) level; (void) log; (void) err; (void) fmt; }

void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{ (void) pool; (void) size; return NULL; }

void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_alloc(size_t size, ngx_log_t *log)
{ (void) size; (void) log; return NULL; }


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


/* Quote a single arg into a fresh buffer starting at offset 0, return the
 * string (or NULL on overflow, with errno left as the function set it). */
static const char *
quote_one(const char *arg, char *buf, size_t cap)
{
    ngx_int_t  rc;

    rc = ngx_autocert_win32_quote_arg(arg, buf, cap, 0);
    if (rc < 0) {
        return NULL;
    }
    return buf;
}


int
main(void)
{
    char  buf[512];
    char  small[4];
    const char  *r;
    ngx_int_t    rc, off;

    /* 1. Plain argument, no special characters: still quoted (matches
     * CreateProcessW convention of always wrapping, which is always safe
     * to parse back). */
    r = quote_one("hook.sh", buf, sizeof(buf));
    CHECK(r != NULL && strcmp(r, " \"hook.sh\"") == 0,
          "plain arg wrapped in quotes with leading space");

    /* 2. Argument containing a space: quoting is what keeps it one arg. */
    r = quote_one("C:\\Program Files\\hook.exe", buf, sizeof(buf));
    CHECK(r != NULL
          && strcmp(r, " \"C:\\Program Files\\hook.exe\"") == 0,
          "arg with a space: backslashes not before a quote pass through "
          "literally");

    /* 3. Embedded double quote: becomes \" -- this is the injection case:
     * an attacker-controlled TXT/domain value containing '"' must not be
     * able to close the argument early. */
    r = quote_one("a\"b", buf, sizeof(buf));
    CHECK(r != NULL && strcmp(r, " \"a\\\"b\"") == 0,
          "embedded \\\" escaped so it cannot close the argument early");

    /* 4. Trailing backslash: doubles because it sits immediately before the
     * closing quote this function appends (else the closing quote would be
     * read as escaped, unterminating the argument). */
    r = quote_one("C:\\certs\\", buf, sizeof(buf));
    CHECK(r != NULL && strcmp(r, " \"C:\\certs\\\\\"") == 0,
          "trailing backslash doubled before the closing quote");

    /* 5. Backslash immediately before an embedded quote: doubles, then the
     * quote is escaped -- two independent rules compounding on one byte. */
    r = quote_one("a\\\"b", buf, sizeof(buf));
    CHECK(r != NULL && strcmp(r, " \"a\\\\\\\"b\"") == 0,
          "backslash-before-quote: backslash doubles, quote escapes");

    /* 6. Run of backslashes with no following quote or end-of-string quote
     * boundary except the final closing quote: ALL of them double, since
     * they are (transitively) immediately before the appended closing
     * quote. */
    r = quote_one("\\\\\\", buf, sizeof(buf));
    CHECK(r != NULL && strcmp(r, " \"\\\\\\\\\\\\\"") == 0,
          "run of backslashes at end-of-arg all double before closing quote");

    /* 7. Empty argument: still produces a quoted empty string, not a
     * zero-length token the child would see as no argument at all. */
    r = quote_one("", buf, sizeof(buf));
    CHECK(r != NULL && strcmp(r, " \"\"") == 0,
          "empty argument becomes a quoted empty string \"\"");

    /* 8. Concatenation: two calls appending into the same buffer at
     * successive offsets build one lpCommandLine, each argument separated
     * by exactly one leading space. */
    off = ngx_autocert_win32_quote_arg("hook.exe", buf, sizeof(buf), 0);
    CHECK(off > 0, "first quote_arg call succeeds");
    off = ngx_autocert_win32_quote_arg("_acme-challenge.example.com", buf,
                                        sizeof(buf), (size_t) off);
    CHECK(off > 0, "second quote_arg call appends at the returned offset");
    CHECK(strcmp(buf, " \"hook.exe\" \"_acme-challenge.example.com\"") == 0,
          "two args concatenate into one space-separated command line");

    /* 9. Overflow: a buffer too small for the worst-case bound is rejected
     * with ENAMETOOLONG, not silently truncated (a truncated command line
     * would run a hook with a mangled/missing argument). */
    errno = 0;
    rc = ngx_autocert_win32_quote_arg("this is too long for a tiny buffer",
                                       small, sizeof(small), 0);
    CHECK(rc == -1 && errno == ENAMETOOLONG,
          "oversized argument rejected (ENAMETOOLONG), not truncated");

    /* 10. Overflow at a nonzero offset (simulating the second arg in a
     * concatenation overflowing what's left of the buffer). */
    {
        char  tight[16];

        off = ngx_autocert_win32_quote_arg("hook", tight, sizeof(tight), 0);
        CHECK(off > 0, "first arg fits in the tight buffer");
        errno = 0;
        rc = ngx_autocert_win32_quote_arg("second-argument-too-long", tight,
                                           sizeof(tight), (size_t) off);
        CHECK(rc == -1 && errno == ENAMETOOLONG,
              "second arg overflowing remaining space rejected "
              "(ENAMETOOLONG)");
    }

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall win32 quote-arg checks passed\n");
    return 0;
}
