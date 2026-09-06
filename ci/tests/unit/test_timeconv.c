/*
 * Unit tests for ngx_autocert_timeconv.h -- the pure seconds->ms clamp
 * factored out of ngx_autocert_driver.c's resolver_timeout assignment so it
 * can be tested without the whole driver TU. No slab / nginx runtime needed;
 * just the nginx string/type headers pulled by ngx_core.h via test_slab.h.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include "../../../src/ngx_autocert_timeconv.h"

#include <stdio.h>


/*
 * Link stubs: ngx_string.o (for ngx_strncasecmp/ngx_strlchr et al pulled in
 * transitively through ngx_core.h) drags in refs to ngx_cycle /
 * ngx_log_error_core / ngx_pnalloc via ngx_sort/ngx_pstrdup, which this test
 * never calls. Provide trivial stubs so the object links standalone without
 * pulling ngx_alloc/ngx_log/ngx_palloc. Same idiom as test_ratecap.c.
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

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL: %s\n", msg);                                \
            failures++;                                                        \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                                \
        }                                                                     \
    } while (0)


int
main(void)
{
    CHECK(ngx_autocert_sec_to_msec_clamped(0) == 0,
          "0s converts to 0ms");

    CHECK(ngx_autocert_sec_to_msec_clamped(3600) == (ngx_msec_t) 3600000,
          "3600s (the cap) converts cleanly to 3600000ms");

    CHECK(ngx_autocert_sec_to_msec_clamped(3601) == (ngx_msec_t) 3600000,
          "3601s (first value past the cap) clamps to 3600000ms");

    /* One below the cap, to pin the boundary is exactly at 3600, not off
     * by one in either direction. */
    CHECK(ngx_autocert_sec_to_msec_clamped(3599) == (ngx_msec_t) 3599000,
          "3599s converts cleanly to 3599000ms");

    CHECK(ngx_autocert_sec_to_msec_clamped(-1) == 0,
          "-1s clamps to 0ms");

    CHECK(ngx_autocert_sec_to_msec_clamped((time_t) -3600) == 0,
          "large negative value clamps to 0ms");

    /*
     * The historical driver.c defect: ngx_parse_time() accepts any value up
     * to NGX_MAX_INT_T_VALUE (e.g. a bare-digit "autocert_resolver_timeout"
     * with no unit suffix is seconds with no further limit), so a configured
     * value near the top of time_t's range must clamp exactly like any other
     * out-of-range value -- not overflow the multiply.
     */
    CHECK(ngx_autocert_sec_to_msec_clamped(
              (time_t) NGX_MAX_INT_T_VALUE) == (ngx_msec_t) 3600000,
          "near-time_t-max value clamps to 3600000ms instead of overflowing");

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }

    fprintf(stderr, "all checks passed\n");
    return 0;
}
