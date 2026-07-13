/*
 * Unit tests for ngx_autocert_ratecap.h (autolabel A3.4) — the pure rate-cap and
 * wildcard-cover primitives factored out of the driver so they can be tested
 * without the whole driver TU. No slab / nginx runtime needed; just the nginx
 * string/type headers pulled by ngx_core.h via test_slab.h.
 *
 * Verifies:
 *   - window_count: empty ring = 0; entries inside the window count, entries
 *     older than the window do not; a zero slot is never counted
 *   - ring_push: wraps at n, overwrites the oldest slot, advances head
 *   - name_covers: exact (case-insensitive) match; "*.suffix" covers exactly one
 *     extra label; does NOT cover two labels deep, the bare apex, a different
 *     suffix, or a bare "*." ; a non-wildcard never matches a deeper host
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include "../../src/ngx_autocert_ratecap.h"

#include <stdio.h>


/*
 * Link stubs: ngx_string.o (for ngx_strncasecmp/ngx_strlchr) drags in refs to
 * ngx_cycle / ngx_log_error_core / ngx_pnalloc via ngx_sort/ngx_pstrdup, which
 * this test never calls. Provide trivial stubs so the object links standalone
 * without pulling ngx_alloc/ngx_log/ngx_palloc.
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


static ngx_uint_t
covers(const char *name, const char *host)
{
    return ngx_autocert_name_covers((const u_char *) name, ngx_strlen(name),
                                    (const u_char *) host, ngx_strlen(host));
}


int
main(void)
{
    time_t      now = 1000000;
    time_t      window = 100;

    /* --- window_count --- */
    {
        time_t  ring[4] = { 0, 0, 0, 0 };

        CHECK(ngx_autocert_rt_window_count(ring, 4, now, window) == 0,
              "window_count: empty ring is 0");

        ring[0] = now;              /* in window */
        ring[1] = now - 50;         /* in window */
        ring[2] = now - window;     /* exactly at edge: NOT > now-window */
        ring[3] = now - window - 1; /* outside */
        CHECK(ngx_autocert_rt_window_count(ring, 4, now, window) == 2,
              "window_count: only entries strictly inside the window count");

        ring[2] = 0;                /* a zero slot must never count */
        CHECK(ngx_autocert_rt_window_count(ring, 4, now, window) == 2,
              "window_count: zero slot ignored");
    }

    /* --- ring_push wraps and overwrites oldest --- */
    {
        time_t      ring[3] = { 0, 0, 0 };
        ngx_uint_t  head = 0;

        ngx_autocert_rt_ring_push(ring, 3, &head, 10);
        ngx_autocert_rt_ring_push(ring, 3, &head, 20);
        ngx_autocert_rt_ring_push(ring, 3, &head, 30);
        CHECK(head == 0, "ring_push: head wraps to 0 after n pushes");
        CHECK(ring[0] == 10 && ring[1] == 20 && ring[2] == 30,
              "ring_push: fills all slots in order");

        ngx_autocert_rt_ring_push(ring, 3, &head, 40);   /* overwrite oldest */
        CHECK(ring[0] == 40 && head == 1,
              "ring_push: wraps and overwrites the oldest slot");
    }

    /* --- window_oldest --- */
    {
        time_t  ring[4] = { 0, 0, 0, 0 };

        CHECK(ngx_autocert_rt_window_oldest(ring, 4, now, window) == 0,
              "window_oldest: empty ring is 0");

        ring[0] = now - 10;
        ring[1] = now - 90;         /* in window, oldest */
        ring[2] = now - 200;        /* outside window: ignored */
        ring[3] = now - 30;
        CHECK(ngx_autocert_rt_window_oldest(ring, 4, now, window) == now - 90,
              "window_oldest: returns oldest IN-window timestamp");
    }

    /* --- name_covers: exact --- */
    CHECK(covers("example.com", "example.com"), "covers: exact match");
    CHECK(covers("Example.COM", "example.com"), "covers: exact case-insensitive");
    CHECK(!covers("example.com", "example.org"), "covers: exact rejects other");
    CHECK(!covers("example.com", "foo.example.com"),
          "covers: non-wildcard does not cover a deeper host");

    /* --- name_covers: wildcard --- */
    CHECK(covers("*.example.com", "foo.example.com"),
          "covers: wildcard covers one extra label");
    CHECK(covers("*.example.com", "FOO.Example.com"),
          "covers: wildcard is case-insensitive");
    CHECK(!covers("*.example.com", "a.b.example.com"),
          "covers: wildcard does NOT cover two labels deep");
    CHECK(!covers("*.example.com", "example.com"),
          "covers: wildcard does NOT cover the bare apex");
    CHECK(!covers("*.example.com", "foo.example.org"),
          "covers: wildcard rejects a different suffix");
    CHECK(!covers("*.example.com", "fooexample.com"),
          "covers: wildcard requires a real label boundary");
    CHECK(!covers("*.", "foo.bar"), "covers: bare '*.' matches nothing");
    CHECK(!covers("*.com", "com"), "covers: '*.com' does not cover bare 'com'");

    if (failures) {
        fprintf(stderr, "\n%d FAILURE(S)\n", failures);
        return 1;
    }
    fprintf(stderr, "\nALL PASS\n");
    return 0;
}
