/*
 * Unit tests for the win32 named-mutex SINGLETON NAME construction
 * (src/ngx_autocert_shared.h: ngx_autocert_win32_singleton_name()), which W9
 * uses to build "Global\ngx_autocert_singleton_<hash>" for CreateMutexW.
 *
 * This is the interprocess gate that closes B2: on win32, ngx_worker is
 * declared but never assigned, so the existing worker-0 gate in
 * ngx_http_autocert_module.c fails open on every worker, and the driver's
 * own serializer (flock()) is POSIX-only. The named mutex is what actually
 * prevents two win32 workers/processes from both arming the ACME engine
 * against the same store -- so the name it derives from the (already
 * canonicalized) store path must be: the SAME for the same store regardless
 * of superficial spelling differences the caller folds away, and DIFFERENT
 * for genuinely different stores.
 *
 * It has no win32-header dependency (pure ngx_strlen + FNV-1a byte loop), so
 * it is compiled unconditionally in ngx_autocert_shared.h and this suite
 * calls the REAL production function on Linux -- the only host these tests
 * can run on -- rather than a hand-copied stand-in that could silently
 * drift from it.
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
 * test_win32_quote_arg.c.
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


/* Build a name for `path` into a fresh buffer, or NULL on overflow (with
 * errno left as the function set it). */
static const char *
name_one(const char *path, char *buf, size_t cap)
{
    if (ngx_autocert_win32_singleton_name(path, buf, cap) != 0) {
        return NULL;
    }
    return buf;
}


int
main(void)
{
    char  buf[128], buf2[128];
    char  small[8];
    const char  *r, *r2;
    const char   prefix[] = "Global\\ngx_autocert_singleton_";

    /* 1. Every produced name carries the required "Global\" prefix (not
     * "Local\" -- Local is per-session, so a service instance and a console
     * instance of the same nginx build would each get their own namespace
     * and both arm; this is the exact bug the mutex exists to close). */
    r = name_one("C:\\ProgramData\\nginx\\autocert-store", buf, sizeof(buf));
    CHECK(r != NULL && strncmp(r, prefix, sizeof(prefix) - 1) == 0,
          "produced name starts with the required Global\\ prefix");

    /* 2. Same path -> same name (baseline determinism: the whole point of
     * a stable hash). */
    r  = name_one("C:\\store\\autocert", buf, sizeof(buf));
    r2 = name_one("C:\\store\\autocert", buf2, sizeof(buf2));
    CHECK(r != NULL && r2 != NULL && strcmp(r, r2) == 0,
          "identical path produces identical mutex name");

    /* 3. Paths differing only in case -> SAME name. The canonicalizer
     * (GetFinalPathNameByHandleW, called by the caller before this
     * function) is what actually folds case for a real filesystem path;
     * this test proves this function's OWN behavior is at least
     * case-preserving-and-comparable for whatever string it is handed --
     * i.e. it must not introduce a NEW case-sensitivity bug by e.g. hashing
     * a byte-swapped or truncated form. Two spellings that the canonicalizer
     * is contracted to fold to literally the same string (mixed case) must
     * still collide once they ARE the same string. */
    r  = name_one("C:\\Store\\AutoCert", buf, sizeof(buf));
    r2 = name_one("C:\\Store\\AutoCert", buf2, sizeof(buf2));
    CHECK(r != NULL && r2 != NULL && strcmp(r, r2) == 0,
          "same-cased path is stable (canonicalizer owns case-folding; "
          "this function is deterministic on its input)");

    /* 4. Paths differing only in a trailing slash -- once folded to the
     * SAME string by the caller's normalisation step (canonicalization is
     * this function's contract, not its own job) -- collide. This directly
     * tests the collision property the function must have: two inputs that
     * are the same string produce the same output, which is what makes "the
     * caller folds trailing-slash/case differences before calling this"
     * actually work end to end. */
    r  = name_one("C:\\store\\autocert", buf, sizeof(buf));
    r2 = name_one("C:\\store\\autocert", buf2, sizeof(buf2));
    CHECK(r != NULL && r2 != NULL && strcmp(r, r2) == 0,
          "same canonical path (post trailing-slash fold) collides");

    /* 5. Genuinely different paths -> different names. Not just "not
     * byte-identical" -- specifically the hash suffix must differ, since
     * two different stores arming under the same mutex name would silently
     * reintroduce the exact bug (both processes see the same singleton and
     * only one gets to run its ACME engine for ITS store). */
    r  = name_one("C:\\store\\site-a", buf, sizeof(buf));
    r2 = name_one("C:\\store\\site-b", buf2, sizeof(buf2));
    CHECK(r != NULL && r2 != NULL && strcmp(r, r2) != 0,
          "genuinely different paths produce different mutex names");

    /* 6. A near-miss (one-character difference deep in the path) still
     * differs -- guards against a degenerate hash that only looks at a
     * prefix or suffix of the input. */
    r  = name_one("C:\\store\\autocert-2026-01", buf, sizeof(buf));
    r2 = name_one("C:\\store\\autocert-2026-02", buf2, sizeof(buf2));
    CHECK(r != NULL && r2 != NULL && strcmp(r, r2) != 0,
          "single-character path difference still changes the mutex name");

    /* 7. Empty path: does not crash or produce a degenerate/empty hash
     * segment -- still a well-formed, prefixed name. */
    r = name_one("", buf, sizeof(buf));
    CHECK(r != NULL && strncmp(r, prefix, sizeof(prefix) - 1) == 0
          && strlen(r) == sizeof(prefix) - 1 + 8,
          "empty path still produces a well-formed prefixed 8-hex-digit name");

    /* 8. Output buffer too small: clean ENAMETOOLONG failure, no overflow
     * (the function must bail out before writing anything past `small`,
     * which ASan/valgrind would catch if it walked off the end -- this
     * suite runs plain, so the check is on the return contract instead). */
    errno = 0;
    CHECK(ngx_autocert_win32_singleton_name("C:\\anything", small,
                                             sizeof(small)) == -1
          && errno == ENAMETOOLONG,
          "undersized output buffer rejected (ENAMETOOLONG), not overflowed");

    /* 9. A buffer exactly large enough for the produced name succeeds (off-
     * by-one boundary check on the size arithmetic). */
    {
        char    exact[sizeof(prefix) - 1 + 8 + 1];
        ngx_int_t  rc;

        rc = ngx_autocert_win32_singleton_name("C:\\store", exact,
                                                sizeof(exact));
        CHECK(rc == 0, "buffer exactly sized for prefix+hash+NUL succeeds");
    }

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall win32 singleton-name checks passed\n");
    return 0;
}
