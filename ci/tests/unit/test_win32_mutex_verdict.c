/*
 * Unit tests for the win32 WaitForSingleObject() result -> singleton-
 * acquisition VERDICT mapping (src/ngx_autocert_shared.h:
 * ngx_autocert_win32_mutex_wait_verdict()), the decision core of the W9
 * named-mutex interprocess ACME driver gate (DESIGN-win32-store-io.md § W2).
 *
 * This is the exact rule a plausible win32 port gets backwards: WAIT_ABANDONED
 * means a PRIOR HOLDER exited (crashed, was killed, whatever) WITHOUT
 * releasing the mutex -- but the kernel has already transferred ownership to
 * the caller of WaitForSingleObject. That is ACQUISITION SUCCESS, not an
 * error. Treating WAIT_ABANDONED as failure means no worker ever acquires the
 * singleton again after one crash, silently and permanently stopping
 * certificate issuance/renewal for that store -- a production outage with no
 * compiler diagnostic and no obvious symptom until certs start expiring.
 *
 * The function takes a plain uint32_t (not DWORD) specifically so it has no
 * win32-header dependency and this suite can call the REAL production
 * function on Linux -- the only host these tests can run on. The four named
 * constants it switches on (NGX_AUTOCERT_WAIT_OBJECT_0/ABANDONED/TIMEOUT/
 * FAILED, defined alongside it in ngx_autocert_shared.h) are numerically
 * identical to the real WinBase.h WAIT_* macros, so this test exercises the
 * exact codepath a win32 build takes with WaitForSingleObject()'s real
 * return value passed straight through.
 *
 * Exit 0 = all pass; non-zero on first failure count.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>
#include <stdio.h>

#include "../../../src/ngx_autocert_shared.h"


/* Link stubs: ngx_string.o is not even linked for this test (the function
 * under test is a bare switch, no string/pool calls), but ngx_core.h still
 * expects ngx_cycle to exist for anything that pulls in ngx_log.h macros. */
volatile ngx_cycle_t  *ngx_cycle;


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
    ngx_int_t  rc;

    /* 1. WAIT_OBJECT_0: clean, uncontended acquisition -> NGX_OK. */
    rc = ngx_autocert_win32_mutex_wait_verdict(NGX_AUTOCERT_WAIT_OBJECT_0);
    CHECK(rc == NGX_OK, "WAIT_OBJECT_0 -> NGX_OK (acquired)");

    /* 2. WAIT_ABANDONED: THE rule this test exists to pin. A prior holder
     * died holding the mutex; the kernel transfers ownership to us. This
     * MUST be NGX_OK, exactly like WAIT_OBJECT_0 -- not NGX_ERROR, not
     * NGX_AGAIN. Getting this backwards is the single most consequential
     * mistake in this whole item: it silently and permanently disables
     * issuance after any worker crash while holding the lock. */
    rc = ngx_autocert_win32_mutex_wait_verdict(NGX_AUTOCERT_WAIT_ABANDONED);
    CHECK(rc == NGX_OK,
          "WAIT_ABANDONED -> NGX_OK (ownership transferred; NOT an error)");

    /* 3. WAIT_TIMEOUT: another process currently holds it. Must map to
     * NGX_AGAIN specifically (not NGX_ERROR) so the caller falls into the
     * SAME relock-timer retry the POSIX flock()/EAGAIN path already uses --
     * this is the whole point of mirroring the POSIX contract, per the
     * design doc's "reuse it, do not add a new timer" instruction. */
    rc = ngx_autocert_win32_mutex_wait_verdict(NGX_AUTOCERT_WAIT_TIMEOUT);
    CHECK(rc == NGX_AGAIN,
          "WAIT_TIMEOUT -> NGX_AGAIN (contended; retry via relock timer)");

    /* 4. WAIT_FAILED: hard OS-level failure -> NGX_ERROR, distinct from both
     * "acquired" and "contended" so the caller logs it as a real failure
     * rather than silently retrying forever or silently treating it as
     * armed. */
    rc = ngx_autocert_win32_mutex_wait_verdict(NGX_AUTOCERT_WAIT_FAILED);
    CHECK(rc == NGX_ERROR, "WAIT_FAILED -> NGX_ERROR (hard failure)");

    /* 5. An unrecognised code (defensive: anything WinBase.h might ever add,
     * or a corrupted value) must NOT be silently treated as success -- fail
     * closed to NGX_ERROR rather than fail open and arm two processes. */
    rc = ngx_autocert_win32_mutex_wait_verdict((uint32_t) 0x12345678u);
    CHECK(rc == NGX_ERROR,
          "unrecognised wait code -> NGX_ERROR (fail closed, never silently "
          "treated as acquired)");

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall win32 mutex-wait-verdict checks passed\n");
    return 0;
}
