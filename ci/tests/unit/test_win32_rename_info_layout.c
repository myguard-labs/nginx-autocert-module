/*
 * Unit test for the FILE_RENAME_INFORMATION / FILE_LINK_INFORMATION
 * variable-length-buffer layout arithmetic used by ngx_autocert_renameat2()
 * and ngx_autocert_linkat() in src/ngx_autocert_win32.h.
 *
 * The offset arithmetic itself lives in ONE place now:
 * NGX_AUTOCERT_FILE_NAME_INFO_OFF() in src/ngx_autocert_shared.h, which is
 * the SAME macro both win32.h functions call in production. This test
 * includes shared.h and asserts against that production symbol directly
 * (on the POSIX arm's ABI stand-in struct, ngx_autocert_test_rename_hdr_s,
 * which shared.h also defines with the exact win32 field widths) -- so a
 * revert of a win32.h call site back to `sizeof(*hdr)` does NOT get caught
 * here (this only tests the macro, not the call sites), but a revert of the
 * MACRO ITSELF back to `sizeof(hdr_type)` fails this test immediately,
 * because the macro is the single point both callers depend on. See the
 * mandatory negative control below and in the worker report for the
 * distinction: this closes the "test reimplements its subject" gap by
 * binding to the production definition instead of a hand-copied one.
 *
 * This test cannot include <windows.h> or call the real win32-only
 * functions (they need real HANDLEs, NtSetInformationFile, etc. and only
 * build under _WIN32) -- shared.h's POSIX arm already solves that: it
 * defines ngx_autocert_test_rename_hdr_s with stand-in types whose sizes
 * match the win32 ABI (BOOLEAN=1 byte, HANDLE=8 bytes as on LLP64/64-bit
 * Windows, ULONG=4 bytes) specifically so NGX_AUTOCERT_FILE_NAME_INFO_OFF()
 * is evaluable on Linux.
 *
 * Exit 0 = pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stddef.h>
#include <stdio.h>

#include "../../../src/ngx_autocert_shared.h"

/*
 * Link stubs: ngx_string.o (needed so this test links against the same
 * shared.h the production win32.h callers use) drags in refs to ngx_cycle /
 * ngx_log_error_core / ngx_pnalloc / ngx_alloc via ngx_sort/ngx_pstrdup,
 * which this test never calls. Same pattern as test_win32_split_root.c.
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

static int failures = 0;

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            failures++; \
        } \
    } while (0)

int
main(void)
{
    size_t  true_off, hdr_size;

#if NGX_WIN32
    /* On a real win32 build the macro is evaluated against the actual NT
     * struct tags declared in ngx_autocert_win32.h; this test binary only
     * builds standalone on POSIX (see ci/tests/unit/run.sh), so this arm
     * exists for completeness and is not exercised in CI. */
    true_off = NGX_AUTOCERT_FILE_NAME_INFO_OFF(
        struct ngx_autocert_rename_hdr_s);
    hdr_size = sizeof(struct ngx_autocert_rename_hdr_s);
#else
    /* Sanity: this ABI model needs a 4-byte ULONG and an 8-byte HANDLE for
     * the padding bug to reproduce at all; skip loudly rather than pass
     * vacuously if the toolchain ever disagrees. */
    if (sizeof(ngx_autocert_test_ulong_t) != 4) {
        fprintf(stderr,
            "SKIP: sizeof(ngx_autocert_test_ulong_t)=%zu != 4, layout model "
            "invalid on this toolchain\n", sizeof(ngx_autocert_test_ulong_t));
        return 0;
    }
    if (sizeof(ngx_autocert_test_handle_t) != 8) {
        fprintf(stderr,
            "SKIP: sizeof(ngx_autocert_test_handle_t)=%zu != 8, layout "
            "model invalid on this toolchain\n",
            sizeof(ngx_autocert_test_handle_t));
        return 0;
    }

    true_off = NGX_AUTOCERT_FILE_NAME_INFO_OFF(
        NGX_AUTOCERT_TEST_RENAME_HDR_T);
    hdr_size = sizeof(NGX_AUTOCERT_TEST_RENAME_HDR_T);
#endif

    /* The real on-the-wire offset: 0 (BOOLEAN) padded to 8 (HANDLE) = 8,
     * +8 (HANDLE) = 16, +4 (ULONG) = 20. */
    CHECK(true_off == 20,
        "NGX_AUTOCERT_FILE_NAME_INFO_OFF(...) != 20 -- production macro "
        "does not match the documented on-the-wire offset");

    /* The bug this test exists to catch: sizeof(struct) rounds up to the
     * HANDLE alignment (8), landing on 24 -- NOT the same as the true
     * offset. If a future compiler/ABI ever made these equal, the old
     * (buggy) code would accidentally be correct and this assertion
     * would need updating alongside it; today, on every ABI this module
     * targets, they must differ. */
    CHECK(hdr_size == 24, "sizeof(header struct) != 24 "
                           "(unexpected padding model for this ABI)");
    CHECK(true_off != hdr_size,
        "NGX_AUTOCERT_FILE_NAME_INFO_OFF(...) must NOT equal sizeof(hdr) -- "
        "this is the exact bug the macro exists to prevent: copying/sizing "
        "off sizeof(*hdr) instead of offsetof(FileNameLength)+sizeof(ULONG)");

    if (failures == 0) {
        printf("OK: all win32 rename/link layout tests passed\n");
        return 0;
    }

    fprintf(stderr, "%d test(s) failed\n", failures);
    return 1;
}
