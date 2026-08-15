/*
 * Unit tests for the win32 ROOT-SPLITTING classifier
 * (src/ngx_autocert_shared.h: ngx_autocert_win32_classify_root(), the pure
 * path-syntax half of ngx_autocert_split_root()).
 *
 * W5g replaced the raw open("/")/open(".") bootstrap at the top of
 * ngx_autocert_open_dir_path() with ngx_autocert_split_root(), which must
 * also work on win32 where paths can be drive-absolute (C:\...), UNC
 * (\\server\share\...), or drive-relative (\... or C:foo -- both rejected,
 * since guessing the current drive is not this module's job). The NT-open
 * half of the win32 body (ngx_autocert_win32_ntopen) needs real Windows
 * headers and cannot run here; the classifier has NO win32-header
 * dependency at all (ngx_strlen/ngx_strlchr/ngx_snprintf are pure
 * nginx-core string routines), so it is compiled unconditionally in
 * ngx_autocert_shared.h specifically so this suite can call the REAL
 * production function on Linux -- the only host these tests can run on --
 * rather than a hand-copied stand-in that could silently drift from it.
 *
 * These tests assert, for each recognised root form:
 *   - drive-absolute, both separators (C:/... and C:\...), case-insensitive
 *   - UNC, both separators (//server/share/... and \\server\share\...)
 *   - relative (no root marker)
 *   - the two EINVAL rejects: drive-relative leading slash (/foo, \foo) and
 *     drive-relative-no-separator (C:foo)
 *   - \-to-/ normalisation happens BEFORE the walk would see "..", so a
 *     "..\" component is caught the same as "../" (checked indirectly here:
 *     *rest always comes back /-separated even when the input used \)
 *
 * Exit 0 = all pass; non-zero on first failure count.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "../../../src/ngx_autocert_shared.h"


/*
 * Link stubs: ngx_string.o (for ngx_snprintf/ngx_strlchr, what the classifier
 * under test actually calls) drags in refs to ngx_cycle / ngx_log_error_core /
 * ngx_pnalloc via ngx_sort/ngx_pstrdup, which this test never calls. Same
 * pattern as test_ratecap.c -- trivial stubs so the object links standalone
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

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


/* Run the classifier and report root/rest for readable CHECK() failures. */
static int
classify(const char *path, char *root, size_t root_cap, const char **rest)
{
    static char  norm[NGX_MAX_PATH];

    errno = 0;
    return ngx_autocert_win32_classify_root(path, norm, sizeof(norm),
                                             root, root_cap, rest);
}


int
main(void)
{
    char         root[NGX_MAX_PATH];
    const char  *rest;
    int          rc;

    /* The config-time DNS-hook predicate shares this exact win32 path
     * grammar. Its native smoke test below covers the NGX_WIN32 arm; these
     * calls pin the POSIX contract that must remain unchanged. */
    {
        ngx_str_t  posix_absolute = ngx_string("/hooks/add");
        ngx_str_t  posix_relative = ngx_string("hooks/add");

        CHECK(ngx_autocert_dns_hook_path_is_absolute(&posix_absolute),
              "POSIX DNS hook accepts /-absolute path");
        CHECK(!ngx_autocert_dns_hook_path_is_absolute(&posix_relative),
              "POSIX DNS hook rejects relative path");
    }

    /* 1. Drive-absolute, forward slash. */
    rc = classify("C:/certs/store", root, sizeof(root), &rest);
    CHECK(rc == 0 && strcmp(root, "\\??\\C:\\") == 0
          && strcmp(rest, "certs/store") == 0,
          "C:/... -> root \\??\\C:\\, rest \"certs/store\"");

    /* 2. Drive-absolute, backslash -- must normalise to the same result. */
    rc = classify("C:\\certs\\store", root, sizeof(root), &rest);
    CHECK(rc == 0 && strcmp(root, "\\??\\C:\\") == 0
          && strcmp(rest, "certs/store") == 0,
          "C:\\... -> root \\??\\C:\\, rest \"certs/store\" (normalised)");

    /* 3. Drive-absolute, lowercase drive letter -- case-insensitive. */
    rc = classify("d:\\data", root, sizeof(root), &rest);
    CHECK(rc == 0 && strcmp(root, "\\??\\d:\\") == 0
          && strcmp(rest, "data") == 0,
          "lowercase drive letter accepted (d:\\...)");

    /* 4. Drive-absolute, bare drive root, no trailing component. */
    rc = classify("C:/", root, sizeof(root), &rest);
    CHECK(rc == 0 && strcmp(root, "\\??\\C:\\") == 0 && strcmp(rest, "") == 0,
          "bare C:/ -> root \\??\\C:\\, empty rest");

    /* 5. UNC, forward slashes. */
    rc = classify("//srv/share/certs", root, sizeof(root), &rest);
    CHECK(rc == 0 && strcmp(root, "\\??\\UNC\\srv\\share\\") == 0
          && strcmp(rest, "certs") == 0,
          "//server/share/... -> root \\??\\UNC\\srv\\share\\, rest \"certs\"");

    /* 6. UNC, backslashes -- must normalise identically to #5. */
    rc = classify("\\\\srv\\share\\certs", root, sizeof(root), &rest);
    CHECK(rc == 0 && strcmp(root, "\\??\\UNC\\srv\\share\\") == 0
          && strcmp(rest, "certs") == 0,
          "\\\\server\\share\\... -> same root/rest as forward-slash UNC");

    /* 7. UNC, share with no trailing component. */
    rc = classify("//srv/share", root, sizeof(root), &rest);
    CHECK(rc == 0 && strcmp(root, "\\??\\UNC\\srv\\share\\") == 0
          && strcmp(rest, "") == 0,
          "//server/share (no trailing component) -> empty rest");

    /* 8. UNC with an empty share ("//srv//x") is EINVAL, not a zero-length
     * share silently accepted. */
    rc = classify("//srv//x", root, sizeof(root), &rest);
    CHECK(rc == -1 && errno == EINVAL,
          "UNC with empty share segment rejected (EINVAL)");

    /* 9. UNC with no share at all ("//srv") is EINVAL. */
    rc = classify("//srv", root, sizeof(root), &rest);
    CHECK(rc == -1 && errno == EINVAL,
          "UNC missing the share entirely rejected (EINVAL)");

    /* 10. Relative path: no root marker at all. */
    rc = classify("certs/store", root, sizeof(root), &rest);
    CHECK(rc == 0 && strcmp(root, ".") == 0
          && strcmp(rest, "certs/store") == 0,
          "relative path -> root \".\", rest unchanged");

    /* 11. Relative path using backslashes -- normalised for the walk even
     * though there is no root to strip. */
    rc = classify("certs\\store", root, sizeof(root), &rest);
    CHECK(rc == 0 && strcmp(root, ".") == 0
          && strcmp(rest, "certs/store") == 0,
          "relative path with \\ separators normalised to /");

    /* 12. EINVAL reject: drive-relative, leading forward slash, no drive. */
    rc = classify("/certs/store", root, sizeof(root), &rest);
    CHECK(rc == -1 && errno == EINVAL,
          "leading / with no drive rejected (EINVAL, no current-drive guess)");

    /* 13. EINVAL reject: drive-relative, leading backslash, no drive. */
    rc = classify("\\certs\\store", root, sizeof(root), &rest);
    CHECK(rc == -1 && errno == EINVAL,
          "leading \\ with no drive rejected (EINVAL, no current-drive guess)");

    /* 14. EINVAL reject: "C:foo" -- drive letter with no separator after
     * the colon is drive-relative to C:'s current directory, which this
     * module refuses to guess. */
    rc = classify("C:foo", root, sizeof(root), &rest);
    CHECK(rc == -1 && errno == EINVAL,
          "\"C:foo\" (no separator after colon) rejected (EINVAL)");

    /* 15. EINVAL reject: "C:" alone -- same drive-relative case, empty
     * tail. */
    rc = classify("C:", root, sizeof(root), &rest);
    CHECK(rc == -1 && errno == EINVAL,
          "\"C:\" alone rejected (EINVAL)");

    /* 16. A single letter that looks like it could start a drive spec but
     * isn't followed by ':' is just a relative path component. */
    rc = classify("C", root, sizeof(root), &rest);
    CHECK(rc == 0 && strcmp(root, ".") == 0 && strcmp(rest, "C") == 0,
          "bare \"C\" (no colon) treated as an ordinary relative path");

    /* 17. Oversized input is rejected before any classification, not
     * silently truncated. */
    {
        char  huge[NGX_MAX_PATH + 16];

        memset(huge, 'a', sizeof(huge) - 1);
        huge[sizeof(huge) - 1] = '\0';
        rc = classify(huge, root, sizeof(root), &rest);
        CHECK(rc == -1 && errno == ENAMETOOLONG,
              "oversized path rejected (ENAMETOOLONG), not truncated");
    }

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall win32 split-root checks passed\n");
    return 0;
}
