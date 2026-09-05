/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for ngx_autocert_slot_fresh() (ngx_autocert_serve.c, audit
 * MINOR): the cert-cache freshness predicate widened from mtime-only to
 * mtime + size + inode/file-id (ngx_file_uniq_t), plus the paired
 * NGX_AUTOCERT_UNIQ_NEVER_LOADED "never loaded" sentinel.
 *
 * Before the fix, ngx_http_autocert_cache_reload() compared mtime alone
 * (whole-second time_t). Two writes inside the same second, or an atomic
 * rename that lands a different file with a coincidentally equal mtime, left
 * a STALE certificate served: mtime matched, so the reload was skipped.
 *
 * The function is static, so this TU slices JUST it (plus the slot struct
 * and sentinel it depends on) from the shipped src/ngx_autocert_serve.c via
 * ci/tests/unit/extract_slotfresh.sh -- the whole .c is the SSL cert_cb +
 * PEM-parse reload path and would drag in ngx_http_ssl_module.h /
 * ngx_http_v2_module.h / ngx_http_v3.h plus OpenSSL linking to reach one
 * three-field comparison. Locked to production code, no copy drift.
 *
 * ngx_autocert_fstat() (ngx_autocert_shared.h) is exercised for real against
 * temp files, so the ngx_autocert_stat_t values fed to the predicate are
 * genuine kernel-reported mtime/size/inode, not hand-constructed fixtures.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/x509.h>
#include <openssl/evp.h>

#include "src/ngx_autocert_shared.h" /* ngx_autocert_stat_t */

#include "generated_slotfresh.inc"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>


/* Trivial stub -- ngx_log_error() on ngx_autocert_shared.h's failure paths
 * needs this to resolve; this TU never triggers those paths for real. */
volatile ngx_cycle_t  *ngx_cycle;

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...);
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{ (void) level; (void) log; (void) err; (void) fmt; }


static int      failures;
static char     base[] = "/tmp/ac-slotfresh-XXXXXX";

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


static int
write_file(const char *path, const char *content, struct timeval tv)
{
    int             fd;
    size_t          len = strlen(content);
    struct timeval  times[2];

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        return -1;
    }
    if (write(fd, content, len) != (ssize_t) len) {
        close(fd);
        return -1;
    }
    close(fd);

    times[0] = tv;
    times[1] = tv;
    return utimes(path, times);
}


static int
stat_file(const char *path, ngx_autocert_stat_t *st)
{
    int  fd, rc;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        return -1;
    }
    rc = ngx_autocert_fstat(fd, st);
    close(fd);
    return rc;
}


int
main(void)
{
    char                 pa[64], pb[64];
    ngx_autocert_stat_t  sta, stb;
    ngx_autocert_slot_t  sl;
    struct timeval       same_tv;

    if (mkdtemp(base) == NULL) {
        fprintf(stderr, "mkdtemp failed\n");
        return 2;
    }

    same_tv.tv_sec = 1700000000;   /* fixed whole-second mtime for both */
    same_tv.tv_usec = 0;

    snprintf(pa, sizeof(pa), "%s/a", base);
    snprintf(pb, sizeof(pb), "%s/b", base);

    /* --- two DIFFERENT files, same size, same whole-second mtime, but
     * necessarily different inodes (two distinct creat()s) -- the exact
     * "atomic rename lands a coincidentally-equal-mtime file" and "two
     * writes inside one second" traps named in the audit finding. --- */
    if (write_file(pa, "AAAA", same_tv) != 0
        || write_file(pb, "BBBB", same_tv) != 0)
    {
        fprintf(stderr, "setup: could not write fixture files\n");
        return 2;
    }
    if (stat_file(pa, &sta) != 0 || stat_file(pb, &stb) != 0) {
        fprintf(stderr, "setup: could not fstat fixture files\n");
        return 2;
    }

    CHECK(sta.st_mtime == stb.st_mtime,
          "fixture: both files share the same whole-second mtime");
    CHECK(sta.st_size == stb.st_size,
          "fixture: both files share the same size (4 bytes)");
    CHECK(sta.st_ino != stb.st_ino,
          "fixture: two distinct files have distinct inodes");

    /* The slot cached file A's key; file B is a DIFFERENT file that landed
     * with an equal mtime and equal size -- the widened key must still
     * detect the swap via inode, where the old mtime-only key would not. */
    memset(&sl, 0, sizeof(sl));
    sl.mtime = sta.st_mtime;
    sl.size = sta.st_size;
    sl.uniq = sta.st_ino;

    CHECK(ngx_autocert_slot_fresh(&sl, &sta) == 1,
          "slot fresh against the SAME file it was loaded from");
    CHECK(ngx_autocert_slot_fresh(&sl, &stb) == 0,
          "slot STALE against a different file with equal mtime+size "
          "(inode differs) -- this is the bug the fix closes");

    /* Same idea, but the two files differ in SIZE (not inode) while keeping
     * the same mtime -- a same-second edit that changed content length. */
    {
        ngx_autocert_stat_t  st_short, st_long;
        char                 ps[64], pl[64];

        snprintf(ps, sizeof(ps), "%s/short", base);
        snprintf(pl, sizeof(pl), "%s/long", base);

        if (write_file(ps, "X", same_tv) != 0
            || write_file(pl, "XXXXXXXXXX", same_tv) != 0
            || stat_file(ps, &st_short) != 0
            || stat_file(pl, &st_long) != 0)
        {
            fprintf(stderr, "setup: size-fixture failed\n");
            return 2;
        }

        CHECK(st_short.st_mtime == st_long.st_mtime,
              "size fixture: same whole-second mtime");
        CHECK(st_short.st_size != st_long.st_size,
              "size fixture: different sizes");

        memset(&sl, 0, sizeof(sl));
        sl.mtime = st_short.st_mtime;
        sl.size = st_short.st_size;
        sl.uniq = st_short.st_ino;

        CHECK(ngx_autocert_slot_fresh(&sl, &st_long) == 0,
              "slot STALE when only size changed at an equal mtime");
    }

    /* mtime alone changing (the pre-existing, always-worked case) must still
     * be caught -- the widened key must not regress the original behavior. */
    {
        ngx_autocert_stat_t  st_new;
        struct timeval       later_tv = same_tv;

        later_tv.tv_sec += 5;
        if (write_file(pa, "AAAA", later_tv) != 0
            || stat_file(pa, &st_new) != 0)
        {
            fprintf(stderr, "setup: mtime-bump fixture failed\n");
            return 2;
        }

        memset(&sl, 0, sizeof(sl));
        sl.mtime = sta.st_mtime;
        sl.size = sta.st_size;
        sl.uniq = sta.st_ino;

        CHECK(st_new.st_mtime != sta.st_mtime,
              "mtime fixture: rewrite advanced mtime");
        CHECK(ngx_autocert_slot_fresh(&sl, &st_new) == 0,
              "slot STALE when only mtime changed (regression guard)");
    }

    /* --- the "never loaded" sentinel must force a first load: it must not
     * equal any real file's fstat'd st_ino, so a freshly zero/sentinel-
     * initialized slot never reports "fresh" against a real file. --- */
    {
        ngx_autocert_stat_t  st_real;

        if (stat_file(pa, &st_real) != 0) {
            fprintf(stderr, "setup: sentinel fixture failed\n");
            return 2;
        }

        CHECK((ngx_file_uniq_t) st_real.st_ino
                  != NGX_AUTOCERT_UNIQ_NEVER_LOADED,
              "sentinel: a real file's inode never collides with the "
              "never-loaded sentinel");

        memset(&sl, 0, sizeof(sl));
        sl.mtime = -1;
        sl.uniq = NGX_AUTOCERT_UNIQ_NEVER_LOADED;
        /* sl.size left 0 by memset -- the never-loaded state ngx_pcalloc
         * produces, mirrored here without needing a real ngx_pool_t. */

        CHECK(ngx_autocert_slot_fresh(&sl, &st_real) == 0,
              "never-loaded sentinel forces a first load against a real "
              "file (mtime=-1 union uniq=NEVER_LOADED never matches)");
    }

    unlink(pa);
    unlink(pb);
    {
        char ps[64], pl[64];
        snprintf(ps, sizeof(ps), "%s/short", base);
        snprintf(pl, sizeof(pl), "%s/long", base);
        unlink(ps);
        unlink(pl);
    }
    rmdir(base);

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
