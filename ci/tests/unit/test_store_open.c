/*
 * Unit tests for GETTING A CERTIFICATE FROM THE STORE
 * (src/ngx_autocert_shared.h: ngx_autocert_open_file_path /
 * ngx_autocert_open_dir_path).
 *
 * At every TLS handshake the serve path reads the leaf cert out of the on-disk
 * store: ngx_http_autocert_cache_reload() builds <store>/<host>/fullchain.pem
 * and hands the string to ngx_autocert_open_file_path() to open it. The store
 * is worker-owned, but the threat model assumes a HOSTILE filesystem underneath
 * it (a co-tenant or a compromised renewal tool that can plant symlinks in the
 * store dir). A plain open(path, O_NOFOLLOW) protects only the LEAF; an attacker
 * who symlinks an ANCESTOR component (e.g. <store>/<host> -> /etc) would still
 * redirect the read. ngx_autocert_open_file_path() defends against this by
 * pinning EVERY path component with openat(O_NOFOLLOW) before opening the leaf.
 *
 * These tests plant real symlinks / traversal in a temp store and assert:
 *   - a legitimate stored cert opens and reads back byte-identically (the happy
 *     "get the cert" path),
 *   - a symlinked leaf is refused (O_NOFOLLOW on the final open),
 *   - a symlinked ANCESTOR directory is refused (per-component pin — the bug a
 *     single O_NOFOLLOW open would miss),
 *   - "." / ".." / empty leaves are rejected up front (EINVAL),
 *   - an absent cert fails with ENOENT (a missing name is a skip, not a crash),
 *   - a NULL / empty path is rejected (EINVAL).
 *
 * Exit 0 = all pass; non-zero on first failure count.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../../src/ngx_autocert_shared.h"


static int   failures;
static char  store[] = "/tmp/ac-store-XXXXXX";

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


static const char  CERT_BODY[] =
    "-----BEGIN CERTIFICATE-----\nNOT-A-REAL-CERT-just-bytes\n"
    "-----END CERTIFICATE-----\n";


/* Write `body` to `path`, creating it fresh. Returns 0 on success. */
static int
write_file(const char *path, const char *body)
{
    int      fd;
    ssize_t  n;
    size_t   len = strlen(body);

    (void) unlink(path);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        return -1;
    }
    n = write(fd, body, len);
    (void) close(fd);
    return (n == (ssize_t) len) ? 0 : -1;
}


/* Open `path` via the module's fd-pinned helper and read it back into buf.
 * Returns the byte count read, or -1 on open failure (errno preserved). */
static ssize_t
open_and_read(const char *path, char *buf, size_t cap)
{
    int      fd;
    ssize_t  n;

    fd = ngx_autocert_open_file_path(path, O_RDONLY);
    if (fd == -1) {
        return -1;
    }
    n = read(fd, buf, cap);
    (void) close(fd);
    return n;
}


int
main(void)
{
    char  hostdir[512], leaf[1024], buf[256];
    ssize_t n;
    int   fd;

    if (mkdtemp(store) == NULL) {
        perror("mkdtemp");
        return 2;
    }

    /* Build a legitimate store entry: <store>/example.com/fullchain.pem */
    snprintf(hostdir, sizeof(hostdir), "%s/example.com", store);
    if (mkdir(hostdir, 0755) == -1) {
        perror("mkdir hostdir");
        return 2;
    }
    snprintf(leaf, sizeof(leaf), "%s/fullchain.pem", hostdir);
    if (write_file(leaf, CERT_BODY) != 0) {
        perror("write leaf");
        return 2;
    }

    /* 1. Happy path: the stored cert opens and reads back byte-identically. */
    memset(buf, 0, sizeof(buf));
    n = open_and_read(leaf, buf, sizeof(buf) - 1);
    CHECK(n == (ssize_t) strlen(CERT_BODY)
          && memcmp(buf, CERT_BODY, strlen(CERT_BODY)) == 0,
          "legitimate stored fullchain.pem opens and reads back verbatim");

    /* 2. Symlinked LEAF is refused (final open is O_NOFOLLOW). Point the leaf
     * name at a secret outside the store; the helper must not follow it. */
    if (write_file("/tmp/ac-store-secret", "SECRET\n") != 0) {
        perror("write secret");
        return 2;
    }
    snprintf(leaf, sizeof(leaf), "%s/evil-leaf.pem", hostdir);
    (void) unlink(leaf);
    if (symlink("/tmp/ac-store-secret", leaf) == -1) {
        perror("symlink leaf");
        return 2;
    }
    errno = 0;
    fd = ngx_autocert_open_file_path(leaf, O_RDONLY);
    CHECK(fd == -1 && errno == ELOOP,
          "symlinked leaf refused with ELOOP (O_NOFOLLOW on final open)");
    if (fd != -1) {
        (void) close(fd);
    }

    /* 3. Symlinked ANCESTOR directory is refused (per-component pin). This is
     * the bug a single open(path, O_NOFOLLOW) would MISS: the leaf itself is a
     * real file, but its parent dir is a symlink out of the store. */
    {
        char evildir[1024], evilleaf[1024], real_target[512];

        /* a real dir with a real fullchain.pem, outside the intended host dir */
        snprintf(real_target, sizeof(real_target), "%s/elsewhere", store);
        if (mkdir(real_target, 0755) == -1) {
            perror("mkdir elsewhere");
            return 2;
        }
        snprintf(evilleaf, sizeof(evilleaf), "%s/fullchain.pem", real_target);
        if (write_file(evilleaf, "ELSEWHERE\n") != 0) {
            perror("write elsewhere leaf");
            return 2;
        }
        /* <store>/hijack -> <store>/elsewhere (an ancestor symlink) */
        snprintf(evildir, sizeof(evildir), "%s/hijack", store);
        (void) unlink(evildir);
        if (symlink(real_target, evildir) == -1) {
            perror("symlink dir");
            return 2;
        }
        /* opening <store>/hijack/fullchain.pem must refuse: the ancestor is a
         * symlink, so open_dir_path's O_NOFOLLOW openat rejects it. */
        snprintf(evilleaf, sizeof(evilleaf), "%s/hijack/fullchain.pem", store);
        errno = 0;
        fd = ngx_autocert_open_file_path(evilleaf, O_RDONLY);
        /* O_NOFOLLOW|O_DIRECTORY on a symlinked component yields ENOTDIR on
         * Linux (the symlink is not itself a directory); ELOOP on kernels that
         * report the un-followed link. Either way the open is refused. */
        CHECK(fd == -1 && (errno == ENOTDIR || errno == ELOOP),
              "symlinked ancestor dir refused (per-component pin)");
        if (fd != -1) {
            (void) close(fd);
        }
    }

    /* 4. Dot / dotdot / trailing-slash leaves are rejected up front (EINVAL),
     * never turned into a directory open. */
    {
        char p[1024];

        snprintf(p, sizeof(p), "%s/example.com/..", store);
        errno = 0;
        fd = ngx_autocert_open_file_path(p, O_RDONLY);
        CHECK(fd == -1 && errno == EINVAL, "\"..\" leaf rejected (EINVAL)");
        if (fd != -1) { (void) close(fd); }

        snprintf(p, sizeof(p), "%s/example.com/.", store);
        errno = 0;
        fd = ngx_autocert_open_file_path(p, O_RDONLY);
        CHECK(fd == -1 && errno == EINVAL, "\".\" leaf rejected (EINVAL)");
        if (fd != -1) { (void) close(fd); }
    }

    /* 5. Absent cert: a name with no stored file fails with ENOENT (the serve
     * path treats this as "this variant not on disk -> skip", not a crash). */
    {
        char p[1024];

        snprintf(p, sizeof(p), "%s/no-such-host.example/fullchain.pem", store);
        errno = 0;
        fd = ngx_autocert_open_file_path(p, O_RDONLY);
        CHECK(fd == -1 && errno == ENOENT,
              "absent stored cert fails with ENOENT");
        if (fd != -1) { (void) close(fd); }
    }

    /* 6. NULL / empty path rejected (EINVAL) — defensive input guard. */
    errno = 0;
    fd = ngx_autocert_open_file_path(NULL, O_RDONLY);
    CHECK(fd == -1 && errno == EINVAL, "NULL path rejected (EINVAL)");
    if (fd != -1) { (void) close(fd); }

    errno = 0;
    fd = ngx_autocert_open_file_path("", O_RDONLY);
    CHECK(fd == -1 && errno == EINVAL, "empty path rejected (EINVAL)");
    if (fd != -1) { (void) close(fd); }

    /* Best-effort cleanup (temp dir; leave it if a step already bailed). */
    (void) unlink("/tmp/ac-store-secret");

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall store-open checks passed\n");
    return 0;
}
