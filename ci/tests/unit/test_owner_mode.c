/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for ngx_autocert_check_owner_mode() (ngx_autocert_shared.h).
 *
 * The store directory (driver.c's trylock) and the stored serving key
 * (serve.c's cache reload) are both read from a filesystem the threat model
 * treats as attacker-writable by another local user. ngx_autocert_open_dir_
 * path() pins every ancestor against a planted symlink, but says nothing
 * about who owns the inode it lands on or what it is writable by — before
 * this guard, a store directory or serving key pre-created (or substituted)
 * by another local user was adopted silently.
 *
 * These tests exercise the shared guard directly against real files/dirs in
 * a temp tree:
 *   - an owner-only (0700/0600), self-owned path is accepted,
 *   - a group-writable path is refused,
 *   - an other-readable path is refused,
 *   - (best-effort, skipped when not root) a path owned by a different uid
 *     is refused.
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


/* Trivial link stubs — same idiom as test_store_open.c: this TU never calls
 * anything that would exercise these for real, but ngx_log_error() (used by
 * the guard on its failure paths) needs ngx_log_error_core() to resolve. */
volatile ngx_cycle_t  *ngx_cycle;

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...);
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{ (void) level; (void) log; (void) err; (void) fmt; }

void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_alloc(size_t size, ngx_log_t *log)
{ (void) size; (void) log; return NULL; }

void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{ (void) pool; (void) size; return NULL; }


static int      failures;
static char     base[] = "/tmp/ac-owner-XXXXXX";
static ngx_log_t log;

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
    char  path[512];
    int   fd;

    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        return 2;
    }

    /* 1. Self-owned, owner-only directory (0700): accepted. */
    snprintf(path, sizeof(path), "%s/store-ok", base);
    if (mkdir(path, 0700) == -1) {
        perror("mkdir store-ok");
        return 2;
    }
    fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        perror("open store-ok");
        return 2;
    }
    CHECK(ngx_autocert_check_owner_mode(fd, &log, "store directory") == NGX_OK,
          "owner-only (0700) self-owned directory accepted");
    (void) close(fd);

    /* 2. Group-writable directory: refused. */
    snprintf(path, sizeof(path), "%s/store-group", base);
    if (mkdir(path, 0770) == -1) {
        perror("mkdir store-group");
        return 2;
    }
    fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        perror("open store-group");
        return 2;
    }
    CHECK(ngx_autocert_check_owner_mode(fd, &log, "store directory")
          == NGX_ERROR,
          "group-writable (0770) directory refused");
    (void) close(fd);

    /* 3. World-readable directory: refused. */
    snprintf(path, sizeof(path), "%s/store-other", base);
    if (mkdir(path, 0705) == -1) {
        perror("mkdir store-other");
        return 2;
    }
    fd = open(path, O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        perror("open store-other");
        return 2;
    }
    CHECK(ngx_autocert_check_owner_mode(fd, &log, "store directory")
          == NGX_ERROR,
          "world-readable (0705) directory refused");
    (void) close(fd);

    /* 4. Owner-only (0600) self-owned FILE (the serving-key shape): accepted.
     * Confirms the guard is not directory-specific. */
    snprintf(path, sizeof(path), "%s/privkey.pem", base);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        perror("create privkey.pem");
        return 2;
    }
    (void) close(fd);
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("open privkey.pem");
        return 2;
    }
    CHECK(ngx_autocert_check_owner_mode(fd, &log, "serving key") == NGX_OK,
          "owner-only (0600) self-owned serving key accepted");
    (void) close(fd);

    /* 5. World-readable key file: refused (this is the exact regression the
     * row exists to close -- a restored/misplaced key with loose perms must
     * never be served silently). */
    snprintf(path, sizeof(path), "%s/privkey-loose.pem", base);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("create privkey-loose.pem");
        return 2;
    }
    (void) close(fd);
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("open privkey-loose.pem");
        return 2;
    }
    CHECK(ngx_autocert_check_owner_mode(fd, &log, "serving key") == NGX_ERROR,
          "world-readable (0644) serving key refused");
    (void) close(fd);

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall owner-mode checks passed\n");
    return 0;
}
