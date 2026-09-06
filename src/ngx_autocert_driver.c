/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * ngx_autocert_driver — the ACME engine driver, run on worker 0.
 *
 * The ACME state machine (account bootstrap, order flow, renewal scheduler) is
 * process-agnostic: it only needs an nginx event loop, a cycle->log, and the
 * outbound TLS client. Rather than run it in a privileged master-spawned helper
 * (the old M4a model, which alone caused the cold-crash problem and was the
 * outlier vs angie's native acme and the official Rust nginx-acme — both drive
 * ACME from worker 0), it is armed from the http module's init_process, gated
 * to worker 0 (or single-process mode). The store dir and account.key are
 * therefore written by the worker user.
 *
 *   - ngx_autocert_driver_init_process() arms the one-shot kick timer (which
 *     builds the client + bootstraps the account, then arms the renewal
 *     scheduler). It runs inside the worker's normal event loop, so no signal
 *     setup, listening-socket close, or channel plumbing is needed — the worker
 *     already did all of that.
 *   - ngx_autocert_driver_exit_process() tears the engine state down on worker
 *     exit (frees the account, in-flight order, and outbound client).
 *
 * Engine TUs (account.c / order.c / acme.c / json.c / challenge.c / alpn.c) are
 * reused unchanged; only the driving process moved.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#if !(NGX_WIN32)
#include <sys/stat.h>          /* mkdirat(2) — M3 per-CA account dirs */
#endif
#include <fcntl.h>             /* openat/AT_* — M3 atomic key migration */
#include <errno.h>             /* EINVAL/ENOTTY/EOPNOTSUPP for renameat2 */

#if !(NGX_WIN32)
#include <sys/file.h>          /* flock(2) — interprocess singleton gate */
#include <unistd.h>            /* close(2), renameat(2) */
#include <dirent.h>            /* A6: opendir/readdir the store container */
#endif

/*
 * M3: migrate the legacy account key with RENAME_NOREPLACE so it can never
 * clobber a key that appeared at the destination after our absence check
 * (renameat2 is Linux 3.15+; called via syscall() to avoid a glibc wrapper
 * dependency, with a plain rename() fallback on ENOSYS/EINVAL — mirrors the
 * RENAME_EXCHANGE use in ngx_autocert_order.c).
 */
#if defined(__linux__)
#include <sys/syscall.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#endif

#include "ngx_autocert_account.h"
#include "ngx_autocert_acme.h"
#include "ngx_autocert_alpn.h"
#include "ngx_autocert_challenge.h"
#include "ngx_autocert_driver.h"
#include "ngx_autocert_order.h"
#include "ngx_autocert_ratecap.h"  /* A3.4: rate-cap + wildcard-cover pures */
#include "ngx_autocert_requests.h" /* A3.3: runtime request drain/set_state */
#include "ngx_autocert_shared.h"
#include "ngx_http_autocert_conf.h" /* store-layout enum */
#include "ngx_http_autocert_crypto.h"

#define NGX_AUTOCERT_KICK         500     /* ms; defer first ACME fetch */
#define NGX_AUTOCERT_RELOCK                                                    \
    5000 /* ms; retry the singleton lock so the                                \
          * surviving worker 0 takes over after a                              \
          * reload/USR2 retires the prior holder */
#define NGX_AUTOCERT_KICK_RETRY   30000   /* ms; re-kick after a transient
                                           * bootstrap failure (client build /
                                           * OOM / register start) so the driver
                                           * doesn't sit idle until reload */
#define NGX_AUTOCERT_HTTP_TIMEOUT 30000   /* ms; per-request transport timeout \
                                           */

/*
 * A6: marker filename dropped beside a runtime cert's fullchain so the driver
 * can rebuild the requests shm zone from disk after a real process restart
 * (fresh shm, unlike a single-process reload which inherits the old segment).
 * Leading dot keeps it out of any directory listing a store tool might do.
 *
 * NGX_AUTOCERT_RUNTIME_MARKER and its open-flag contract
 * (NGX_AUTOCERT_MARKER_OPEN_WRITE / _READ) are defined once in
 * ngx_autocert_shared.h so ci/tests/unit/test_marker_open.c shares the exact
 * same flags this file uses, instead of keeping its own copy that could
 * silently drift from production.
 */


/*
 * M5 per-name failure backoff slot. Defined up here (was below the scheduler
 * section) because each CA's state now carries its own per-name backoff array.
 */
typedef struct {
    time_t      next_eligible;   /* don't retry before this (0 = ready) */
    ngx_uint_t  fails;           /* consecutive failures */
} ngx_autocert_backoff_t;


/*
 * M5 multi-engine driver: one ACME engine per distinct CA the instance issues
 * against (ngx_autocert_conf.ca_list, an ngx_autocert_ca_entry_t array grouped
 * by effective CA at postconfig). Each CA gets its own outbound client, its own
 * registered account (with that CA's directory URL + EAB), and its own per-name
 * backoff array. A SINGLE order is in flight across all CAs at any time
 * (ngx_autocert_order below) and the renewal scheduler walks CAs × names with a
 * (ca, name) cursor, so the ACME flows never overlap. Account bootstrap is
 * SEQUENTIAL: CA[i]'s registration terminal starts CA[i+1]'s; when the last
 * account is live (or skipped) the scheduler is armed.
 */
typedef struct {
    ngx_autocert_ca_entry_t *entry; /* &ca_list[i]: ca_conf,names,hash,key */
    ngx_autocert_acme_client_t   client;       /* per-CA outbound client */
    ngx_uint_t                   client_ready;
    ngx_autocert_account_t      *account;      /* per-CA registered account */
    ngx_pool_t                  *account_pool;
    ngx_uint_t                   account_live;  /* registration succeeded */
    /* Dual-cert: one backoff slot per (name, keytype). Flat array sized
     * names*backoff_nkt; slot index = name_i*backoff_nkt + kt_i. */
    ngx_autocert_backoff_t      *backoff;
    ngx_uint_t                   backoff_n;     /* total slots (names*nkt) */
    ngx_uint_t                   backoff_nkt;   /* keytypes per name (stride) */
} ngx_autocert_ca_state_t;


static void ngx_autocert_kick_handler(ngx_event_t *ev);
static ngx_int_t ngx_autocert_driver_trylock(ngx_cycle_t *cycle);
static void ngx_autocert_relock_handler(ngx_event_t *ev);
static void ngx_autocert_account_done(ngx_autocert_account_t *acct,
    ngx_int_t rc);
static void ngx_autocert_bootstrap_ca(ngx_cycle_t *cycle, ngx_uint_t ca_idx);
static void ngx_autocert_start_order(ngx_cycle_t *cycle);
static void ngx_autocert_order_complete(ngx_autocert_order_t *order,
    ngx_int_t rc);
static void ngx_autocert_runtime_marker_remove(ngx_cycle_t *cycle,
    ngx_autocert_conf_t *acf, ngx_str_t *host);
static void ngx_autocert_runtime_marker_write(ngx_cycle_t *cycle,
    ngx_autocert_conf_t *acf, ngx_str_t *host);
static void ngx_autocert_runtime_seed(ngx_cycle_t *cycle);


/*
 * The per-CA engines (clients + accounts + backoff), allocated once from the
 * cycle pool at the first kick, one entry per ca_list CA. NULL until the kick
 * builds them.
 */
static ngx_autocert_ca_state_t     *ngx_autocert_ca_states;
static ngx_uint_t                   ngx_autocert_ca_states_n;
static ngx_cycle_t                 *ngx_autocert_cycle; /* for account_done */

/*
 * A single ACME order is in flight at a time across every CA — serialised by
 * the scheduler's (ca, name) cursor. The order carries its CA's account +
 * directory URL, so one global order slot suffices.
 */
static ngx_autocert_order_t        *ngx_autocert_order;
static ngx_pool_t                  *ngx_autocert_order_pool;
static ngx_uint_t                   ngx_autocert_test_seeded;
static ngx_uint_t                   ngx_autocert_test_alpn_seeded;
static ngx_uint_t                   ngx_autocert_test_runtime_seeded;
static ngx_event_t                  ngx_autocert_kick_timer;

/*
 * Interprocess singleton gate. The ACME engine must drive from EXACTLY ONE
 * process, but `ngx_worker == 0` alone only picks one worker PER GENERATION:
 * across a graceful reload or USR2 hot upgrade the retiring worker 0 and the
 * fresh worker 0 overlap, and both would otherwise arm the engine and race the
 * same account nonce / submit duplicate CA orders. An flock(LOCK_EX) on a lock
 * file in the store dir serializes them: only the lock holder arms the engine.
 * The kernel drops the lock when the holder exits (clean or crash), and the
 * loser retries on a slow timer so the survivor takes over with no gap.
 */
/*
 * A CRT/POSIX int fd, not ngx_fd_t: it is assigned from
 * ngx_autocert_openat_mode() (the int-returning pinned-open helper), passed
 * to flock(), and closed via ngx_autocert_close(). ngx_fd_t is HANDLE on
 * win32 (see os/win32/ngx_files.h); using it here would mean assigning a CRT
 * int into a HANDLE-typed variable and later CloseHandle()'ing it, both
 * wrong. int keeps this variable coherent with the shim family it is
 * actually built on.
 */
static int                          ngx_autocert_lock_fd = -1;
static ngx_event_t                  ngx_autocert_relock_timer;

#if (NGX_WIN32)
/*
 * W9 — win32 named-mutex singleton handle. Process-lifetime: opened at most
 * once by ngx_autocert_win32_driver_trylock() below, closed only in
 * ngx_autocert_driver_exit_process(). NEVER closed/reopened per relock tick —
 * that would open a window where two workers could both hold it briefly.
 */
static HANDLE                       ngx_autocert_win32_mutex = NULL;
#endif



/* ngx_autocert_renameat2() is shared via ngx_autocert_shared.h — used by both
 * the account-key migration here and the store commit in order.c, so the two
 * security-sensitive fd-pinned renames can never drift. */


/*
 * M3 (TOCTOU-hardened): mkdir a 0700 sub-directory <leaf> inside the pinned
 * parent dir fd, tolerating an existing real directory (EEXIST) but rejecting a
 * planted symlink/non-dir. Returns an fd for the resulting directory (opened
 * NOFOLLOW so a swapped <leaf> cannot redirect it), or -1 on failure. The leaf
 * is a single path component, so it cannot itself traverse; pinning the parent
 * inode means a swap of an ancestor component cannot redirect the mkdir/open.
 */
static int
ngx_autocert_mkdirat_secure(ngx_cycle_t *cycle, int pfd, const char *leaf)
{
    int                   fd;
    ngx_autocert_stat_t   st;

    if ( ngx_autocert_mkdirat( pfd, leaf, 0700 ) == -1 &&
         ngx_errno != NGX_EEXIST ) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: mkdir(\"%s\") failed", leaf);
        return -1;
    }

    fd = ngx_autocert_openat( pfd, leaf,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC );
    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: \"%s\" is not a directory", leaf);
        return -1;
    }
    if (ngx_autocert_fstat(fd, &st) == -1 || !S_ISDIR(st.st_mode)) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: \"%s\" is not a directory", leaf);
        (void) ngx_autocert_close(fd);
        return -1;
    }
    return fd;
}

/*
 * M3/M5: ensure the per-CA account dir <path>/accounts/<ca_hash>/ exists (0700)
 * and migrate the legacy flat <path>/account.key into it ONCE (rename only if
 * the new key is absent and the old one is present). `ca` is the ca_list entry
 * this engine drives. Returns the per-CA key path (aliases the config-pool
 * string ca->account_key_path), or NULL on a hard failure.
 *
 * M5: the legacy-flat migration only makes sense for the PRIMARY CA (the one a
 * single-CA deploy used). `migrate` gates it so the second+ CA never tries to
 * rename the one shared flat key into its own dir (it would migrate to the
 * wrong CA's account dir, or — once the primary already took it — find it
 * absent and silently generate a fresh per-CA key, which is the correct
 * behavior anyway).
 */
static u_char *
ngx_autocert_prepare_account_key(ngx_cycle_t *cycle, ngx_autocert_conf_t *acf,
    ngx_autocert_ca_entry_t *ca, ngx_uint_t migrate, ngx_pool_t *pool)
{
    u_char                   *key_path, *base, *p;
    int                       bfd, accfd, cafd;
    ngx_autocert_stat_t       st;
    char                      hash[NGX_AUTOCERT_CA_HASH_HEX + 1];

    key_path = ca->account_key_path.data; /* config pool; outlives worker */

    /* Pin the base store dir <path> (created during driver lock acquire).
     * NOFOLLOW: <path> itself must not be a planted symlink. All sub-dir
     * creation + the migration rename are *at()-relative to fds derived here.
     */
    base = ngx_pnalloc(pool, acf->path.len + 1);
    if (base == NULL) {
        return NULL;
    }
    p = ngx_cpymem(base, acf->path.data, acf->path.len);
    *p = '\0';

    bfd = ngx_autocert_open_dir_path((char *) base, 0, 0);
    if (bfd == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: open store dir \"%s\" failed", base);
        return NULL;
    }

    /* <path>/accounts then <path>/accounts/<ca_hash>, each pinned NOFOLLOW. */
    accfd = ngx_autocert_mkdirat_secure(cycle, bfd, "accounts");
    if (accfd == -1) {
        (void) ngx_autocert_close(bfd);
        return NULL;
    }

    ngx_memcpy(hash, ca->ca_hash, NGX_AUTOCERT_CA_HASH_HEX);
    hash[NGX_AUTOCERT_CA_HASH_HEX] = '\0';

    cafd = ngx_autocert_mkdirat_secure(cycle, accfd, hash);
    (void) ngx_autocert_close(accfd);
    if (cafd == -1) {
        (void) ngx_autocert_close(bfd);
        return NULL;
    }

    /* One-time migration of the legacy flat key — PRIMARY CA only (M5). A
     * single-CA deploy's flat <path>/account.key belongs to the first CA; a
     * second CA must not claim it. */
    if (!migrate) {
        (void) ngx_autocert_close(cafd);
        (void) ngx_autocert_close(bfd);
        return key_path;
    }

    /* Migrate <path>/account.key -> <path>/accounts/<ca_hash>/account.key,
     * both relative to pinned dir fds. RENAME_NOREPLACE never clobbers a key
     * that raced into the destination after our absence check. */
    if ( ngx_autocert_fstatat( cafd, "account.key", &st,
                               AT_SYMLINK_NOFOLLOW ) == -1 ) {
        if (ngx_errno != NGX_ENOENT) {
            /* unknown error — do NOT treat as "absent" and migrate over it */
            ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                          "autocert: stat(\"%s\") failed; skipping account-key "
                          "migration", key_path);

        } else if ( ngx_autocert_fstatat( bfd, "account.key", &st,
                                          AT_SYMLINK_NOFOLLOW ) == 0 ) {
            /* new key absent + legacy key present: migrate atomically, once. */
            ngx_int_t  rc;

            rc = ngx_autocert_renameat2(bfd, "account.key", cafd, "account.key",
                                        RENAME_NOREPLACE);

            if (rc == NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                              "autocert: migrated account key -> \"%s\"",
                              key_path);

            } else if (rc == NGX_DECLINED) {
                /* No RENAME_NOREPLACE on this kernel/fs. We do NOT fall back to
                 * a plain renameat() — without the flag a destination that
                 * raced in after the fstatat would be clobbered. Skip the
                 * migration; a fresh per-CA key is generated at key_path
                 * instead (correct, and the legacy flat key is left untouched).
                 * renameat2 is Linux 3.15+ so this is effectively unreachable
                 * in practice. */
                ngx_log_error(
                    NGX_LOG_WARN, cycle->log, 0,
                    "autocert: RENAME_NOREPLACE unsupported; skipping "
                    "account-key migration (fresh key generated)" );

            } else if (ngx_errno == NGX_EEXIST) {
                /* a key raced into the destination — already migrated; fine */

            } else {
                /* non-fatal: a fresh per-CA key is generated at key_path */
                ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                              "autocert: account key migration rename failed "
                              "(-> \"%s\")", key_path);
            }
        }
    }

    (void) ngx_autocert_close(cafd);
    (void) ngx_autocert_close(bfd);
    return key_path;
}


/*
 * One-shot startup kick: build the outbound client (TLS trust + resolver from
 * the HTTP config) on first fire, then GET the CA directory to prove the
 * transport end to end. Failures are logged, not fatal -- the driver keeps
 * running so the ACME flow (M4c+) can retry.
 */
static void
ngx_autocert_kick_handler(ngx_event_t *ev)
{
    ngx_cycle_t              *cycle = ev->data;
    ngx_autocert_conf_t       acf;
    ngx_int_t                 ensure_rc;

    if (ngx_quit || ngx_terminate || ngx_exiting) {
        return;
    }

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK || !acf.configured) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: no http{} autocert config; driver idle");
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "autocert: kick config CAs:%ui names:%ui challenge:%ui",
                   acf.ca_list ? acf.ca_list->nelts : 0,
                   acf.names ? acf.names->nelts : 0,
                   (ngx_uint_t) acf.challenge);

    /* TEST-ONLY: seed the configured challenge into the shared store once, so
     * the :80 serve path can be exercised before the order flow exists. */
    if (!ngx_autocert_test_seeded
        && acf.challenge_zone != NULL && acf.test_token.len != 0)
    {
        ngx_autocert_test_seeded = 1;
        if (ngx_autocert_challenge_set(acf.challenge_zone, &acf.test_token,
                                       &acf.test_keyauth)
            == NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "autocert: seeded test challenge token \"%V\"",
                          &acf.test_token);
        } else {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: failed to seed test challenge token");
        }
    }

    /* TEST-ONLY (M10b): build the tls-alpn-01 challenge cert for the configured
     * domain once and seed it into the ALPN store, so the worker's ALPN serve
     * path can be exercised before the order wiring (M10c) exists. */
    if (!ngx_autocert_test_alpn_seeded
        && acf.alpn_zone != NULL && acf.test_alpn_domain.len != 0)
    {
        EVP_PKEY    *akey;
        X509        *acert;
        ngx_pool_t  *atmp;
        ngx_str_t    acert_pem, akey_pem;

        ngx_autocert_test_alpn_seeded = 1;

        atmp = ngx_create_pool(4096, cycle->log);
        /* Ephemeral tls-alpn-01 challenge cert: always EC, independent of the
         * configured certificate key type. */
        akey = ngx_http_autocert_key_generate(NGX_HTTP_AUTOCERT_KEY_P384);
        acert = NULL;

        if (atmp != NULL && akey != NULL) {
            acert = ngx_http_autocert_acme_tls_cert(akey,
                        &acf.test_alpn_domain, &acf.test_alpn_keyauth);
        }

        if (acert != NULL
            && ngx_http_autocert_cert_to_pem(atmp, acert, &acert_pem) == NGX_OK
            && ngx_http_autocert_key_to_pem(atmp, akey, &akey_pem) == NGX_OK
            && ngx_autocert_alpn_set(acf.alpn_zone, &acf.test_alpn_domain,
                                     &acert_pem, &akey_pem) == NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "autocert: seeded test tls-alpn-01 cert for \"%V\"",
                          &acf.test_alpn_domain);
        } else {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: failed to seed test tls-alpn-01 cert");
        }

        if (acert != NULL) {
            X509_free(acert);
        }
        if (akey != NULL) {
            ngx_http_autocert_key_free(akey);
        }
        if (atmp != NULL) {
            ngx_destroy_pool(atmp);
        }
    }

    /* TEST-ONLY (autolabel C): seed a single host into requests_zone as
     * REQUESTED once, via the SAME ngx_autocert_requests_ensure() path a real
     * consumer module (label-autoconf) would use. Lets the Pebble e2e drive
     * the full runtime-issuance lifecycle (drain/order -> serve -> persist)
     * without a real consumer. set_state() forces REQUESTED even if ensure()
     * found an existing node (e.g. re-seeded from the A6 disk marker on a
     * fresh worker), so the test always gets a fresh order. */
    if (!ngx_autocert_test_runtime_seeded
        && acf.requests_zone != NULL && acf.test_runtime_host.len != 0)
    {
        ngx_autocert_test_runtime_seeded = 1;
        ensure_rc = ngx_autocert_requests_ensure(acf.requests_zone,
                                                  &acf.test_runtime_host);

        if (ensure_rc != NGX_AUTOCERT_REQ_UNKNOWN
            && ensure_rc != NGX_AUTOCERT_REQ_DENIED
            && ngx_autocert_requests_set_state(acf.requests_zone,
                                                &acf.test_runtime_host,
                                                NGX_AUTOCERT_REQ_REQUESTED, 0)
               == NGX_OK)
        {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "autocert: seeded test runtime request \"%V\"",
                          &acf.test_runtime_host);
        } else {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: failed to seed test runtime request "
                          "\"%V\"", &acf.test_runtime_host);
        }
    }

    /*
     * M4 (Codex #4) / M5: nothing to issue under => do NOT build any ACME
     * client or bootstrap any account.
     *
     * The gate is ca_list ALONE (autolabel C). It used to also require
     * names->nelts != 0, which made a runtime-only deployment — a label-driven
     * gateway with regex/catch-all vhosts and zero config names — go
     * permanently idle: no account, so a runtime name drained from
     * requests_zone had nothing to order under. postconfig now materializes a
     * CA group for the effective CA of an enabled vhost even when it collected
     * no names, so an empty ca_list really does mean "autocert is enabled
     * nowhere".
     *
     * A CA group with an empty name list is fine here: the renewal scheduler
     * skips it (it iterates entry->names), while the runtime drain path orders
     * by drained host, not from the group's name list. The test seeds above are
     * intentionally exempt (they exercise the serve path without an order
     * flow).
     */
    if (acf.ca_list == NULL || acf.ca_list->nelts == 0) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: not enabled on any server; driver idle "
                      "(no account)");
        return;
    }

    /* Build the per-CA engine array once (idempotent across kick retries). */
    if (ngx_autocert_ca_states == NULL) {
        ngx_autocert_ca_entry_t  *entries = acf.ca_list->elts;
        ngx_uint_t                n = acf.ca_list->nelts;
        ngx_uint_t                i;

        if (n > NGX_MAX_SIZE_T_VALUE / sizeof(ngx_autocert_ca_state_t)) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: implausible CA count");
            return;
        }

        ngx_autocert_ca_states = ngx_pcalloc(cycle->pool,
            n * sizeof(ngx_autocert_ca_state_t));
        if (ngx_autocert_ca_states == NULL) {
            ngx_add_timer(ev, NGX_AUTOCERT_KICK_RETRY);
            return;
        }
        for (i = 0; i < n; i++) {
            ngx_autocert_ca_states[i].entry = &entries[i];
        }
        ngx_autocert_ca_states_n = n;
        ngx_autocert_cycle = cycle;

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: %ui CA engine(s) to bootstrap", n);
    }

    /* Kick the SEQUENTIAL account bootstrap from the first CA (idempotent: if
     * CA[0] is already live/in-flight, bootstrap_ca short-circuits). The chain
     * (account_done -> next CA -> ... -> arm scheduler) takes it from here. */
    ngx_autocert_bootstrap_ca(cycle, 0);
}

/*
 * M5: bootstrap (build client + register account) for one CA engine, then
 * chain. Skips a CA that is already live or already has an in-flight bootstrap.
 * On a transient failure to START this CA's bootstrap, SKIPS to the next CA (a
 * single bad CA must not wedge the others); the scheduler is armed once the
 * chain reaches the end with at least one live account, else the kick is
 * re-armed.
 */
static void
ngx_autocert_bootstrap_ca(ngx_cycle_t *cycle, ngx_uint_t ca_idx)
{
    ngx_autocert_conf_t       acf;
    ngx_autocert_ca_state_t  *state;
    ngx_autocert_account_t   *acct;
    ngx_pool_t               *pool;
    ngx_uint_t                i, any_live, any_dead;

    if (ngx_quit || ngx_terminate || ngx_exiting) {
        return;
    }

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK || !acf.configured) {
        return;
    }

    while (ca_idx < ngx_autocert_ca_states_n) {
        state = &ngx_autocert_ca_states[ca_idx];

        /* Already live, or bootstrap already in flight: move past it. */
        if (state->account != NULL) {
            ca_idx++;
            continue;
        }

        /* Build this CA's outbound client lazily. */
        if (!state->client_ready) {
            if (ngx_autocert_acme_client_create(&state->client, cycle,
                    &state->entry->ca_conf.ca_certificate, acf.resolver,
                    NGX_AUTOCERT_HTTP_TIMEOUT)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                              "autocert: failed to build ACME client for %V; "
                              "skipping this CA", &state->entry->ca_conf.ca);
                ca_idx++;
                continue;
            }
            state->client.resolver_timeout = acf.resolver_timeout * 1000;

            /*
             * Pin the outbound client to the configured directory origin so the
             * CA cannot redirect account-signed requests to another trusted
             * HTTPS origin (SSRF-shaped hardening). The configured CA URL was
             * already validated at postconfig, so a parse failure here is a
             * hard startup error, not a skip. cycle->pool owns the host copy
             * (worker lifetime, same as the client).
             */
            if (ngx_autocert_acme_client_set_origin(&state->client, cycle->pool,
                    &state->entry->ca_conf.ca)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                              "autocert: cannot pin ACME origin for %V; "
                              "skipping this CA", &state->entry->ca_conf.ca);
                ngx_autocert_acme_client_destroy(&state->client);
                ca_idx++;
                continue;
            }

            state->client_ready = 1;
        }

        pool = ngx_create_pool(NGX_MIN_POOL_SIZE, cycle->log);
        if (pool == NULL) {
            ca_idx++;
            continue;
        }

        acct = ngx_pcalloc(pool, sizeof(ngx_autocert_account_t));
        if (acct == NULL) {
            ngx_destroy_pool(pool);
            ca_idx++;
            continue;
        }

        acct->client = &state->client;
        acct->cycle = cycle;
        acct->log = cycle->log;
        acct->directory_url = state->entry->ca_conf.ca;
        /* The ACME account key signs JWS and is independent of the certificate
         * key type: account JWS only supports ES256/ES384, so the account key
         * is always EC (P-384) even when certificates are issued as RSA. */
        acct->key_type = NGX_HTTP_AUTOCERT_KEY_P384;
        /* Per-CA contact: this CA group's own email, or the legacy
         * first-overall email if the group set none. */
        acct->email = state->entry->email.len ? state->entry->email : acf.email;
        acct->eab_kid = state->entry->ca_conf.eab_kid;
        acct->eab_hmac_key = state->entry->ca_conf.eab_hmac_key;
        acct->handler = ngx_autocert_account_done;
        acct->data = state;             /* chain key: which CA engine this is */

        /* M3/M5: per-CA account key <path>/accounts/<ca_hash>/account.key. Only
         * the first CA (ca_idx 0) migrates the legacy flat key into its dir. */
        acct->key_path.data = ngx_autocert_prepare_account_key(cycle, &acf,
                                  state->entry, ca_idx == 0, pool);
        if (acct->key_path.data == NULL) {
            ngx_destroy_pool(pool);
            ca_idx++;
            continue;
        }
        acct->key_path.len = ngx_strlen(acct->key_path.data);

        state->account = acct;
        state->account_pool = pool;

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: registering ACME account via %V",
                      &state->entry->ca_conf.ca);

        if (ngx_autocert_account_register(acct) != NGX_OK) {
            ngx_log_error(
                NGX_LOG_ERR, cycle->log, 0,
                "autocert: could not start ACME account registration "
                "for %V; skipping this CA",
                &state->entry->ca_conf.ca );
            ngx_destroy_pool(pool);
            state->account = NULL;
            state->account_pool = NULL;
            ca_idx++;
            continue;
        }

        /* Registration started; its terminal (account_done) resumes the chain.
         */
        return;
    }

    /*
     * Chain reached the end. Arm the renewal scheduler if at least one account
     * came up. Independently, if ANY CA is still dead (transient client-build /
     * OOM / register-start / registration failure), re-arm the kick timer so
     * the dead CA(s) are retried — even when the scheduler is already armed for
     * the live ones (Codex M5 MED: a transient failure for one CA must not be
     * permanent just because another CA succeeded). The retry re-enters
     * bootstrap_ca(0): live accounts short-circuit, and start_order() /
     * sched arming are both idempotent.
     */
    any_live = 0;
    any_dead = 0;
    for (i = 0; i < ngx_autocert_ca_states_n; i++) {
        if (ngx_autocert_ca_states[i].account_live) {
            any_live = 1;
        } else {
            any_dead = 1;
        }
    }

    if (any_live) {
        ngx_autocert_start_order(cycle);
    }

    if (any_dead && !ngx_quit && !ngx_terminate && !ngx_exiting
        && ngx_autocert_kick_timer.handler != NULL
        && !ngx_autocert_kick_timer.timer_set)
    {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: %s; retrying bootstrap for the dead CA(s)",
                      any_live ? "some ACME accounts did not come up"
                               : "no ACME account came up");
        ngx_add_timer(&ngx_autocert_kick_timer, NGX_AUTOCERT_KICK_RETRY);
    }
}

/*
 * Terminal callback of a CA's account bootstrap (M5: data == that CA's engine
 * state). On failure the account is freed and the CA is left dead (account_live
 * stays 0). On success the account is kept ALIVE as the ACME session for that
 * CA (it owns the kid, key and current nonce that every later kid-signed POST
 * is signed with). Either way the SEQUENTIAL bootstrap chain resumes at the
 * NEXT CA (bootstrap_ca), which arms the renewal scheduler once the last CA is
 * handled with >=1 live account. The CI asserts on the success line emitted by
 * the account module.
 */
static void
ngx_autocert_account_done(ngx_autocert_account_t *acct, ngx_int_t rc)
{
    ngx_autocert_ca_state_t  *state = acct->data;
    ngx_cycle_t              *cycle = ngx_autocert_cycle;
    ngx_uint_t                next;

    /* Recover this CA's index to resume the chain at the next one. */
    next = (ngx_uint_t) (state - ngx_autocert_ca_states) + 1;

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: ACME account registration failed for %V",
                      &state->entry->ca_conf.ca);
        ngx_autocert_account_free(acct);            /* key + bootstrap pool */
        state->account = NULL;
        if (state->account_pool) {
            ngx_destroy_pool(state->account_pool);
            state->account_pool = NULL;
        }
        /* Leave this CA dead; the chain continues with the rest. */
        ngx_autocert_bootstrap_ca(cycle, next);
        return;
    }

    state->account_live = 1;
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, acct->log, 0,
                   "autocert: ACME account ready, kid \"%V\"", &acct->kid);

    /* Account kept alive; resume the bootstrap chain at the next CA (the last
     * CA arms the renewal scheduler in bootstrap_ca). */
    ngx_autocert_bootstrap_ca(cycle, next);
}

/*
 * M8 renewal scheduler.
 *
 * Instead of ordering a single name once, the driver runs a periodic timer
 * (ngx_autocert_sched_timer). On each tick it walks the collected name set in
 * order; for each name it decides whether the stored certificate needs work
 * (no cert on disk yet, or inside its renew_before window) and, if so, launches
 * exactly one ACME order. Orders are serialised through the single global
 * ngx_autocert_order: the order's terminal callback
 * (ngx_autocert_order_complete) pumps the scan forward to the next due name.
 * When the scan reaches the end with no order in flight, the periodic timer is
 * rearmed.
 *
 * Renewed certs land on disk via the M6b atomic store; the per-worker serve
 * path (M7) hot-reloads them on mtime change, so no config reload is needed.
 */

/* Periodic check interval, capped so we re-examine within a renew window. */
#define NGX_AUTOCERT_SCHED_INTERVAL                                            \
    ( 12 * 60 * 60 * 1000 ) /* 12h, ms ceiling */
/* Never sweep faster than this, even for a tiny renew_before (avoid busy-loop).
 * Under NGX_AUTOCERT_TEST this is 5s instead of 60s so the Pebble e2e suite's
 * polling loops (retry-after.sh / backoff.sh / runtime-ttl-gc.sh / renewal.sh)
 * don't have to sit through a real-world 60s floor; production keeps 60s. */
#if (NGX_AUTOCERT_TEST)
#define NGX_AUTOCERT_SCHED_FLOOR     (5 * 1000)              /* 5s, ms (test) */
#else
#define NGX_AUTOCERT_SCHED_FLOOR     (60 * 1000)             /* 60s, ms */
#endif
/* First scan shortly after startup (account is registered by then). */
#define NGX_AUTOCERT_SCHED_INITIAL   (1000)                  /* 1s, ms */

/*
 * Per-name failure backoff: after a failed order for a name, hold off
 * retrying it for BASE << min(fails-1, MAXSHIFT) seconds, capped at CAP, so a
 * persistently failing name (bad DNS, ACME rate limit) doesn't get hammered
 * every sweep. A success clears it. (ngx_autocert_backoff_t is defined near the
 * top; each CA engine owns its own per-name array in ngx_autocert_ca_state_t.)
 */
/* Under NGX_AUTOCERT_TEST the first hold is 5s instead of 60s so backoff.sh /
 * retry-after.sh don't wait a real minute per observed attempt; MAXSHIFT/CAP
 * keep their production semantics (only the base hold shrinks). */
#if (NGX_AUTOCERT_TEST)
#define NGX_AUTOCERT_BACKOFF_BASE 5 /* 5s first retry hold (test) */
#else
#define NGX_AUTOCERT_BACKOFF_BASE    60          /* 60s first retry hold */
#endif
#define NGX_AUTOCERT_BACKOFF_MAXSHIFT                                          \
    6 /* growth is BASE<<min(fails-1,MAXSHIFT):                                \
       * 60s..3840s in production (BASE=60),                                   \
       * 5s..320s under NGX_AUTOCERT_TEST (BASE=5) */
#define NGX_AUTOCERT_BACKOFF_CAP     (60 * 60)   /* 1h ceiling, seconds */

static ngx_event_t              ngx_autocert_sched_timer;
static ngx_uint_t               ngx_autocert_sched_ca;     /* next CA to scan */
static ngx_uint_t ngx_autocert_sched_index;  /* next name in that CA */
static ngx_uint_t ngx_autocert_sched_kt;     /* next keytype for that name */
static ngx_uint_t ngx_autocert_sched_cur_ca; /* CA index in flight */
static ngx_uint_t ngx_autocert_sched_cur;    /* backoff slot in flight */
/*
 * A3.3: the order in flight may be for a RUNTIME host (drained from the
 * requests shm zone) rather than a config name. Runtime outcomes are recorded
 * on the shm node (set_state ISSUED/FAILED) — its backoff lives there — NOT in
 * a CA's per-config-name backoff array (which has no slot for it). This flag
 * tells order_complete which ledger to write.
 */
static ngx_uint_t ngx_autocert_sched_runtime; /* in-flight order is runtime */

/*
 * A3.4: driver-local global rate cap on RUNTIME new-orders. The driver runs on
 * a single process (worker 0, interprocess-flock singleton), so a plain
 * in-process rolling window suffices — no shm. This guards Let's Encrypt
 * account limits so a hostile label flood (via the requests zone) cannot burn
 * the ACME budget:
 *   - a global rolling window of new runtime orders (default 300 / 3h), and
 *   - a per-host rolling window of runtime FAILURES (default 5 / 1h).
 * Config names are NOT counted (the operator's own set; the config sweep bounds
 * itself by name count + per-name backoff). Over either cap, the drained host
 * is released to REQUESTED with a hold until the window frees, so nothing is
 * lost.
 *
 * The windows are simple ring buffers of unix timestamps; "count in window" is
 * a scan of the ring dropping entries older than the window. Sizes are the
 * caps, so a full ring == at cap. Cheap: the rings are tiny and only touched on
 * the runtime order path (already rate-limited by the one-in-flight singleton).
 */
#define NGX_AUTOCERT_RT_ORDER_MAX 300 /* new runtime orders / window */
#define NGX_AUTOCERT_RT_ORDER_WINDOW                                           \
    ( 3 * 60 * 60 )                /* 3h, seconds (LE new-order) */
#define NGX_AUTOCERT_RT_FAIL_MAX 5 /* runtime fails / host / window */
#define NGX_AUTOCERT_RT_FAIL_WINDOW   (60 * 60)     /* 1h, seconds */

static time_t   ngx_autocert_rt_order_ring[NGX_AUTOCERT_RT_ORDER_MAX];
static ngx_uint_t ngx_autocert_rt_order_head; /* next write slot (wraps) */

typedef struct {
    u_char     host[256]; /* NUL-terminated drained host */
    size_t   len;
    time_t   ring[NGX_AUTOCERT_RT_FAIL_MAX];
    ngx_uint_t head;
} ngx_autocert_rt_fail_t;

/* Per-host fail windows for the hosts currently or recently failing. Small
 * fixed table (LRU-evict the oldest on overflow); a runtime flood is bounded by
 * the order cap above, so this need only be large enough for the concurrent
 * failing set, not every host ever seen. */
#define NGX_AUTOCERT_RT_FAIL_HOSTS    64
static ngx_autocert_rt_fail_t ngx_autocert_rt_fail[NGX_AUTOCERT_RT_FAIL_HOSTS];

static void ngx_autocert_sched_handler(ngx_event_t *ev);
static void ngx_autocert_sched_pump(ngx_cycle_t *cycle);
static ngx_int_t ngx_autocert_name_due(ngx_cycle_t *cycle,
    ngx_autocert_conf_t *acf, ngx_str_t *name, ngx_uint_t key_type);
static ngx_int_t ngx_autocert_start_order_for(ngx_cycle_t *cycle,
    ngx_autocert_conf_t *acf, ngx_autocert_ca_state_t *state, ngx_str_t *name,
    ngx_uint_t key_type, ngx_uint_t runtime);
static void ngx_autocert_sched_pump_runtime(ngx_cycle_t *cycle,
    ngx_autocert_conf_t *acf);
static ngx_uint_t ngx_autocert_rt_order_at_cap(time_t now);
static void ngx_autocert_rt_order_record(time_t now);
static void ngx_autocert_rt_order_accounted(ngx_autocert_order_t *order);
static ngx_uint_t ngx_autocert_rt_fail_at_cap(ngx_str_t *host, time_t now);
static void ngx_autocert_rt_fail_record(ngx_str_t *host, time_t now);
static ngx_int_t ngx_autocert_ca_backoff_ensure(ngx_cycle_t *cycle,
    ngx_autocert_conf_t *acf, ngx_autocert_ca_state_t *state);
static void ngx_autocert_backoff_record(ngx_autocert_ca_state_t *state,
    ngx_uint_t index, ngx_uint_t success);
static void ngx_autocert_backoff_hold(ngx_autocert_ca_state_t *state,
    ngx_uint_t index, time_t when);


/*
 * Arm the renewal scheduler once the account is live. Called from
 * account_done; the first scan fires NGX_AUTOCERT_SCHED_INITIAL later so the
 * worker is fully settled.
 */
static void
ngx_autocert_start_order(ngx_cycle_t *cycle)
{
    if (ngx_autocert_sched_timer.handler != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: renewal scheduler already armed");
        return;                         /* already armed */
    }

    ngx_memzero(&ngx_autocert_sched_timer, sizeof(ngx_event_t));
    ngx_autocert_sched_timer.handler = ngx_autocert_sched_handler;
    ngx_autocert_sched_timer.data = cycle;
    ngx_autocert_sched_timer.log = cycle->log;
    /* Cancelable: the renewal interval is up to 12h, but a long pending timer
     * must NOT keep a gracefully-shutting-down worker alive (it would pin the
     * worker — and the singleton lock — open until the timer fires, so the next
     * generation's worker 0 can never take over). nginx skips cancelable timers
     * in ngx_event_no_timers_left(), so the worker exits promptly on reload. */
    ngx_autocert_sched_timer.cancelable = 1;

    ngx_add_timer(&ngx_autocert_sched_timer, NGX_AUTOCERT_SCHED_INITIAL);
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "autocert: renewal scheduler armed in %M ms",
                   (ngx_msec_t) NGX_AUTOCERT_SCHED_INITIAL);
}


/*
 * Timer tick: restart the scan from the first name and pump until either an
 * order is launched or the whole set is found up to date (which rearms us).
 */
static void
ngx_autocert_sched_handler(ngx_event_t *ev)
{
    ngx_cycle_t  *cycle = ev->data;

    if (ngx_quit || ngx_terminate || ngx_exiting) {
        return; /* retiring worker: don't start a sweep */
    }

    if (ngx_autocert_order != NULL) {
        /* An order is still in flight from a previous tick; let its completion
         * drive the scan. Rearm so we don't lose the periodic beat. */
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: scheduler tick while order in flight");
        ngx_add_timer(&ngx_autocert_sched_timer, NGX_AUTOCERT_SCHED_INTERVAL);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "autocert: scheduler sweep starting");
    ngx_autocert_sched_ca = 0;
    ngx_autocert_sched_index = 0;
    ngx_autocert_sched_kt = 0;
    ngx_autocert_sched_pump(cycle);
}


/*
 * M5: lazily size a CA engine's per-name backoff array to its name count.
 * Allocated from the cycle pool; the name set is stable for the worker's life
 * (a reload spawns fresh workers), so a realloc-on-mismatch is enough. Returns
 * NGX_OK with state->backoff valid, or NGX_ERROR (skip this CA this sweep).
 */
static ngx_int_t
ngx_autocert_ca_backoff_ensure(ngx_cycle_t *cycle, ngx_autocert_conf_t *acf,
    ngx_autocert_ca_state_t *state)
{
    ngx_uint_t  names, nkt, n;

    names = (state->entry->names != NULL) ? state->entry->names->nelts : 0;
    nkt = (acf->cert_key_types != NULL) ? acf->cert_key_types->nelts : 1;

    if (names == 0 || nkt == 0) {
        return NGX_ERROR;
    }

    /* Guard both multiplies against wrap (both operator-controlled). */
    if (nkt > NGX_MAX_SIZE_T_VALUE / names) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: implausible name*keytype count");
        state->backoff_n = 0;
        return NGX_ERROR;
    }
    n = names * nkt;

    if (state->backoff != NULL && state->backoff_n == n
        && state->backoff_nkt == nkt)
    {
        return NGX_OK;
    }

    if (n > NGX_MAX_SIZE_T_VALUE / sizeof(ngx_autocert_backoff_t)) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: implausible server name count");
        state->backoff_n = 0;
        return NGX_ERROR;
    }

    state->backoff = ngx_pcalloc(cycle->pool,
                                 n * sizeof(ngx_autocert_backoff_t));
    if (state->backoff == NULL) {
        state->backoff_n = 0;
        return NGX_ERROR;
    }
    state->backoff_n = n;
    state->backoff_nkt = nkt;
    return NGX_OK;
}

/*
 * Advance the (CA, name) cursor from (sched_ca, sched_index), launching an
 * order for the first due name under a live CA engine. One order in flight
 * across all CAs. If the whole CAs×names space is exhausted with nothing to do,
 * rearm the periodic timer.
 */
static void
ngx_autocert_sched_pump(ngx_cycle_t *cycle)
{
    ngx_autocert_conf_t       acf;
    ngx_autocert_ca_state_t  *state;
    ngx_str_t                *names, *name;

    ngx_memzero(&acf, sizeof(ngx_autocert_conf_t));

    /* Don't launch new orders once the worker is retiring (Codex M5 MED): a
     * graceful QUIT must let the order in flight finish and then STOP — pumping
     * the next due name here would keep issuing and pin the singleton lock
     * open, blocking the next generation's worker 0 from taking over. The sched
     * timer is cancelable, so simply not rearming lets the worker exit
     * promptly. */
    if (ngx_quit || ngx_terminate || ngx_exiting) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: worker exiting; scheduler pump stops");
        return;
    }

    if (ngx_autocert_order != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: scheduler pump paused, order in flight");
        return;                         /* one order at a time */
    }

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK || !acf.configured) {
        goto rearm;
    }
    if (acf.challenge_zone == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: no challenge zone; cannot run order");
        goto rearm;
    }

    /*
     * Cursors: CA engine -> name within that CA -> keytype for that name. Each
     * (name, keytype) issues independently (its own ACME order + own backoff
     * slot + own on-disk pair), so an EC and an RSA cert for one name renew on
     * their own clocks. One order in flight across the whole space.
     */
    for ( ; ngx_autocert_sched_ca < ngx_autocert_ca_states_n;
         ngx_autocert_sched_ca++, ngx_autocert_sched_index = 0,
         ngx_autocert_sched_kt = 0)
    {
        ngx_uint_t  *kts, nkt;

        state = &ngx_autocert_ca_states[ngx_autocert_sched_ca];

        /* A CA whose account never came up is skipped (its names can't issue).
         */
        if (!state->account_live || state->account == NULL) {
            continue;
        }
        if (state->entry->names == NULL || state->entry->names->nelts == 0) {
            continue;
        }
        if (ngx_autocert_ca_backoff_ensure(cycle, &acf, state) != NGX_OK) {
            continue;
        }

        names = state->entry->names->elts;
        kts = acf.cert_key_types->elts;
        nkt = state->backoff_nkt;       /* == acf.cert_key_types->nelts */

        while (ngx_autocert_sched_index < state->entry->names->nelts) {
            ngx_uint_t  i = ngx_autocert_sched_index;

            name = &names[i];

            while (ngx_autocert_sched_kt < nkt) {
                ngx_uint_t  k = ngx_autocert_sched_kt++;
                ngx_uint_t  key_type = kts[k];
                ngx_uint_t  slot = i * nkt + k;

                /* Per-(name,keytype) failure backoff before any disk/clock
                 * check. */
                if (state->backoff[slot].next_eligible > ngx_time()) {
                    ngx_log_debug2(
                        NGX_LOG_DEBUG_CORE, cycle->log, 0,
                        "autocert: name \"%V\" held by backoff until %T", name,
                        state->backoff[slot].next_eligible );
                    continue;
                }

                if (!ngx_autocert_name_due(cycle, &acf, name, key_type)) {
                    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                                   "autocert: name \"%V\" not due", name);
                    continue;
                }

                ngx_autocert_sched_cur_ca = ngx_autocert_sched_ca;
                ngx_autocert_sched_cur =
                    slot; /* (CA, name, keytype) in flight */

                if (ngx_autocert_start_order_for(cycle, &acf, state, name,
                                                 key_type, 0) == NGX_OK)
                {
                    return;             /* order_complete will pump again */
                }
                /* Launch failed (transient: pool/OOM) — treat as a failure for
                 * the backoff so we don't spin on it, then try the next
                 * variant. */
                ngx_autocert_backoff_record(state, slot, 0);
            }

            /* This name's keytypes are exhausted; advance to the next name. */
            ngx_autocert_sched_index++;
            ngx_autocert_sched_kt = 0;
        }
    }

    /*
     * A3.3: config names are all up to date this sweep. Now service runtime
     * requests (label-autoconf et al.) enqueued in the requests shm zone. This
     * runs only with no order in flight (the config loop above returns the
     * moment it launches one), so the one-order-at-a-time invariant holds. If a
     * runtime order launches, pump_runtime has set ngx_autocert_order and we
     * stop here; order_complete pumps again. Otherwise fall through to rearm.
     */
    ngx_autocert_sched_pump_runtime(cycle, &acf);
    if (ngx_autocert_order != NULL) {
        return; /* runtime order launched; complete re-pumps */
    }

rearm:

    /*
     * Sweep again no later than half the renew_before window, capped at the
     * 12h ceiling and floored so a tiny window can't busy-loop. A fixed 12h
     * would miss renew_before values shorter than 12h and let a cert expire
     * between sweeps.
     */
    {
        ngx_msec_t  interval = NGX_AUTOCERT_SCHED_INTERVAL;
        time_t      now = ngx_time();
        time_t      soonest = 0;
        ngx_uint_t  c, i;

        if (acf.configured && acf.renew_before > 0) {
            /* Compute in 64-bit: renew_before is time_t seconds; a large
             * operator value would overflow a 32-bit ngx_msec_t if narrowed
             * before the *1000, yielding a bogusly small (too-frequent)
             * interval. Clamp to the ceiling before narrowing. */
            uint64_t  half = (uint64_t) acf.renew_before * 1000 / 2;
            if (half < (uint64_t) interval) {
                interval = (ngx_msec_t) half;
            }
        }

        /* Idle-TTL GC runs on this tick too: bound the interval to the TTL so
         * eviction lag never exceeds one TTL period (a 12h tick would let a
         * short TTL — e.g. the e2e's seconds-scale one — sit unevicted for
         * hours). Same 64-bit-then-narrow discipline as renew_before above;
         * the FLOOR below still applies, so a tiny TTL can't busy-loop. */
        if (acf.configured && acf.runtime_ttl > 0
            && acf.requests_zone != NULL)
        {
            uint64_t  ttl_ms = (uint64_t) acf.runtime_ttl * 1000;
            if (ttl_ms < (uint64_t) interval) {
                interval = (ngx_msec_t) ttl_ms;
            }
        }

        /* If any name under any CA is backing off, wake when the soonest hold
         * expires (so a 60s backoff isn't stuck behind a 12h sweep). */
        for (c = 0; c < ngx_autocert_ca_states_n; c++) {
            ngx_autocert_ca_state_t  *s = &ngx_autocert_ca_states[c];
            for (i = 0; i < s->backoff_n; i++) {
                time_t  e = s->backoff[i].next_eligible;
                if (e > now && (soonest == 0 || e < soonest)) {
                    soonest = e;
                }
            }
        }
        if (soonest != 0) {
            /* 64-bit multiply BEFORE the ngx_msec_t narrow (mirrors the
             * renew_before math above): soonest is CAP-bounded today so this
             * cannot wrap, but doing it in 64-bit is regression-proof if the
             * eligibility CAP ever grows. */
            ngx_msec_t until =
                (ngx_msec_t) ( (uint64_t) ( soonest - now ) * 1000 );
            if (until < interval) {
                interval = until;
            }
        }

        if (interval < NGX_AUTOCERT_SCHED_FLOOR) {
            interval = NGX_AUTOCERT_SCHED_FLOOR;
        }
        ngx_add_timer(&ngx_autocert_sched_timer, interval);
    }
}


/*
 * Record the outcome of an order attempt for name `index` into its backoff
 * slot. Success clears the backoff; failure grows it exponentially
 * (BASE << min(fails-1, MAXSHIFT)), capped at CAP, so a persistently failing
 * name is retried with increasing delay instead of every sweep.
 */
static void
ngx_autocert_backoff_record(ngx_autocert_ca_state_t *state, ngx_uint_t index,
    ngx_uint_t success)
{
    ngx_autocert_backoff_t  *b;
    ngx_uint_t               shift;
    time_t                   delay;

    if (state->backoff == NULL || index >= state->backoff_n) {
        return;
    }

    b = &state->backoff[index];

    if (success) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "autocert: clearing backoff for name index %ui", index);
        b->fails = 0;
        b->next_eligible = 0;
        return;
    }

    b->fails++;
    shift = b->fails - 1;
    if (shift > NGX_AUTOCERT_BACKOFF_MAXSHIFT) {
        shift = NGX_AUTOCERT_BACKOFF_MAXSHIFT;
    }

    delay = (time_t) NGX_AUTOCERT_BACKOFF_BASE << shift;
    if (delay > NGX_AUTOCERT_BACKOFF_CAP) {
        delay = NGX_AUTOCERT_BACKOFF_CAP;
    }

    b->next_eligible = ngx_time() + delay;
    ngx_log_debug3(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "autocert: backoff for name index %ui fails:%ui until %T",
                   index, b->fails, b->next_eligible);
}


/*
 * Override a name's next-eligible time with a CA-supplied Retry-After deadline
 * (HTTP 429 rate limit). We push next_eligible no earlier than `when` — taking
 * the later of the exponential backoff already recorded and the CA's request —
 * so honouring the rate limit never shortens the hold. fails is left as the
 * failure path set it.
 */
static void
ngx_autocert_backoff_hold(ngx_autocert_ca_state_t *state, ngx_uint_t index,
    time_t when)
{
    ngx_autocert_backoff_t  *b;

    if (state->backoff == NULL || index >= state->backoff_n) {
        return;
    }

    b = &state->backoff[index];
    if (when > b->next_eligible) {
        b->next_eligible = when;
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                       "autocert: Retry-After holds name index %ui until %T",
                       index, when);
    }
}


/*
 * Decide whether `name` needs an order now: true if no fullchain.pem is stored
 * yet, if it is unreadable/corrupt, or if it is inside the renew_before window
 * (now >= notAfter - renew_before).
 */
static ngx_int_t
ngx_autocert_name_due(ngx_cycle_t *cycle, ngx_autocert_conf_t *acf,
    ngx_str_t *name, ngx_uint_t key_type)
{
    u_char      path[NGX_MAX_PATH];
    u_char      key_path[NGX_MAX_PATH];
    u_char     *p;
    size_t      base, key_base;
    time_t      not_after, now;
    ngx_int_t   rc;
    ngx_uint_t  certbot;
    ngx_str_t   seg;
    ngx_str_t   chain;
    ngx_str_t   priv;
    ngx_str_t   verify, *verifyp;
    u_char      seg_buf[NGX_AUTOCERT_DOMAIN_SEG_MAX];
    u_char      verify_buf[256];

    /* Per-keytype fullchain leaf name: EC keeps the legacy flat name, RSA gets
     * the .rsa. variant — must match the store writer (order.c). */
    ngx_str_set(&chain, "/fullchain.pem");
    ngx_str_set(&priv, "/privkey.pem");
    if (key_type == NGX_HTTP_AUTOCERT_KEY_RSA2048
        || key_type == NGX_HTTP_AUTOCERT_KEY_RSA3072
        || key_type == NGX_HTTP_AUTOCERT_KEY_RSA4096)
    {
        ngx_str_set(&chain, "/fullchain.rsa.pem");
        ngx_str_set(&priv, "/privkey.rsa.pem");
    }

    if (acf->path.len == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: name \"%V\" due because store path is unset",
                       name);
        return 1;                       /* store path unset; let order log it */
    }

    /*
     * The name is used as a path segment under the store dir; reject anything
     * that could escape it (mirrors the M6b store writer's guard). An unsafe
     * name is a config error: skip it (logged), do NOT mark it due — an order
     * for it would only fail in the store step and loop every sweep.
     */
    if (name->len == 0 || name->data[0] == '.') {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: refusing unsafe server name \"%V\"", name);
        return 0;
    }
    for (p = name->data; p < name->data + name->len; p++) {
        if (*p == '/' || *p == '\0') {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "autocert: refusing unsafe server name \"%V\"", name);
            return 0;
        }
    }

    /*
     * fullchain path for the freshness check. Must match where the store
     * writer + serve path put it, per layout:
     *   secure:  <path>/<name>/fullchain.pem
     *   certbot: <path>/live/<name>/fullchain.pem
     * (a mismatch here would make a certbot-mode name look perpetually
     * un-issued and reissue every sweep.)
     */
    certbot = (acf->store == NGX_HTTP_AUTOCERT_STORE_CERTBOT);

    /* D4: a wildcard name "*.rest" is stored under "_wildcard_.rest"; map to
     * the same fs segment the store writer + serve path use so the freshness
     * check stats the file that was actually written (else it would look
     * perpetually un-issued and reorder every sweep). */
    seg.data = seg_buf;
    seg.len = ngx_autocert_fs_segment(seg_buf, sizeof(seg_buf), name);
    if (seg.len == 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: store segment too long for \"%V\"", name);
        return 0;
    }

    base = acf->path.len + (certbot ? sizeof("/live") - 1 : 0)
           + 1 + seg.len + chain.len + 1 /* NUL */;
    if (base > NGX_MAX_PATH) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: store path too long for \"%V\"", name);
        return 0;
    }

    p = ngx_cpymem(path, acf->path.data, acf->path.len);
    if (certbot) {
        p = ngx_cpymem(p, "/live", sizeof("/live") - 1);
    }
    *p++ = '/';
    p = ngx_cpymem(p, seg.data, seg.len);
    p = ngx_cpymem(p, chain.data, chain.len);
    *p = '\0';

    /*
     * Sibling privkey path for the pair check, derived EXACTLY like the chain
     * path above (same store root, same /live prefix in certbot mode, same fs
     * segment) but with this slot's key name -- privkey.pem for EC,
     * privkey.rsa.pem for RSA. Both must come from the same derivation or the
     * pair check would compare a leaf against another slot's key and report a
     * permanent false mismatch. Length is bounded separately: the key leaf is
     * not the same length as the chain leaf, so `base` does not cover it.
     */
    key_base = acf->path.len + (certbot ? sizeof("/live") - 1 : 0)
               + 1 + seg.len + priv.len + 1 /* NUL */;
    if (key_base > NGX_MAX_PATH) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: store key path too long for \"%V\"", name);
        return 0;
    }

    p = ngx_cpymem(key_path, acf->path.data, acf->path.len);
    if (certbot) {
        p = ngx_cpymem(p, "/live", sizeof("/live") - 1);
    }
    *p++ = '/';
    p = ngx_cpymem(p, seg.data, seg.len);
    p = ngx_cpymem(p, priv.data, priv.len);
    *p = '\0';

    /*
     * Identity probe for the freshness SAN check (M2). serve.c rejects a stored
     * leaf that does not cover the requested name; the scheduler must use the
     * same criterion or a wrong-domain (but right-family, unexpired) cert reads
     * as fresh and the vhost wedges. For a wildcard "*.rest" we cannot ask
     * X509_check_host about the wildcard literal, so probe with a concrete
     * sub-label "x.rest" — default wildcard matching then answers whether the
     * leaf's "*.rest" SAN covers it. Oversized names skip the check (verifyp
     * NULL): they are already rejected as unsafe segments above.
     */
    verifyp = NULL;
    if (name->len < sizeof(verify_buf)) {
        if (name->len > 2 && name->data[0] == '*' && name->data[1] == '.') {
            verify.data = verify_buf;
            verify_buf[0] = 'x';
            ngx_memcpy(verify_buf + 1, name->data + 1, name->len - 1);
            verify.len = name->len;     /* '*' -> 'x', same length */
        } else {
            verify = *name;
        }
        verifyp = &verify;
    }

    {
        int  stored_id = EVP_PKEY_NONE;
        int  want_id = (key_type == NGX_HTTP_AUTOCERT_KEY_RSA2048
                        || key_type == NGX_HTTP_AUTOCERT_KEY_RSA3072
                        || key_type == NGX_HTTP_AUTOCERT_KEY_RSA4096)
                           ? EVP_PKEY_RSA : EVP_PKEY_EC;

        rc = ngx_http_autocert_cert_not_after((char *) path, &not_after,
                                              &stored_id, verifyp,
                                              (char *) key_path, cycle->log);

        if (rc == NGX_DECLINED) {
            ngx_log_debug1(
                NGX_LOG_DEBUG_CORE, cycle->log, 0,
                "autocert: name \"%V\" due because no cert is stored", name );
            return 1;                   /* no cert yet -> issue */
        }
        if (rc == NGX_ABORT) {
            /* Either the leaf does not cover this name, or the stored
             * private key does not pair with it (a torn or partially
             * restored key/chain pair). Both are unserveable and both are
             * fixed by reissuing. */
            ngx_log_error(
                NGX_LOG_NOTICE, cycle->log, 0,
                "autocert: \"%V\" stored cert does not cover this name or "
                "does not match the stored private key; reissuing",
                name );
            return 1;                   /* identity/pair mismatch -> reissue */
        }
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "autocert: cannot read notAfter of \"%s\"; reissuing",
                          path);
            return 1;                   /* corrupt/unreadable -> reissue */
        }

        /*
         * The fullchain filename selects the slot (EC = flat, RSA = .rsa.), but
         * its contents must match the slot's key family. A pre-dual-cert
         * single-RSA deployment wrote its RSA leaf to the flat fullchain.pem;
         * the EC slot would otherwise read it, see a valid notAfter, and skip
         * EC issuance until expiry. Treat a family mismatch as due so the
         * correct keytype gets issued (its commit seeds-from-live, preserving
         * the other).
         */
        if (stored_id != want_id) {
            ngx_log_error(
                NGX_LOG_NOTICE, cycle->log, 0,
                "autocert: \"%V\" stored cert is the wrong key family "
                "for this keytype; reissuing",
                name );
            return 1;
        }
    }

    now = ngx_time();
    if (now >= not_after - acf->renew_before) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: \"%V\" within renew window (notAfter=%T)",
                      name, not_after);
        return 1;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "autocert: cert for \"%V\" fresh until %T",
                   name, not_after);
    return 0;                           /* still fresh */
}


/*
 * Launch the M6a/M6b order flow for one name under a given CA engine, reusing
 * that CA's live account as the ACME session and its directory URL. Returns
 * NGX_OK if the order started (ngx_autocert_order set); NGX_ERROR otherwise
 * (caller moves on to the next name). EAB is on the account (set at register),
 * so the order needs none.
 */
static ngx_int_t
ngx_autocert_start_order_for(ngx_cycle_t *cycle, ngx_autocert_conf_t *acf,
    ngx_autocert_ca_state_t *state, ngx_str_t *name, ngx_uint_t key_type,
    ngx_uint_t runtime)
{
    ngx_pool_t            *pool;
    ngx_autocert_order_t  *order;

    if (ngx_autocert_order != NULL) {
        return NGX_ERROR;               /* already running */
    }

    pool = ngx_create_pool(NGX_MIN_POOL_SIZE, cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    order = ngx_pcalloc(pool, sizeof(ngx_autocert_order_t));
    if (order == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    /* Copy the domain into the order pool. A config name aliases the HTTP
     * main-conf pool (outlives the order), but a runtime host (A3.3) aliases
     * the caller's short-lived drain pool, freed the moment pump_runtime
     * returns — before the order completes. Duplicating here makes
     * order->domain valid for the whole order lifetime regardless of the
     * caller's allocation. */
    order->account = state->account;
    order->log = cycle->log;
    order->directory_url = state->entry->ca_conf.ca;
    order->issuance_certificate = state->entry->ca_conf.issuance_certificate;
    order->domain.len = name->len;
    order->domain.data = ngx_pnalloc(pool, name->len);
    if (order->domain.data == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }
    ngx_memcpy(order->domain.data, name->data, name->len);
    order->challenge_zone = acf->challenge_zone;
    /*
     * A5 policy: runtime (label-autoconf) names must never use dns-01. ACME
     * validation IS the runtime allowlist (2026-07-10 design decision) — a
     * dns-01 challenge only proves control of DNS, not that the name points
     * here, so it would let anyone with DNS control on any zone mint a cert
     * served by this instance. Config-name orders keep the operator's chosen
     * challenge; runtime orders fall back to http-01 (challenge_zone is
     * always provisioned whenever acf->names is non-empty, independent of the
     * configured challenge mode, so it's always available as the fallback).
     */
    order->challenge =
        ( runtime && acf->challenge == NGX_AUTOCERT_CHALLENGE_DNS_01 )
            ? NGX_AUTOCERT_CHALLENGE_HTTP_01
            : acf->challenge;                   /* M10c/M16: http/alpn/dns */
    order->alpn_zone = acf->alpn_zone;          /* M10b store, used when alpn */
    order->dns_hook_add = acf->dns_hook_add;            /* M16 dns-01 */
    order->dns_hook_remove = acf->dns_hook_remove;
    order->dns_propagation_delay = acf->dns_propagation_delay;
    order->dns_hook_timeout = acf->dns_hook_timeout;
    order->key_type = key_type; /* dual-cert: this variant's leaf key type */
    order->store = acf->store;
    order->store_path = acf->path;
    order->profile = acf->profile;
    order->handler = ngx_autocert_order_complete;
    order->data = cycle;
    /* A3.4: only runtime orders count against the global new-order cap; the
     * hook fires once, when the real newOrder POST is accepted (not here at
     * launch). */
    order->on_new_order = runtime ? ngx_autocert_rt_order_accounted : NULL;

    ngx_autocert_order = order;
    ngx_autocert_order_pool = pool;
    ngx_autocert_sched_runtime =
        runtime; /* A3.3: which ledger completion writes */

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: starting ACME order for \"%V\"%s", name,
                  runtime ? " (runtime)" : "");

    if (ngx_autocert_order_start(order) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: could not start ACME order for \"%V\"", name);
        ngx_destroy_pool(pool);
        ngx_autocert_order = NULL;
        ngx_autocert_order_pool = NULL;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * A3.3: is `host` already a configured autocert name (under any CA)? Runtime
 * requests for names the operator already manages must NOT trigger a second
 * ACME order — the config sweep covers them. Case-insensitive: config names are
 * stored as written; drained runtime hosts are lowercased by the shm
 * normalizer.
 *
 * A3.4 MINOR (a): also matches a config WILDCARD covering the host, and — when
 * `covering` is non-NULL — outputs the matched CONFIG name (which may be the
 * wildcard "*.example.com", not the concrete host). The freshness check must
 * run against the config name so a wildcard's on-disk store key
 * ("_wildcard_.example.com") is found, not the concrete host's.
 */
static ngx_uint_t
ngx_autocert_name_is_config(ngx_str_t *host, ngx_str_t **covering)
{
    ngx_uint_t                c, i;
    ngx_autocert_ca_state_t  *state;
    ngx_str_t                *names;

    if (covering != NULL) {
        *covering = NULL;
    }

    for (c = 0; c < ngx_autocert_ca_states_n; c++) {
        state = &ngx_autocert_ca_states[c];
        if (state->entry->names == NULL) {
            continue;
        }
        names = state->entry->names->elts;
        for (i = 0; i < state->entry->names->nelts; i++) {
            /*
             * Exact match, or (A3.3 MINOR a) a config wildcard "*.example.com"
             * covering a runtime host one label deeper.
             * ngx_autocert_name_covers handles both and is unit-tested
             * (ngx_autocert_ratecap.h).
             */
            if (ngx_autocert_name_covers(names[i].data, names[i].len,
                                         host->data, host->len))
            {
                if (covering != NULL) {
                    *covering = &names[i];
                }
                return 1;
            }
        }
    }
    return 0;
}


/* A3.4: is the GLOBAL runtime new-order window at cap? */
static ngx_uint_t
ngx_autocert_rt_order_at_cap(time_t now)
{
    return ngx_autocert_rt_window_count(ngx_autocert_rt_order_ring,
               NGX_AUTOCERT_RT_ORDER_MAX, now, NGX_AUTOCERT_RT_ORDER_WINDOW)
           >= NGX_AUTOCERT_RT_ORDER_MAX;
}


/* A3.4: record one runtime new-order launch in the global window. */
static void
ngx_autocert_rt_order_record(time_t now)
{
    ngx_autocert_rt_ring_push(ngx_autocert_rt_order_ring,
        NGX_AUTOCERT_RT_ORDER_MAX, &ngx_autocert_rt_order_head, now);
}

/*
 * A3.4: order->on_new_order hook for runtime orders. Fires exactly once, from
 * the order flow, when the ACME newOrder POST has been accepted for sending —
 * so the global cap counts real CA orders, not launch attempts that die before
 * newOrder.
 */
static void
ngx_autocert_rt_order_accounted(ngx_autocert_order_t *order)
{
    ngx_autocert_rt_order_record(ngx_time());
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: counted runtime new-order for \"%V\"",
                   &order->domain);
}


/*
 * A3.4: find the per-host fail entry for `host`, or NULL. Match is on the exact
 * NUL-free bytes (drained hosts are already lowercased by the shm normalizer).
 */
static ngx_autocert_rt_fail_t *
ngx_autocert_rt_fail_find(ngx_str_t *host)
{
    ngx_uint_t               i;
    ngx_autocert_rt_fail_t  *e;

    if (host->len == 0 || host->len >= sizeof(e->host)) {
        return NULL;
    }
    for (i = 0; i < NGX_AUTOCERT_RT_FAIL_HOSTS; i++) {
        e = &ngx_autocert_rt_fail[i];
        if (e->len == host->len
            && ngx_memcmp(e->host, host->data, host->len) == 0)
        {
            return e;
        }
    }
    return NULL;
}


/* A3.4: is this host's runtime-FAILURE window at cap? Unknown host => not. */
static ngx_uint_t
ngx_autocert_rt_fail_at_cap(ngx_str_t *host, time_t now)
{
    ngx_autocert_rt_fail_t  *e;

    e = ngx_autocert_rt_fail_find(host);
    if (e == NULL) {
        return 0;
    }
    return ngx_autocert_rt_window_count(e->ring, NGX_AUTOCERT_RT_FAIL_MAX,
               now, NGX_AUTOCERT_RT_FAIL_WINDOW) >= NGX_AUTOCERT_RT_FAIL_MAX;
}

/*
 * A3.4: record one runtime FAILURE for `host`. Reuse its entry if present, else
 * claim a slot: a free one, else one whose failure window has fully EXPIRED
 * (window_count == 0). A slot that still holds in-window failures is NEVER
 * evicted — otherwise a host at its cap could be dropped and immediately fail
 * anew inside the same window, bypassing the cap (Codex A3.4 MAJOR). If every
 * slot holds active (in-window) failures, we simply don't track this host: that
 * requires >= NGX_AUTOCERT_RT_FAIL_HOSTS distinct hosts each failing within the
 * window — a flood already bounded by the GLOBAL new-order cap (each failure
 * was preceded by a counted order). Silently no-ops on an over-long host (can't
 * happen for a valid drained name — the normalizer caps at 253).
 */
static void
ngx_autocert_rt_fail_record(ngx_str_t *host, time_t now)
{
    ngx_uint_t               i;
    ngx_autocert_rt_fail_t  *e, *slot;

    if (host->len == 0 || host->len >= sizeof(e->host)) {
        return;
    }

    e = ngx_autocert_rt_fail_find(host);
    if (e == NULL) {
        slot = NULL;
        for (i = 0; i < NGX_AUTOCERT_RT_FAIL_HOSTS; i++) {
            e = &ngx_autocert_rt_fail[i];
            if (e->len == 0) {
                slot = e;                   /* free slot: take it */
                break;
            }
            if (slot == NULL
                && ngx_autocert_rt_window_count(e->ring,
                       NGX_AUTOCERT_RT_FAIL_MAX, now,
                       NGX_AUTOCERT_RT_FAIL_WINDOW) == 0)
            {
                slot = e;                   /* reusable: fully aged out */
            }
        }
        if (slot == NULL) {
            return; /* table full of active hosts; skip */
        }
        e = slot;
        ngx_memcpy(e->host, host->data, host->len);
        e->len = host->len;
        ngx_memzero(e->ring, sizeof(e->ring));
        e->head = 0;
    }

    ngx_autocert_rt_ring_push(e->ring, NGX_AUTOCERT_RT_FAIL_MAX, &e->head, now);
}

/*
 * A3.3: service runtime certificate requests. Drains REQUESTED nodes from the
 * requests shm zone (each flipped to PENDING under the shm lock by the drain),
 * then for each drained host:
 *   - already a config name  => set_state(ISSUED): the config sweep owns it, no
 *     runtime order (dedupe). It is "issued" from the requester's point of
 * view.
 *   - genuinely runtime       => launch ONE ACME order under ca_list[0]; the
 * rest stay PENDING and are released back to REQUESTED so a later tick retries
 *     them (a PENDING node the caller never completes would wedge forever — the
 *     drain contract). order_complete records ISSUED/FAILED on the shm node.
 *
 * Only ca_list[0] issues runtime names (no per-name CA selection at runtime).
 * Requires that CA's account to be live; if it is not, every drained host is
 * released so nothing is lost. At most one order launches per call (the global
 * one-in-flight singleton); pump_runtime is re-entered from order_complete via
 * the sched pump until the REQUESTED set drains.
 */
static void
ngx_autocert_sched_pump_runtime(ngx_cycle_t *cycle, ngx_autocert_conf_t *acf)
{
    ngx_pool_t               *pool;
    ngx_array_t              *hosts;
    ngx_str_t                *h;
    ngx_autocert_ca_state_t  *state;
    ngx_int_t                 n;
    ngx_uint_t                key_type;

    if (acf->requests_zone == NULL || ngx_autocert_ca_states_n == 0) {
        return;                         /* no runtime surface / no CA engines */
    }

    /* ca_list[0] is the runtime issuer. If its account is not live, leave every
     * REQUESTED node untouched (drain not run) and try again next tick. */
    state = &ngx_autocert_ca_states[0];
    if (!state->account_live || state->account == NULL) {
        return;
    }

    /* runtime cert key type: the first configured variant (dual-cert runtime
     * issuance is a later refinement — A3 issues one key type per runtime
     * name). */
    key_type = (acf->cert_key_types != NULL && acf->cert_key_types->nelts > 0)
             ? ((ngx_uint_t *) acf->cert_key_types->elts)[0]
             : NGX_HTTP_AUTOCERT_KEY_P256;

    /* Short-lived pool for the drained host copies (freed before we return). */
    pool = ngx_create_pool(NGX_MIN_POOL_SIZE, cycle->log);
    if (pool == NULL) {
        return;
    }

    /*
     * Drain ONE host at a time (max=1) and dispose of it before claiming the
     * next. This avoids claiming the whole REQUESTED backlog and then releasing
     * most of it back — a distinct-host flood cannot make one pump churn the
     * full set (Codex A3.3 MAJOR). Each iteration terminally disposes the
     * claimed PENDING node (ISSUED / held-REQUESTED / FAILED / launched-order),
     * so a re-drain never re-sees it and the loop converges. The GLOBAL
     * new-order rate cap is A3.4; this only bounds per-pump work.
     */
    for ( ;; ) {
        if (ngx_quit || ngx_terminate || ngx_exiting) {
            break;                      /* retiring: stop claiming new work */
        }

        hosts = ngx_array_create(pool, 1, sizeof(ngx_str_t));
        if (hosts == NULL) {
            break;
        }

        n = ngx_autocert_requests_drain(acf->requests_zone, pool, hosts, 1);
        if (n <= 0) {
            break;                      /* 0: nothing eligible. <0: bad zone. */
        }

        h = hosts->elts;                /* exactly one host (max=1) */

        {
        ngx_str_t  *cover;

        if (ngx_autocert_name_is_config(h, &cover)) {
            /*
             * Operator already manages this name; the config sweep owns its
             * issuance+renewal. Only report ISSUED if a valid cert is actually
             * on disk — the config sweep may not have issued it yet (CA account
             * not live, backoff, or a prior failure), so an unconditional
             * ISSUED would lie to the requester (Codex A3.3 MAJOR). If no cert
             * yet, release to REQUESTED with a short hold so we re-check after
             * the config sweep has had a chance to run, without spinning.
             *
             * A3.4 MINOR (a): freshness is checked against the COVERING config
             * name (`cover`), not the concrete host — a wildcard
             * "*.example.com" stores its cert under "_wildcard_.example.com",
             * so name_due(host) would stat the wrong path and never see the
             * cert, spinning the host on the 300s re-check forever.
             */
            if (!ngx_autocert_name_due(cycle, acf, cover, key_type)) {
                (void) ngx_autocert_requests_set_state(acf->requests_zone, h,
                                                   NGX_AUTOCERT_REQ_ISSUED, 0);
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                               "autocert: runtime host \"%V\" covered by a "
                               "config cert already on disk", h);
            } else {
                (void) ngx_autocert_requests_set_state(
                    acf->requests_zone, h, NGX_AUTOCERT_REQ_REQUESTED,
                    ngx_time() + 300 /* s: re-check after config sweep */ );
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                               "autocert: runtime host \"%V\" is a config name "
                               "not yet issued; deferring to config sweep", h);
            }
            continue;
        }
        }

        /*
         * A3.4 global rate cap: refuse to launch a runtime order over the LE
         * budget. Over the GLOBAL new-order window, or this host's FAILURE
         * window, release the host to REQUESTED with a hold until the window
         * frees so it retries later without being lost or hammering the CA. The
         * config sweep is unaffected (it does not go through this cap).
         */
        {
            time_t  now = ngx_time();
            time_t  oldest;

            if (ngx_autocert_rt_order_at_cap(now)) {
                oldest = ngx_autocert_rt_window_oldest(
                             ngx_autocert_rt_order_ring,
                             NGX_AUTOCERT_RT_ORDER_MAX, now,
                             NGX_AUTOCERT_RT_ORDER_WINDOW);
                ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                    "autocert: runtime new-order rate cap reached (%d / %d s); "
                    "deferring \"%V\"", NGX_AUTOCERT_RT_ORDER_MAX,
                    NGX_AUTOCERT_RT_ORDER_WINDOW, h);
                /* hold only until the window actually frees: the oldest counted
                 * order ages out at oldest+window; +1 clears the strict-`>`
                 * edge. Fall back to a full window if oldest is somehow unset.
                 */
                (void) ngx_autocert_requests_set_state(acf->requests_zone, h,
                           NGX_AUTOCERT_REQ_REQUESTED,
                           oldest ? oldest + NGX_AUTOCERT_RT_ORDER_WINDOW + 1
                                  : now + NGX_AUTOCERT_RT_ORDER_WINDOW);
                continue;
            }

            if (ngx_autocert_rt_fail_at_cap(h, now)) {
                ngx_autocert_rt_fail_t  *fe = ngx_autocert_rt_fail_find(h);
                oldest = fe ? ngx_autocert_rt_window_oldest(fe->ring,
                                  NGX_AUTOCERT_RT_FAIL_MAX, now,
                                  NGX_AUTOCERT_RT_FAIL_WINDOW)
                            : 0;
                ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                    "autocert: runtime host \"%V\" over failure cap "
                    "(%d / %d s); deferring", h, NGX_AUTOCERT_RT_FAIL_MAX,
                    NGX_AUTOCERT_RT_FAIL_WINDOW);
                (void) ngx_autocert_requests_set_state(acf->requests_zone, h,
                           NGX_AUTOCERT_REQ_REQUESTED,
                           oldest ? oldest + NGX_AUTOCERT_RT_FAIL_WINDOW + 1
                                  : now + NGX_AUTOCERT_RT_FAIL_WINDOW);
                continue;
            }
        }

        /* Genuinely runtime: launch the order under ca_list[0]. The shm node is
         * already PENDING (drain set it); order_complete writes ISSUED/FAILED.
         * The GLOBAL new-order count is NOT bumped here — start_order_for only
         * launches directory discovery; the real ACME newOrder POST is counted
         * later via ngx_autocert_rt_order_account() from the order flow, so a
         * pre-newOrder failure never consumes budget (Codex A3.4 MAJOR). */
        if (ngx_autocert_start_order_for(cycle, acf, state, h, key_type, 1)
            == NGX_OK)
        {
            break; /* singleton consumed; complete re-pumps */
        }

        /*
         * Launch failed (transient pool/OOM, or a deterministic startup
         * reject). Mark FAILED so the shm node's own backoff advances —
         * releasing to REQUESTED,0 would retry it every sweep with no failure
         * count and spin on a persistent failure (Codex A3.3 MAJOR).
         * set_state(FAILED,0) computes the exponential backoff on the node.
         */
        (void) ngx_autocert_requests_set_state(acf->requests_zone, h,
                                               NGX_AUTOCERT_REQ_FAILED, 0);
    }

    /*
     * A3.5 renewal scan: a runtime cert already ISSUED must be re-ordered
     * before it expires. The drain loop above only ever sees REQUESTED nodes,
     * so an ISSUED node would sit forever. Walk the ISSUED nodes (read-only),
     * and for any whose on-disk cert is inside its renew_before window, flip it
     * back to REQUESTED so the NEXT pump's drain re-orders it — through the
     * same A3.4 global rate cap and per-name backoff as a fresh request. We do
     * not launch the order here: routing renewals back through REQUESTED keeps
     * a single order-launch path and one rate-cap gate.
     *
     * Config-covered names are skipped: the config sweep owns their renewal, so
     * re-requesting here would only bounce the node back to a 300s defer.
     */
    {
        ngx_array_t  *issued;
        ngx_str_t    *iv;
        ngx_int_t     m;
        ngx_uint_t    j;

        issued = ngx_array_create(pool, 4, sizeof(ngx_str_t));
        if (issued != NULL) {
            m = ngx_autocert_requests_list_issued(acf->requests_zone, pool,
                                                  issued, 0);
            iv = issued->elts;

            for (j = 0; m > 0 && j < (ngx_uint_t) m; j++) {
                if (ngx_autocert_name_is_config(&iv[j], NULL)) {
                    continue; /* config sweep owns this name's renewal */
                }

                /* Runtime certs are stored under the concrete host (no wildcard
                 * cover), so name_due stats the right path directly. */
                if (ngx_autocert_name_due(cycle, acf, &iv[j], key_type)) {
                    (void) ngx_autocert_requests_set_state(acf->requests_zone,
                               &iv[j], NGX_AUTOCERT_REQ_REQUESTED, 0);
                    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                        "autocert: runtime cert \"%V\" is due for renewal; "
                        "re-queued", &iv[j]);
                }
            }
        }
    }

    /*
     * Idle-TTL GC: evict registry nodes whose last_seen is older than
     * autocert_runtime_ttl (0 = off). The registry is a bounded table
     * (NGX_AUTOCERT_REQUESTS_MAX); without eviction a gateway churning
     * distinct runtime hosts wedges at the cap (ensure() => REQ_DENIED).
     * Live hosts never age out: the consumer's ensure() and every driver
     * set_state() (including the renewal re-queue above) refresh last_seen.
     * PENDING nodes are skipped by gc() itself (order in flight).
     *
     * For each evicted host, remove its A6 marker — otherwise the next true
     * restart's runtime_seed() would resurrect the node the GC just removed.
     * The rearm clamp in the sched handler bounds the tick interval to the
     * TTL so eviction lag never exceeds one TTL period.
     */
    if (acf->runtime_ttl > 0) {
        ngx_array_t  *evicted;
        ngx_str_t    *ev;
        ngx_int_t     n_ev;
        ngx_uint_t    j;

        evicted = ngx_array_create(pool, 4, sizeof(ngx_str_t));
        if (evicted != NULL) {
            n_ev = ngx_autocert_requests_gc(acf->requests_zone,
                                            acf->runtime_ttl, pool, evicted);
            ev = evicted->elts;

            for (j = 0; n_ev > 0 && j < (ngx_uint_t) n_ev; j++) {
                ngx_autocert_runtime_marker_remove(cycle, acf, &ev[j]);
            }
        }
    }

    ngx_destroy_pool(pool);             /* host copies no longer needed */
}


/*
 * Terminal callback of the order flow. M6b runs the full issuance (finalize →
 * download → store), so NGX_OK here means the certificate is on disk. Whatever
 * the outcome, advance the renewal scan to the next due name (M8).
 */
static void
ngx_autocert_order_complete(ngx_autocert_order_t *order, ngx_int_t rc)
{
    ngx_cycle_t              *cycle = order->data;
    ngx_autocert_ca_state_t  *state;

    if (rc == NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, order->log, 0,
                      "autocert: certificate provisioned for \"%V\"",
                      &order->domain);
    } else {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: ACME order failed for \"%V\"", &order->domain);
    }

    if (ngx_autocert_sched_runtime) {
        /*
         * A3.3: this order was a runtime host drained from the requests shm
         * zone, not a config name. Its backoff lives on the shm node, so record
         * the outcome there via set_state (which computes next_eligible on
         * FAILED), NOT in a CA's per-config-name backoff array (no slot for
         * it).
         */
        ngx_autocert_conf_t  acf;

        if (ngx_autocert_get_conf(cycle, &acf) == NGX_OK
            && acf.requests_zone != NULL)
        {
            time_t  hold = (rc != NGX_OK && order->retry_after > 0)
                         ? order->retry_after : 0;

            /* A3.4: count a runtime failure against this host's fail window so
             * a host that keeps failing is deferred once it trips the cap. */
            if (rc != NGX_OK) {
                ngx_autocert_rt_fail_record(&order->domain, ngx_time());
            }

            /* A6: on success, drop a marker beside the fullchain so a real
             * process restart (fresh shm, cert survives on disk) can rebuild
             * this node instead of losing the runtime request permanently. */
            if (rc == NGX_OK) {
                ngx_autocert_runtime_marker_write(cycle, &acf, &order->domain);
            }

            /*
             * A3.3 MINOR (b): a failed set_state must not silently strand the
             * node PENDING (it would wedge — never re-drained). Alert-log and
             * best-effort release to REQUESTED so a later tick retries it.
             */
            if (ngx_autocert_requests_set_state(acf.requests_zone,
                    &order->domain,
                    rc == NGX_OK ? NGX_AUTOCERT_REQ_ISSUED
                                 : NGX_AUTOCERT_REQ_FAILED,
                    hold) != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                    "autocert: failed to record runtime outcome for \"%V\"; "
                    "releasing to REQUESTED to avoid a wedged PENDING node",
                    &order->domain);
                (void) ngx_autocert_requests_set_state(acf.requests_zone,
                           &order->domain, NGX_AUTOCERT_REQ_REQUESTED, hold);
            }
        }

    } else {
        /* The in-flight (CA, name) was recorded at launch. Record the outcome
         * into THAT CA's per-name backoff: success clears it, failure grows the
         * per-name retry delay (don't hammer a failing name). */
        state = &ngx_autocert_ca_states[ngx_autocert_sched_cur_ca];

        ngx_autocert_backoff_record( state, ngx_autocert_sched_cur,
                                     rc == NGX_OK );

        /* If the CA rate-limited us (429), honour its Retry-After: hold this
         * name at least until then, on top of the exponential backoff just
         * recorded. */
        if (rc != NGX_OK && order->retry_after > 0) {
            ngx_autocert_backoff_hold(state, ngx_autocert_sched_cur,
                                      order->retry_after);
        }
    }

    ngx_autocert_order_free(order);     /* drops token, frees order pool... */
    ngx_autocert_order = NULL;
    if (ngx_autocert_order_pool) {
        ngx_destroy_pool(ngx_autocert_order_pool);
        ngx_autocert_order_pool = NULL;
    }

    /* Continue the current sweep with the next name (or rearm if done). A
     * failed name is held off by its backoff slot; the next periodic tick
     * retries it once next_eligible passes. */
    ngx_autocert_sched_pump(cycle);
}

/*
 * A6: build "<container>/<seg>" (the same directory the store writer /
 * freshness check / serve path already agree on) into `buf`, NUL-terminated.
 * `container` is store_path, or store_path "/live" in certbot mode (order.c
 * convention). Returns the length written, or 0 if it would not fit / the
 * segment is invalid.
 */
static size_t
ngx_autocert_runtime_dir(ngx_autocert_conf_t *acf, ngx_str_t *host,
    u_char *buf, size_t cap)
{
    u_char    seg_buf[NGX_AUTOCERT_DOMAIN_SEG_MAX];
    ngx_str_t seg;
    size_t    need;
    u_char   *p;

    seg.data = seg_buf;
    seg.len = ngx_autocert_fs_segment(seg_buf, sizeof(seg_buf), host);
    if (seg.len == 0 || acf->path.len == 0) {
        return 0;
    }

    need = acf->path.len
         + (acf->store == NGX_HTTP_AUTOCERT_STORE_CERTBOT
            ? sizeof("/live") - 1 : 0)
         + 1 /* "/" */ + seg.len;
    if (need >= cap) {
        return 0;
    }

    p = ngx_cpymem(buf, acf->path.data, acf->path.len);
    if (acf->store == NGX_HTTP_AUTOCERT_STORE_CERTBOT) {
        p = ngx_cpymem(p, "/live", sizeof("/live") - 1);
    }
    *p++ = '/';
    p = ngx_cpymem(p, seg.data, seg.len);
    *p = '\0';

    return need;
}


/*
 * A6 persist (write side): after a runtime host is successfully issued, drop a
 * small marker file <container>/<seg>/.autocert-runtime containing the literal
 * (pre fs-segment-mangling) host bytes. On a real process restart the shm zone
 * is fresh/empty (unlike a single-process reload, which inherits the old
 * segment) — ngx_autocert_runtime_seed() reads these markers back at boot to
 * reconstruct ISSUED nodes so the scheduler's renewal walk and the A4 serve
 * gate keep working for a name the shm zone would otherwise have forgotten.
 * Best-effort: a write failure only means a slower re-request via label
 * re-discovery, not data loss (the cert itself is safely on disk already).
 */
static void
ngx_autocert_runtime_marker_write(ngx_cycle_t *cycle, ngx_autocert_conf_t *acf,
    ngx_str_t *host)
{
    u_char                dir[NGX_MAX_PATH];
    size_t                dlen;
    int                   dfd, fd;
    ngx_autocert_stat_t   st;

    dlen = ngx_autocert_runtime_dir(acf, host, dir, sizeof(dir));
    if (dlen == 0) {
        return;
    }
    dir[dlen] = '\0';

    /*
     * Pin the per-host cert directory itself (every ancestor component walked
     * with O_NOFOLLOW|O_DIRECTORY by ngx_autocert_open_dir_path — same fd-pin
     * discipline as the store writer), then create/open the marker leaf
     * relative to that pinned fd with an explicit mode and O_NOFOLLOW so a
     * pre-planted symlink/FIFO/device at the leaf can't be followed or opened
     * in a mode that blocks (Codex A6 audit: the shared open-file helper takes
     * no mode arg, so O_CREAT through it left permissions undefined pending a
     * later fchmod race).
     */
    dfd = ngx_autocert_open_dir_path((const char *) dir, 0, 0);
    if (dfd == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: A6 failed to pin store dir for \"%V\" "
                      "(restart will not remember this name)", host);
        return;
    }

    /*
     * O_NONBLOCK is REQUIRED, and O_TRUNC must NOT be set here.
     *
     * O_NOFOLLOW rejects a symlink at the leaf, but it does NOT stop us opening
     * a FIFO that was planted there directly. Opening a FIFO O_WRONLY blocks in
     * openat() until a reader appears (POSIX), so the S_ISREG check below would
     * never be reached: the sole ACME driver event loop — and this nginx worker
     * — would wedge indefinitely after a successful runtime issuance.
     * O_NONBLOCK makes that open fail fast with ENXIO instead (and is harmless
     * on a regular file, where it has no effect on the write path).
     *
     * O_TRUNC is likewise deferred: it acts BEFORE we can fstat the fd, so it
     * would let a hostile leaf be truncated before we established it is a
     * regular file. We open, verify the type, and only then ftruncate the
     * pinned fd.
     */
    fd = ngx_autocert_openat_mode(dfd, NGX_AUTOCERT_RUNTIME_MARKER,
                NGX_AUTOCERT_MARKER_OPEN_WRITE, 0644);
    (void) ngx_autocert_close(dfd);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: A6 failed to write runtime marker for \"%V\" "
                      "(restart will not remember this name)", host);
        return;
    }

    /* Only ever write into a regular file, and only one with a single link — a
     * hard link to someone else's file must not be truncated through this fd.
     */
    if (ngx_autocert_fstat(fd, &st) == -1 || !S_ISREG(st.st_mode)
        || st.st_nlink != 1)
    {
        (void) ngx_autocert_close(fd);
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: A6 refusing non-regular runtime marker path "
                      "for \"%V\"", host);
        return;
    }

    /* now that the fd is known to be a plain, single-linked regular file */
    if (ngx_autocert_ftruncate(fd, 0) == -1) {
        (void) ngx_autocert_close(fd);
        ngx_log_error(
            NGX_LOG_ERR, cycle->log, ngx_errno,
            "autocert: A6 failed to truncate runtime marker for \"%V\"", host );
        return;
    }

    if (ngx_autocert_write(fd, host->data, host->len) != (ssize_t) host->len) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: A6 short/failed write of runtime marker "
                      "for \"%V\"", host);
    }

    (void) ngx_autocert_close(fd);
}


/*
 * A6 persist (GC side): remove the runtime marker of a host the idle-TTL GC
 * just evicted from the requests shm zone. Leaving the marker behind would
 * resurrect the evicted node as ISSUED on the next true restart
 * (ngx_autocert_runtime_seed reads markers back at boot), un-doing the
 * eviction. The cert files themselves are NOT touched — they are harmless
 * without a registry node (the A4 serve gate no longer admits the SNI) and
 * a re-learned host reuses them via the freshness check.
 *
 * Best-effort: same fd-pin discipline as the writer (every ancestor walked
 * O_NOFOLLOW|O_DIRECTORY), unlinkat() relative to the pinned dir fd. ENOENT
 * is silent (nothing to clean); other failures are logged and the marker is
 * re-seen by the next GC pass's eviction of the re-seeded node.
 */
static void
ngx_autocert_runtime_marker_remove(ngx_cycle_t *cycle,
    ngx_autocert_conf_t *acf, ngx_str_t *host)
{
    u_char  dir[NGX_MAX_PATH];
    size_t  dlen;
    int     dfd;

    dlen = ngx_autocert_runtime_dir(acf, host, dir, sizeof(dir));
    if (dlen == 0) {
        return;
    }
    dir[dlen] = '\0';

    dfd = ngx_autocert_open_dir_path((const char *) dir, 0, 0);
    if (dfd == -1) {
        return;                 /* no per-host dir => no marker to remove */
    }

    if (ngx_autocert_unlinkat(dfd, NGX_AUTOCERT_RUNTIME_MARKER, 0) == -1
        && ngx_errno != NGX_ENOENT)
    {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                      "autocert: failed to remove runtime marker for evicted "
                      "\"%V\" (restart may resurrect it)", host);
    }

    (void) ngx_autocert_close(dfd);
}


/*
 * A6 persist (read side): rebuild of the requests shm zone from on-disk
 * markers. Called from ngx_autocert_driver_init_process() on every
 * init_process (boot, and on every master+workers reload that spawns a new
 * worker), and from ngx_autocert_relock_handler() after a worker-0 handoff or
 * graceful reload (USR2 upgrade) takes the lock. On a SIGHUP reload this
 * process has already inherited the live shm segment, so the seed is a no-op
 * for names still present in config but re-inserts any markers whose hosts
 * were dropped from config and then auto-restored by new label events. After a
 * USR2 upgrade the new master maps a fresh shm zone, so the seed is a full
 * rebuild there.
 *
 * For each top-level directory entry in the store container that carries the
 * marker: read the literal host, skip it if a config name now covers it (the
 * config sweep owns it), otherwise re-insert it as ISSUED if a valid fullchain
 * is still on disk (ngx_autocert_name_due == 0), or drop the stale marker
 * (cert expired/missing while the process was down — a fresh label event will
 * re-request it; there is nothing safe to seed for a nonexistent cert).
 *
 * Failure anywhere (open/read/enumerate) is logged and skipped per-entry —
 * A6 is a best-effort warm start, never a hard boot dependency.
 */
static void
ngx_autocert_runtime_seed(ngx_cycle_t *cycle)
{
    ngx_autocert_conf_t   acf;
    u_char                container[NGX_MAX_PATH];
    u_char                *p;
    size_t                content_len;
    ngx_autocert_dir_t    *dh;
    ngx_autocert_dirent_t *de;
    int                   dfd, mfd, cfd;
    ssize_t               n;
    ngx_autocert_stat_t   mst;
    u_char                hostbuf[NGX_AUTOCERT_REQUEST_NAME_MAX];
    ngx_str_t             host;
    ngx_uint_t            key_type;
    ngx_int_t             rc;

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK
        || acf.requests_zone == NULL
        || acf.path.len == 0)
    {
        return;
    }

    content_len = acf.path.len
         + (acf.store == NGX_HTTP_AUTOCERT_STORE_CERTBOT
            ? sizeof("/live") - 1 : 0);
    if (content_len >= sizeof(container)) {
        return;
    }
    p = ngx_cpymem(container, acf.path.data, acf.path.len);
    if (acf.store == NGX_HTTP_AUTOCERT_STORE_CERTBOT) {
        p = ngx_cpymem(p, "/live", sizeof("/live") - 1);
    }
    *p = '\0';

    cfd = ngx_autocert_open_dir_path((const char *) container, 0, 0);
    if (cfd == -1) {
        return;                          /* no store yet: nothing to seed */
    }

    dh = ngx_autocert_fdopendir(cfd);
    if (dh == NULL) {
        (void) ngx_autocert_close(cfd);
        return;
    }

    key_type = (acf.cert_key_types != NULL && acf.cert_key_types->nelts > 0)
             ? ((ngx_uint_t *) acf.cert_key_types->elts)[0]
             : NGX_HTTP_AUTOCERT_KEY_P256;

    while ((de = ngx_autocert_readdir(dh)) != NULL) {
        if (de->d_name[0] == '.') {
            continue;                    /* skip ".", "..", any dotfile entry */
        }

        /* O_NOFOLLOW: a symlinked entry can't be used to read a marker from
         * outside the pinned store dir. Non-directory entries fail harmlessly.
         */
        dfd = ngx_autocert_openat(cfd, de->d_name,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dfd == -1) {
            continue;
        }

        /*
         * O_NONBLOCK so a planted FIFO can't block worker-0 init while it
         * holds the driver singleton lock (Codex A6 audit); the immediate
         * fstat()+S_ISREG check below then refuses anything that isn't a
         * plain file before reading (a FIFO opened O_NONBLOCK|O_RDONLY with
         * no writer would otherwise return EOF/short-read, not hang — the
         * type check is the actual gate, O_NONBLOCK just removes the hang
         * as a possibility even before that check runs).
         */
        mfd = ngx_autocert_openat(dfd, NGX_AUTOCERT_RUNTIME_MARKER,
                     NGX_AUTOCERT_MARKER_OPEN_READ);
        if (mfd == -1) {
            (void) ngx_autocert_close(dfd);
            continue; /* not a runtime dir (or config-only) */
        }

        if (ngx_autocert_fstat(mfd, &mst) == -1 || !S_ISREG(mst.st_mode)
            || mst.st_size <= 0
            || (size_t) mst.st_size > NGX_AUTOCERT_REQUEST_NAME_MAX)
        {
            (void) ngx_autocert_close(mfd);
            (void) ngx_autocert_close(dfd);
            continue;                    /* not a plain, right-sized marker */
        }

        n = ngx_autocert_read(mfd, hostbuf, sizeof(hostbuf));
        (void) ngx_autocert_close(mfd);
        (void) ngx_autocert_close(dfd);

        if (n <= 0 || (size_t) n != (size_t) mst.st_size) {
            continue; /* short read / raced truncate: ignore */
        }

        host.data = hostbuf;
        host.len = (size_t) n;

        if (ngx_autocert_name_is_config(&host, NULL)) {
            continue;                    /* config sweep owns it now */
        }

        if (ngx_autocert_name_due(cycle, &acf, &host, key_type)) {
            /* Cert gone/expired while the process was down. Nothing valid to
             * seed; do not fabricate an ISSUED state. Next label-autoconf
             * discovery re-enqueues it via a fresh ensure(). */
            continue;
        }

        /* REQ_UNKNOWN means the insert did not happen (bad zone/host), and
         * REQ_DENIED is terminal — in neither case is there a node to move to
         * ISSUED, so claiming a restore would be fail-open. Only log the
         * restore once set_state() has actually committed it. */
        rc = ngx_autocert_requests_ensure(acf.requests_zone, &host);
        if (rc == NGX_AUTOCERT_REQ_UNKNOWN || rc == NGX_AUTOCERT_REQ_DENIED) {
            continue;
        }

        if (ngx_autocert_requests_set_state(acf.requests_zone, &host,
                                            NGX_AUTOCERT_REQ_ISSUED, 0)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "autocert: A6 could not restore runtime name \"%V\"",
                          &host);
            continue;
        }

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: A6 restored runtime name \"%V\" from disk",
                      &host);
    }

    (void) ngx_autocert_closedir(dh);     /* also closes cfd via fdopendir */
}


#if (NGX_WIN32)
/*
 * W9/B2 — win32 named-mutex singleton gate, DESIGN-win32-store-io.md § W2.
 * `dfd` is the already-open store dir fd (still owned by the caller — this
 * function neither closes nor duplicates it). Returns NGX_OK if this process
 * now holds (or already held) the singleton, NGX_AGAIN if another process
 * holds it (caller falls back to the existing relock-timer retry, same as
 * the POSIX EAGAIN path), NGX_ERROR on a hard failure.
 *
 * The wait-result -> verdict mapping (including the WAIT_ABANDONED ==
 * success rule) lives in ngx_autocert_shared.h's
 * ngx_autocert_win32_mutex_wait_verdict() so it has a Linux unit test; this
 * function is the thin orchestration around it that only compiles on win32
 * (CreateMutexW / WaitForSingleObject / GetFinalPathNameByHandleW are not
 * available to unit-test directly on Linux).
 */
static ngx_int_t
ngx_autocert_win32_driver_trylock(int dfd, ngx_log_t *log)
{
    char        canon[NGX_MAX_PATH];
    char        name[64];
    wchar_t     wname[64];
    ngx_int_t   verdict;
    DWORD       wait_rc;
    HANDLE      h;
    int         n;

    if (ngx_autocert_win32_mutex != NULL) {
        return NGX_OK;                      /* already held by this process */
    }

    if (ngx_autocert_win32_canon_store_path(dfd, canon, sizeof(canon)) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "autocert: could not canonicalize store dir path "
                      "for singleton mutex name");
        return NGX_ERROR;
    }

    if (ngx_autocert_win32_singleton_name(canon, name, sizeof(name)) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "autocert: could not build singleton mutex name");
        return NGX_ERROR;
    }

    n = MultiByteToWideChar(CP_UTF8, 0, name, -1, wname,
                             (int) (sizeof(wname) / sizeof(wname[0])));
    if (n <= 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "autocert: could not convert singleton mutex name "
                      "\"%s\" to UTF-16, GetLastError=%ui",
                      name, (ngx_uint_t) GetLastError());
        return NGX_ERROR;
    }

    h = ngx_autocert_win32_mutex_open_and_wait(wname, &wait_rc);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "autocert: CreateMutexW(\"%s\") failed", name);
        return NGX_ERROR;
    }

    verdict = ngx_autocert_win32_mutex_wait_verdict((uint32_t) wait_rc);

    if (verdict == NGX_AGAIN) {
        /* Not acquired: close now — the static must reflect actual
         * ownership, and a not-owned handle must not linger. */
        CloseHandle(h);
        return NGX_AGAIN;
    }

    if (verdict == NGX_ERROR) {
        DWORD err = GetLastError(); /* save BEFORE CloseHandle, which can
                                     * overwrite the thread's last-error */

        CloseHandle(h);
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "autocert: WaitForSingleObject on singleton mutex "
                      "\"%s\" failed, GetLastError=%ui",
                      name, (ngx_uint_t) err);
        return NGX_ERROR;
    }

    /* verdict == NGX_OK: WAIT_OBJECT_0 (clean acquire) or WAIT_ABANDONED
     * (prior holder exited without releasing; ownership transferred to us —
     * treated as success, never as an error: getting this backwards means
     * issuance stops forever after one worker crash).
     *
     * WAIT_ABANDONED is the EXPECTED outcome on every graceful reload, not
     * just a crash indicator: ngx_worker_thread() (nginx-1.31.3
     * src/os/win32/ngx_process_cycle.c:763) is a separate thread from the
     * one that runs ngx_worker_process_exit() (same file, line 754, called
     * from the main worker-process thread's WaitForMultipleObjects loop).
     * This module's init_process/relock timer -- and so the CreateMutexW
     * acquire above -- runs on ngx_worker_thread; exit_process's ReleaseMutex
     * below runs on the other thread. A win32 mutex is thread-affine, so
     * that ReleaseMutex always fails with ERROR_NOT_OWNER and never actually
     * releases; the mutex is only freed when the process exits and the
     * kernel closes the handle, which marks it abandoned. The successor
     * worker therefore takes this branch on every ordinary reload, not only
     * after a crash. */
    if (wait_rc == NGX_AUTOCERT_WAIT_ABANDONED) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "autocert: singleton mutex \"%s\" ownership transferred "
                      "from a prior holder that exited without an explicit "
                      "release (crash or normal shutdown -- see comment above)",
                      name);
    }

    ngx_autocert_win32_mutex = h;
    return NGX_OK;
}

/*
 * W9 — release + close the win32 singleton mutex and NULL the static. The
 * ONE place this happens; every caller (both the post-gate hard-error paths
 * in ngx_autocert_driver_trylock() below and
 * ngx_autocert_driver_exit_process()) shares this so the release logic cannot
 * drift between them.
 *
 * ReleaseMutex is EXPECTED to fail here with ERROR_NOT_OWNER when called from
 * ngx_autocert_driver_exit_process(): a win32 mutex is thread-affine (only
 * the acquiring thread may release it), and exit_process runs from
 * ngx_worker_process_exit() (nginx-1.31.3 src/os/win32/ngx_process_cycle.c:824,
 * called from the main worker-process thread's WaitForMultipleObjects loop at
 * line 754) -- a different thread than ngx_worker_thread() (line 763), which
 * is what runs ngx_autocert_win32_driver_trylock() (via init_process/the
 * relock timer) and therefore actually acquired the mutex. Called from the
 * trylock error paths, by contrast, this runs on ngx_worker_thread -- the
 * SAME thread that just acquired it -- so ReleaseMutex genuinely succeeds
 * there.
 *
 * Correctness never depends on ReleaseMutex succeeding: CloseHandle below
 * still surrenders this process's reference on any outcome, and once the
 * process exits the kernel marks the mutex abandoned, which the successor's
 * WAIT_ABANDONED branch above already treats as a successful acquisition.
 * So a failed ReleaseMutex here is a log-accuracy matter, not a correctness
 * one: report what actually happened instead of unconditionally claiming
 * "released".
 */
static void
ngx_autocert_win32_driver_unlock(ngx_log_t *log)
{
    if (ngx_autocert_win32_mutex == NULL) {
        return;
    }

    if (ReleaseMutex(ngx_autocert_win32_mutex)) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "autocert: released win32 singleton mutex, pid %P",
                      ngx_pid);
    } else {
        DWORD  err = GetLastError();

        if (err == ERROR_NOT_OWNER) {
            /* Expected on exit_process's thread (see comment above); not an
             * ERR — it fires on every clean win32 shutdown and would
             * otherwise be mistaken for a fault. */
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                          "autocert: ReleaseMutex on singleton mutex "
                          "skipped (ERROR_NOT_OWNER — released on a "
                          "different thread than it was acquired on, "
                          "expected on win32; ownership surrenders via "
                          "CloseHandle instead), pid %P", ngx_pid);
        } else {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "autocert: ReleaseMutex on singleton mutex "
                          "failed unexpectedly, GetLastError=%ui, pid %P",
                          (ngx_uint_t) err, ngx_pid);
        }
    }

    /* Unconditional regardless of ReleaseMutex's outcome: closing the handle
     * is what actually surrenders this process's ownership here, and it
     * must not be skipped on the failure path. */
    CloseHandle(ngx_autocert_win32_mutex);
    ngx_autocert_win32_mutex = NULL;
}
#endif /* NGX_WIN32 */

/*
 * Try to acquire the interprocess singleton lock: open (creating) the lock file
 * in the store dir and take a non-blocking exclusive flock. Returns NGX_OK if
 * this process now holds it, NGX_AGAIN if another process holds it (retry
 * later), NGX_ERROR on a hard failure (no config / can't build path / open
 * failed for a reason other than contention).
 *
 * The fd is kept open for the driver's lifetime (the lock lives as long as an
 * open fd holding it); exit_process / a crash closes it and the kernel
 * releases. win32: the named-mutex gate above
 * (ngx_autocert_win32_driver_trylock) is acquired FIRST, in front of this
 * flock-based serializer — see its comment.
 */
static ngx_int_t
ngx_autocert_driver_trylock(ngx_cycle_t *cycle)
{
    ngx_autocert_conf_t  acf;
    u_char               path[NGX_MAX_PATH];
    int                  bfd;

    if (ngx_autocert_lock_fd != -1) {
        return NGX_OK;                      /* already held */
    }

    if (ngx_autocert_get_conf(cycle, &acf) != NGX_OK || !acf.configured) {
        return NGX_ERROR; /* nothing configured; nothing to do */
    }

    if (acf.path.len >= NGX_MAX_PATH) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "autocert: store path too long");
        return NGX_ERROR;
    }

    /* Create every missing store-path component relative to its already-pinned
     * parent. A path-based mkdir/open would follow an attacker-planted ancestor
     * symlink before the later fd-pinned store operations get a chance to help.
     */
    ngx_memcpy(path, acf.path.data, acf.path.len);
    path[acf.path.len] = '\0';

    bfd = ngx_autocert_open_dir_path((char *) path, 1, 0700);
    if (bfd == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: cannot open/create store dir \"%s\"", path);
        return NGX_ERROR;
    }

    /*
     * open_dir_path() creates missing path components at 0700, but adopts an
     * ALREADY EXISTING store directory whatever its owner or mode — a store
     * pre-created (or substituted) by another local user under e.g. /var/tmp
     * would otherwise be adopted silently, letting that user plant or swap
     * certificate material underneath us. Refuse before taking the lock.
     */
    if (ngx_autocert_check_owner_mode(bfd, cycle->log, "store directory", 0)
        != NGX_OK)
    {
        (void) ngx_autocert_close(bfd);
        return NGX_ERROR;
    }

#if (NGX_WIN32)
    /* W9/B2: gate IN FRONT OF the flock-based serializer below, which is
     * POSIX-only (LockFileEx contention maps to EAGAIN, but the worker-0
     * gate in ngx_http_autocert_module.c fails open on win32 because
     * ngx_worker is declared but never assigned there — every win32 worker
     * reaches this function). Canonicalize via the already-open store dir
     * handle, not the configured string (case/trailing-slash/8.3 form would
     * otherwise let two spellings of the same store both arm). */
    switch (ngx_autocert_win32_driver_trylock(bfd, cycle->log)) {

    case NGX_OK:
        break;                               /* fall through to flock below */

    case NGX_AGAIN:
        (void) ngx_autocert_close(bfd);
        return NGX_AGAIN;

    default:
        (void) ngx_autocert_close(bfd);
        return NGX_ERROR;
    }
#endif

    ngx_autocert_lock_fd = ngx_autocert_openat_mode(bfd, ".driver.lock",
                                  O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                                  0600);
    (void) ngx_autocert_close(bfd);
    if (ngx_autocert_lock_fd == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: open lock file in store \"%s\" failed", path);
#if (NGX_WIN32)
        /* The mutex gate above already succeeded (NGX_OK fell through to
         * here); a terminal NGX_ERROR return must give it back, or this
         * process holds the Global\ singleton for its whole lifetime while
         * never arming — locking out every OTHER worker/instance on this
         * store forever. Deliberately NOT done on the NGX_AGAIN path above:
         * the relock timer retries and reuses the already-owned handle. */
        ngx_autocert_win32_driver_unlock(cycle->log);
#endif
        return NGX_ERROR;
    }

    for ( ;; ) {
        if (ngx_autocert_flock_ex_nb(ngx_autocert_lock_fd) == 0) {
            break;
        }
        if (ngx_autocert_err_is_intr(ngx_errno)) {
            continue;                       /* interrupted by a signal; retry */
        }
        if (ngx_errno == NGX_EAGAIN || ngx_errno == EWOULDBLOCK) {
            /* Another process (the prior generation's worker 0) holds it. */
            (void) ngx_autocert_close(ngx_autocert_lock_fd);
            ngx_autocert_lock_fd = -1;
            return NGX_AGAIN;
        }
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "autocert: flock() lock file \"%s\" failed", path);
        (void) ngx_autocert_close(ngx_autocert_lock_fd);
        ngx_autocert_lock_fd = -1;
#if (NGX_WIN32)
        /* Same reasoning as the open-lock-file failure above: give back the
         * already-acquired mutex on this terminal-NGX_ERROR path so a later
         * attempt (this process or another) can still acquire it. */
        ngx_autocert_win32_driver_unlock(cycle->log);
#endif
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: acquired driver lock, pid %P", ngx_pid);

    return NGX_OK;                          /* we are now the sole driver */
}


/* Arm the kick timer (one-shot ACME bootstrap → renewal scheduler). */
static void
ngx_autocert_driver_arm(ngx_cycle_t *cycle)
{
    ngx_memzero(&ngx_autocert_kick_timer, sizeof(ngx_event_t));
    ngx_autocert_kick_timer.handler = ngx_autocert_kick_handler;
    ngx_autocert_kick_timer.data = cycle;
    ngx_autocert_kick_timer.log = cycle->log;
    ngx_autocert_kick_timer.cancelable =
        1; /* don't pin a shutting-down worker */
    ngx_add_timer(&ngx_autocert_kick_timer, NGX_AUTOCERT_KICK);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: ACME driver armed on worker 0, pid %P", ngx_pid);
}


/*
 * Relock retry. The previous holder (a retiring worker 0) has not released yet;
 * keep retrying on a slow timer so this survivor takes over the moment the lock
 * frees, with no driver gap.
 */
static void
ngx_autocert_relock_handler(ngx_event_t *ev)
{
    ngx_cycle_t  *cycle = ev->data;

    if (ngx_quit || ngx_terminate || ngx_exiting) {
        return;
    }

    switch (ngx_autocert_driver_trylock(cycle)) {

    case NGX_OK:
        /* A6: same seed-before-arm as the immediate-acquisition path in
         * ngx_autocert_driver_init_process — the singleton was only just
         * taken here, so this worker's shm view may still be missing markers
         * a prior generation never got to (or a fresh restart never had). */
        ngx_autocert_runtime_seed(cycle);
        ngx_autocert_driver_arm(cycle);
        return;                             /* acquired; stop retrying */

    case NGX_AGAIN:
        ngx_add_timer(&ngx_autocert_relock_timer, NGX_AUTOCERT_RELOCK);
        return;

    default:
        return;                             /* hard error; logged in trylock */
    }
}

/*
 * Worker-0 entry point. Called from the http module's init_process, already
 * gated to worker 0 (or single-process mode), inside the worker's running event
 * loop. Take the interprocess singleton lock; if held by a retiring prior-
 * generation worker, retry on a timer. Once held, arm the kick timer;
 * everything else (client build, account bootstrap, renewal scheduler) chains
 * from there. The worker already installed signal handlers, set up the event
 * engine, and kept its listening sockets (it serves the :80 / tls-alpn
 * challenge), so no helper-style process init is needed here.
 */
void
ngx_autocert_driver_init_process(ngx_cycle_t *cycle)
{
    switch (ngx_autocert_driver_trylock(cycle)) {

    case NGX_OK:
        /* A6: rebuild requests-zone ISSUED nodes from on-disk markers before
         * arming. Idempotent (ensure()+set_state() only fill/confirm gaps), so
         * running it on every init_process — true boot AND a master+workers
         * reload that spawned this worker — is safe and cheap (skipped by
         * ngx_autocert_name_is_config/name_due for anything already settled).
         */
        ngx_autocert_runtime_seed(cycle);
        ngx_autocert_driver_arm(cycle);
        break;

    case NGX_AGAIN:
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: ACME driver lock held by prior generation; "
                      "worker 0 (pid %P) waiting to take over", ngx_pid);
        ngx_memzero(&ngx_autocert_relock_timer, sizeof(ngx_event_t));
        ngx_autocert_relock_timer.handler = ngx_autocert_relock_handler;
        ngx_autocert_relock_timer.data = cycle;
        ngx_autocert_relock_timer.log = cycle->log;
        ngx_autocert_relock_timer.cancelable =
            1; /* don't pin a shutting-down worker */
        ngx_add_timer(&ngx_autocert_relock_timer, NGX_AUTOCERT_RELOCK);
        break;

    default:
        break;                              /* not configured / error; idle */
    }
}


/*
 * Shared teardown primitives, used by BOTH exit_process and the
 * master_process-off reload path so the two can never drift (a field freed in
 * one but not the other would be a latent leak on whichever path was missed).
 */

/* Cancel every driver timer bound to the (old) cycle. */
static void
ngx_autocert_driver_cancel_timers(void)
{
    if (ngx_autocert_kick_timer.timer_set) {
        ngx_del_timer(&ngx_autocert_kick_timer);
    }
    if (ngx_autocert_sched_timer.timer_set) {
        ngx_del_timer(&ngx_autocert_sched_timer);
    }
    if (ngx_autocert_relock_timer.timer_set) {
        ngx_del_timer(&ngx_autocert_relock_timer);
    }

    /* The dns-01 orphan reaper is module-scoped inside order.c but lives in
     * this cycle's timer tree like the three above, so it is cancelled with
     * them. Its pid table is process-lifetime and deliberately survives. */
    ngx_autocert_order_cancel_timers();
}

/* Free the in-flight order and its (cycle-independent) pool. */
static void
ngx_autocert_driver_drop_order(void)
{
    if (ngx_autocert_order != NULL) {
        /*
         * A3.3 BLOCKER: if the order in flight is for a RUNTIME host, its shm
         * node was flipped to PENDING by the drain and its completion callback
         * will now never run (we free the order here on exit /
         * master_process-off reload). Left PENDING, the node wedges forever —
         * future drains skip it. Release it back to REQUESTED so the
         * next-generation worker 0 (or this process after a reload re-arm)
         * re-drains and retries it. Best-effort: if the zone is gone the module
         * is being torn down and nothing reads it.
         */
        if (ngx_autocert_sched_runtime && ngx_cycle != NULL) {
            ngx_autocert_conf_t  acf;

            if (ngx_autocert_get_conf((ngx_cycle_t *) ngx_cycle, &acf) == NGX_OK
                && acf.requests_zone != NULL)
            {
                (void) ngx_autocert_requests_set_state(acf.requests_zone,
                           &ngx_autocert_order->domain,
                           NGX_AUTOCERT_REQ_REQUESTED, 0);
            }
        }
        ngx_autocert_sched_runtime = 0;

        ngx_autocert_order_free(ngx_autocert_order);
        ngx_autocert_order = NULL;
    }
    if (ngx_autocert_order_pool != NULL) {
        ngx_destroy_pool(ngx_autocert_order_pool);
        ngx_autocert_order_pool = NULL;
    }
}

/* Tear down every per-CA engine (account + bootstrap pool + client). The
 * ca_states array itself lives in the cycle pool (freed by nginx), so just drop
 * the pointer after releasing each engine's owned resources. */
static void
ngx_autocert_driver_drop_ca_states(void)
{
    ngx_uint_t  i;

    if (ngx_autocert_ca_states == NULL) {
        return;
    }

    for (i = 0; i < ngx_autocert_ca_states_n; i++) {
        ngx_autocert_ca_state_t  *state = &ngx_autocert_ca_states[i];

        if (state->account != NULL) {
            ngx_autocert_account_free(state->account);
            state->account = NULL;
        }
        if (state->account_pool != NULL) {
            ngx_destroy_pool(state->account_pool);
            state->account_pool = NULL;
        }
        if (state->client_ready) {
            ngx_autocert_acme_client_destroy(&state->client);
            state->client_ready = 0;
        }
    }

    ngx_autocert_ca_states = NULL;
    ngx_autocert_ca_states_n = 0;
}


/*
 * Worker-0 teardown on exit_process. Best-effort: free the in-flight order, the
 * live account (account key + bootstrap pool), and the outbound client. The
 * kernel would reclaim everything on exit anyway, but freeing explicitly keeps
 * leak checkers (valgrind/asan CI) quiet and mirrors a clean worker shutdown.
 */
void
ngx_autocert_driver_exit_process(ngx_cycle_t *cycle)
{
    (void) cycle;

    ngx_autocert_driver_cancel_timers();
    ngx_autocert_driver_drop_order();
    ngx_autocert_driver_drop_ca_states();

    /* Release the singleton lock (kernel drops it on close) so the next
     * generation's worker 0 can take over immediately. */
    if (ngx_autocert_lock_fd != -1) {
        (void) ngx_autocert_close(ngx_autocert_lock_fd);
        ngx_autocert_lock_fd = -1;
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "autocert: released driver lock, pid %P", ngx_pid);
    }

#if (NGX_WIN32)
    /* W9: release + close the win32 singleton mutex here — process-lifetime
     * handle, never closed/reopened per relock tick (that would open a
     * window where two workers could both hold it briefly). See
     * ngx_autocert_win32_driver_unlock()'s comment for why ReleaseMutex is
     * EXPECTED to fail here specifically (thread affinity: this function
     * runs on a different thread than the one that acquired the mutex). */
    ngx_autocert_win32_driver_unlock(cycle->log);
#endif
}

/*
 * `master_process off` reload. In single-process mode the same process survives
 * a SIGHUP: ngx_single_process_cycle() runs ngx_init_cycle() (which re-reads
 * the config and re-runs every module's init_module) but never calls
 * exit_process / init_process again. Without this, the driver keeps timers,
 * per-CA engines, the in-flight order, and the test-seed latches all bound to
 * the dead cycle and its pool, so a reload silently ignores new autocert config
 * and can touch freed cycle memory. init_module calls this on the
 * single-process path to tear the engine state down and re-arm it against the
 * NEW cycle. The POSIX interprocess lock is released and re-acquired: the lock
 * file lives in the store dir, so a reload that changes autocert_path must pick
 * up the correct lock file location from the new cycle's config.
 *
 * There is no matching Win32 arm here, because this function is POSIX-only by
 * REACHABILITY (not by #ifdef). Its single caller is
 * ngx_http_autocert_init_module(), gated on `ngx_process == NGX_PROCESS_SINGLE
 * && ngx_http_autocert_single_started`, so reaching it needs a SECOND
 * ngx_init_cycle() inside a process that is already running single-process.
 * Win32 nginx has no such path (verified against nginx-1.31.4):
 *
 *   - ngx_init_cycle() is re-run at exactly one site in
 *     src/os/win32/ngx_process_cycle.c — line 203, inside
 *     ngx_master_process_cycle()'s "reconfiguring" branch (line 195). That
 *     branch runs only when ngx_process == NGX_PROCESS_MASTER, which
 *     src/core/nginx.c:339-341 and :379-384 make mutually exclusive with
 *     NGX_PROCESS_SINGLE.
 *   - win32 ngx_single_process_cycle() (same file, :986-1003) spawns
 *     ngx_worker_thread() (:996) and then parks the calling thread in
 *     WaitForSingleObject(ngx_stop_event, INFINITE) (:1002). It waits on the
 *     STOP event only — never on ngx_reload_event — and never calls
 *     ngx_init_cycle() itself.
 *   - ngx_worker_thread() (:763-820), which runs init_process and the event
 *     loop, handles only ngx_quit / ngx_terminate / ngx_reopen (:811). It
 *     never inspects ngx_reconfigure and never re-enters ngx_init_cycle().
 *
 * So `nginx -s reload` under `master_process off` on Windows sets
 * ngx_reload_event and nothing consumes it: the config is not re-read, no
 * init_module re-runs, and this function does not execute. Releasing
 * ngx_autocert_win32_mutex here would therefore be dead code no test can
 * reach — and it would not be safe by default if a win32 reload path ever
 * appeared. The mutex is thread-affine and is acquired on ngx_worker_thread
 * (via init_process / the relock timer); a release from any other thread hits
 * the ERROR_NOT_OWNER path in ngx_autocert_win32_driver_unlock() and then
 * CloseHandle()s our only reference while the named object stays owned by a
 * still-live thread. The zero-timeout reacquire in
 * ngx_autocert_win32_mutex_open_and_wait() would return WAIT_TIMEOUT forever
 * and the driver would never re-arm — strictly worse than holding the old
 * store's mutex. If win32 ever grows an in-process reload, settle which
 * thread performs the release BEFORE adding one here.
 *
 * Must run inside the worker event loop (true on reload — init_module fires
 * from ngx_init_cycle() while the loop is live), since it re-arms a timer.
 */
void
ngx_autocert_driver_reload(ngx_cycle_t *cycle)
{
    /* Cancel every driver timer bound to the old cycle. The handlers carry the
     * old cycle in ev->data, so they must not fire after the cycle is gone. */
    ngx_autocert_driver_cancel_timers();

    /* Detach any pending ACME resolver/socket event BEFORE freeing the pools
     * its request lives in: the process keeps running across this reload, so a
     * live event would otherwise fire on freed memory (and its handler would
     * touch the dead-cycle driver state we are about to drop). */
    ngx_autocert_acme_cancel_inflight();

    /* Drop the in-flight order (pool is cycle-independent) and every per-CA
     * engine. ca_states was allocated from the OLD cycle pool (freed by
     * ngx_clean_old_cycles when the old cycle retires); the helper drops the
     * pointer and the kick rebuilds it from the new cycle's ca_list. Same free
     * set as exit_process — shared so the two paths cannot drift. */
    ngx_autocert_driver_drop_order();
    ngx_autocert_driver_drop_ca_states();

    /* Reset the scheduler cursor and the one-shot test-seed latches so the new
     * config is scanned and (re)seeded from scratch. */
    ngx_autocert_sched_ca = 0;
    ngx_autocert_sched_index = 0;
    ngx_autocert_sched_cur_ca = 0;
    ngx_autocert_sched_cur = 0;
    ngx_memzero(&ngx_autocert_sched_timer, sizeof(ngx_event_t));
    ngx_autocert_test_seeded = 0;
    ngx_autocert_test_alpn_seeded = 0;
    ngx_autocert_test_runtime_seeded = 0;

    ngx_autocert_cycle = cycle;

    /*
     * Release the old lock and re-acquire from scratch. The lock file lives in
     * the store dir, so a reload that changes autocert_path (or disables
     * autocert entirely) would otherwise leave us holding the OLD store's lock
     * while the new store runs unlocked. Closing here + going back through
     * init_process makes trylock() derive the lock path from the NEW cycle's
     * config: it re-locks the same path when unchanged, moves to the new path
     * when changed, and stays unlocked (idle) when the new config has no
     * issuable names. */
    if (ngx_autocert_lock_fd != -1) {
        (void) ngx_autocert_close(ngx_autocert_lock_fd);
        ngx_autocert_lock_fd = -1;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "autocert: reload (master_process off) — re-arming driver "
                  "against new cycle, pid %P", ngx_pid);

    ngx_autocert_driver_init_process(cycle);
}
