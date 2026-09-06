/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the dns-01 orphan-reap table (ngx_autocert_order.c,
 * audit MAJOR/Robustness).
 *
 * ngx_autocert_order_free() used to SIGKILL an outstanding dns-01 hook child
 * and then reap it with a BLOCKING waitpid(pid, &status, 0). A child wedged in
 * uninterruptible kernel I/O (a hung NFS/FUSE mount under the operator's hook
 * binary) does not die on SIGKILL, so that reap parked the worker event loop
 * and wedged reload and shutdown. The fix hands {pid, saved sigmask} to a
 * module-scoped table whose standalone timer WNOHANG-reaps it, so the pid
 * outlives ngx_autocert_order_t and _free() never blocks.
 *
 * WHAT THIS COVERS: the table logic — add stores an entry, a still-running
 * child (waitpid -> 0) keeps its entry and reports work outstanding, a reaped
 * child (waitpid -> pid) drops its entry and restores THAT entry's saved
 * sigmask, ECHILD also drops the entry (already reaped elsewhere: keeping it
 * would leak the slot forever), a permanently-stuck child is polled and never
 * blocks, EINTR retries, and add reports NGX_DECLINED once the table is full.
 * waitpid is injected (ngx_autocert_waitpid_pt), so a "stuck" child is modelled
 * exactly — no real process needs to be hung to test it.
 *
 * WHAT THIS DOES NOT COVER: the nginx-event-loop half — ngx_autocert_orphan_
 * arm()/the timer handler re-arming, and ngx_autocert_order_cancel_timers()
 * being called from ngx_autocert_driver_cancel_timers(). Those need a live
 * cycle and timer rbtree, which this suite has no harness for; they are
 * exercised by the module's integration path.
 *
 * The table is static in ngx_autocert_order.c, so this TU slices JUST it via
 * ci/tests/unit/extract_orphan.sh — the whole .c is the ACME order state
 * machine (account POST, JSON, challenge/ALPN shm, OpenSSL, the event loop)
 * and would drag all of that in to reach one pid array. Locked to production
 * code, no copy drift.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "src/ngx_autocert_shared.h"    /* ngx_autocert_err_is_intr */

#include "generated_orphan.inc"


/* The reap loop logs an unexpected waitpid errno through ngx_cycle->log, and
 * ngx_log_error() reads log->log_level BEFORE reaching the stub below. A NULL
 * ngx_cycle therefore turns any such errno into a segfault that MASKS whatever
 * assertion was being proven -- observed while mutation-testing this file.
 * Give the slice a real cycle and log so that branch is survivable. */
static ngx_log_t    test_log;
static ngx_cycle_t  test_cycle;

volatile ngx_cycle_t  *ngx_cycle = &test_cycle;

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...);
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{ (void) level; (void) log; (void) err; (void) fmt; }


static int  failures;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (cond) {                                                           \
            fprintf(stderr, "  ok   %s\n", (msg));                            \
        } else {                                                              \
            fprintf(stderr, "  FAIL %s (%s:%d)\n", (msg), __FILE__,           \
                    __LINE__);                                                \
            failures++;                                                       \
        }                                                                     \
    } while (0)


/* --- injectable waitpid: a scripted child ---------------------------------
 *
 * fake_state[pid] decides what waitpid() reports for that pid. The whole point
 * of the fix is that a child which NEVER exits must not stall anything, and a
 * real hung process cannot be created portably in a unit test.
 */

#define FAKE_RUNNING    0       /* -> returns 0: still alive, forever */
#define FAKE_EXITED     1       /* -> returns pid once, then ECHILD */
#define FAKE_ECHILD     2       /* -> returns -1/ECHILD: already reaped */
#define FAKE_EINTR_ONCE 3       /* -> -1/EINTR once, then behaves as EXITED */

static int  fake_state[64];
static int  fake_calls[64];


static pid_t
fake_waitpid(pid_t pid, int *status, int options)
{
    if (pid < 0 || pid >= 64) {
        errno = ECHILD;
        return -1;
    }

    fake_calls[pid]++;

    if (status != NULL) {
        *status = 0;
    }

    /* Every call from the reaper must be non-blocking. If it ever asks for a
     * blocking wait, that is the regression this whole change exists to
     * prevent — fail loudly rather than quietly passing. */
    if (!(options & WNOHANG)) {
        fprintf(stderr, "  FAIL waitpid() called WITHOUT WNOHANG for pid %d "
                        "-- the reap would block the event loop\n", (int) pid);
        failures++;
        /* ECHILD, not a bare -1: the reaper logs any other errno through
         * ngx_cycle->log, and reporting this failure must not also crash the
         * run in a way that hides it. */
        errno = ECHILD;
        return -1;
    }

    switch (fake_state[pid]) {

    case FAKE_RUNNING:
        return 0;

    case FAKE_EXITED:
        fake_state[pid] = FAKE_ECHILD;
        return pid;

    case FAKE_EINTR_ONCE:
        fake_state[pid] = FAKE_EXITED;
        errno = EINTR;
        return -1;

    case FAKE_ECHILD:
    default:
        errno = ECHILD;
        return -1;
    }
}


static void
reset_all(void)
{
    memset(fake_state, 0, sizeof(fake_state));
    memset(fake_calls, 0, sizeof(fake_calls));
    ngx_autocert_orphans_reset();
}


static ngx_uint_t
table_len(void)
{
    ngx_uint_t  i, n = 0;

    for (i = 0; i < NGX_AUTOCERT_ORPHAN_MAX; i++) {
        if (ngx_autocert_orphans[i].pid != NGX_INVALID_PID) {
            n++;
        }
    }
    return n;
}


int
main(void)
{
    test_log.log_level = NGX_LOG_ERR;
    test_cycle.log = &test_log;

    sigset_t    empty, blocked, now;
    ngx_uint_t  i, live;

    /* The production binding must satisfy the injection point's type: if
     * ngx_autocert_orphan_reap() ever stops taking an injectable waitpid, or
     * the real one stops matching it, this stops compiling. */
    {
        ngx_autocert_waitpid_pt  real = ngx_autocert_real_waitpid;
        CHECK(real != NULL && real != fake_waitpid,
              "production binds a real waitpid through the same injection point");
    }

    sigemptyset(&empty);
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGCHLD);

    /* --- 1. handoff stores the entry; it is NOT reaped at add time ------- */
    reset_all();
    CHECK(ngx_autocert_orphan_add(11, &empty) == NGX_OK,
          "add() accepts a pid into an empty table");
    CHECK(table_len() == 1, "the handed-off pid is held in the table");
    CHECK(fake_calls[11] == 0, "add() does not wait on the child at all");

    /* --- 2. a permanently-stuck child never blocks and stays held -------- */
    reset_all();
    fake_state[12] = FAKE_RUNNING;
    (void) ngx_autocert_orphan_add(12, &empty);
    for (i = 0; i < 5; i++) {
        live = ngx_autocert_orphan_reap(fake_waitpid);
        CHECK(live == 1, "a stuck child keeps the reaper armed");
    }
    CHECK(table_len() == 1, "a stuck child is retained across sweeps");
    CHECK(fake_calls[12] == 5, "the stuck child is polled once per sweep");

    /* --- 3. an exited child is dropped ---------------------------------- */
    reset_all();
    fake_state[13] = FAKE_EXITED;
    (void) ngx_autocert_orphan_add(13, &empty);
    CHECK(ngx_autocert_orphan_reap(fake_waitpid) == 0,
          "reaping the last child leaves nothing outstanding");
    CHECK(table_len() == 0, "the reaped entry is removed from the table");

    /* --- 4. ECHILD drops the entry (no forever-leak on that path) -------- */
    reset_all();
    fake_state[14] = FAKE_ECHILD;
    (void) ngx_autocert_orphan_add(14, &empty);
    CHECK(ngx_autocert_orphan_reap(fake_waitpid) == 0,
          "ECHILD counts as done, not as outstanding work");
    CHECK(table_len() == 0, "an ECHILD entry is dropped, never leaked");

    /* --- 5. EINTR is retried inside one sweep --------------------------- */
    reset_all();
    fake_state[15] = FAKE_EINTR_ONCE;
    (void) ngx_autocert_orphan_add(15, &empty);
    CHECK(ngx_autocert_orphan_reap(fake_waitpid) == 0,
          "an EINTR is retried and the child still reaped in one sweep");
    CHECK(fake_calls[15] == 2, "EINTR caused exactly one retry");

    /* --- 6. the sigmask is restored on reap, not on handoff ------------- */
    reset_all();
    CHECK(sigprocmask(SIG_SETMASK, &empty, NULL) == 0,
          "test starts from an empty signal mask");
    fake_state[16] = FAKE_RUNNING;
    (void) ngx_autocert_orphan_add(16, &blocked);
    /* Model what the spawn path leaves in place: SIGCHLD blocked while the
     * child is outstanding, so nginx's generic reaper cannot steal the
     * status. The saved mask handed to the table is the PRE-spawn one. */
    CHECK(sigprocmask(SIG_BLOCK, &blocked, NULL) == 0, "block SIGCHLD");
    (void) ngx_autocert_orphan_reap(fake_waitpid);
    CHECK(sigprocmask(SIG_BLOCK, NULL, &now) == 0, "read mask back");
    CHECK(sigismember(&now, SIGCHLD) == 1,
          "a still-running orphan keeps SIGCHLD blocked");
    fake_state[16] = FAKE_EXITED;
    (void) ngx_autocert_orphan_reap(fake_waitpid);
    CHECK(sigprocmask(SIG_BLOCK, NULL, &now) == 0, "read mask back after reap");
    CHECK(sigismember(&now, SIGCHLD) == 1,
          "the reaped entry's own saved mask is restored (SIGCHLD in it)");

    /* --- 7. a full table declines rather than overwriting --------------- */
    reset_all();
    for (i = 0; i < NGX_AUTOCERT_ORPHAN_MAX; i++) {
        fake_state[20 + i] = FAKE_RUNNING;
        CHECK(ngx_autocert_orphan_add((ngx_pid_t) (20 + i), &empty) == NGX_OK,
              "add() fills every slot");
    }
    CHECK(ngx_autocert_orphan_add(99, &empty) == NGX_DECLINED,
          "add() declines once the table is full");
    CHECK(table_len() == NGX_AUTOCERT_ORPHAN_MAX,
          "a declined add does not evict a held pid");

    /* --- 8. mixed table: only the exited entries drain ------------------ */
    reset_all();
    fake_state[30] = FAKE_RUNNING;
    fake_state[31] = FAKE_EXITED;
    fake_state[32] = FAKE_RUNNING;
    (void) ngx_autocert_orphan_add(30, &empty);
    (void) ngx_autocert_orphan_add(31, &empty);
    (void) ngx_autocert_orphan_add(32, &empty);
    CHECK(ngx_autocert_orphan_reap(fake_waitpid) == 2,
          "a mixed sweep reports exactly the still-running entries");
    CHECK(table_len() == 2, "only the exited entry was dropped");

    (void) sigprocmask(SIG_SETMASK, &empty, NULL);

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
