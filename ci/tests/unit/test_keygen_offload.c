/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for off-event-loop RSA certificate-key generation
 * (ngx_autocert_order.c, ledger MINOR "move RSA keygen off the event loop").
 *
 * ngx_autocert_order_finalize() generated the leaf key inline on the worker's
 * event loop. For the EC key types that is free (P-256 ~30us, P-384 ~150us),
 * but autocert_key_type also accepts rsa2048/rsa3072/rsa4096, and RSA keygen
 * is a prime search: measured at ~70ms / ~200ms / ~700ms worst-of-N on the
 * development host, with a long tail. Every connection the worker owns stops
 * being served for that whole time. The RSA arm now goes to the nginx thread
 * pool and resumes the order state machine from a completion handler on the
 * event loop.
 *
 * The hazard that makes this worth testing is NOT the keygen: it is ownership.
 * An nginx thread task cannot be cancelled -- once posted it runs and its
 * completion fires -- while a reload or shutdown calls
 * ngx_autocert_driver_drop_order() -> ngx_autocert_order_free(), destroying
 * order->pool AND the pool holding the order struct. A completion handler that
 * still believed in that order would write a fresh EVP_PKEY into freed memory;
 * one that simply bailed would leak the key.
 *
 * WHAT THIS COVERS, by driving the SHIPPED functions:
 *   - is_rsa() routes exactly the three RSA types and no EC type, so the EC
 *     arm provably still runs inline (a regression that offloaded P-256 would
 *     fail here).
 *   - the worker-thread body publishes a real generated key, and reports
 *     failure through `failed` rather than by touching the order.
 *   - the live path: completion adopts the key into order->cert_key, resumes
 *     via _finalize_csr(), and releases the slot BEFORE resuming (so the next
 *     order can post).
 *   - the abandoned path: _abandon() detaches, the later completion FREES the
 *     generated key exactly once (key_free is instrumented in this TU, so a
 *     leaked or double-freed key is observable) and never dereferences the
 *     dead order.
 *   - _abandon() is scoped: abandoning some OTHER order must not detach this
 *     one, and abandoning when no task is in flight is a no-op.
 *   - a keygen failure on the thread finishes the order with NGX_ERROR
 *     instead of resuming with a NULL key.
 *
 *   - every DEGRADED path through _post(), which is where both of this
 *     change's real bugs lived: no "default" pool, a post that fails, a slot
 *     still busy with an orphan after a reload, and busy-and-attached. All but
 *     the last must still ISSUE (inline) rather than lose the renewal, and a
 *     failed post must DISCARD the cached task -- nginx leaves event.active=1
 *     on its cond_signal failure path, and this slot reuses one task for the
 *     life of the worker, so keeping it would wedge RSA issuance permanently.
 *     _post()'s four external symbols (ngx_thread_pool_get,
 *     ngx_thread_task_post, ngx_alloc, ngx_cycle) are supplied by this TU.
 *
 * WHAT THIS DOES NOT COVER: the real nginx thread pool -- no task is ever run
 * on a real worker thread here, so the pool's own queueing and the genuine
 * cross-thread memory publication are not exercised. Those are exercised by
 * the module's integration path (ci/tests/e2e/rsa-issue.sh issues against
 * Pebble with rsa2048).
 *
 * The slot is static in ngx_autocert_order.c, so this TU slices just it via
 * ci/tests/unit/extract_keygen.sh, whose header explains why the whole .c is
 * not include-shimmed. Locked to production code, no copy drift.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_thread_pool.h>

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#include "src/ngx_http_autocert_conf.h"     /* key-type enum */
#include "src/ngx_http_autocert_crypto.h"   /* key_generate / key_free */
#include <openssl/rsa.h>
#include <openssl/ec.h>

/* The slice needs the order type for its `order` back-pointer and for the two
 * state-machine calls the completion handler makes. */
#include "src/ngx_autocert_order.h"


static int failures;

#define OK(cond, msg)                                                         \
    do {                                                                      \
        if (cond) {                                                           \
            printf("ok:   %s\n", (msg));                                      \
        } else {                                                              \
            printf("FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__);          \
            failures++;                                                       \
        }                                                                     \
    } while (0)


/* --- minimal nginx runtime the slice's logging touches ------------------- */

static ngx_log_t    test_log;
static ngx_cycle_t  test_cycle;

volatile ngx_cycle_t  *ngx_cycle = &test_cycle;

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...);
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}


/* --- key_generate / key_free, instrumented ------------------------------ */
/*
 * The slice calls both of these by name, so this TU supplies them -- the same
 * injection seam the orphan-reap test uses for waitpid. Instrumenting _free is
 * what turns "did the abandoned path release the key?" into an OBSERVABLE
 * fact. OpenSSL 3 exposes no refcount getter, so an EVP_PKEY_up_ref()-based
 * probe cannot distinguish a leak from a correct free (up_ref returns 1
 * whatever the count is); counting the module's own free call can.
 */

static EVP_PKEY  *freed_keys[8];
static int        freed_n;

EVP_PKEY *
ngx_http_autocert_key_generate(ngx_uint_t curve)
{
    EVP_PKEY      *pkey = NULL;
    EVP_PKEY_CTX  *ctx;
    int            bits;

    /* Only the RSA arm is reachable from the sliced code under test. */
    bits = (curve == NGX_HTTP_AUTOCERT_CRYPTO_RSA2048) ? 2048
         : (curve == NGX_HTTP_AUTOCERT_CRYPTO_RSA4096) ? 4096 : 3072;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) != 1
        || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) != 1
        || EVP_PKEY_keygen(ctx, &pkey) != 1)
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void
ngx_http_autocert_key_free(EVP_PKEY *pkey)
{
    if (freed_n < (int) (sizeof(freed_keys) / sizeof(freed_keys[0]))) {
        freed_keys[freed_n] = pkey;
    }
    freed_n++;
    EVP_PKEY_free(pkey);
}


/* Did the code under test free exactly this key, exactly once? */
static int
freed_exactly_once(EVP_PKEY *key)
{
    int  i, n = 0;

    if (freed_n > (int) (sizeof(freed_keys) / sizeof(freed_keys[0]))) {
        return 0;               /* overflowed the log; cannot answer */
    }
    for (i = 0; i < freed_n; i++) {
        if (freed_keys[i] == key) {
            n++;
        }
    }
    return n == 1;
}


/* --- the thread-pool seam _post() reaches the outside world through ------- */
/*
 * _post() touches exactly four external symbols: ngx_thread_pool_get(),
 * ngx_thread_task_post(), ngx_alloc() and ngx_cycle. Supplying all four here
 * (the same injection seam the orphan-reap test uses for waitpid) makes its
 * DEGRADED paths testable with no real thread pool: no "default" pool, a slot
 * still busy with an abandoned task, and a post that fails. Those paths are
 * where the ownership bugs live, so they are the ones worth reaching.
 */

/* Opaque to us; _post() only ever passes the pointer straight back. */
struct ngx_thread_pool_s { int placeholder; };

static ngx_thread_pool_t   fake_pool;
static ngx_thread_pool_t  *pool_get_result;      /* NULL models "no pool" */
static ngx_int_t           task_post_result = NGX_OK;
static int                 task_post_calls;
static ngx_thread_task_t  *task_posted;

ngx_thread_pool_t *
ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name)
{
    (void) cycle; (void) name;
    return pool_get_result;
}

ngx_int_t
ngx_thread_task_post(ngx_thread_pool_t *tp, ngx_thread_task_t *task)
{
    (void) tp;
    task_post_calls++;
    task_posted = task;

    if (task_post_result != NGX_OK) {
        /*
         * Model the REAL failure mode this fix exists for: nginx's
         * ngx_thread_task_post() sets event.active = 1 before the
         * ngx_thread_cond_signal() that can fail, and that failure path
         * returns without clearing it and without enqueueing the task
         * (nginx 1.31.4 src/core/ngx_thread_pool.c:251-258). A task left
         * active is refused by every later post.
         */
        task->event.active = 1;
    }

    return task_post_result;
}


/* --- the two state-machine seams the completion handler calls ------------ */
/*
 * These are the REAL production symbols as far as the slice is concerned: it
 * calls them by name and this TU supplies them, exactly as the orphan-reap
 * test supplies its injected waitpid. Recording the calls is what makes the
 * completion handler's decisions observable.
 */

static int        csr_calls;
static int        csr_rc = NGX_OK;
static int        finish_calls;
static ngx_int_t  finish_rc_seen;
/* Slot state observed from INSIDE the resume, to prove the handler released
 * the slot before re-entering the state machine. */
static ngx_uint_t busy_during_csr;

static ngx_int_t ngx_autocert_order_finalize_csr(ngx_autocert_order_t *order);
static void ngx_autocert_order_finish(ngx_autocert_order_t *order,
    ngx_int_t rc);

#include "generated_keygen.inc"

static ngx_int_t
ngx_autocert_order_finalize_csr(ngx_autocert_order_t *order)
{
    (void) order;
    csr_calls++;
    busy_during_csr = ngx_autocert_keygen.busy;
    return csr_rc;
}

static void
ngx_autocert_order_finish(ngx_autocert_order_t *order, ngx_int_t rc)
{
    (void) order;
    finish_calls++;
    finish_rc_seen = rc;
}


/* --- helpers ------------------------------------------------------------- */

static void
reset_state(void)
{
    /* The slot caches one heap task for the life of the process; drop it here
     * so each case starts clean without leaking it under LeakSanitizer. */
    if (ngx_autocert_keygen.task != NULL) {
        ngx_free(ngx_autocert_keygen.task);
    }
    ngx_memzero(&ngx_autocert_keygen, sizeof(ngx_autocert_keygen));
    csr_calls = 0;
    csr_rc = NGX_OK;
    pool_get_result = &fake_pool;
    task_post_result = NGX_OK;
    task_post_calls = 0;
    task_posted = NULL;
    freed_n = 0;
    ngx_memzero(freed_keys, sizeof(freed_keys));
    finish_calls = 0;
    finish_rc_seen = NGX_OK;
    busy_during_csr = 999;
}


/*
 * Put the slot in the state ngx_autocert_keygen_post() leaves it in on a
 * successful post, without needing a thread pool: task posted, order attached,
 * completion pending.
 */
static void
arm_slot(ngx_autocert_order_t *order, ngx_uint_t key_type)
{
    ngx_autocert_keygen.order = order;
    ngx_autocert_keygen.key_type = key_type;
    ngx_autocert_keygen.key = NULL;
    ngx_autocert_keygen.failed = 0;
    ngx_autocert_keygen.busy = 1;
}


/* Drive the shipped completion handler the way ngx_thread_pool_handler()
 * does: through a ngx_event_t whose data is the slot. */
static void
run_completion(void)
{
    ngx_event_t  ev;

    ngx_memzero(&ev, sizeof(ngx_event_t));
    ev.data = &ngx_autocert_keygen;
    ev.log = &test_log;

    ngx_autocert_keygen_completion(&ev);
}


int
main(void)
{
    ngx_autocert_order_t  order;
    ngx_autocert_order_t  other;

    test_cycle.log = &test_log;

    printf("== keygen offload: which key types are offloaded ==\n");

    /* The EC arm must stay inline. If a change ever routes P-256 through the
     * thread pool, this goes red -- the offload exists for the RSA prime
     * search, and a 30us keygen does not repay a thread round-trip plus the
     * in-flight cancellation window. */
    OK(!ngx_autocert_keygen_is_rsa(NGX_HTTP_AUTOCERT_CRYPTO_P256),
       "P-256 is NOT offloaded (stays on the event loop)");
    OK(!ngx_autocert_keygen_is_rsa(NGX_HTTP_AUTOCERT_CRYPTO_P384),
       "P-384 is NOT offloaded (stays on the event loop)");
    OK(ngx_autocert_keygen_is_rsa(NGX_HTTP_AUTOCERT_CRYPTO_RSA2048),
       "RSA-2048 is offloaded");
    OK(ngx_autocert_keygen_is_rsa(NGX_HTTP_AUTOCERT_CRYPTO_RSA3072),
       "RSA-3072 is offloaded");
    OK(ngx_autocert_keygen_is_rsa(NGX_HTTP_AUTOCERT_CRYPTO_RSA4096),
       "RSA-4096 is offloaded");

    printf("== keygen offload: the worker-thread body ==\n");

    /* RSA-2048 rather than 4096: same code path, seconds cheaper in CI. */
    reset_state();
    ngx_memzero(&order, sizeof(order));
    order.log = &test_log;
    arm_slot(&order, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048);

    ngx_autocert_keygen_thread(&ngx_autocert_keygen, &test_log);

    OK(ngx_autocert_keygen.key != NULL,
       "thread body published a generated key into the slot");
    OK(ngx_autocert_keygen.failed == 0,
       "thread body did not report failure for a good key type");
    OK(ngx_autocert_keygen.key != NULL
       && EVP_PKEY_bits(ngx_autocert_keygen.key) == 2048,
       "thread body generated the key type the slot asked for (RSA-2048)");
    /* The thread must not have touched the order: it runs concurrently with an
     * event loop that may be freeing it. */
    OK(order.cert_key == NULL,
       "thread body did NOT write into the order (event loop owns it)");

    printf("== keygen offload: live completion resumes the order ==\n");

    {
        EVP_PKEY  *generated = ngx_autocert_keygen.key;

        run_completion();

        OK(order.cert_key == generated,
           "completion adopted the generated key into order->cert_key");
        OK(csr_calls == 1, "completion resumed the state machine via _csr()");
        OK(finish_calls == 0, "completion did not finish a healthy order");
        OK(ngx_autocert_keygen.busy == 0, "completion released the slot");
        OK(ngx_autocert_keygen.order == NULL,
           "completion cleared the slot's order back-pointer");
        OK(ngx_autocert_keygen.key == NULL,
           "completion cleared the slot's key (ownership transferred)");
        /* Load-bearing: _finalize_csr() can fail -> _finish() -> the driver's
         * completion, which may start the NEXT order. If the slot were still
         * busy at that moment that order's keygen would be refused. */
        OK(busy_during_csr == 0,
           "slot was already free when the state machine was re-entered");

        ngx_http_autocert_key_free(order.cert_key);
        order.cert_key = NULL;
    }

    printf("== keygen offload: a resume failure finishes the order ==\n");

    reset_state();
    ngx_memzero(&order, sizeof(order));
    order.log = &test_log;
    arm_slot(&order, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048);
    ngx_autocert_keygen_thread(&ngx_autocert_keygen, &test_log);
    csr_rc = NGX_ERROR;

    run_completion();

    OK(csr_calls == 1, "completion attempted the resume");
    OK(finish_calls == 1 && finish_rc_seen == NGX_ERROR,
       "a failed resume finished the order with NGX_ERROR");
    ngx_http_autocert_key_free(order.cert_key);
    order.cert_key = NULL;

    printf("== keygen offload: a thread-side failure finishes the order ==\n");

    reset_state();
    ngx_memzero(&order, sizeof(order));
    order.log = &test_log;
    arm_slot(&order, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048);
    /* Model the keygen failing without spending a real keygen: exactly the
     * state the thread body leaves behind on EVP failure. */
    ngx_autocert_keygen.failed = 1;
    ngx_autocert_keygen.key = NULL;

    run_completion();

    OK(csr_calls == 0, "a failed keygen did NOT resume with a NULL key");
    OK(finish_calls == 1 && finish_rc_seen == NGX_ERROR,
       "a failed keygen finished the order with NGX_ERROR");
    OK(order.cert_key == NULL, "a failed keygen left order->cert_key NULL");
    OK(ngx_autocert_keygen.busy == 0, "a failed keygen released the slot");

    printf("== keygen offload: abandoned order (reload/shutdown race) ==\n");

    reset_state();
    ngx_memzero(&order, sizeof(order));
    order.log = &test_log;
    arm_slot(&order, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048);
    ngx_autocert_keygen_thread(&ngx_autocert_keygen, &test_log);

    {
        EVP_PKEY  *generated = ngx_autocert_keygen.key;

        OK(generated != NULL, "a key was generated before the order died");

        /* Hold our own reference so the key stays allocated after the
         * handler's free -- comparing the logged pointer against `generated`
         * below must not be a use-after-free read of a recycled address. */
        EVP_PKEY_up_ref(generated);
        freed_n = 0;

        /* This is ngx_autocert_order_free()'s call, made while `order` is
         * still a valid pointer to compare against. */
        ngx_autocert_keygen_abandon(&order);

        OK(ngx_autocert_keygen.order == NULL,
           "_abandon() detached the dying order from the slot");
        OK(ngx_autocert_keygen.busy == 1,
           "_abandon() left the task in flight (a posted task cannot be "
           "cancelled)");

        /* From here `order` is dead as far as production is concerned; the
         * handler must not touch it. Poison it so a stray write is caught by
         * the assertions below (and by ASan, under SANITIZE=1). */
        ngx_memset(&order, 0xA5, sizeof(order));

        run_completion();

        OK(csr_calls == 0, "abandoned completion did NOT resume a dead order");
        OK(finish_calls == 0,
           "abandoned completion did NOT finish a dead order");
        OK(ngx_autocert_keygen.busy == 0, "abandoned completion freed the slot");
        OK(ngx_autocert_keygen.key == NULL,
           "abandoned completion cleared the slot's key");

        /* THE ORACLE. A handler that leaks the key of a dead order calls
         * _key_free zero times and this goes red; one that frees it twice
         * also goes red. This is the whole point of the abandoned path:
         * the key belongs to nobody, so it must be released exactly once. */
        OK(freed_n == 1,
           "abandoned completion called key_free exactly once");
        OK(freed_exactly_once(generated),
           "abandoned completion freed THE GENERATED KEY (not leaked, not "
           "double-freed)");

        EVP_PKEY_free(generated);       /* our own reference */
    }

    printf("== keygen offload: _post() degraded paths ==\n");

    /*
     * These are the paths the first version of this change got wrong, and they
     * are all failure-shaped: no thread pool, a post that fails, a slot still
     * busy with an orphan. Each must still ISSUE, because losing a name's
     * renewal attempt is worse than one stall on the event loop.
     */

    /* (a) no "default" thread pool -> inline, and the order still proceeds. */
    reset_state();
    ngx_memzero(&order, sizeof(order));
    order.log = &test_log;
    pool_get_result = NULL;

    OK(ngx_autocert_keygen_post(&order, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048)
       == NGX_OK,
       "no \"default\" pool: _post() reports the key was made inline (NGX_OK, "
       "not NGX_ERROR)");
    OK(task_post_calls == 0, "no \"default\" pool: nothing was posted");
    OK(csr_calls == 1, "no \"default\" pool: the order still reached the CSR");
    OK(order.cert_key != NULL, "no \"default\" pool: a real key was generated");
    OK(ngx_autocert_keygen.busy == 0,
       "no \"default\" pool: the slot was left free");
    ngx_http_autocert_key_free(order.cert_key);
    order.cert_key = NULL;

    /* (b) the post fails -> inline, AND the poisoned task must be discarded.
     * This is the wedge: nginx leaves event.active = 1 on the cond_signal
     * failure path, and this slot reuses ONE task forever, so keeping it would
     * make every later post fail with "task #N already active" until the
     * worker restarted. */
    reset_state();
    ngx_memzero(&order, sizeof(order));
    order.log = &test_log;
    task_post_result = NGX_ERROR;

    OK(ngx_autocert_keygen_post(&order, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048)
       == NGX_OK,
       "failed post: _post() falls back inline instead of failing the order");
    OK(task_post_calls == 1, "failed post: a post was actually attempted");
    OK(csr_calls == 1, "failed post: the order still reached the CSR");
    OK(order.cert_key != NULL, "failed post: a real key was generated");
    OK(ngx_autocert_keygen.busy == 0, "failed post: the slot was left free");
    OK(ngx_autocert_keygen.order == NULL,
       "failed post: the slot was detached");
    OK(ngx_autocert_keygen.task == NULL,
       "failed post: the POISONED task was discarded (reusing it would wedge "
       "RSA issuance for the life of the worker)");
    OK(task_posted != NULL && task_posted->event.active == 1,
       "failed post: the discarded task really was left active by the pool");
    ngx_http_autocert_key_free(order.cert_key);
    order.cert_key = NULL;

    /* (c) the very next attempt must succeed -- proof the wedge is gone. A
     * cached poisoned task would be refused here by the real pool. */
    {
        ngx_thread_task_t  *first = task_posted;

        ngx_memzero(&order, sizeof(order));
        order.log = &test_log;
        csr_calls = 0;
        task_post_calls = 0;
        task_post_result = NGX_OK;

        OK(ngx_autocert_keygen_post(&order, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048)
           == NGX_AGAIN,
           "after a failed post the NEXT order posts normally (NGX_AGAIN)");
        OK(task_post_calls == 1, "after a failed post: a post was attempted");
        OK(task_posted != first,
           "after a failed post: a FRESH task was allocated, not the poisoned "
           "one");
        OK(task_posted != NULL && task_posted->event.active == 0,
           "after a failed post: the fresh task is not already active");
        OK(ngx_autocert_keygen.busy == 1 && ngx_autocert_keygen.order == &order,
           "after a failed post: the slot is properly armed");

        /* Production deliberately leaks the poisoned task; free it here so the
         * suite stays clean under LeakSanitizer. Guarded: if a regression left
         * it cached in the slot, `first` is still the slot's task and freeing
         * it would double-free at the next reset_state() -- an abort that would
         * hide which assertion above went red. */
        if (first != ngx_autocert_keygen.task) {
            ngx_free(first);
        }
    }

    /* (d) happy path: a successful post arms the slot and returns NGX_AGAIN,
     * generating nothing inline. */
    reset_state();
    ngx_memzero(&order, sizeof(order));
    order.log = &test_log;

    OK(ngx_autocert_keygen_post(&order, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048)
       == NGX_AGAIN,
       "happy path: _post() reports the task is in flight (NGX_AGAIN)");
    OK(csr_calls == 0, "happy path: the CSR waits for the completion");
    OK(order.cert_key == NULL, "happy path: no key was generated inline");
    OK(ngx_autocert_keygen.busy == 1 && ngx_autocert_keygen.order == &order,
       "happy path: the slot is armed and attached");
    OK(ngx_autocert_keygen.key_type == NGX_HTTP_AUTOCERT_CRYPTO_RSA2048,
       "happy path: the requested key type reached the slot");

    /* (e) busy AND DETACHED (an orphan after a reload) -> inline, no ALERT,
     * and the in-flight orphan is left strictly alone. */
    {
        ngx_thread_task_t  *orphan_task = ngx_autocert_keygen.task;

        ngx_autocert_keygen_abandon(&order);     /* order_free()'s call */
        csr_calls = 0;
        task_post_calls = 0;

        ngx_memzero(&other, sizeof(other));
        other.log = &test_log;

        OK(ngx_autocert_keygen_post(&other, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048)
           == NGX_OK,
           "busy+detached: the next order generates inline rather than failing");
        OK(task_post_calls == 0, "busy+detached: nothing new was posted");
        OK(csr_calls == 1, "busy+detached: the order still reached the CSR");
        OK(other.cert_key != NULL, "busy+detached: a real key was generated");
        OK(ngx_autocert_keygen.busy == 1 && ngx_autocert_keygen.task
           == orphan_task,
           "busy+detached: the orphaned task was left untouched");
        ngx_http_autocert_key_free(other.cert_key);
        other.cert_key = NULL;
    }

    /* (f) busy AND ATTACHED is the one genuinely impossible state: two orders
     * in flight at once. That still fails loudly. */
    reset_state();
    ngx_memzero(&order, sizeof(order));
    ngx_memzero(&other, sizeof(other));
    order.log = &test_log;
    other.log = &test_log;
    arm_slot(&order, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048);

    OK(ngx_autocert_keygen_post(&other, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048)
       == NGX_ERROR,
       "busy+attached: two orders in flight is still a hard error");
    OK(csr_calls == 0, "busy+attached: no key was generated inline");
    OK(ngx_autocert_keygen.order == &order,
       "busy+attached: the live order kept its slot");

    printf("== keygen offload: an abandoned task leaves the slot orphaned ==\n");

    /*
     * The state _post() must distinguish. After _abandon(), the slot is busy
     * with NO owner, and stays that way until the orphaned keygen finishes.
     * A reload runs drop_order() inside the live event loop and re-arms the
     * kick, so the next order can reach finalize inside that window; _post()
     * treats busy+detached as "generate inline this once", and reserves the
     * ALERT for busy+ATTACHED, which really would mean two orders in flight.
     *
     * _post() itself needs a live cycle and thread pool and is not sliced, so
     * what is pinned here is the predicate it branches on -- that the two busy
     * states are distinguishable at all, which is what makes the fix possible.
     */
    reset_state();
    ngx_memzero(&order, sizeof(order));
    order.log = &test_log;
    arm_slot(&order, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048);

    OK(ngx_autocert_keygen.busy == 1 && ngx_autocert_keygen.order == &order,
       "a live task is busy AND attached (two orders in flight would be a "
       "real invariant break)");

    ngx_autocert_keygen_abandon(&order);

    OK(ngx_autocert_keygen.busy == 1 && ngx_autocert_keygen.order == NULL,
       "an abandoned task is busy but DETACHED (reachable after a reload; "
       "not an invariant break)");

    printf("== keygen offload: _abandon() is scoped to its own order ==\n");

    reset_state();
    ngx_memzero(&order, sizeof(order));
    ngx_memzero(&other, sizeof(other));
    order.log = &test_log;
    other.log = &test_log;
    arm_slot(&order, NGX_HTTP_AUTOCERT_CRYPTO_RSA2048);

    /* A different order being freed must not detach the in-flight one. */
    ngx_autocert_keygen_abandon(&other);
    OK(ngx_autocert_keygen.order == &order,
       "_abandon(other) left this order's task attached");

    /* And with nothing in flight, _abandon() is a harmless no-op. Leave a
     * sentinel it must not touch: reset_state() has already zeroed order and
     * busy, so re-checking only those two would pass with the call deleted. */
    reset_state();
    ngx_autocert_keygen.key = (EVP_PKEY *) 0x1;   /* must not be touched */
    ngx_autocert_keygen_abandon(&order);
    OK(ngx_autocert_keygen.order == NULL && ngx_autocert_keygen.busy == 0
       && ngx_autocert_keygen.key == (EVP_PKEY *) 0x1,
       "_abandon() with no task in flight is a no-op");
    ngx_autocert_keygen.key = NULL;

    /* An idle slot must also not be detached by a stale pointer match: busy=0
     * means there is no completion coming, so nothing to abandon. */
    reset_state();
    ngx_autocert_keygen.order = &order;      /* stale, not busy */
    ngx_autocert_keygen_abandon(&order);
    OK(ngx_autocert_keygen.order == &order,
       "_abandon() ignores a non-busy slot (no completion is pending)");

    /* That last case parks a pointer to a main() local in a file-scope struct.
     * Clear it before returning so the slot never outlives the storage it
     * names (clang-analyzer-core.StackAddressEscape, and true regardless). */
    reset_state();

    if (failures) {
        printf("\n%d test(s) FAILED\n", failures);
        return 1;
    }

    printf("\nall tests passed\n");
    return 0;
}
