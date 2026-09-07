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
 * WHAT THIS DOES NOT COVER: ngx_autocert_keygen_post(), which needs a live
 * cycle and a configured "default" thread pool (ngx_thread_pool_get /
 * ngx_thread_task_post) that this TU has no harness for -- including its
 * no-pool inline fallback. Those are exercised by the module's integration
 * path. The predicate that gates entry to _post() IS covered here.
 *
 * The slot is static in ngx_autocert_order.c, so this TU slices just it via
 * ci/tests/unit/extract_keygen.sh -- the whole .c is the ACME order state
 * machine and would drag in the account POST primitive, JSON, the shm zones
 * and the event loop to reach one struct. Locked to production code, no copy
 * drift.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

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
    ngx_memzero(&ngx_autocert_keygen, sizeof(ngx_autocert_keygen));
    csr_calls = 0;
    csr_rc = NGX_OK;
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

    /* And with nothing in flight, _abandon() is a harmless no-op. */
    reset_state();
    ngx_autocert_keygen_abandon(&order);
    OK(ngx_autocert_keygen.order == NULL && ngx_autocert_keygen.busy == 0,
       "_abandon() with no task in flight is a no-op");

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
