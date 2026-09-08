/*
 * Unit tests for ngx_autocert_loadcap.h — the per-worker, per-second cap on
 * synchronous certificate loads performed on the TLS handshake path. Pure
 * primitive, no slab / nginx runtime needed; same header-only idiom as
 * test_ratecap.c.
 *
 * The defect this guards: serve.c's per-name `checked` throttle bounds disk
 * reloads to once per second PER NAME, so N distinct SNIs arriving in one
 * second cost N synchronous open+read+PEM-parse loads on the worker event
 * loop, with N chosen by the attacker. The cap is the missing GLOBAL bound.
 *
 * Verifies:
 *   - a fresh (zeroed) cap admits the first `limit` loads and no more
 *   - the budget resets when the second rolls over, forwards AND backwards
 *   - limit == 0 disables the cap entirely (unlimited, counter untouched)
 *   - THE LOAD-BEARING ONE: an SNI flood of many distinct names inside a
 *     single second is bounded to `limit` loads, not one per name. This is the
 *     assertion that goes red when the cap is neutered; the individual
 *     admit/deny checks above are satisfied by a no-op admit() only in part,
 *     so this one models the actual attack.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include "../../../src/ngx_autocert_loadcap.h"

#include <stdio.h>


/*
 * Link stubs: ngx_core.h's headers pull an extern ngx_cycle reference in. This
 * test calls nothing from the nginx runtime, so a trivial definition suffices
 * plus the ngx_pnalloc/ngx_alloc refs ngx_string.o drags in via
 * ngx_pstrdup/ngx_sort, which this test never calls (same idiom as
 * test_ratecap.c).
 */
volatile ngx_cycle_t  *ngx_cycle;

void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{ (void) pool; (void) size; return NULL; }

void *ngx_alloc(size_t size, ngx_log_t *log);
void *ngx_alloc(size_t size, ngx_log_t *log)
{ (void) size; (void) log; return NULL; }


static int  failures;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL: %s\n", msg);                                \
            failures++;                                                        \
        } else {                                                               \
            fprintf(stderr, "ok:   %s\n", msg);                                \
        }                                                                      \
    } while (0)


/*
 * Model the serve.c hot path for a flood of `nnames` DISTINCT SNIs arriving
 * inside wall second `now`. Every name is a fresh cache entry, so every one of
 * them passes the per-name `now != cert->checked` test — which is precisely the
 * hole the per-name throttle cannot close. Returns how many of them actually
 * reached the synchronous disk load.
 */
static ngx_uint_t
flood(ngx_autocert_loadcap_t *cap, time_t now, ngx_uint_t nnames,
    ngx_uint_t limit)
{
    ngx_uint_t  i, loads;

    loads = 0;
    for (i = 0; i < nnames; i++) {
        /* per-name gate: always true here, each name is a new entry */
        if (ngx_autocert_loadcap_admit(cap, now, limit)) {
            loads++;
        }
    }
    return loads;
}


int
main(void)
{
    ngx_autocert_loadcap_t  cap;
    ngx_uint_t              i, admitted;

    /* --- a fresh, zeroed cap admits exactly `limit` --- */
    ngx_memzero(&cap, sizeof(cap));
    admitted = 0;
    for (i = 0; i < 10; i++) {
        admitted += ngx_autocert_loadcap_admit(&cap, 1000, 4);
    }
    CHECK(admitted == 4, "zeroed cap admits exactly limit loads in one second");
    CHECK(cap.spent == 4, "spent stops at the limit, it does not keep counting");

    /* The zeroed state must not be mistaken for "second 0, already spent" --
     * ngx_time() is never 0 in a live worker, but the reset is on inequality
     * so the very first handshake of the worker's life is admitted. */
    ngx_memzero(&cap, sizeof(cap));
    CHECK(ngx_autocert_loadcap_admit(&cap, 1, 1) == 1,
          "the first load of a worker's life is admitted");

    /* --- the budget resets on a new second --- */
    ngx_memzero(&cap, sizeof(cap));
    (void) flood(&cap, 2000, 100, 4);
    CHECK(ngx_autocert_loadcap_admit(&cap, 2000, 4) == 0,
          "still denied later in the same second");
    CHECK(ngx_autocert_loadcap_admit(&cap, 2001, 4) == 1,
          "budget resets when the second rolls over");

    /* A backwards clock step compares unequal exactly like a forwards one, so
     * it resets rather than wedging the worker at a permanently-spent budget. */
    ngx_memzero(&cap, sizeof(cap));
    (void) flood(&cap, 3000, 100, 4);
    CHECK(ngx_autocert_loadcap_admit(&cap, 2990, 4) == 1,
          "a backwards clock step resets rather than wedging the budget");

    /* --- limit == 0 is off --- */
    ngx_memzero(&cap, sizeof(cap));
    CHECK(flood(&cap, 4000, 1000, 0) == 1000,
          "limit 0 disables the cap (all 1000 admitted)");
    CHECK(cap.spent == 0 && cap.second == 0,
          "limit 0 does not touch the counter state");

    /*
     * --- THE ATTACK, bounded ---
     *
     * 10000 distinct SNIs inside one second. Without the global cap every one
     * of them is a fresh cache entry and therefore a fresh synchronous
     * open + fstat + up-to-1MB read + PEM parse on the worker event loop. With
     * it, the worker does at most `limit` of them and serves cached/bootstrap
     * certs for the rest, deferring their loads to later seconds.
     */
    ngx_memzero(&cap, sizeof(cap));
    CHECK(flood(&cap, 5000, 10000, 64) == 64,
          "an SNI flood of 10000 distinct names costs 64 loads, not 10000");

    /* And the deferral is real: the next second admits a fresh budget, so a
     * legitimate name caught behind the flood still loads rather than being
     * starved forever. */
    CHECK(ngx_autocert_loadcap_admit(&cap, 5001, 64) == 1,
          "a name deferred by the flood loads in the next second");

    /* A limit of 1 is a degenerate but legal configuration. */
    ngx_memzero(&cap, sizeof(cap));
    CHECK(flood(&cap, 6000, 500, 1) == 1,
          "limit 1 admits exactly one load per second");

    /*
     * --- DUAL-SLOT: the cap must charge the WHOLE reload batch, not one
     * unit per batch regardless of slot count ---
     *
     * This is the CodeRabbit MAJOR: serve.c's gate charged a single unit via
     * ngx_autocert_loadcap_admit() and then reloaded up to NGX_AUTOCERT_NSLOTS
     * slots in the loop it guarded, so a dual-key (EC+RSA) deployment got 2x
     * the configured budget. Model one admitted "handshake" as a request for
     * 2 units (2 enabled slots) via admit_n, repeated once per distinct SNI
     * (the per-name gate always passes here, same as flood() above). With
     * limit 64 and 2 slots/name, total slot reloads across the flood must
     * stay <= 64 -- NOT 128. This assertion is red against the unfixed
     * single-unit-per-batch charging (it would allow 64 batches * 2 slots =
     * 128 slot reloads).
     */
    {
        ngx_uint_t  reqs, slot_reloads, limit;

        ngx_memzero(&cap, sizeof(cap));
        limit = 64;
        reqs = 0;
        slot_reloads = 0;
        for (i = 0; i < 10000; i++) {
            if (ngx_autocert_loadcap_admit_n(&cap, 7000, limit, 2)) {
                reqs++;
                slot_reloads += 2;
            }
        }
        CHECK(reqs == 32, "dual-slot: 32 handshakes admitted, not 64");
        CHECK(slot_reloads <= limit,
              "dual-slot: total slot reloads stay within the configured "
              "limit (<=64, not 128)");
        CHECK(slot_reloads == 64,
              "dual-slot: the full budget is used, none wasted");
    }

    /*
     * --- all-or-nothing: a request that does not fully fit charges NOTHING
     * ---
     *
     * 3 units remain (limit 10, spent 7); a request for 5 must be denied and
     * must not partially charge the 3 that *would* fit.
     */
    ngx_memzero(&cap, sizeof(cap));
    CHECK(ngx_autocert_loadcap_admit_n(&cap, 8000, 10, 7) == 1,
          "all-or-nothing setup: 7 of 10 admitted");
    CHECK(cap.spent == 7, "all-or-nothing setup: spent is exactly 7");
    CHECK(ngx_autocert_loadcap_admit_n(&cap, 8000, 10, 5) == 0,
          "all-or-nothing: a request of 5 with only 3 left is denied");
    CHECK(cap.spent == 7,
          "all-or-nothing: spent is UNCHANGED by the denied request "
          "(no partial charge)");
    CHECK(ngx_autocert_loadcap_admit_n(&cap, 8000, 10, 3) == 1,
          "all-or-nothing: the exact remaining amount is still admitted");
    CHECK(cap.spent == 10, "all-or-nothing: spent now reflects the full 10");

    /*
     * --- wedge case: a batch bigger than the configured limit must never
     * wedge cert loading permanently ---
     *
     * limit 1 with 2 enabled slots (e.g. autocert_handshake_load_limit 1 with
     * both EC and RSA configured) can never satisfy an all-or-nothing
     * reservation of 2 units. Denying forever would permanently stop
     * certificate loading, which is worse than the unbounded-cost bug this
     * cap fixes. The documented behaviour: such a request is admitted once
     * per window (making progress every second) and consumes the whole
     * window's budget, rather than being denied forever.
     */
    ngx_memzero(&cap, sizeof(cap));
    CHECK(ngx_autocert_loadcap_admit_n(&cap, 9000, 1, 2) == 1,
          "wedge: a 2-unit request under limit 1 is admitted once "
          "(does not wedge)");
    CHECK(ngx_autocert_loadcap_admit_n(&cap, 9000, 1, 2) == 0,
          "wedge: a second 2-unit request in the same second is denied");
    CHECK(ngx_autocert_loadcap_admit_n(&cap, 9001, 1, 2) == 1,
          "wedge: the next second admits again -- progress is made, "
          "not a permanent stall");

    if (failures) {
        fprintf(stderr, "\n%d FAILURE(S)\n", failures);
        return 1;
    }
    fprintf(stderr, "\nALL PASS\n");
    return 0;
}
