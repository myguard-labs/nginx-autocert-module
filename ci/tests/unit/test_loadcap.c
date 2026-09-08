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
        /* per-name gate: always true here, each name is a new entry. Every
         * flood name is a FIRST attempt (retry 0) -- a name only becomes a
         * retry by having been denied in an earlier window, which is exactly
         * what the attacker cannot manufacture at will. */
        if (ngx_autocert_loadcap_admit(cap, now, limit)) {
            loads++;
        }
    }
    return loads;
}


/*
 * The general (non-reserved) share of `limit`: what a first attempt can reach
 * in one window. Mirrors ngx_autocert_loadcap_reserve() so the expectations
 * below read as arithmetic rather than magic numbers.
 */
static ngx_uint_t
general_of(ngx_uint_t limit)
{
    return limit - ngx_autocert_loadcap_reserve(limit);
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
    CHECK(admitted == general_of(4),
          "zeroed cap admits exactly the general share of limit in one second");
    CHECK(cap.spent == general_of(4),
          "spent stops at the general share, it does not keep counting");
    CHECK(cap.spent_res == 0,
          "first attempts never touch the retry reserve");

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
    CHECK(flood(&cap, 5000, 10000, 64) == general_of(64),
          "an SNI flood of 10000 distinct names costs at most the general "
          "share of the budget, not 10000");
    CHECK(cap.spent + cap.spent_res <= 64,
          "an SNI flood never exceeds the configured per-second limit");

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
        CHECK(reqs == general_of(limit) / 2,
              "dual-slot: handshakes admitted are the general share / 2, "
              "not one per name");
        CHECK(slot_reloads <= limit,
              "dual-slot: total slot reloads stay within the configured "
              "limit (<=64, not 128)");
        CHECK(slot_reloads == general_of(limit),
              "dual-slot: the whole general share is used, none wasted");
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
          "all-or-nothing: a request of 5 with only 1 general unit left is "
          "denied");
    CHECK(cap.spent == 7,
          "all-or-nothing: spent is UNCHANGED by the denied request "
          "(no partial charge)");
    CHECK(ngx_autocert_loadcap_admit_n(&cap, 8000, 10, 1) == 1,
          "all-or-nothing: the exact remaining general amount is admitted");
    CHECK(cap.spent == general_of(10),
          "all-or-nothing: spent now reflects the full general share");

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

    /*
     * --- FAIRNESS: a deferred name is retried within a BOUNDED number of
     * windows under a sustained flood ---
     *
     * This is the starvation the plain fixed window could not prevent. Model a
     * client that opens enough distinct-SNI handshakes at the TOP of every
     * window to drain whatever budget a first attempt can reach, and one
     * legitimate name that arrives AFTER the flood in each window. On the
     * unmodified fixed window the legitimate name is denied in window 1, and
     * denied again in window 2, and in window 3, ... forever: the flood always
     * gets there first and there is nothing it cannot spend. With the reserve,
     * the legitimate name is a RETRY from window 2 onward and draws on a pool
     * the flood -- made entirely of first attempts -- can never touch, so it
     * loads in window 2.
     *
     * The assertion is the bound, not a specific window: served within a small
     * constant number of windows, and NOT "eventually, if the flood stops".
     */
    {
        ngx_uint_t  limit, slots, w, deferred, served_in_window;

        limit = 64;
        slots = 2;                       /* dual-key deployment: EC + RSA */
        deferred = 0;                    /* victim not yet denied by cap */
        served_in_window = 0;

        ngx_memzero(&cap, sizeof(cap));

        for (w = 1; w <= 8 && served_in_window == 0; w++) {
            time_t  now = 20000 + (time_t) w;

            /* The flood: 10000 distinct new SNIs, first in the window. */
            for (i = 0; i < 10000; i++) {
                (void) ngx_autocert_loadcap_admit_retry_n(&cap, now, limit,
                                                          slots, 0);
            }

            /* The victim, arriving after the flood has had its turn. */
            if (ngx_autocert_loadcap_admit_retry_n(&cap, now, limit, slots,
                                                   deferred))
            {
                served_in_window = w;

            } else {
                deferred = 1;            /* serve.c sets cert->deferred here */
            }
        }

        CHECK(served_in_window != 0,
              "fairness: a deferred name is retried under a sustained flood "
              "instead of being starved indefinitely");
        CHECK(served_in_window != 0 && served_in_window <= 2,
              "fairness: the retry happens within 2 windows, a bound the "
              "flood cannot push out");
    }

    /*
     * --- the reserve is retry-ONLY: a flood cannot spend it by pretending
     * to be busy ---
     *
     * A first attempt stops at the general share even when it asks forever,
     * leaving the reserve intact for names the cap itself deferred. This is
     * what makes the bound above independent of flood size.
     */
    ngx_memzero(&cap, sizeof(cap));
    (void) flood(&cap, 21000, 100000, 64);
    CHECK(cap.spent_res == 0,
          "reserve: 100000 first attempts leave the retry reserve untouched");
    CHECK(ngx_autocert_loadcap_admit_retry_n(&cap, 21000, 64, 2, 1) == 1,
          "reserve: a retry is admitted in the SAME window the flood "
          "exhausted the general share");
    CHECK(ngx_autocert_loadcap_admit_retry_n(&cap, 21000, 64, 2, 0) == 0,
          "reserve: a first attempt is still denied in that window");

    /*
     * --- the reserve is bounded too: it does not become a second unbounded
     * budget for retries ---
     */
    {
        ngx_uint_t  reserve, admitted_retries;

        reserve = ngx_autocert_loadcap_reserve(64);
        ngx_memzero(&cap, sizeof(cap));
        (void) flood(&cap, 22000, 100000, 64);   /* drain the general share */
        admitted_retries = 0;
        for (i = 0; i < 10000; i++) {
            admitted_retries += ngx_autocert_loadcap_admit_retry_n(&cap, 22000,
                                                                   64, 1, 1);
        }
        CHECK(admitted_retries == reserve,
              "reserve: retries are capped at the reserve, not unbounded");
        CHECK(cap.spent + cap.spent_res <= 64,
              "reserve: general + reserve never exceeds the configured limit");
    }

    /*
     * --- a retry prefers the general pool, so the split is invisible on a
     * quiet worker ---
     */
    ngx_memzero(&cap, sizeof(cap));
    CHECK(ngx_autocert_loadcap_admit_retry_n(&cap, 23000, 64, 2, 1) == 1,
          "quiet worker: a retry is admitted");
    CHECK(cap.spent == 2 && cap.spent_res == 0,
          "quiet worker: the retry spends the general pool, not the reserve");

    /* --- reserve sizing: never zero once splittable, never the whole budget,
     * so first-time loads (cache warm-up) are never locked out --- */
    CHECK(ngx_autocert_loadcap_reserve(1) == 0,
          "reserve sizing: limit 1 is not splittable (reserve 0)");
    CHECK(ngx_autocert_loadcap_reserve(2) == 1
          && ngx_autocert_loadcap_reserve(3) == 1,
          "reserve sizing: a small limit still reserves one unit");
    CHECK(ngx_autocert_loadcap_reserve(64) == 16,
          "reserve sizing: a quarter of the budget");
    for (i = 1; i <= 1024; i++) {
        if (ngx_autocert_loadcap_reserve(i) >= i) {
            break;
        }
    }
    CHECK(i == 1025,
          "reserve sizing: the reserve is never the whole budget for any "
          "limit in 1..1024");

    /* limit 1 keeps its degenerate first-come behaviour: no reserve to give. */
    ngx_memzero(&cap, sizeof(cap));
    CHECK(flood(&cap, 24000, 500, 1) == 1,
          "limit 1: still exactly one load per second (no reserve to split)");
    CHECK(ngx_autocert_loadcap_admit_retry_n(&cap, 24000, 1, 1, 1) == 0,
          "limit 1: a retry gets no reserve either, the budget is spent");

    if (failures) {
        fprintf(stderr, "\n%d FAILURE(S)\n", failures);
        return 1;
    }
    fprintf(stderr, "\nALL PASS\n");
    return 0;
}
