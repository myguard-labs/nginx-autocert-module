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
 *   - FAIRNESS against the REAL adversary: serve.c marks EVERY denial
 *     deferred, so a flood's own names come back as retries from the second
 *     window and DO compete for the reserve. The strong "a flood can never
 *     touch the reserve" claim holds for exactly one window. What bounds the
 *     damage instead is serve.c's `matched` gate: only configured /
 *     wildcard-covered / runtime-issued names ever get a cache entry, so the
 *     deferred set is capped by the operator's name set. See FAIRNESS CASE 2
 *     in main() for the measured bound and the threshold past which a
 *     last-arriving name can still be starved.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include "../../../src/ngx_autocert_loadcap.h"

#include <assert.h>
#include <stdio.h>


#define TEST_MAX_DEFERRED  64


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
     * --- FAIRNESS, CASE 1: a flood whose names never re-present ---
     *
     * SCOPE, stated up front because the obvious reading of this case is
     * WRONG: every flood request here passes retry = 0 in every window, so
     * this models an attacker STRICTLY WEAKER than the real one. Real serve.c
     * marks every denial cert->deferred = 1, so a real flood's names come back
     * as retries from window 2. This case is kept only because it pins the one
     * window where the strong property genuinely holds -- the window a flood
     * STARTS, when its names have never been denied and so cannot reach the
     * reserve at all. The honest bound against the real adversary is measured
     * by CASE 2 below; do not read this assertion as the module's guarantee.
     *
     * On the unmodified fixed window the legitimate name is denied in window 1
     * and again in every later window: the flood always gets there first and
     * there is nothing it cannot spend. With the reserve, the legitimate name
     * is a RETRY from window 2 onward and draws on a pool that THIS
     * (non-re-presenting) flood can never touch, so it loads in window 2.
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
              "fairness case 1 (non-re-presenting flood): a deferred name is "
              "retried instead of being starved indefinitely");
        CHECK(served_in_window != 0 && served_in_window <= 2,
              "fairness case 1 (non-re-presenting flood): the retry happens "
              "within 2 windows -- NOTE this models a weaker adversary than "
              "serve.c produces; see case 2 for the real bound");
    }

    /*
     * --- FAIRNESS, CASE 2: THE REAL ADVERSARY -- a flood that re-presents its
     * own denied names as retries ---
     *
     * This is the case that measures the module's actual guarantee.
     * ngx_autocert_serve.c sets cert->deferred = 1 on EVERY denial, in the
     * unconditional `else if (now != cert->checked)` branch, with no
     * filtering. So a flood name denied in window W arrives in window W+1 with
     * retry = 1 and competes for the reserve alongside the victim. The claim
     * "a flood can only ever touch the general pool" is true for exactly one
     * window and false thereafter.
     *
     * What keeps this bounded is a different mechanism: serve.c only creates a
     * cache entry -- and therefore only ever sets a deferred bit -- for a name
     * that passed its `matched` gate (configured / wildcard-covered /
     * runtime-issued). An unconfigured SNI returns the bootstrap certificate
     * before any entry exists. So the deferred set D is bounded by the
     * OPERATOR'S configured name set and CANNOT be inflated by attacker-chosen
     * SNIs, however much entropy the client has.
     *
     * The measured property, derived from the code rather than picked to make
     * a test pass (G = general share, R = reserve, n = units per name):
     *
     *   D <  (G + 2R) / n : the deferred set drains faster than it refills and
     *                       the victim is served within a few windows.
     *   D >= (G + 2R) / n : the gated deferred set alone can refill both pools
     *                       every window, and since a fixed window has no
     *                       ordering fairness, a victim that consistently
     *                       arrives LAST can be pushed back indefinitely.
     *
     * BE PLAIN ABOUT THIS: the bound asserted below is much larger than case
     * 1's "<= 2", and above the threshold there is no bound at all. That is
     * still a real improvement over the plain fixed window, which is starved
     * by ANY sustained flood at ANY D including D = 0 -- SNI entropy alone was
     * enough. Here the attack requires the operator to have configured more
     * names than a window can refresh, and it self-heals as soon as the
     * deferred set drops back under the threshold.
     */
    {
        ngx_uint_t  limit, slots, reserve, general, w, threshold;
        ngx_uint_t  ndef, served_in_window;
        static ngx_uint_t  attacker_deferred[TEST_MAX_DEFERRED];
        ngx_uint_t  victim_deferred, j;

        limit = 64;
        slots = 2;                       /* dual-key deployment: EC + RSA */
        reserve = ngx_autocert_loadcap_reserve(limit);
        general = limit - reserve;

        /* The exact point past which the property gives out, in NAMES. */
        threshold = (general + 2 * reserve) / slots;

        CHECK(threshold == 40,
              "fairness case 2: threshold (G + 2R)/n is 40 names for "
              "limit 64, 2 key types -- the arithmetic the cases below use");

        /*
         * (a) BELOW the threshold: a gated deferred set that re-presents every
         * window, plus a victim arriving last, still gets the victim served.
         */
        /*
         * D is a LITERAL, not `threshold - 1`. Deriving it from the live
         * reserve would let a mutation that removes the reserve also move the
         * D under test, and the case would stay green against the very change
         * it exists to catch. 39 sits in the gap that only the reserve opens:
         * without a reserve the deferred set alone refills the window from
         * D = G/n = 32 upward and 39 starves; with it the threshold moves out
         * to (G + 2R)/n = 40 and 39 is still served. That gap IS the reserve's
         * measurable benefit against the real adversary.
         */
        ndef = 39;
        assert(ndef <= TEST_MAX_DEFERRED);
        for (j = 0; j < ndef; j++) {
            attacker_deferred[j] = 0;
        }
        victim_deferred = 0;
        served_in_window = 0;

        ngx_memzero(&cap, sizeof(cap));

        for (w = 1; w <= 64 && served_in_window == 0; w++) {
            time_t  now = 30000 + (time_t) w;

            /* The REAL flood: each name re-presents carrying whatever
             * deferred bit serve.c would have left on it last window. */
            for (j = 0; j < ndef; j++) {
                attacker_deferred[j] =
                    ngx_autocert_loadcap_admit_retry_n(&cap, now, limit, slots,
                                                       attacker_deferred[j])
                    ? 0 : 1;
            }

            /* The victim, arriving last -- the worst ordering for it. */
            if (ngx_autocert_loadcap_admit_retry_n(&cap, now, limit, slots,
                                                   victim_deferred))
            {
                served_in_window = w;

            } else {
                victim_deferred = 1;     /* serve.c sets cert->deferred here */
            }
        }

        CHECK(served_in_window != 0,
              "fairness case 2a (real flood, D just under threshold): the "
              "victim is eventually served, not starved");
        CHECK(served_in_window != 0 && served_in_window <= 3,
              "fairness case 2a: served within 3 windows at D = threshold - 1 "
              "-- weaker than case 1's <= 2, and it degrades to no bound at "
              "all one name later (case 2b)");

        /*
         * (b) AT the threshold: the same flood with one more gated name
         * starves the victim outright. Asserting this is the point -- a test
         * that only showed the good case would be modelling the weak
         * adversary all over again.
         */
        ndef = 40;                       /* == threshold, likewise a literal */
        assert(ndef <= TEST_MAX_DEFERRED);
        for (j = 0; j < ndef; j++) {
            attacker_deferred[j] = 0;
        }
        victim_deferred = 0;
        served_in_window = 0;

        ngx_memzero(&cap, sizeof(cap));

        for (w = 1; w <= 512 && served_in_window == 0; w++) {
            time_t  now = 40000 + (time_t) w;

            for (j = 0; j < ndef; j++) {
                attacker_deferred[j] =
                    ngx_autocert_loadcap_admit_retry_n(&cap, now, limit, slots,
                                                       attacker_deferred[j])
                    ? 0 : 1;
            }

            if (ngx_autocert_loadcap_admit_retry_n(&cap, now, limit, slots,
                                                   victim_deferred))
            {
                served_in_window = w;

            } else {
                victim_deferred = 1;
            }
        }

        CHECK(served_in_window == 0,
              "fairness case 2b (real flood, D at threshold): the victim IS "
              "pushed back indefinitely -- the documented limit of the "
              "reserve, asserted so nobody re-derives the false strong claim");
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

    /* --- EXHAUSTIVE IDLE-WORKER INVARIANT SWEEP ---
     *
     * The invariant: on an idle worker (nothing spent this window) any request
     * with n <= limit MUST be admitted, retry or not. The reserve may only
     * redistribute budget under contention; it must never make an idle worker
     * refuse work it has the budget for.
     *
     * This class of bug -- a guard whose condition no longer matches the
     * effective ceiling after a refactor -- is invisible to hand-picked cases:
     * the reserve made the first-attempt ceiling `general`, while the wedge
     * guard still tested `n > limit`, so every n in `general < n <= limit`
     * (e.g. limit 2, n 2, the dual RSA+EC default) was denied permanently in
     * every window. Only a sweep over every real combination catches that.
     *
     * Also asserts the unsigned-arithmetic safety net: `limit - reserve` and
     * `reserve - spent_res` are ngx_uint_t subtractions, so an invariant slip
     * underflows to a huge value rather than going negative. reserve < limit
     * and spent_res <= reserve are checked for every swept limit.
     */
    {
        static const ngx_uint_t  big[] = { 100, 255, 256, 1000, 65535,
                                           1000000 };
        ngx_uint_t               lim, nn, rr, k, res, gen, ok;
        ngx_uint_t               bad_admit = 0, bad_res = 0, bad_charge = 0;
        ngx_uint_t               bad_wedge_once = 0;

        for (k = 0; k < 64 + 1 + sizeof(big) / sizeof(big[0]); k++) {

            lim = (k <= 64) ? k : big[k - 65];

            res = ngx_autocert_loadcap_reserve(lim);

            /* reserve must never reach the limit, or `limit - reserve`
             * underflows / the general pool vanishes. */
            if (lim > 0 && res >= lim) {
                bad_res++;
            }
            if (lim == 0 && res != 0) {
                bad_res++;
            }

            gen = lim - res;

            for (nn = 0; nn <= 4; nn++) {
                for (rr = 0; rr <= 1; rr++) {

                    ngx_memzero(&cap, sizeof(cap));

                    ok = ngx_autocert_loadcap_admit_retry_n(&cap, 30000, lim,
                                                            nn, rr);

                    /* limit 0 disables the cap; n 0 charges nothing. Every
                     * other request with n <= limit must be admitted on an
                     * idle worker. */
                    if (lim == 0 || nn == 0 || nn <= lim) {
                        if (ok != 1) {
                            bad_admit++;
                        }
                    }

                    /* n > limit is the operator-misconfiguration path: still
                     * admitted once per window, never denied forever. */
                    if (lim > 0 && nn > lim && ok != 1) {
                        bad_admit++;
                    }

                    /* The wedge path is a once-per-window admission, not a
                     * standing exemption: a second call in the SAME window
                     * with identical args must now be denied, because the
                     * first call already charged both pools closed. Reusing
                     * `cap` here (no memzero) is the point -- it is what
                     * distinguishes this from the ok==1 check above, which a
                     * cap that always admits n > limit would also pass. */
                    if (lim > 0 && nn > lim && ok == 1) {
                        ngx_uint_t  ok2;

                        ok2 = ngx_autocert_loadcap_admit_retry_n(&cap, 30000,
                                                                 lim, nn, rr);
                        if (ok2 != 0) {
                            bad_wedge_once++;
                        }
                    }

                    /* Charging must stay inside both pools -- a slip here is
                     * what makes `reserve - spent_res` underflow later. */
                    if (cap.spent > gen || cap.spent_res > res) {
                        bad_charge++;
                    }
                }
            }
        }

        CHECK(bad_res == 0,
              "sweep: reserve is < limit for every limit (no underflow of "
              "limit - reserve)");
        CHECK(bad_admit == 0,
              "sweep: an idle worker admits every request with n <= limit, "
              "retry or not (no permanent wedge)");
        CHECK(bad_charge == 0,
              "sweep: neither pool is ever overcharged (no underflow of "
              "reserve - spent_res)");
        CHECK(bad_wedge_once == 0,
              "sweep: the wedge path (n > limit) admits at most once per "
              "window -- an immediate second call with the same args is "
              "denied");
    }

    if (failures) {
        fprintf(stderr, "\n%d FAILURE(S)\n", failures);
        return 1;
    }
    fprintf(stderr, "\nALL PASS\n");
    return 0;
}
