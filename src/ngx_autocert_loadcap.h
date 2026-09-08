/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * Per-worker, per-second cap on synchronous certificate loads performed on the
 * TLS handshake path, factored out as a pure primitive so it can be unit-tested
 * without the whole serve TU (which pulls OpenSSL and the store I/O). No global
 * state here — the window is passed in by the caller.
 *
 * WHY. ngx_http_autocert_cache_reload() does open + fstat + up to 1 MB of reads
 * per slot plus PEM parsing SYNCHRONOUSLY on the worker event loop. The cache
 * entry's `checked` throttle bounds that to once per second PER NAME, which is
 * exactly the wrong axis: an attacker who varies the SNI gets a fresh cache
 * entry every time, so N distinct SNIs in one second cost N synchronous
 * multi-syscall PEM loads and N is chosen by the attacker. This adds the
 * missing GLOBAL (per-worker) bound on top of the per-name one; both hold.
 *
 * DEGRADATION when the budget is exhausted (documented contract, do not change
 * without changing the docs): the handshake SKIPS the disk load and installs
 * whatever the cache entry already holds — i.e. the previously loaded, still
 * valid certificate for that exact name. That is byte-for-byte the behaviour of
 * the existing per-name throttle on a second handshake within the same second,
 * so it is not a new failure mode. A name with nothing cached (never loaded, or
 * not yet issued) installs nothing and cert_cb returns 1, letting nginx serve
 * the server's configured/bootstrap certificate exactly as it does before
 * issuance.
 * A deferred load is retried on the next handshake in the next second: the cap
 * delays a load, it never abandons one, and it never substitutes another name's
 * certificate. Serving a wrong certificate or failing the handshake are both
 * excluded by construction — this code only ever answers "load now?" with no.
 *
 * FAIRNESS. "Retried in the next second" is only true if the retry actually
 * wins budget in that second, and a plain fixed window is first-come-first-
 * served: a client that opens enough distinct-SNI handshakes at the top of
 * every window drains the whole budget before the deferred name is retried,
 * and does so again the next window, and the next. The deferred name then
 * keeps serving its last-good cached certificate (or the bootstrap one) for as
 * long as the flood lasts — unbounded, which is starvation, not deferral.
 *
 * The fix is a RESERVE. Each window's budget is split in two:
 *
 *     general  = limit - reserve   any request may draw from it
 *     reserve  = limit / 4 (>=1)   ONLY a request marked as a RETRY may draw
 *                                  from it — that is, a name the cap itself
 *                                  denied in an EARLIER window.
 *
 * A flood is made of names the cap has never seen, so every one of its
 * requests is a first attempt and can only ever touch `general`. It therefore
 * cannot consume the reserve no matter how many distinct SNIs it presents.
 * A name deferred in window W arrives in window W+1 as a retry, competing for
 * the reserve against other deferred names only — a set the attacker cannot
 * inflate, because entering it requires having already been denied. That turns
 * "retried eventually, maybe never" into a bounded wait: with R reserve units
 * and D genuinely deferred names, every deferred name is retried within
 * ceil(D / R) windows regardless of flood size.
 *
 * Retries draw from `general` FIRST and only fall back to the reserve, so on
 * an idle or lightly loaded worker the split is invisible: the full `limit` is
 * still available to whoever asks, and the reserve is normally never reached.
 * The invariant that keeps this honest is: on an idle worker (nothing spent
 * this window) any request with n <= limit is ADMITTED, retry or not. The
 * reserve only ever redistributes budget under contention; it must never make
 * an idle worker refuse work it has the budget for. See WEDGE CASE below for
 * the one path that enforces this when n does not fit in `general`, and for
 * the configurations where it costs the ceil(D / R) bound.
 * The reserve costs the flood nothing it was entitled to either — those units
 * were always going to be spent on somebody.
 */
#ifndef NGX_AUTOCERT_LOADCAP_H_INCLUDED
#define NGX_AUTOCERT_LOADCAP_H_INCLUDED


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * The per-worker load budget, one instance per worker process (a file-static in
 * the serve TU). Zeroed state is correct at startup: second 0 with 0 spent
 * still admits the first `limit` loads because the counter is reset whenever
 * `second` does not equal now, and ngx_time() is never 0 in a running worker.
 */
typedef struct {
    time_t      second;     /* the wall second the counters are charged to */
    ngx_uint_t  spent;      /* units taken from the general pool that second */
    ngx_uint_t  spent_res;  /* units taken from the retry reserve that second */
} ngx_autocert_loadcap_t;


/*
 * Size of the retry-only reserve carved out of `limit` for the window. A
 * quarter of the budget, never less than one unit once there is more than one
 * unit to split, and never the whole budget — a reserve equal to `limit` would
 * lock first-time loads (cache warm-up after a reload, the common case) out
 * entirely, which is a worse failure than the starvation it guards against.
 * limit == 1 yields reserve 0: there is nothing to split, and the degenerate
 * single-unit budget keeps its existing first-come behaviour.
 */
static ngx_inline ngx_uint_t
ngx_autocert_loadcap_reserve(ngx_uint_t limit)
{
    if (limit < 2) {
        return 0;
    }

    return limit / 4 ? limit / 4 : 1;
}


/*
 * Ask for permission to perform `n` synchronous certificate loads at `now`,
 * as one all-or-nothing reservation: either all `n` units are admitted and
 * charged together, or none are and the counters are left untouched. This is
 * what lets a caller reserve for a whole batch of slot reloads up front instead
 * of charging per-iteration inside the loop, which would let a request that
 * only partially fits the remaining budget still perform some of its disk I/O.
 *
 * `retry` marks a request whose name this cap DENIED in an earlier window. Such
 * a request may draw on the retry reserve when the general pool is exhausted;
 * a first attempt (`retry` 0) may not. See the FAIRNESS note at the top of this
 * file for why that bounds the wait of a deferred name under a sustained flood.
 * The caller owns the per-name "was deferred" bit — the cap is stateless per
 * name by design (one struct per worker, not per entry).
 *
 * WEDGE CASE: a request that cannot fit in the pool it is allowed to draw from
 * would be denied in every window forever, on an idle worker, which is worse
 * than the bug this cap fixes. The effective ceiling for a request that may
 * only touch the general pool is `general`, NOT `limit`, so the guard tests
 * `n > general` -- testing `n > limit` would leave every `n` in
 * `general < n <= limit` denied permanently (e.g. limit 2 with two enabled
 * slots: reserve 1, general 1, n 2 -- denied as a first attempt AND as a
 * retry, since n also exceeds the reserve). Whenever the request cannot fit in
 * `general`, treat the whole limit as `n` for this call (i.e. admit once
 * nothing has been spent yet, charging BOTH pools) so the batch still goes
 * through exactly once per second rather than never.
 *
 * DOCUMENTED LIMIT of the reserve's fairness bound: this fallback lets a FIRST
 * attempt reach the reserve, so the ceil(D / R) bound above holds only while
 * `general >= n`, i.e. `limit >= n + reserve`. With the module's slot count of
 * 1 or 2 that means limit >= 2 for one slot and limit >= 3 for two (RSA + EC).
 * Below that threshold the window admits at most ONE batch in total, so there
 * is no budget left to allocate fairly and the pre-reserve first-come
 * behaviour is the only non-wedging option. Ordinary configurations
 * (limit >= n + reserve) are unaffected and keep the strict bound.
 */
static ngx_inline ngx_uint_t
ngx_autocert_loadcap_admit_retry_n(ngx_autocert_loadcap_t *cap, time_t now,
    ngx_uint_t limit, ngx_uint_t n, ngx_uint_t retry)
{
    ngx_uint_t  reserve, general, left;

    if (limit == 0) {
        return 1;                            /* cap disabled */
    }

    if (n == 0) {
        return 1;                            /* nothing to charge */
    }

    if (cap->second != now) {
        cap->second = now;
        cap->spent = 0;
        cap->spent_res = 0;
    }

    reserve = ngx_autocert_loadcap_reserve(limit);
    general = limit - reserve;

    /* Wedge guard: a request that can never fit in the pool it may draw from
     * (n > general) is admitted once per window instead of denied forever --
     * see comment above the function. Charging both pools closes the window
     * for every later request, retry or not, exactly as the pre-reserve code
     * did. */
    if (n > general) {
        if (cap->spent != 0 || cap->spent_res != 0) {
            return 0;
        }
        cap->spent = general;
        cap->spent_res = reserve;
        return 1;
    }

    /* General pool first, for retries too: on a quiet worker the reserve is
     * never reached and the split is invisible. */
    if (n <= general && cap->spent <= general - n) {
        cap->spent += n;
        return 1;
    }

    if (!retry) {
        return 0;                    /* first attempt: reserve is off limits */
    }

    /* Retry fallback: spend from the reserve, all-or-nothing as above. */
    left = reserve - cap->spent_res;
    if (n > left) {
        return 0;
    }

    cap->spent_res += n;
    return 1;
}


/*
 * Ask for permission to perform `n` synchronous certificate loads at `now` as
 * a FIRST attempt (no access to the retry reserve). Kept as the plain-batch
 * spelling of ngx_autocert_loadcap_admit_retry_n().
 */
static ngx_inline ngx_uint_t
ngx_autocert_loadcap_admit_n(ngx_autocert_loadcap_t *cap, time_t now,
    ngx_uint_t limit, ngx_uint_t n)
{
    return ngx_autocert_loadcap_admit_retry_n(cap, now, limit, n, 0);
}


/*
 * Ask for permission to perform one synchronous certificate load at `now`.
 * Returns 1 when the load is admitted (and charges it), 0 when the per-second
 * budget for `now` is exhausted and the caller must fall back to the cached
 * certificate. `limit` of 0 means unlimited: the cap is off and every call is
 * admitted without touching the counters, so an operator can restore the exact
 * pre-cap behaviour.
 *
 * Rolling into a new second (including a backwards clock step, which compares
 * unequal just like a forwards one) resets the budget rather than extrapolating
 * — a coarse fixed window is deliberate. A sliding window would need a ring per
 * worker and buys nothing here: the property we need is "bounded work per
 * second", not smoothness, and the worst case of a fixed window (2 * limit
 * across a second boundary) is still a constant, which is the whole point.
 * Fairness WITHIN a window is the reserve's job, not the window shape's.
 */
static ngx_inline ngx_uint_t
ngx_autocert_loadcap_admit(ngx_autocert_loadcap_t *cap, time_t now,
    ngx_uint_t limit)
{
    return ngx_autocert_loadcap_admit_retry_n(cap, now, limit, 1, 0);
}


#endif /* NGX_AUTOCERT_LOADCAP_H_INCLUDED */
