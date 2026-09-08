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
    time_t      second;    /* the wall second `spent` is counted against */
    ngx_uint_t  spent;     /* loads admitted during that second */
} ngx_autocert_loadcap_t;


/*
 * Ask for permission to perform one synchronous certificate load at `now`.
 * Returns 1 when the load is admitted (and charges it), 0 when the per-second
 * budget for `now` is exhausted and the caller must fall back to the cached
 * certificate. `limit` of 0 means unlimited: the cap is off and every call is
 * admitted without touching the counter, so an operator can restore the exact
 * pre-cap behaviour.
 *
 * Rolling into a new second (including a backwards clock step, which compares
 * unequal just like a forwards one) resets the budget rather than extrapolating
 * — a coarse fixed window is deliberate. A sliding window would need a ring per
 * worker and buys nothing here: the property we need is "bounded work per
 * second", not smoothness, and the worst case of a fixed window (2 * limit
 * across a second boundary) is still a constant, which is the whole point.
 */
static ngx_inline ngx_uint_t
ngx_autocert_loadcap_admit(ngx_autocert_loadcap_t *cap, time_t now,
    ngx_uint_t limit)
{
    if (limit == 0) {
        return 1;                            /* cap disabled */
    }

    if (cap->second != now) {
        cap->second = now;
        cap->spent = 0;
    }

    if (cap->spent >= limit) {
        return 0;                            /* budget exhausted this second */
    }

    cap->spent++;
    return 1;
}


#endif /* NGX_AUTOCERT_LOADCAP_H_INCLUDED */
