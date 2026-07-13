/*
 * A3.4: pure, driver-local rate-cap + wildcard-cover primitives, factored out of
 * ngx_autocert_driver.c so they can be unit-tested without the whole driver TU
 * (which pulls order/acme/http). No global state here — all windows are passed in
 * by the caller. Header-only static-inline: the driver includes it once.
 *
 * The rate cap guards Let's Encrypt account limits against a hostile runtime
 * label flood; see the driver for how these are wired. Kept deliberately simple
 * (linear ring scans over tiny fixed arrays) — correctness over cleverness.
 */
#ifndef NGX_AUTOCERT_RATECAP_H_INCLUDED
#define NGX_AUTOCERT_RATECAP_H_INCLUDED


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * Count timestamps in `ring` (size `n`, unordered) within `window` seconds of
 * `now`. A slot of 0 is empty (never written). This is the shared primitive for
 * both the global new-order window and each per-host failure window.
 */
static ngx_inline ngx_uint_t
ngx_autocert_rt_window_count(const time_t *ring, ngx_uint_t n, time_t now,
    time_t window)
{
    ngx_uint_t  i, c;

    c = 0;
    for (i = 0; i < n; i++) {
        if (ring[i] != 0 && ring[i] > now - window) {
            c++;
        }
    }
    return c;
}


/*
 * The oldest in-window timestamp in `ring` (size `n`), or 0 if none. Used to
 * hold a rate-capped host only until the window actually frees (that oldest
 * entry + window), rather than a full window from now.
 */
static ngx_inline time_t
ngx_autocert_rt_window_oldest(const time_t *ring, ngx_uint_t n, time_t now,
    time_t window)
{
    ngx_uint_t  i;
    time_t      oldest;

    oldest = 0;
    for (i = 0; i < n; i++) {
        if (ring[i] != 0 && ring[i] > now - window) {
            if (oldest == 0 || ring[i] < oldest) {
                oldest = ring[i];
            }
        }
    }
    return oldest;
}


/* Append `now` to a ring of size `n`, advancing `*head` (wraps). */
static ngx_inline void
ngx_autocert_rt_ring_push(time_t *ring, ngx_uint_t n, ngx_uint_t *head,
    time_t now)
{
    ring[*head] = now;
    *head = (*head + 1) % n;
}


/*
 * Does the config name `name` (which may be an exact name or a "*.suffix"
 * wildcard) cover the runtime host `host`? Case-insensitive. A wildcard covers
 * exactly one extra label: "*.example.com" covers "foo.example.com" but NOT
 * "a.b.example.com" nor the bare "example.com". Exact match also returns 1.
 */
static ngx_inline ngx_uint_t
ngx_autocert_name_covers(const u_char *name, size_t nlen,
    const u_char *host, size_t hlen)
{
    const u_char  *suffix, *dot, *rest;
    size_t         slen, rlen;

    if (nlen == hlen
        && ngx_strncasecmp((u_char *) name, (u_char *) host, hlen) == 0)
    {
        return 1;                               /* exact */
    }

    if (nlen <= 2 || name[0] != '*' || name[1] != '.') {
        return 0;                               /* not a wildcard */
    }

    suffix = name + 2;                          /* config: after "*." */
    slen   = nlen - 2;

    dot = ngx_strlchr((u_char *) host, (u_char *) host + hlen, '.');
    if (dot == NULL || dot == host) {
        return 0;                               /* host has no first label */
    }

    rest = dot + 1;                             /* host: after first label */
    rlen = (size_t) (host + hlen - rest);

    /*
     * A wildcard replaces exactly one label: the host must equal "<label>.<suffix>"
     * where <suffix> is the whole config name after "*.". Since we split on the
     * host's FIRST dot, rest == suffix already guarantees the host is exactly one
     * label deeper — "a.b.example.com" splits to "b.example.com" != "example.com".
     */
    return (rlen == slen
            && ngx_strncasecmp((u_char *) rest, (u_char *) suffix, rlen) == 0);
}


#endif /* NGX_AUTOCERT_RATECAP_H_INCLUDED */
