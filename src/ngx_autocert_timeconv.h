/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Pure seconds-to-milliseconds conversion for a configured `time_t` timeout,
 * clamped so the multiply can never overflow and never wrap a negative or
 * absurd configured value into a tiny/huge ngx_msec_t. A wait beyond an hour
 * is nonsensical for any of these knobs, so all of them cap at 3600s. Used by
 * the driver's resolver_timeout and by
 * ngx_autocert_order_dns_delay_start()'s dns_propagation_delay — both treat
 * a negative value as "no wait" (0), matching this helper exactly.
 * ngx_autocert_order_dns_hook()'s dns_hook_timeout applies the same 3600s cap
 * but stays open-coded: it treats "<= 0" as "no timeout", a different
 * boundary than this helper's "< 0", so substituting the helper there would
 * change behaviour for a configured 0. Header-only static-inline so it can be
 * unit-tested without pulling in the driver's whole event-loop TU.
 */
#ifndef NGX_AUTOCERT_TIMECONV_H_INCLUDED
#define NGX_AUTOCERT_TIMECONV_H_INCLUDED


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_AUTOCERT_TIMECONV_CAP_SEC  3600


static ngx_inline ngx_msec_t
ngx_autocert_sec_to_msec_clamped(time_t sec)
{
    if (sec < 0) {
        return 0;
    }

    if (sec > NGX_AUTOCERT_TIMECONV_CAP_SEC) {
        return (ngx_msec_t) NGX_AUTOCERT_TIMECONV_CAP_SEC * 1000;
    }

    return (ngx_msec_t) sec * 1000;
}


#endif /* NGX_AUTOCERT_TIMECONV_H_INCLUDED */
