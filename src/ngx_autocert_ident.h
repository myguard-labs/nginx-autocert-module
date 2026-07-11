/*
 * ngx_autocert_ident — identifier classification + store-segment mapping
 * helpers, shared across the CORE and HTTP modules AND the standalone crypto
 * unit tests (M3/M8).
 *
 * Deliberately http-free: it pulls only ngx_core.h + openssl/x509v3.h, never
 * <ngx_http.h>. ngx_http_autocert_crypto.c needs ngx_autocert_str_is_ip /
 * ngx_autocert_cert_covers but is compiled standalone by the crypto/cert-expiry
 * unit-test jobs with only the core/event/os include paths — dragging the HTTP
 * config struct header (and its <ngx_http.h>) in there broke that build. Keep
 * the pure ident helpers here and the http-dependent config structs in
 * ngx_http_autocert_conf.h, which includes this file.
 */

#ifndef _NGX_AUTOCERT_IDENT_H_INCLUDED_
#define _NGX_AUTOCERT_IDENT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <openssl/x509v3.h>


/*
 * D4 wildcard (#16): map an issuable name to its on-disk store segment. A
 * wildcard name "*.example.com" is not a legal path segment (the leading "*"),
 * so it is stored under "_wildcard_.example.com"; every other name maps to
 * itself. Writes into buf (cap bytes incl. no NUL) and returns the written
 * length, or 0 if it would not fit. Shared by the driver freshness check, the
 * order store writer, and the serve cache key so all three agree on the dir.
 *
 * static ngx_inline in the shared header: each TU that uses it gets its own
 * copy, and TUs that include the header without using it don't warn under
 * -Werror (inline suppresses the unused-function diagnostic).
 */
#define NGX_AUTOCERT_WILDCARD_SEG  "_wildcard_."

/* IPv6 store-key prefix. An IPv6 identifier is stored under a normalized,
 * fully-expanded 8-group hex segment with ':' rendered as '-' — a durable
 * on-disk contract (2001:db8::1 -> _ip6_2001-0db8-0000-...-0001). IPv4 needs no
 * mapping (no path-illegal chars) and is stored verbatim like a dns name. Do
 * NOT change this encoding: it orphans every stored IPv6 cert. */
#define NGX_AUTOCERT_IP6_SEG       "_ip6_"

/* "_ip6_" + 8 groups of 4 hex + 7 '-' separators. */
#define NGX_AUTOCERT_IP6_SEG_LEN   (sizeof(NGX_AUTOCERT_IP6_SEG) - 1 + 8 * 4 + 7)

/* Upper bound for a mapped store segment: a 253-char name minus "*." plus the
 * "_wildcard_." prefix, rounded up. Also covers the fixed IPv6 segment. Sizes
 * the stack buffers callers pass in. */
#define NGX_AUTOCERT_DOMAIN_SEG_MAX  288


/* Classify an identifier as IPv4, IPv6, or a dns name. Returns the address
 * family (AF_INET / AF_INET6) for an IP literal, or 0 for a dns name. Mirrors
 * angie's ngx_acme_str_is_ip: ngx_inet_addr for v4, ngx_inet6_addr for v6. The
 * v6 result is written to out6 (when non-NULL) so the fs-segment mapper can
 * reuse the parse instead of parsing twice. */
static ngx_inline int
ngx_autocert_str_is_ip(const ngx_str_t *name, struct in6_addr *out6)
{
    in_addr_t        v4;
    struct in6_addr  v6;

    /* ngx_inet_addr returns INADDR_NONE (0xffffffff) both on parse failure AND
     * for the valid all-ones address 255.255.255.255, so that one literal would
     * be misread as a non-IP. Disambiguate by matching the literal explicitly:
     * a real 255.255.255.255 is IPv4, a parse failure falls through to IPv6. */
    v4 = ngx_inet_addr(name->data, name->len);
    if (v4 != INADDR_NONE
        || (name->len == sizeof("255.255.255.255") - 1
            && ngx_strncmp(name->data, "255.255.255.255", name->len) == 0))
    {
        return AF_INET;
    }

    if (ngx_inet6_addr(name->data, name->len, v6.s6_addr) == NGX_OK) {
        if (out6 != NULL) {
            *out6 = v6;
        }
        return AF_INET6;
    }

    return 0;
}


/* Verify an X.509 leaf covers the identifier `id`. A dns name (incl. a wildcard
 * probe) goes through X509_check_host against the leaf's dNSName SANs; an IP
 * identifier goes through X509_check_ip_asc against its iPAddress SANs (the two
 * never cross-match). Returns 1 on match, 0 otherwise. The IP path copies into
 * a bounded stack buffer, so `id` need not be NUL-terminated. */
static ngx_inline int
ngx_autocert_cert_covers(X509 *leaf, const ngx_str_t *id)
{
    u_char  ipbuf[NGX_INET6_ADDRSTRLEN + 1];

    if (ngx_autocert_str_is_ip(id, NULL) != 0) {
        if (id->len >= sizeof(ipbuf)) {
            return 0;
        }
        ngx_memcpy(ipbuf, id->data, id->len);
        ipbuf[id->len] = '\0';
        return X509_check_ip_asc(leaf, (char *) ipbuf, 0) == 1;
    }

    return X509_check_host(leaf, (char *) id->data, id->len, 0, NULL) == 1;
}

static ngx_inline size_t
ngx_autocert_fs_segment(u_char *buf, size_t cap, ngx_str_t *name)
{
    u_char          *p;
    size_t           rest, need;
    ngx_uint_t       i;
    struct in6_addr  v6;

    if (name->len >= 2 && name->data[0] == '*' && name->data[1] == '.') {
        rest = name->len - 2;                         /* after the "*." */
        need = sizeof(NGX_AUTOCERT_WILDCARD_SEG) - 1 + rest;
        if (need > cap) {
            return 0;
        }
        p = ngx_cpymem(buf, NGX_AUTOCERT_WILDCARD_SEG,
                       sizeof(NGX_AUTOCERT_WILDCARD_SEG) - 1);
        ngx_memcpy(p, name->data + 2, rest);
        return need;
    }

    /* IPv6 literal: normalize to "_ip6_" + 8 zero-padded hex groups joined by
     * '-'. IPv4 falls through to the verbatim copy below (no illegal chars). */
    if (ngx_autocert_str_is_ip(name, &v6) == AF_INET6) {
        if (NGX_AUTOCERT_IP6_SEG_LEN > cap) {
            return 0;
        }
        p = ngx_cpymem(buf, NGX_AUTOCERT_IP6_SEG,
                       sizeof(NGX_AUTOCERT_IP6_SEG) - 1);
        for (i = 0; i < 8; i++) {
            if (i != 0) {
                *p++ = '-';
            }
            p = ngx_sprintf(p, "%04xd",
                            (v6.s6_addr[i * 2] << 8) | v6.s6_addr[i * 2 + 1]);
        }
        return (size_t) (p - buf);
    }

    if (name->len > cap) {
        return 0;
    }
    ngx_memcpy(buf, name->data, name->len);
    return name->len;
}


#endif /* _NGX_AUTOCERT_IDENT_H_INCLUDED_ */
