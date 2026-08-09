/*
 * Minimal nginx surface for fuzzing ngx_http_autocert_base64url_decode()
 * (sliced by extract_b64.sh into generated_b64.inc).
 *
 * The decode wrapper enforces a strict RFC 4648 §5 URL-safe alphabet (no
 * '=' padding, reject on the first byte outside A-Za-z0-9-_) before handing
 * off to nginx's own ngx_decode_base64url(), because nginx's decoder is
 * permissive (accepts padding, silently stops at the first bad byte) — a
 * hostile/MITM'd ACME response encoding a JWS field this way must be
 * rejected outright, not silently truncated. That hand-written validation
 * loop plus the size-arithmetic overflow guard is the parsing logic worth
 * fuzzing; ngx_decode_base64url() itself is reproduced verbatim below from
 * nginx's src/core/ngx_string.c so the slice compiles standalone.
 *
 * Only the fields/helpers the wrapper and the verbatim decoder touch:
 *   - ngx_pool_t (log field only, for parity with the other shims)
 *   - ngx_pnalloc
 *   - ngx_str_t, NGX_OK / NGX_ERROR
 *   - NGX_MAX_SIZE_T_VALUE, ngx_base64_decoded_length()
 *   - ngx_decode_base64url() (verbatim nginx core, not the module's code —
 *     kept here rather than sliced, since it never changes independently of
 *     the nginx version pin and isn't part of THIS module's attack surface;
 *     the module-owned validation loop is what extract_b64.sh slices live).
 */

#ifndef NGX_AUTOCERT_B64_FUZZ_SHIM_H
#define NGX_AUTOCERT_B64_FUZZ_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef unsigned char u_char;

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

#define NGX_OK            0
#define NGX_ERROR        -1

#if (UINTPTR_MAX > 0xffffffffUL)
#define NGX_MAX_SIZE_T_VALUE   0x7fffffffffffffffLL
#else
#define NGX_MAX_SIZE_T_VALUE   0x7fffffff
#endif

#define ngx_base64_decoded_length(len)  (((len + 3) / 4) * 3)

typedef struct ngx_log_s  ngx_log_t;
struct ngx_log_s {
    int  dummy;
};

#define NGX_FUZZ_POOL_MAX_ALLOCS  4096

typedef struct {
    void         *allocs[NGX_FUZZ_POOL_MAX_ALLOCS];
    size_t        nallocs;
    ngx_log_t    *log;
} ngx_pool_t;

static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    if (pool->nallocs >= NGX_FUZZ_POOL_MAX_ALLOCS) {
        return NULL;
    }
    p = malloc(size ? size : 1);
    if (p == NULL) {
        return NULL;
    }
    pool->allocs[pool->nallocs++] = p;
    return p;
}

static void
ngx_fuzz_pool_reset(ngx_pool_t *pool)
{
    size_t  i;

    for (i = 0; i < pool->nallocs; i++) {
        free(pool->allocs[i]);
    }
    pool->nallocs = 0;
}

/* --- verbatim nginx core: src/core/ngx_string.c ngx_decode_base64url() +
 * its ngx_decode_base64_internal() helper (nginx 1.31.1). Not module code,
 * not sliced by extract_b64.sh — this is the fixed nginx-version dependency
 * the module's wrapper calls into. */

static ngx_int_t ngx_decode_base64_internal(ngx_str_t *dst, ngx_str_t *src,
    const u_char *basis);

static ngx_int_t
ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src)
{
    static u_char   basis64[] = {
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
        77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 63,
        77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
    };

    return ngx_decode_base64_internal(dst, src, basis64);
}

static ngx_int_t
ngx_decode_base64_internal(ngx_str_t *dst, ngx_str_t *src, const u_char *basis)
{
    size_t          len;
    u_char         *d, *s;

    for (len = 0; len < src->len; len++) {
        if (src->data[len] == '=') {
            break;
        }

        if (basis[src->data[len]] == 77) {
            return NGX_ERROR;
        }
    }

    if (len % 4 == 1) {
        return NGX_ERROR;
    }

    s = src->data;
    d = dst->data;

    while (len > 3) {
        *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
        *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
        *d++ = (u_char) (basis[s[2]] << 6 | basis[s[3]]);

        s += 4;
        len -= 4;
    }

    if (len > 1) {
        *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
    }

    if (len > 2) {
        *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
    }

    dst->len = d - dst->data;

    return NGX_OK;
}

#endif /* NGX_AUTOCERT_B64_FUZZ_SHIM_H */
