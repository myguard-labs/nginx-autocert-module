/*
 * Minimal nginx surface for the autocert ACME HTTP-response / URL parser
 * (ngx_autocert_acme_parse_url / parse_response / dechunk / header / memmem /
 * url_part_safe), sliced from ../../src/ngx_autocert_acme.c by extract_http.sh
 * into generated_http.inc.
 *
 * Those bodies operate on an ngx_autocert_acme_request_t but touch only a
 * subset of its fields (no event/SSL/resolver machinery), plus the
 * ngx_string/ngx_array helpers below. We reproduce that subset faithfully:
 * field names, types and semantics match src/ngx_autocert_acme.h exactly so
 * the sliced code compiles unchanged. The bodies are NOT copied — only the
 * struct surface they read is shimmed.
 *
 * Used by BOTH the standalone unit test (tests/unit/test_http.c, compiled against
 * an nginx tree but the parser surface still routed through this slice) — no,
 * see test_http.c which includes this shim + the .inc directly — and the
 * libFuzzer target fuzz/fuzz_http.c.
 */

#ifndef NGX_AUTOCERT_HTTP_FUZZ_SHIM_H
#define NGX_AUTOCERT_HTTP_FUZZ_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- core types (nginx ngx_config.h) --- */
typedef intptr_t    ngx_int_t;
typedef uintptr_t   ngx_uint_t;
typedef unsigned char u_char;
typedef uint16_t    in_port_t;
typedef long        off_t_shim;        /* avoid clashing with system off_t */

#ifndef _OFF_T_DECLARED
/* the slice uses off_t for content_length; the system header provides it. */
#include <sys/types.h>
#endif

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/* --- constants --- */
#define NGX_OK            0
#define NGX_ERROR        -1
#define NGX_AGAIN        -2
#define NGX_DONE         -4
#define NGX_DECLINED     -5

#if (UINTPTR_MAX > 0xffffffffUL)
#define NGX_MAX_SIZE_T_VALUE   0x7fffffffffffffffLL
#define NGX_MAX_INT_T_VALUE    9223372036854775807LL
#else
#define NGX_MAX_SIZE_T_VALUE   0x7fffffff
#define NGX_MAX_INT_T_VALUE    2147483647
#endif

/* off_t is 64-bit on this target (LFS). Match nginx's ngx_atoof bound. */
#define NGX_MAX_OFF_T_VALUE    0x7fffffffffffffffLL

#define CRLF  "\r\n"

/* --- logging: silent in unit/fuzz harness --- */
#define NGX_LOG_DEBUG_CORE  0
#define NGX_LOG_ERR         0

typedef struct ngx_log_s  ngx_log_t;
struct ngx_log_s { int dummy; };

#define ngx_log_debug1(level, log, err, fmt, a1)              ((void)0)
#define ngx_log_debug2(level, log, err, fmt, a1, a2)          ((void)0)
#define ngx_log_debug3(level, log, err, fmt, a1, a2, a3)      ((void)0)
#define ngx_log_error(level, log, err, ...)                   ((void)0)

/* --- pool shim with an allocation-budget oracle ---
 *
 * Malloc-backed and tracked so the harness frees the lot after every input.
 *
 * This registry used to be a fixed 4096-entry array whose allocator returned
 * NULL once full.  That hid allocation blowup behind the parser's own
 * out-of-memory path: a response asking for a million header allocations got
 * NULL and produced a clean rejection, which looks identical to correct
 * behaviour.  A pool-allocated overflow has no per-allocation redzone either,
 * so ASan cannot see it.  The invariant has to be asserted directly.
 *
 * THE INVARIANT
 *
 * ngx_autocert_acme_parse_response / dechunk allocate at:
 *   - the host copy            (r->host.len + 1, a substring of the input)
 *   - the header array         (ngx_array_create, then doubling on push;
 *                               cumulative growth is < 2x the final array)
 *   - per-header name + value  (each a disjoint substring of the input)
 *   - the dechunked body       (total decoded bytes <= input length)
 *
 * Every one of those is charged to input bytes that are consumed once, so both
 * the allocation count and the total allocated bytes are O(N) in the response
 * length.  Measured worst cases:
 *
 *   "a:b\r\n" x 20000     alloc/len 0.40   bytes/len 21.4  (array doubling)
 *   "1\r\nx\r\n" x 20000  alloc/len 0.00   bytes/len  0.17
 *   minimal 19-byte 200   alloc/len 0.11   bytes/len 15.6  <- constant term
 *
 * The bounds carry headroom over those figures.  Superlinear growth exceeds
 * any linear bound eventually, so slack costs detection latency, not detection
 * power.  A violation abort()s and libFuzzer saves the offending input.
 */

/* allocs <= K1 * len + C1 */
#define NGX_HTTP_FUZZ_ALLOC_COUNT_K   2
#define NGX_HTTP_FUZZ_ALLOC_COUNT_C   8

/* bytes  <= K2 * len + C2 */
#define NGX_HTTP_FUZZ_ALLOC_BYTES_K   64
#define NGX_HTTP_FUZZ_ALLOC_BYTES_C   4096

typedef struct {
    void       **allocs;      /* growable registry, realloc'd as needed */
    size_t       nallocs;
    size_t       cap;
    size_t       nbytes;
    size_t       input_len;   /* the budget is a function of this */
    ngx_log_t   *log;
} ngx_pool_t;

/*
 * NGX_HTTP_FUZZ_NO_BUDGET disables the budget for callers that are not fuzzing
 * a sized input -- the unit suite drives fixed fixtures through this shim and
 * has no meaningful input_len to charge against. It still uses the growable
 * registry, so allocations are tracked and freed exactly as before.
 */
#define NGX_HTTP_FUZZ_NO_BUDGET  ((size_t) -1)

static void
ngx_http_fuzz_pool_charge(ngx_pool_t *pool, size_t size)
{
    size_t  max_allocs, max_bytes;

    pool->nbytes += size;

    if (pool->input_len == NGX_HTTP_FUZZ_NO_BUDGET) {
        return;
    }

    max_allocs = (size_t) NGX_HTTP_FUZZ_ALLOC_COUNT_K * pool->input_len
                 + NGX_HTTP_FUZZ_ALLOC_COUNT_C;
    max_bytes  = (size_t) NGX_HTTP_FUZZ_ALLOC_BYTES_K * pool->input_len
                 + NGX_HTTP_FUZZ_ALLOC_BYTES_C;

    if (pool->nallocs + 1 > max_allocs) {
        fprintf(stderr,
                "ngx_http_fuzz: ALLOCATION BUDGET EXCEEDED (count): "
                "input_len=%zu allocs=%zu budget=%zu\n",
                pool->input_len, pool->nallocs + 1, max_allocs);
        abort();
    }

    if (pool->nbytes > max_bytes) {
        fprintf(stderr,
                "ngx_http_fuzz: ALLOCATION BUDGET EXCEEDED (bytes): "
                "input_len=%zu bytes=%zu budget=%zu\n",
                pool->input_len, pool->nbytes, max_bytes);
        abort();
    }
}

/*
 * Register a live pointer, growing the registry geometrically.  The registry
 * must never be what fails -- a full registry returning NULL would reintroduce
 * the blindness this oracle removes.  Only the budget assertion may stop a
 * parse.
 */
static int
ngx_http_fuzz_pool_register(ngx_pool_t *pool, void *p)
{
    void  **na;
    size_t  ncap;

    if (pool->nallocs == pool->cap) {
        ncap = pool->cap ? pool->cap * 2 : 64;
        na = (void **) realloc(pool->allocs, ncap * sizeof(void *));
        if (na == NULL) {
            /* Genuine host OOM growing a registry the budget already bounded:
             * a machine limit, not a parser defect. */
            free(p);
            return 0;
        }
        pool->allocs = na;
        pool->cap = ncap;
    }

    pool->allocs[pool->nallocs++] = p;
    return 1;
}

static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    ngx_http_fuzz_pool_charge(pool, size);

    p = malloc(size ? size : 1);
    if (p == NULL) {
        return NULL;
    }
    if (!ngx_http_fuzz_pool_register(pool, p)) {
        return NULL;
    }
    return p;
}

/* Initialise the pool for one input; input_len is the budget's denominator. */
static void
ngx_http_fuzz_pool_init(ngx_pool_t *pool, ngx_log_t *log, size_t input_len)
{
    pool->allocs = NULL;
    pool->nallocs = 0;
    pool->cap = 0;
    pool->nbytes = 0;
    pool->input_len = input_len;
    pool->log = log;
}

static void
ngx_http_fuzz_pool_reset(ngx_pool_t *pool)
{
    size_t i;
    for (i = 0; i < pool->nallocs; i++) {
        free(pool->allocs[i]);
    }
    free(pool->allocs);
    pool->allocs = NULL;
    pool->nallocs = 0;
    pool->cap = 0;
    pool->nbytes = 0;
}

/* --- ngx_array surface used by the header scan --- */
typedef struct {
    void       *elts;
    ngx_uint_t  nelts;
    size_t      size;
    ngx_uint_t  nalloc;
    ngx_pool_t *pool;
} ngx_array_t;

static ngx_array_t *
ngx_array_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    ngx_array_t *a = ngx_pnalloc(pool, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }
    a->elts = ngx_pnalloc(pool, n * size);
    if (a->elts == NULL) {
        return NULL;
    }
    a->nelts = 0;
    a->size = size;
    a->nalloc = n;
    a->pool = pool;
    return a;
}

static void *
ngx_array_push(ngx_array_t *a)
{
    void *elt;
    if (a->nelts == a->nalloc) {
        /* grow x2 */
        void   *new_elts;
        size_t  n = 2 * (a->nalloc ? a->nalloc : 1);
        new_elts = ngx_pnalloc(a->pool, n * a->size);
        if (new_elts == NULL) {
            return NULL;
        }
        memcpy(new_elts, a->elts, a->nelts * a->size);
        a->elts = new_elts;
        a->nalloc = n;
    }
    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;
    return elt;
}

/* --- string helpers (verbatim nginx semantics) --- */
#define ngx_memcpy(d, s, n)        memcpy(d, s, n)
#define ngx_memcmp(a, b, n)        memcmp(a, b, n)
#define ngx_cpymem(d, s, n)        ((u_char *) memcpy(d, s, n) + (n))
#define ngx_strlen(s)              strlen((const char *)(s))
#define ngx_strncmp(s1, s2, n)     strncmp((const char *)(s1), (const char *)(s2), n)

static int
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    while (n) {
        u_char c1 = *s1++, c2 = *s2++;
        if (c1 >= 'A' && c1 <= 'Z') c1 |= 0x20;
        if (c2 >= 'A' && c2 <= 'Z') c2 |= 0x20;
        if (c1 != c2) {
            return c1 < c2 ? -1 : 1;
        }
        if (c1 == 0) {
            return 0;
        }
        n--;
    }
    return 0;
}

static u_char *
ngx_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {
        if (*p == c) {
            return p;
        }
        p++;
    }
    return NULL;
}

/* ngx_string("literal") initialiser used in parse_url's scheme. */
#define ngx_string(str)   { sizeof(str) - 1, (u_char *) str }

static void
ngx_str_set_impl(ngx_str_t *s, const char *lit)
{
    s->len = strlen(lit);
    s->data = (u_char *) lit;
}
#define ngx_str_set(str, text)   ngx_str_set_impl(str, (const char *) text)

/* ngx_atoi / ngx_atoof over a (data,len) span — verbatim nginx semantics:
 * return NGX_ERROR on a non-digit or on overflow, else the value. */
static ngx_int_t
ngx_atoi(u_char *line, size_t n)
{
    ngx_int_t value, cutoff, cutlim;
    if (n == 0) {
        return NGX_ERROR;
    }
    cutoff = NGX_MAX_INT_T_VALUE / 10;
    cutlim = NGX_MAX_INT_T_VALUE % 10;
    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }
        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return NGX_ERROR;
        }
        value = value * 10 + (*line - '0');
    }
    return value;
}

static off_t
ngx_atoof(u_char *line, size_t n)
{
    off_t value, cutoff, cutlim;
    if (n == 0) {
        return NGX_ERROR;
    }
    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;
    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }
        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return NGX_ERROR;
        }
        value = value * 10 + (*line - '0');
    }
    return value;
}

/* --- ngx_buf_t surface the response parser reads --- */
typedef struct {
    u_char  *pos;
    u_char  *last;
    u_char  *start;
    u_char  *end;
} ngx_buf_t;

/* --- captured response header (mirror of ngx_autocert_acme.h) --- */
typedef struct {
    ngx_str_t  name;
    ngx_str_t  value;
} ngx_autocert_acme_header_t;

/*
 * Reduced ngx_autocert_acme_request_t: ONLY the fields the sliced parser
 * functions touch, with identical names/types/order-independent semantics.
 * (The real struct also carries client/peer/resolve/ssl/send/timers, none of
 * which the parser functions reference.)
 */
typedef struct ngx_autocert_acme_request_s  ngx_autocert_acme_request_t;
struct ngx_autocert_acme_request_s {
    ngx_pool_t  *pool;
    ngx_log_t   *log;

    ngx_str_t    url;
    ngx_str_t    host;
    ngx_uint_t   host_is_ip;
    ngx_uint_t   host_is_ipv6;
    in_port_t    port;
    ngx_str_t    uri;

    ngx_uint_t   status;
    ngx_str_t    body_out;

    ngx_array_t *headers;

    ngx_buf_t   *recv;

    ngx_uint_t   headers_done;
    ngx_uint_t   chunked;
    off_t        content_length;
    size_t       body_offset;
    size_t       hdr_scan_pos;
    size_t       dechunk_pos;
    size_t       dechunk_total;
};

/*
 * Forward prototypes for the sliced static parser functions. The slice keeps
 * source order (parse_response is emitted before dechunk but calls it), so a
 * forward declaration is required — the production .c has the same prototypes
 * near its top. The harness (test or fuzzer) calls parse_url / parse_response /
 * header / memmem directly; declaring all of them here also silences
 * -Wunused-function for the ones a given harness doesn't call.
 */
static ngx_int_t ngx_autocert_acme_url_part_safe(ngx_str_t *s);
static ngx_int_t ngx_autocert_acme_parse_url(ngx_autocert_acme_request_t *r);
static u_char *ngx_autocert_memmem(u_char *hay, size_t n, const char *needle,
    size_t m);
static ngx_int_t ngx_autocert_acme_parse_response(
    ngx_autocert_acme_request_t *r);
static ngx_int_t ngx_autocert_acme_dechunk(ngx_autocert_acme_request_t *r);
/* ngx_autocert_acme_header is public (non-static) in the source. */
ngx_str_t *ngx_autocert_acme_header(ngx_autocert_acme_request_t *r,
    const char *name);

#endif /* NGX_AUTOCERT_HTTP_FUZZ_SHIM_H */
