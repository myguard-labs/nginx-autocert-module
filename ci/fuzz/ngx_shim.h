/*
 * Minimal nginx surface for fuzzing the autocert JSON parser
 * (ngx_autocert_json_parse and accessors).
 *
 * The JSON parser reads attacker-influenceable bytes — ACME server responses
 * over a TLS channel, but still parsed defensively for correctness. It uses:
 *   - ngx_pool_t  (with a ->log field for ngx_log_debug1)
 *   - ngx_pcalloc / ngx_pnalloc
 *   - ngx_strncmp / ngx_strlen
 *   - ngx_log_debug1 (debug trace, no-op in fuzzing)
 *   - core types: u_char, ngx_int_t, ngx_uint_t, ngx_str_t
 *   - NGX_OK, NGX_ERROR, NGX_DECLINED
 *
 * Everything here is the faithful nginx surface those calls touch, reduced to
 * exactly the fields and semantics the sliced parser bodies use. The parser
 * bodies themselves are NOT copied — they are sliced from the shipped
 * src/ngx_autocert_json.c at build time by extract_parser.sh into
 * generated_json.inc, so the fuzzer always exercises production code with no
 * drift.
 */

#ifndef NGX_AUTOCERT_FUZZ_SHIM_H
#define NGX_AUTOCERT_FUZZ_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- core types (nginx ngx_config.h) --- */
typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef unsigned char u_char;

/* nginx ngx_string.h */
typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/* --- core constants --- */
#define NGX_OK            0
#define NGX_ERROR        -1
#define NGX_AGAIN        -2
#define NGX_DECLINED     -5

#if (UINTPTR_MAX > 0xffffffffUL)
#define NGX_MAX_INT_T_VALUE  9223372036854775807LL
#else
#define NGX_MAX_INT_T_VALUE  2147483647
#endif

/* --- logging stubs ---
 * The parser calls ngx_log_debug1(level, log, err, fmt, arg).
 * In fuzzing we want complete silence; the macro expands to nothing.
 * We also need NGX_LOG_DEBUG_CORE to compile the call site.
 */
#define NGX_LOG_DEBUG_CORE  0

/* Stub ngx_log_t so pool->log is a valid (NULL) pointer field. */
typedef struct ngx_log_s  ngx_log_t;
struct ngx_log_s {
    int  dummy;
};

/* ngx_log_debug1 expands to nothing in the fuzzer — we don't need trace. */
#define ngx_log_debug1(level, log, err, fmt, arg1)   ((void)0)

/*
 * Pool shim with an allocation-budget oracle.
 *
 * The parser allocates ngx_autocert_json_value_t, ngx_autocert_json_member_t,
 * ngx_autocert_json_element_t, and decoded string buffers via ngx_pcalloc /
 * ngx_pnalloc.  We back each alloc with malloc and register it so the harness
 * can free the lot after every input (otherwise libFuzzer's leak check fires).
 *
 * WHY A BUDGET ORACLE RATHER THAN A CAP
 *
 * This registry used to be a fixed array of 4096 entries, and both allocators
 * returned NULL once it filled.  That made allocation blowup INVISIBLE: a
 * document that asked for a million nodes hit the cap, got NULL, and the
 * parser's own out-of-memory path returned a clean error.  To libFuzzer that
 * is a well-behaved rejection, not a defect.  Worse, a pool-allocated overflow
 * carries no per-allocation redzone, so ASan cannot see it either -- there is
 * no sanitizer that reports "this parser allocated superlinearly".  Detecting
 * that class of bug requires asserting the invariant directly.
 *
 * THE INVARIANT
 *
 * ngx_autocert_json.c has exactly four allocation sites, and every one of them
 * is charged to input bytes that are consumed and never revisited:
 *
 *   - ngx_pcalloc(value_t)   (24 bytes) -- one per JSON value.  A value needs
 *     at least one input byte of its own token.
 *   - ngx_pcalloc(member_t)  (32 bytes) -- one per object member.  A member
 *     needs at minimum `"":0` plus a separator.
 *   - ngx_pcalloc(element_t) (16 bytes) -- one per array element.  An element
 *     needs at minimum one value byte plus a separator.
 *   - ngx_pnalloc(span)      -- one per string, sized to the raw span between
 *     the quotes.  Spans are disjoint substrings of the input, so the sum of
 *     all string allocations is bounded by the input length.
 *
 * Therefore both the allocation COUNT and the total allocated BYTES are O(N)
 * in the document length.  Measured worst cases over the densest documents
 * that can be written (all ratios below are allocations, or bytes, per input
 * byte):
 *
 *   [[[[...  (32 deep)  alloc/len 2.00   bytes/len 40.0   <- both worst cases
 *   [0,0,0,...]         alloc/len 1.00   bytes/len 20.0   (24 + 16 per 2 bytes)
 *   ["","",...]         alloc/len 1.00   bytes/len 13.3
 *   {"":0,"":0,...}     alloc/len 0.60   bytes/len 11.2   (24 + 32 per 5 bytes)
 *   "aaaa...a"          alloc/len 0.00   bytes/len  1.0
 *   `0` (one byte)      alloc/len 1.00   bytes/len 24.0   <- constant-term case
 *
 * A linear bound catches superlinear growth whatever its slack, because
 * superlinear growth exceeds ANY linear bound once the document is long
 * enough -- slack only decides how long "long enough" is, so it costs
 * detection latency, not detection power.
 *
 * The two bounds are NOT equally slack.  K2 = 64 bytes/len has real headroom
 * over the 40.0 bytes/len worst case above.  K1 = 2 allocs/len is EXACT: an
 * exhaustive sweep of every six-byte document over `[]{}",:0` finds `[[[[[[`
 * saturating it at 2.00 allocs per input byte with zero coefficient slack.
 * That family stays under budget only because C1 = 8 absorbs it and
 * NGX_AUTOCERT_JSON_MAX_DEPTH (32) truncates it at 64 allocations.  A future
 * parser change that adds even one allocation per value on the array path
 * will make `[[[...` abort here: re-derive K1 rather than raising it blindly.
 *
 * A violation abort()s, so libFuzzer records it as a crash with the offending
 * input, exactly like a sanitizer finding.
 */

/* allocs <= K1 * len + C1 */
#define NGX_FUZZ_ALLOC_COUNT_K   2
#define NGX_FUZZ_ALLOC_COUNT_C   8

/* bytes  <= K2 * len + C2 */
#define NGX_FUZZ_ALLOC_BYTES_K   64
#define NGX_FUZZ_ALLOC_BYTES_C   4096

typedef struct {
    void        **allocs;      /* growable registry, realloc'd as needed */
    size_t        nallocs;     /* entries in use */
    size_t        cap;         /* entries the registry can hold */
    size_t        nbytes;      /* total bytes handed to the parser */
    size_t        input_len;   /* the budget is a function of this */
    ngx_log_t    *log;         /* parser dereferences pool->log in macros */
} ngx_pool_t;

/*
 * NGX_FUZZ_NO_BUDGET disables the budget for callers that are not fuzzing a
 * sized input. The growable registry still tracks and frees every allocation.
 */
#define NGX_FUZZ_NO_BUDGET  ((size_t) -1)

/*
 * Charge one allocation against the budget and abort if either bound is
 * exceeded.  Called AFTER the size is known and BEFORE the pointer is handed
 * back, so the aborting input is the one libFuzzer saves.
 */
static void
ngx_fuzz_pool_charge(ngx_pool_t *pool, size_t size)
{
    size_t  max_allocs, max_bytes;

    pool->nbytes += size;

    if (pool->input_len == NGX_FUZZ_NO_BUDGET) {
        return;
    }

    max_allocs = (size_t) NGX_FUZZ_ALLOC_COUNT_K * pool->input_len
                 + NGX_FUZZ_ALLOC_COUNT_C;
    max_bytes  = (size_t) NGX_FUZZ_ALLOC_BYTES_K * pool->input_len
                 + NGX_FUZZ_ALLOC_BYTES_C;

    if (pool->nallocs + 1 > max_allocs) {
        fprintf(stderr,
                "ngx_fuzz: ALLOCATION BUDGET EXCEEDED (count): "
                "input_len=%zu allocs=%zu budget=%zu\n",
                pool->input_len, pool->nallocs + 1, max_allocs);
        abort();
    }

    if (pool->nbytes > max_bytes) {
        fprintf(stderr,
                "ngx_fuzz: ALLOCATION BUDGET EXCEEDED (bytes): "
                "input_len=%zu bytes=%zu budget=%zu\n",
                pool->input_len, pool->nbytes, max_bytes);
        abort();
    }
}

/*
 * Register a live pointer, growing the registry geometrically.  The registry
 * must never be the thing that fails: a full registry that returned NULL would
 * reintroduce exactly the blindness this oracle exists to remove.  Only the
 * budget assertion above may stop a parse.
 */
static int
ngx_fuzz_pool_register(ngx_pool_t *pool, void *p)
{
    void  **na;
    size_t  ncap;

    if (pool->nallocs == pool->cap) {
        ncap = pool->cap ? pool->cap * 2 : 64;
        na = (void **) realloc(pool->allocs, ncap * sizeof(void *));
        if (na == NULL) {
            /* A genuine host OOM growing a registry the budget already
             * bounded.  Free the pointer rather than leak it and fail the
             * allocation; this is a machine limit, not a parser defect. */
            free(p);
            return 0;
        }
        pool->allocs = na;
        pool->cap = ncap;
    }

    pool->allocs[pool->nallocs++] = p;
    return 1;
}

/* ngx_pcalloc: zeroing alloc (used for value/member/element nodes). */
static void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    ngx_fuzz_pool_charge(pool, size);

    p = calloc(1, size ? size : 1);
    if (p == NULL) {
        return NULL;
    }
    if (!ngx_fuzz_pool_register(pool, p)) {
        return NULL;
    }
    return p;
}

/* ngx_pnalloc: non-zeroing alloc (used for decoded string buffers). */
static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    ngx_fuzz_pool_charge(pool, size);

    p = malloc(size ? size : 1);
    if (p == NULL) {
        return NULL;
    }
    if (!ngx_fuzz_pool_register(pool, p)) {
        return NULL;
    }
    return p;
}

/*
 * Initialise the pool for one input.  input_len is what the budget is measured
 * against, so it must be set before the first allocation.
 */
static void
ngx_fuzz_pool_init(ngx_pool_t *pool, ngx_log_t *log, size_t input_len)
{
    pool->allocs = NULL;
    pool->nallocs = 0;
    pool->cap = 0;
    pool->nbytes = 0;
    pool->input_len = input_len;
    pool->log = log;
}

/* Reset the pool: free all tracked allocs and the registry itself. */
static void
ngx_fuzz_pool_reset(ngx_pool_t *pool)
{
    size_t  i;

    for (i = 0; i < pool->nallocs; i++) {
        free(pool->allocs[i]);
    }
    free(pool->allocs);
    pool->allocs = NULL;
    pool->nallocs = 0;
    pool->cap = 0;
    pool->nbytes = 0;
}

/* --- verbatim nginx string helpers --- */

/* ngx_strlen: verbatim nginx macro — accepts u_char* or char* without warning. */
#define ngx_strlen(s)  strlen((const char *)(s))

/* ngx_strncmp: strncmp over u_char/void */
#define ngx_strncmp(s1, s2, n)  strncmp((const char *)(s1), (const char *)(s2), n)

/*
 * The autocert_json_type enum and value/member/element structs live in
 * ngx_autocert_json.h, which we include directly (it needs only our shim
 * types above).  The .inc include that follows provides the parser function
 * bodies compiled against this shim rather than real nginx headers.
 *
 * ngx_autocert_json.h normally includes <ngx_config.h> and <ngx_core.h>;
 * the extract step strips those includes so the .inc is self-contained with
 * only our shim + the typed structs.
 */

#endif /* NGX_AUTOCERT_FUZZ_SHIM_H */
