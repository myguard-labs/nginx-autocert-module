/*
 * ngx_autocert_requests — shared-memory runtime cert-request registry (autolabel A1).
 *
 * The autolabel integration lets a SEPARATE module (nginx-label-autoconf-module)
 * ask autocert to obtain a certificate for a host discovered at runtime (from a
 * Docker label `nda.tls.auto=true`), without either module linking the other.
 *
 * The two modules ship as distinct dlopen()ed .so files. nginx opens them with
 * RTLD_NOW|RTLD_GLOBAL (src/os/unix/ngx_dlopen.h), so a plain code-copy of the
 * helpers below would export the SAME global symbol names from both .so files and
 * ELF interposition would bind BOTH modules to whichever .so loaded first — one
 * version's layout parsing another version's shm, defeating the api_version
 * fail-safe on a skewed upgrade. Every definition in ngx_autocert_requests.c is
 * therefore compiled with NGX_AUTOCERT_REQUESTS_API (hidden visibility): each .so
 * binds its OWN copy, load order is irrelevant, and autocert being absent is not a
 * link-time problem for the consumer. Consumers vendor BOTH the .h and the .c.
 *
 * The integration surface is thus not an exported function API but a NAMED
 * shared-memory zone plus a versioned on-shm layout both sides agree on.
 *
 * Contract:
 *   - Zone name = NGX_AUTOCERT_REQUESTS_ZONE, size = NGX_AUTOCERT_REQUESTS_ZONE_SIZE,
 *     tag = NULL. The tag MUST be NULL on both sides: each .so has its own address
 *     for any global, so a per-module tag pointer would make ngx_shared_memory_add()
 *     reject the second module's attach as a different use of the same name. Both
 *     modules must also pass the SAME size (this macro) or nginx errors on mismatch.
 *   - Whichever module's postconfig runs first ngx_shared_memory_add()s it; the
 *     other attaches the same name (nginx dedups on name+tag). autocert registers
 *     ngx_autocert_requests_init_zone (owner: stamps `api_version`). A consumer
 *     registers
 *     ngx_autocert_requests_init_zone_consumer, but ONLY when `zone->init == NULL`
 *     — an already-set init means autocert claimed the zone and must not be
 *     overwritten. (`zone->data` is NOT the claim test: nginx leaves it NULL at
 *     config time, so the old docs' `zone->data == NULL` check matched even when
 *     autocert HAD claimed the zone, and the consumer then silently disabled it.)
 *     A consumer reads the stamped `api_version` (0/absent => autocert not managing
 *     this zone => feature off).
 *   - RELOAD: nginx reuses the old mapping — it copies the old shm.addr onto the new
 *     cycle's zone and calls init() WITHOUT setting shm.exists (ngx_cycle.c; that
 *     flag only covers the platform/named-shm case and is always 0 on Linux). Since
 *     the header lives IN the arena at `shpool->data`, which the reuse path carries
 *     over untouched, a non-NULL `shpool->data` is the reuse signal and every
 *     REQUESTED/PENDING/ISSUED/FAILED node survives a reconfigure. Keying off
 *     `shm.exists` instead re-allocated a fresh header on every reload and orphaned
 *     the whole tree. The init callback's `data` argument is unused.
 *   - STAMP FOLLOWS THE CALLBACK, both directions. Each init RE-stamps the header it
 *     inherits: owner => NGX_AUTOCERT_API_VERSION, consumer => 0. The callback that
 *     runs is the claim, so enabling autocert on a reload promotes a consumer's
 *     0-stamped zone to live, and DISABLING autocert (names removed / module
 *     unloaded) demotes it back to 0 — leaving a stale nonzero stamp would tell the
 *     consumer the feature is live while no driver exists to drain it.
 *   - The consumer inserts REQUESTED nodes itself via ngx_autocert_requests_ensure()
 *     (a shared helper compiled into both modules, operating on the same slab under
 *     the slab mutex). autocert's worker-0 driver polls REQUESTED nodes, orders,
 *     and flips state to PENDING/ISSUED/FAILED.
 *   - LOCKING: every access to the rbtree — including a consumer walking it
 *     directly — MUST hold ((ngx_slab_pool_t *) zone->shm.addr)->mutex for the
 *     whole traversal. Nodes are inserted/rotated under that mutex, so an unlocked
 *     walk can observe a relinked tree. The ensure/state/set_state helpers below
 *     take the mutex themselves; a consumer doing its own walk must lock too.
 *
 * All state values are ABI: the consumer compiles against these enum ints, so a
 * layout/enum change MUST bump NGX_AUTOCERT_API_VERSION.
 */

#ifndef _NGX_AUTOCERT_REQUESTS_H_INCLUDED_
#define _NGX_AUTOCERT_REQUESTS_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * Visibility of the vendored helpers. nginx dlopen()s modules with RTLD_GLOBAL, so
 * two .so files each carrying a copy of ngx_autocert_requests.c would export the
 * same names and interpose on each other (first .so loaded wins for BOTH). Hiding
 * them gives every module its own private copy: no interposition, no load-order
 * dependency, no unresolved symbol when the other module is absent, and an N/N+1
 * version skew degrades through the api_version check instead of silently parsing
 * a foreign layout. Falls back to plain extern where the attribute is unsupported.
 */
#if defined(__GNUC__) || defined(__clang__)
#define NGX_AUTOCERT_REQUESTS_API  __attribute__((visibility("hidden")))
#else
#define NGX_AUTOCERT_REQUESTS_API
#endif


/* Bump on ANY change to the on-shm layout below or the state enum. Consumer
 * compares the zone-header `api_version` against its compiled value and disables
 * the feature on mismatch (fail safe, never mis-parse a foreign layout). */
#define NGX_AUTOCERT_API_VERSION   1

/* The shared zone's name. Both modules add/attach by this exact string. */
#define NGX_AUTOCERT_REQUESTS_ZONE  "autocert_requests"

/* The shared zone's size — part of the ABI: both modules MUST pass this to
 * ngx_shared_memory_add() or nginx rejects the mismatch. Holds the header plus up
 * to NGX_AUTOCERT_REQUESTS_MAX inline-host nodes with slab overhead. */
#define NGX_AUTOCERT_REQUESTS_ZONE_SIZE  (128 * 1024)

/* Defensive caps. A DNS name is <= 253 chars (RFC 1035); the label producer is
 * hostile input, so bound everything. host_len is stored u_short, guarded below. */
#define NGX_AUTOCERT_REQUEST_NAME_MAX   253
#define NGX_AUTOCERT_REQUESTS_MAX       64   /* max runtime names (over-cap => DENIED) */

typedef char ngx_autocert_request_name_fits_ushort[
    (NGX_AUTOCERT_REQUEST_NAME_MAX <= 65535) ? 1 : -1];


/* Request lifecycle. ABI-stable ints (see version note). UNKNOWN is never stored
 * (it means "no node") — it is the return value for a name absent from the tree. */
typedef enum {
    NGX_AUTOCERT_REQ_UNKNOWN   = 0,   /* not in registry */
    NGX_AUTOCERT_REQ_REQUESTED = 1,   /* enqueued by consumer, driver not yet acted */
    NGX_AUTOCERT_REQ_PENDING   = 2,   /* driver has an ACME order in flight */
    NGX_AUTOCERT_REQ_ISSUED    = 3,   /* cert obtained + on disk */
    NGX_AUTOCERT_REQ_FAILED    = 4,   /* order failed; retry gated by next_eligible */
    NGX_AUTOCERT_REQ_DENIED    = 5    /* rejected (cap/charset/policy); terminal */
} ngx_autocert_request_state_e;


/* One runtime request. host bytes follow the node inline (str-rbtree convention).
 * node.key = ngx_crc32_long(host); full host compared on collision. */
typedef struct {
    ngx_rbtree_node_t   node;
    ngx_uint_t          state;         /* ngx_autocert_request_state_e */
    time_t              first_seen;
    time_t              last_attempt;
    time_t              next_eligible;  /* backoff gate: driver skips until now >= this */
    ngx_uint_t          fail_count;
    u_short             host_len;
    u_char              host[1];        /* host_len bytes, inline (lowercased) */
} ngx_autocert_request_t;


/* Zone-wide shared header (lives at shpool->data). `api_version` is the presence/
 * compatibility cell the consumer checks; `count` bounds insertion. */
typedef struct {
    ngx_uint_t          api_version;   /* NGX_AUTOCERT_API_VERSION, stamped by autocert */
    ngx_uint_t          count;         /* live node count, for the cap */
    ngx_rbtree_t        rbtree;
    ngx_rbtree_node_t   sentinel;
} ngx_autocert_requests_sh_t;


/*
 * OWNER zone init callback (autocert side). autocert always registers this as
 * shm_zone->init, overriding a consumer's callback if the consumer's postconfig
 * ran first (the owner deliberately claims the zone).
 *
 * Fresh start: allocates the header at `shpool->data` and stamps
 * `api_version = NGX_AUTOCERT_API_VERSION`.
 * Reload: adopts the header already in the arena (see the RELOAD note at the top)
 * — tree and all — and re-stamps it NGX_AUTOCERT_API_VERSION, so a zone a consumer
 * created with stamp 0 while autocert was disabled becomes live the moment autocert
 * is enabled. Owner/consumer is decided by WHICH callback runs; the `data` argument
 * is unused.
 */
NGX_AUTOCERT_REQUESTS_API ngx_int_t
ngx_autocert_requests_init_zone(ngx_shm_zone_t *shm_zone, void *data);


/*
 * CONSUMER zone init callback. A consumer registers this ONLY when
 * `shm_zone->init == NULL` (i.e. autocert has not already claimed the zone); it
 * builds the same layout but stamps `api_version = 0`, so the version check reports
 * "not managed" and the consumer degrades gracefully. On reload it adopts the
 * arena's existing header exactly like the owner callback (the tree survives) and
 * re-stamps it 0.
 *
 * That re-stamp is deliberate and is the FAIL-SAFE direction: this callback runs
 * only when autocert did NOT install its owner callback in this cycle, i.e. autocert
 * is absent or has no issuable names. Leaving an inherited nonzero stamp in place
 * would tell the consumer "autocert is managing this zone" when no driver exists to
 * drain it — ensure() would keep accepting REQUESTED nodes up to the cap and serve.c
 * would admit an SNI whose state can never advance. Stamping 0 makes the feature
 * inert instead.
 */
NGX_AUTOCERT_REQUESTS_API ngx_int_t
ngx_autocert_requests_init_zone_consumer(ngx_shm_zone_t *shm_zone,
    void *data);


/*
 * Idempotent enqueue. Validates host (non-empty, <= NGX_AUTOCERT_REQUEST_NAME_MAX,
 * LDH charset, no wildcard, no trailing dot), lowercases it, and under the slab
 * mutex either returns the existing node's state or inserts a fresh REQUESTED
 * node. Over the NGX_AUTOCERT_REQUESTS_MAX cap => returns REQ_DENIED without
 * allocating. Returns the resulting ngx_autocert_request_state_e as an ngx_int_t.
 * Callable from any worker (shm is mapped everywhere). Bad zone => REQ_UNKNOWN.
 */
NGX_AUTOCERT_REQUESTS_API ngx_int_t
ngx_autocert_requests_ensure(ngx_shm_zone_t *shm_zone,
    ngx_str_t *host);


/*
 * Look up a host's current state without inserting (serve/consumer read path).
 * Returns the ngx_autocert_request_state_e; REQ_UNKNOWN if absent or bad input.
 * Lowercases + validates the same way as ensure so a hit is charset-consistent.
 */
NGX_AUTOCERT_REQUESTS_API ngx_int_t
ngx_autocert_requests_state(ngx_shm_zone_t *shm_zone,
    ngx_str_t *host);


/*
 * Driver-side state transition (autocert only). Sets an existing node's state and,
 * for FAILED, bumps fail_count + stamps next_eligible = now + backoff. No-op if
 * the host is absent. Under the slab mutex. Returns NGX_OK / NGX_ERROR (bad arg).
 */
NGX_AUTOCERT_REQUESTS_API ngx_int_t
ngx_autocert_requests_set_state(ngx_shm_zone_t *shm_zone,
    ngx_str_t *host, ngx_uint_t state, time_t next_eligible);


/*
 * Driver-side drain-and-claim (autocert worker-0 only). Under the slab mutex,
 * walks the tree and, for every REQUESTED node — or FAILED node whose backoff has
 * elapsed — whose next_eligible has passed (now >= next_eligible), flips it to
 * PENDING and appends a COPY of its host
 * (allocated from `pool`) to `out`. Claiming under the same lock that reads the
 * node makes a concurrent re-drain see PENDING, so a host is handed out once.
 *
 * At most `max` hosts are claimed per call (0 = no limit); the rest stay
 * REQUESTED for the next tick. The caller MUST, for each returned host, either
 * drive an order to completion (then set_state ISSUED/FAILED) or, if it cannot
 * launch (e.g. global rate cap), release it with
 * set_state(host, REQ_REQUESTED, 0) so it is retried — a PENDING node never
 * drained again would wedge forever.
 *
 * Returns the number of hosts claimed (appended to `out`), or -1 on bad
 * zone/version or an allocation failure mid-walk (partial claims already in
 * `out` are valid and still owned by the caller). Host strings in `out` are
 * ngx_str_t with pool-owned data; safe to use after the lock is dropped.
 */
NGX_AUTOCERT_REQUESTS_API ngx_int_t
ngx_autocert_requests_drain(ngx_shm_zone_t *shm_zone, ngx_pool_t *pool,
    ngx_array_t *out, ngx_uint_t max);


/*
 * Driver-side renewal scan (autocert worker-0 only, A3.5). Under the slab mutex,
 * walks the tree and appends a COPY of the host (allocated from `pool`) of every
 * ISSUED node to `out`. This is a READ-ONLY walk: it does NOT change any node's
 * state — unlike drain, it makes no claim. The caller decides, per host, whether
 * the on-disk cert is inside its renew window (ngx_autocert_name_due) and only
 * then flips the node back to REQUESTED via set_state, so the next drain re-orders
 * it through the SAME global rate cap as a fresh request. Leaving the walk
 * side-effect-free means a not-yet-due ISSUED node is untouched and a re-scan is
 * idempotent.
 *
 * At most `max` hosts are copied per call (0 = no limit); the rest are seen on
 * the next scan. Returns the number of hosts appended to `out`, or -1 on bad
 * zone/version. An allocation failure MID-WALK returns the positive count copied
 * so far (partial list, all valid) — same convention as drain(); only a failure
 * on the very first copy returns -1. The renewal scan is idempotent, so a
 * truncated list just re-lists the rest next scan. Host strings in `out` are
 * pool-owned ngx_str_t, safe after unlock.
 */
NGX_AUTOCERT_REQUESTS_API ngx_int_t
ngx_autocert_requests_list_issued(ngx_shm_zone_t *shm_zone,
    ngx_pool_t *pool, ngx_array_t *out, ngx_uint_t max);


#endif /* _NGX_AUTOCERT_REQUESTS_H_INCLUDED_ */
