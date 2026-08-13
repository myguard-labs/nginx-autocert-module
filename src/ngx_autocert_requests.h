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
 *     A consumer reads the stamped `api_version`: the exact current version means
 *     autocert is active; NGX_AUTOCERT_API_INACTIVE_VERSION records the same layout
 *     with no active owner, so the feature is off without forgetting which layout
 *     is already stored in the arena.
 *   - RELOAD: nginx reuses the old mapping — it copies the old shm.addr onto the new
 *     cycle's zone and calls init() WITHOUT setting shm.exists (ngx_cycle.c; that
 *     flag only covers the platform/named-shm case and is always 0 on Linux). Since
 *     the header lives IN the arena at `shpool->data`, which the reuse path carries
 *     over untouched, a non-NULL `shpool->data` is the reuse signal and every
 *     REQUESTED/PENDING/ISSUED/FAILED node survives a reconfigure. Keying off
 *     `shm.exists` instead re-allocated a fresh header on every reload and orphaned
 *     the whole tree. The init callback's `data` argument is unused.
 *   - ACTIVITY AND LAYOUT ARE BOTH STAMPED. The owner uses the exact current API
 *     version; a consumer-only cycle uses NGX_AUTOCERT_API_INACTIVE_VERSION. They
 *     can toggle safely because both stamps identify the SAME layout. An inherited
 *     arena with any other nonzero stamp is never relabelled: the owner rejects the
 *     reload, because old workers may still populate or traverse that foreign layout.
 *     A true stop/start supplies a fresh arena for an incompatible upgrade.
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
 *
 * ELF visibility is a property of the TARGET/binary format, not the compiler, so
 * the guard must also exclude PE/COFF targets: MinGW-GCC defines __GNUC__ but
 * targets PE/COFF, which has no visibility concept, so the attribute is rejected
 * under -Werror=attributes. This is safe to fall back on, not just quiet: the
 * RTLD_GLOBAL interposition hazard above is a dlopen()/ELF concern that does not
 * arise on Windows, where each DLL already has its own private symbol namespace.
 */
#if (defined(__GNUC__) || defined(__clang__)) \
    && !defined(_WIN32) && !defined(__CYGWIN__)
#define NGX_AUTOCERT_REQUESTS_API  __attribute__((visibility("hidden")))
#else
#define NGX_AUTOCERT_REQUESTS_API
#endif


/* Bump on ANY change to the on-shm layout below or the state enum. Consumer
 * compares the zone-header `api_version` against its compiled value and disables
 * the feature on mismatch (fail safe, never mis-parse a foreign layout). */
#define NGX_AUTOCERT_API_VERSION   2

/* Reserve the high bit as the inactive marker. The low bits still identify the
 * immutable on-shm layout, while an exact unflagged version means an autocert
 * owner is active in this cycle. Existing consumers already require exact
 * equality with NGX_AUTOCERT_API_VERSION, so the inactive form fails safe. */
#define NGX_AUTOCERT_API_INACTIVE_FLAG                              \
    ((ngx_uint_t) 1 << (sizeof(ngx_uint_t) * 8 - 1))
#define NGX_AUTOCERT_API_INACTIVE_VERSION                           \
    (NGX_AUTOCERT_API_INACTIVE_FLAG | NGX_AUTOCERT_API_VERSION)

typedef char ngx_autocert_api_version_fits_activity_stamp[
    (NGX_AUTOCERT_API_VERSION & NGX_AUTOCERT_API_INACTIVE_FLAG) == 0 ? 1 : -1];

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
    time_t              last_seen;      /* idle-TTL marker: stamped on insert, on
                                           every ensure() hit (the consumer re-
                                           asserting the host is still wanted) and
                                           on every set_state() (driver activity:
                                           issuance outcome, renewal re-queue).
                                           gc() evicts nodes idle past the TTL.
                                           NOT last_attempt, which tracks issuance
                                           attempts only. ABI: added in version 2. */
    time_t              next_eligible;  /* backoff gate: driver skips until now >= this */
    ngx_uint_t          fail_count;
    u_short             host_len;
    u_char              host[1];        /* host_len bytes, inline (lowercased) */
} ngx_autocert_request_t;


/* Zone-wide shared header (lives at shpool->data). `api_version` carries both the
 * immutable layout identity and whether an owner is active; `count` bounds
 * insertion. */
typedef struct {
    ngx_uint_t          api_version;   /* active or inactive current-layout stamp */
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
 * — tree and all — and activates it only when its stamp proves the layout is
 * current. A legacy zero-stamped EMPTY arena is also safe to activate. A non-empty
 * zero-stamped or any foreign-version arena rejects the reload rather than risking
 * a foreign node-layout parse. Owner/consumer is decided by WHICH callback runs;
 * the `data` argument is unused.
 */
NGX_AUTOCERT_REQUESTS_API ngx_int_t
ngx_autocert_requests_init_zone(ngx_shm_zone_t *shm_zone, void *data);


/*
 * CONSUMER zone init callback. A consumer registers this ONLY when
 * `shm_zone->init == NULL` (i.e. autocert has not already claimed the zone); it
 * builds the same layout but stamps NGX_AUTOCERT_API_INACTIVE_VERSION, so the
 * exact-version check reports "not managed" while retaining the layout identity.
 * On reload it adopts the arena's existing header exactly like the owner callback
 * (the tree survives) and changes only a proven-current layout to inactive.
 *
 * That re-stamp is deliberate and is the FAIL-SAFE direction: this callback runs
 * only when autocert did NOT install its owner callback in this cycle, i.e. autocert
 * is absent or disabled. Leaving an inherited active stamp in place
 * would tell the consumer "autocert is managing this zone" when no driver exists to
 * drain it — ensure() would keep accepting REQUESTED nodes up to the cap and serve.c
 * would admit an SNI whose state can never advance. The inactive-current stamp
 * makes the feature inert without making a later reload guess the stored layout.
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


/*
 * Driver-side idle-TTL garbage collection (autocert worker-0 only). The
 * registry is a bounded table (NGX_AUTOCERT_REQUESTS_MAX): without eviction a
 * long-lived gateway churning distinct runtime hosts wedges at the cap
 * (ensure() => REQ_DENIED forever). Eviction must be autocert-side — a
 * consumer has no write path beyond ensure().
 *
 * Under the slab mutex, walks the tree and evicts every node whose
 * `last_seen` is more than `ttl` seconds in the past — EXCEPT PENDING nodes
 * (an ACME order is in flight for them; they are re-stamped by set_state()
 * when the order completes, and evicting one would orphan the completion's
 * set_state into a no-op that then re-inserts nothing). A node is kept alive
 * by ensure() hits (the consumer re-asserting the host) and by set_state()
 * (driver activity, including the renewal re-queue), so a live host never
 * ages out while a de-labelled one does.
 *
 * For each evicted node a COPY of its host (allocated from `pool`) is
 * appended to `out` so the caller can clean up per-host residue (the A6
 * on-disk runtime marker — leaving it would resurrect the evicted node on
 * the next true restart). `sh->count` is decremented per eviction, freeing
 * cap slots. An allocation failure mid-walk stops the sweep and returns the
 * evictions performed so far (all valid; the rest age out again next sweep).
 * If the copy for a node cannot be allocated, that node is NOT evicted (the
 * caller could never clean its marker).
 *
 * ttl <= 0 disables (returns 0, touches nothing). Returns the number of
 * nodes evicted (== hosts appended to `out`), or -1 on bad zone/version/args.
 */
NGX_AUTOCERT_REQUESTS_API ngx_int_t
ngx_autocert_requests_gc(ngx_shm_zone_t *shm_zone, time_t ttl,
    ngx_pool_t *pool, ngx_array_t *out);


#endif /* _NGX_AUTOCERT_REQUESTS_H_INCLUDED_ */
