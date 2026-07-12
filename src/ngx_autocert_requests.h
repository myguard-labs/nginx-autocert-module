/*
 * ngx_autocert_requests — shared-memory runtime cert-request registry (autolabel A1).
 *
 * The autolabel integration lets a SEPARATE module (nginx-label-autoconf-module)
 * ask autocert to obtain a certificate for a host discovered at runtime (from a
 * Docker label `nda.tls.auto=true`), without either module linking the other.
 *
 * The two modules ship as distinct dlopen()ed .so files and nginx loads each
 * WITHOUT RTLD_GLOBAL, so they cannot cross-resolve C symbols (this is the same
 * wall documented in ngx_http_autocert_conf.h). The integration surface is
 * therefore NOT an exported function API but a NAMED shared-memory zone plus a
 * versioned on-shm layout that both sides agree on — exactly this header.
 *
 * Contract:
 *   - Zone name = NGX_AUTOCERT_REQUESTS_ZONE, size = NGX_AUTOCERT_REQUESTS_ZONE_SIZE,
 *     tag = NULL. The tag MUST be NULL on both sides: each .so has its own address
 *     for any global, so a per-module tag pointer would make ngx_shared_memory_add()
 *     reject the second module's attach as a different use of the same name. Both
 *     modules must also pass the SAME size (this macro) or nginx errors on mismatch.
 *   - Whichever module's postconfig runs first ngx_shared_memory_add()s it; the
 *     other attaches the same name (nginx dedups on name+tag). autocert registers
 *     ngx_autocert_requests_init_zone (stamps `api_version`); a consumer that may
 *     create the zone first registers ngx_autocert_requests_init_zone_consumer
 *     (stamps 0). Owner/consumer is decided by WHICH init callback runs, never by
 *     the callback's `data` arg (nginx passes the old cycle's data there, NULL on a
 *     fresh start, so it cannot identify the owner). A consumer reads the stamped
 *     `api_version` (0/absent => autocert not managing this zone => feature off).
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
 * OWNER zone init callback (autocert side). Sets up the rbtree and stamps
 * `api_version = NGX_AUTOCERT_API_VERSION`. autocert registers this as
 * shm_zone->init. On reload the old cycle's tree (and its stamp) is inherited.
 * The `data` argument is IGNORED — nginx passes the old cycle's zone data there
 * (NULL on a fresh start), so it cannot indicate owner vs consumer; that is why
 * there are two distinct init callbacks rather than one branching on `data`.
 */
ngx_int_t ngx_autocert_requests_init_zone(ngx_shm_zone_t *shm_zone, void *data);


/*
 * CONSUMER zone init callback. A consumer that may create the zone BEFORE autocert
 * attaches (autocert absent or later in load order) registers this instead; it
 * builds the same layout but stamps `api_version = 0`, so the version check reports
 * "not managed" and the consumer degrades gracefully. If autocert is present it
 * creates the zone first and this is never invoked. `data` ignored (see above).
 */
ngx_int_t ngx_autocert_requests_init_zone_consumer(ngx_shm_zone_t *shm_zone,
    void *data);


/*
 * Idempotent enqueue. Validates host (non-empty, <= NGX_AUTOCERT_REQUEST_NAME_MAX,
 * LDH charset, no wildcard, no trailing dot), lowercases it, and under the slab
 * mutex either returns the existing node's state or inserts a fresh REQUESTED
 * node. Over the NGX_AUTOCERT_REQUESTS_MAX cap => returns REQ_DENIED without
 * allocating. Returns the resulting ngx_autocert_request_state_e as an ngx_int_t.
 * Callable from any worker (shm is mapped everywhere). Bad zone => REQ_UNKNOWN.
 */
ngx_int_t ngx_autocert_requests_ensure(ngx_shm_zone_t *shm_zone,
    ngx_str_t *host);


/*
 * Look up a host's current state without inserting (serve/consumer read path).
 * Returns the ngx_autocert_request_state_e; REQ_UNKNOWN if absent or bad input.
 * Lowercases + validates the same way as ensure so a hit is charset-consistent.
 */
ngx_int_t ngx_autocert_requests_state(ngx_shm_zone_t *shm_zone,
    ngx_str_t *host);


/*
 * Driver-side state transition (autocert only). Sets an existing node's state and,
 * for FAILED, bumps fail_count + stamps next_eligible = now + backoff. No-op if
 * the host is absent. Under the slab mutex. Returns NGX_OK / NGX_ERROR (bad arg).
 */
ngx_int_t ngx_autocert_requests_set_state(ngx_shm_zone_t *shm_zone,
    ngx_str_t *host, ngx_uint_t state, time_t next_eligible);


#endif /* _NGX_AUTOCERT_REQUESTS_H_INCLUDED_ */
