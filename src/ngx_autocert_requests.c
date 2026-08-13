/*
 * ngx_autocert_requests — shared-memory runtime cert-request registry (autolabel A1).
 * See the header for the cross-module contract. An rbtree of host->state in a slab
 * zone, keyed by crc32(host) with the full host compared on collision. Compiled
 * into both the autocert modules AND (verbatim, via the shared header) the consumer,
 * all operating on the same slab addressed through the named zone.
 */

#include <ngx_config.h>

#include "ngx_autocert_requests.h"


/* Retry backoff: base doubled per failure, clamped. Used by set_state(FAILED)
 * only when the caller passes next_eligible == 0 (0 => "compute it for me"). */
#define NGX_AUTOCERT_REQ_BACKOFF_BASE   300      /* 5 min */
#define NGX_AUTOCERT_REQ_BACKOFF_MAX    86400    /* 1 day */


static ngx_autocert_request_t *ngx_autocert_requests_lookup(
    ngx_autocert_requests_sh_t *sh, ngx_str_t *host, uint32_t hash);


/*
 * Is `buf`/`len` a dotted-quad IPv4 literal (a.b.c.d, each octet 0-255)?
 *
 * The runtime API is DNS-name-only: IP certificates are config-driven
 * (`autocert` on a server whose name is a literal), never runtime-requested, so
 * a label producer must not be able to enqueue one. This is a deliberately
 * dependency-light parser rather than ngx_autocert_str_is_ip(): this TU is
 * vendored verbatim into consumer modules and includes nothing beyond
 * ngx_core.h, while str_is_ip lives in a header that drags in <openssl/x509v3.h>.
 *
 * IPv6 literals cannot reach here at all — the LDH gate below rejects ':' — but
 * this stays correct if that charset is ever loosened, because a v6 literal has
 * no dotted-quad shape either. Runs AFTER normalization, on the lowercased copy.
 */
static ngx_int_t
ngx_autocert_requests_is_ipv4(const u_char *buf, size_t len)
{
    size_t      i;
    ngx_uint_t  octet, digits, dots;

    octet = 0;
    digits = 0;
    dots = 0;

    for (i = 0; i < len; i++) {
        if (buf[i] == '.') {
            if (digits == 0) {
                return 0;
            }
            dots++;
            octet = 0;
            digits = 0;
            continue;
        }

        if (buf[i] < '0' || buf[i] > '9') {
            return 0;              /* any non-digit => a DNS name */
        }

        octet = octet * 10 + (ngx_uint_t) (buf[i] - '0');
        digits++;

        if (digits > 3 || octet > 255) {
            return 0;
        }
    }

    /* exactly four octets, the last one non-empty */
    return (dots == 3 && digits > 0) ? 1 : 0;
}


/*
 * Validate + normalize a runtime host into `buf` (caller supplies
 * NGX_AUTOCERT_REQUEST_NAME_MAX bytes). Rules: non-empty, within cap, LDH per
 * label (letters/digits/hyphen), dot-separated, no leading/trailing dot, no
 * wildcard, no empty label, and NOT an IP literal (the runtime API is
 * DNS-name-only — IP certs are config-driven). Lowercases into buf. Returns the
 * length, or 0 on reject. This is the single gate both ensure() and state()
 * share so a stored key and a lookup key always normalize identically.
 */
static size_t
ngx_autocert_requests_normalize(ngx_str_t *host, u_char *buf)
{
    size_t  i, label_len;
    u_char  c;

    if (host->len == 0 || host->len > NGX_AUTOCERT_REQUEST_NAME_MAX) {
        return 0;
    }

    label_len = 0;

    for (i = 0; i < host->len; i++) {
        c = host->data[i];

        if (c == '.') {
            if (label_len == 0) {          /* leading dot or empty label ".." */
                return 0;
            }
            /* a label cannot end in a hyphen */
            if (buf[i - 1] == '-') {
                return 0;
            }
            label_len = 0;
            buf[i] = '.';
            continue;
        }

        if (c >= 'A' && c <= 'Z') {
            c = (u_char) (c - 'A' + 'a');   /* lowercase */

        } else if (!((c >= 'a' && c <= 'z')
                     || (c >= '0' && c <= '9')
                     || c == '-'))
        {
            return 0;                        /* not LDH (rejects '*', '_', etc.) */
        }

        /* a label cannot start with a hyphen */
        if (c == '-' && label_len == 0) {
            return 0;
        }

        buf[i] = c;
        label_len++;

        if (label_len > 63) {                /* max DNS label length */
            return 0;
        }
    }

    if (label_len == 0) {                    /* trailing dot */
        return 0;
    }

    /* the final label cannot end in a hyphen either (the in-loop check only
     * fires at a dot boundary, so a trailing "-" reaches here unvalidated) */
    if (buf[host->len - 1] == '-') {
        return 0;
    }

    /* An IP literal is LDH-clean (127.0.0.1 is all digits and dots), so the loop
     * above happily accepts one. The runtime API is DNS-name-only — reject it,
     * or a label producer could spend the bounded ledger/CA budget on an IP
     * order that policy says must be config-driven. */
    if (ngx_autocert_requests_is_ipv4(buf, host->len)) {
        return 0;
    }

    return host->len;
}


static void
ngx_autocert_requests_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t       **p;
    ngx_autocert_request_t   *rn, *rnt;

    for ( ;; ) {
        if (node->key != temp->key) {
            p = (node->key < temp->key) ? &temp->left : &temp->right;

        } else {
            rn = (ngx_autocert_request_t *) node;
            rnt = (ngx_autocert_request_t *) temp;

            if (rn->host_len != rnt->host_len) {
                p = (rn->host_len < rnt->host_len) ? &temp->left : &temp->right;
            } else {
                p = (ngx_memcmp(rn->host, rnt->host, rn->host_len) < 0)
                    ? &temp->left : &temp->right;
            }
        }

        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


/*
 * Shared init body. The OWNER uses the exact current version; a consumer-only
 * cycle uses the inactive-current stamp. That preserves layout identity while
 * making every helper inert when no autocert driver exists. Owner/consumer is
 * decided by WHICH init callback runs (the two thin wrappers below), never by the
 * `data` argument.
 *
 * RELOAD HANDOFF. nginx's zone-reuse path (ngx_cycle.c) copies the old mapping's
 * shm.addr onto the new zone and calls init(new_zone, old_zone->data) WITHOUT
 * setting shm.exists — that flag only covers the platform/named-shm case. So
 * `shpool->data` is the reliable reuse signal, and shm.exists alone is not: relying
 * on it re-allocated a fresh header on every reload and orphaned the whole request
 * tree. Adopt that header, but change only the activity bit of a layout proven to
 * be current. Never relabel an unknown layout: retiring workers can still
 * access the same mapping during a graceful reload, so in-place migration or reset
 * is unsafe.
 */
static ngx_int_t
ngx_autocert_requests_init_body(ngx_shm_zone_t *shm_zone, ngx_uint_t owner)
{
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh;
    ngx_uint_t                   api_version, inherited, legacy_empty, log_level;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    /* Reuse across reload: adopt the existing header, never re-allocate. The
     * header lives at shpool->data, i.e. INSIDE the arena that the reuse path
     * carries over untouched — so a non-NULL shpool->data is itself the reliable
     * reuse signal, and a fresh arena (mmap'd zero-filled) gives NULL. This is
     * the same test the alpn and challenge zones use. */
    sh = shpool->data;

    if (sh != NULL) {
        inherited = sh->api_version;
        api_version = owner ? NGX_AUTOCERT_API_VERSION
                            : NGX_AUTOCERT_API_INACTIVE_VERSION;

        /* Version 0 was the pre-fix consumer-only marker. It carried no layout
         * identity, so it is safe to promote only while the known legacy header
         * proves that no nodes exist. Do not inspect any fields beyond the stamp
         * for other foreign versions. */
        legacy_empty = inherited == 0
                       && sh->count == 0
                       && sh->rbtree.root == &sh->sentinel
                       && sh->rbtree.sentinel == &sh->sentinel;

        if (inherited == NGX_AUTOCERT_API_VERSION
            || inherited == NGX_AUTOCERT_API_INACTIVE_VERSION
            || legacy_empty)
        {
            sh->api_version = api_version;

            ngx_log_debug2(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                           "autocert: requests zone inherited "
                           "(api_version %ui -> %ui)",
                           inherited, sh->api_version);
            return NGX_OK;
        }

        if (shm_zone->shm.log != NULL) {
            log_level = owner ? NGX_LOG_EMERG : NGX_LOG_WARN;
            ngx_log_error(log_level, shm_zone->shm.log, 0,
                          "autocert: requests zone has incompatible or "
                          "ambiguous layout stamp %ui (compiled layout %ui); %s",
                          inherited, (ngx_uint_t) NGX_AUTOCERT_API_VERSION,
                          owner ? "stop nginx completely before enabling this "
                                  "autocert module version"
                                : "runtime certificate requests remain disabled");
        }

        /* A consumer remains safely inert because its helpers require the exact
         * current active stamp. An owner must abort this reload: stamping current
         * here would make it parse foreign nodes while old workers share them. */
        return owner ? NGX_ERROR : NGX_OK;
    }

    sh = ngx_slab_alloc(shpool, sizeof(ngx_autocert_requests_sh_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    shpool->data = sh;

    sh->api_version = owner ? NGX_AUTOCERT_API_VERSION
                            : NGX_AUTOCERT_API_INACTIVE_VERSION;
    sh->count = 0;

    ngx_rbtree_init(&sh->rbtree, &sh->sentinel,
                    ngx_autocert_requests_insert_value);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                   "autocert: requests zone initialized (api_version %ui)",
                   sh->api_version);

    return NGX_OK;
}


ngx_int_t
ngx_autocert_requests_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    /* `data` (the old cycle's shm_zone->data) is deliberately unused: the header
     * we inherit lives in the ARENA, at shpool->data, which the reuse path carries
     * over untouched. See ngx_autocert_requests_init_body. */
    (void) data;
    return ngx_autocert_requests_init_body(shm_zone, 1);
}


ngx_int_t
ngx_autocert_requests_init_zone_consumer(ngx_shm_zone_t *shm_zone, void *data)
{
    (void) data;
    return ngx_autocert_requests_init_body(shm_zone, 0);
}


static ngx_autocert_request_t *
ngx_autocert_requests_lookup(ngx_autocert_requests_sh_t *sh, ngx_str_t *host,
    uint32_t hash)
{
    ngx_rbtree_node_t       *node, *sentinel;
    ngx_autocert_request_t  *rn;
    ngx_int_t                rc;

    node = sh->rbtree.root;
    sentinel = sh->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }

        rn = (ngx_autocert_request_t *) node;

        if (host->len != rn->host_len) {
            node = (host->len < rn->host_len) ? node->left : node->right;
            continue;
        }

        rc = ngx_memcmp(host->data, rn->host, host->len);
        if (rc == 0) {
            return rn;
        }
        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


ngx_int_t
ngx_autocert_requests_ensure(ngx_shm_zone_t *shm_zone, ngx_str_t *host)
{
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh;
    ngx_autocert_request_t      *rn;
    ngx_str_t                    norm;
    u_char                       buf[NGX_AUTOCERT_REQUEST_NAME_MAX];
    uint32_t                     hash;
    ngx_int_t                    state;

    if (shm_zone == NULL || shm_zone->shm.addr == NULL) {
        return NGX_AUTOCERT_REQ_UNKNOWN;
    }

    norm.len = ngx_autocert_requests_normalize(host, buf);
    if (norm.len == 0) {
        return NGX_AUTOCERT_REQ_DENIED;
    }
    norm.data = buf;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;

    /* Fail safe: never mutate a zone whose header is absent (init not yet run)
     * or a foreign/older layout. A mismatched api_version means the on-shm
     * struct is not the one we compile against, so we must not parse it. */
    if (sh == NULL || sh->api_version != NGX_AUTOCERT_API_VERSION) {
        return NGX_AUTOCERT_REQ_UNKNOWN;
    }

    hash = ngx_crc32_long(norm.data, norm.len);

    ngx_shmtx_lock(&shpool->mutex);

    rn = ngx_autocert_requests_lookup(sh, &norm, hash);
    if (rn != NULL) {
        /* Idle-TTL keep-alive: an ensure() hit is the consumer re-asserting
         * the host is still wanted, so refresh last_seen or gc() would evict
         * a live host the consumer keeps asking about. */
        rn->last_seen = ngx_time();
        state = (ngx_int_t) rn->state;
        ngx_shmtx_unlock(&shpool->mutex);
        return state;
    }

    if (sh->count >= NGX_AUTOCERT_REQUESTS_MAX) {
        ngx_shmtx_unlock(&shpool->mutex);
        if (shm_zone->shm.log != NULL) {
            ngx_log_error(NGX_LOG_WARN, shm_zone->shm.log, 0,
                          "autocert: runtime request \"%V\" denied "
                          "(cap %ui reached)",
                          &norm, (ngx_uint_t) NGX_AUTOCERT_REQUESTS_MAX);
        }
        return NGX_AUTOCERT_REQ_DENIED;
    }

    rn = ngx_slab_alloc_locked(shpool,
             offsetof(ngx_autocert_request_t, host) + norm.len);
    if (rn == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_AUTOCERT_REQ_UNKNOWN;    /* OOM: report as not-tracked */
    }

    rn->node.key = hash;
    rn->state = NGX_AUTOCERT_REQ_REQUESTED;
    rn->first_seen = ngx_time();
    rn->last_seen = rn->first_seen;
    rn->last_attempt = 0;
    rn->next_eligible = 0;
    rn->fail_count = 0;
    rn->host_len = (u_short) norm.len;
    ngx_memcpy(rn->host, norm.data, norm.len);

    ngx_rbtree_insert(&sh->rbtree, &rn->node);
    sh->count++;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                   "autocert: runtime request enqueued \"%V\"", &norm);

    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_AUTOCERT_REQ_REQUESTED;
}


ngx_int_t
ngx_autocert_requests_state(ngx_shm_zone_t *shm_zone, ngx_str_t *host)
{
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh;
    ngx_autocert_request_t      *rn;
    ngx_str_t                    norm;
    u_char                       buf[NGX_AUTOCERT_REQUEST_NAME_MAX];
    uint32_t                     hash;
    ngx_int_t                    state;

    if (shm_zone == NULL || shm_zone->shm.addr == NULL) {
        return NGX_AUTOCERT_REQ_UNKNOWN;
    }

    norm.len = ngx_autocert_requests_normalize(host, buf);
    if (norm.len == 0) {
        return NGX_AUTOCERT_REQ_UNKNOWN;
    }
    norm.data = buf;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;

    if (sh == NULL || sh->api_version != NGX_AUTOCERT_API_VERSION) {
        return NGX_AUTOCERT_REQ_UNKNOWN;
    }

    hash = ngx_crc32_long(norm.data, norm.len);

    ngx_shmtx_lock(&shpool->mutex);
    rn = ngx_autocert_requests_lookup(sh, &norm, hash);
    state = (rn != NULL) ? (ngx_int_t) rn->state : NGX_AUTOCERT_REQ_UNKNOWN;
    ngx_shmtx_unlock(&shpool->mutex);

    return state;
}


ngx_int_t
ngx_autocert_requests_drain(ngx_shm_zone_t *shm_zone, ngx_pool_t *pool,
    ngx_array_t *out, ngx_uint_t max)
{
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh;
    ngx_autocert_request_t      *rn;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_str_t                   *host;
    u_char                      *data;
    time_t                       now;
    ngx_int_t                    claimed;

    if (shm_zone == NULL || shm_zone->shm.addr == NULL
        || pool == NULL || out == NULL)
    {
        return -1;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;

    if (sh == NULL || sh->api_version != NGX_AUTOCERT_API_VERSION) {
        return -1;
    }

    now = ngx_time();
    claimed = 0;

    ngx_shmtx_lock(&shpool->mutex);

    sentinel = sh->rbtree.sentinel;

    if (sh->rbtree.root == sentinel) {
        ngx_shmtx_unlock(&shpool->mutex);
        return 0;
    }

    for (node = ngx_rbtree_min(sh->rbtree.root, sentinel);
         node != NULL;
         node = ngx_rbtree_next(&sh->rbtree, node))
    {
        if (max != 0 && (ngx_uint_t) claimed >= max) {
            break;
        }

        rn = (ngx_autocert_request_t *) node;

        /* Claim a node the driver should (re)order now: a fresh REQUESTED enqueue,
         * or a FAILED node whose backoff has elapsed. set_state(FAILED,...) stamps
         * next_eligible via the exponential backoff, so a runtime order that fails
         * transiently (fresh request OR an A3.5 renewal re-queue) is retried once
         * the window passes instead of being stranded FAILED forever. Both gate on
         * next_eligible (0 = eligible immediately). */
        if ((rn->state != NGX_AUTOCERT_REQ_REQUESTED
             && rn->state != NGX_AUTOCERT_REQ_FAILED)
            || (rn->next_eligible != 0 && now < rn->next_eligible))
        {
            continue;
        }

        /* Copy the host out first: if allocation fails the node stays in its
         * current state and is retried next tick, rather than being
         * claimed-but-lost. */
        host = ngx_array_push(out);
        if (host == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return (claimed > 0) ? claimed : -1;
        }

        data = ngx_pnalloc(pool, rn->host_len);
        if (data == NULL) {
            out->nelts--;               /* undo the push we can't fill */
            ngx_shmtx_unlock(&shpool->mutex);
            return (claimed > 0) ? claimed : -1;
        }

        ngx_memcpy(data, rn->host, rn->host_len);
        host->data = data;
        host->len = rn->host_len;

        /* Claim it: a concurrent drain now sees PENDING and skips it. */
        rn->state = NGX_AUTOCERT_REQ_PENDING;
        rn->last_attempt = now;
        claimed++;
    }

    ngx_shmtx_unlock(&shpool->mutex);
    return claimed;
}


ngx_int_t
ngx_autocert_requests_list_issued(ngx_shm_zone_t *shm_zone, ngx_pool_t *pool,
    ngx_array_t *out, ngx_uint_t max)
{
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh;
    ngx_autocert_request_t      *rn;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_str_t                   *host;
    u_char                      *data;
    ngx_int_t                    listed;

    if (shm_zone == NULL || shm_zone->shm.addr == NULL
        || pool == NULL || out == NULL)
    {
        return -1;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;

    if (sh == NULL || sh->api_version != NGX_AUTOCERT_API_VERSION) {
        return -1;
    }

    listed = 0;

    ngx_shmtx_lock(&shpool->mutex);

    sentinel = sh->rbtree.sentinel;

    if (sh->rbtree.root == sentinel) {
        ngx_shmtx_unlock(&shpool->mutex);
        return 0;
    }

    for (node = ngx_rbtree_min(sh->rbtree.root, sentinel);
         node != NULL;
         node = ngx_rbtree_next(&sh->rbtree, node))
    {
        if (max != 0 && (ngx_uint_t) listed >= max) {
            break;
        }

        rn = (ngx_autocert_request_t *) node;

        if (rn->state != NGX_AUTOCERT_REQ_ISSUED) {
            continue;
        }

        /* Read-only: copy the host out, never touch node state. On alloc failure
         * return what we have; the node is unchanged and re-listed next scan. */
        host = ngx_array_push(out);
        if (host == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return (listed > 0) ? listed : -1;
        }

        data = ngx_pnalloc(pool, rn->host_len);
        if (data == NULL) {
            out->nelts--;               /* undo the push we can't fill */
            ngx_shmtx_unlock(&shpool->mutex);
            return (listed > 0) ? listed : -1;
        }

        ngx_memcpy(data, rn->host, rn->host_len);
        host->data = data;
        host->len = rn->host_len;
        listed++;
    }

    ngx_shmtx_unlock(&shpool->mutex);
    return listed;
}


ngx_int_t
ngx_autocert_requests_gc(ngx_shm_zone_t *shm_zone, time_t ttl,
    ngx_pool_t *pool, ngx_array_t *out)
{
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh;
    ngx_autocert_request_t      *rn;
    ngx_autocert_request_t      *victims[NGX_AUTOCERT_REQUESTS_MAX];
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_str_t                   *host;
    u_char                      *data;
    time_t                       now;
    ngx_uint_t                   nvictims, i;
    ngx_int_t                    evicted;

    if (shm_zone == NULL || shm_zone->shm.addr == NULL
        || pool == NULL || out == NULL)
    {
        return -1;
    }

    if (ttl <= 0) {
        return 0;                       /* GC disabled */
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;

    if (sh == NULL || sh->api_version != NGX_AUTOCERT_API_VERSION) {
        return -1;
    }

    now = ngx_time();
    evicted = 0;

    ngx_shmtx_lock(&shpool->mutex);

    sentinel = sh->rbtree.sentinel;

    if (sh->rbtree.root == sentinel) {
        ngx_shmtx_unlock(&shpool->mutex);
        return 0;
    }

    /*
     * Collect-then-delete: rbtree deletion relinks nodes, so deleting while
     * iterating with ngx_rbtree_next is fragile. The tree is hard-bounded at
     * NGX_AUTOCERT_REQUESTS_MAX nodes (sh->count gates insertion), so a fixed
     * stack array always fits.
     */
    nvictims = 0;

    for (node = ngx_rbtree_min(sh->rbtree.root, sentinel);
         node != NULL && nvictims < NGX_AUTOCERT_REQUESTS_MAX;
         node = ngx_rbtree_next(&sh->rbtree, node))
    {
        rn = (ngx_autocert_request_t *) node;

        /* PENDING = an order is in flight; its completion set_state() will
         * re-stamp last_seen, so evicting a live one would orphan that
         * completion. Protect it for the TTL, not forever: a completion can be
         * lost for good, and then nothing ever clears the node.
         *
         * The way that happens in practice is a graceful disable. set_state()
         * rejects every write while the zone carries the INACTIVE stamp, so an
         * order that fails during a consumer-only cycle cannot record FAILED or
         * REQUESTED. Re-enabling autocert leaves the node PENDING with no disk
         * marker for startup seeding to repair, and an unconditional skip here
         * meant that hostname could never be requested again short of a full
         * restart (a reload reuses the zone).
         *
         * A real order is minutes; a node PENDING for a whole idle TTL has lost
         * its completion, so age it out like any other. The cost of being wrong
         * is one redundant re-request, against a permanently stuck name. */
        if (now - rn->last_seen <= ttl) {
            continue;
        }

        if (rn->state == NGX_AUTOCERT_REQ_PENDING) {
            ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                          "autocert: evicting runtime request \"%*s\" stuck "
                          "PENDING for %T seconds; its order completion was "
                          "lost (graceful disable, or a worker died mid-order)",
                          (size_t) rn->host_len, rn->host,
                          (time_t) (now - rn->last_seen));
        }

        victims[nvictims++] = rn;
    }

    for (i = 0; i < nvictims; i++) {
        rn = victims[i];

        /* Copy the host out FIRST: the caller must be able to clean up the
         * per-host residue (A6 marker). If the copy fails, keep the node —
         * it just ages out again next sweep. */
        host = ngx_array_push(out);
        if (host == NULL) {
            break;
        }

        data = ngx_pnalloc(pool, rn->host_len);
        if (data == NULL) {
            out->nelts--;               /* undo the push we can't fill */
            break;
        }

        ngx_memcpy(data, rn->host, rn->host_len);
        host->data = data;
        host->len = rn->host_len;

        ngx_rbtree_delete(&sh->rbtree, &rn->node);
        ngx_slab_free_locked(shpool, rn);

        if (sh->count > 0) {
            sh->count--;
        }

        evicted++;

        if (shm_zone->shm.log != NULL) {
            ngx_log_error(NGX_LOG_NOTICE, shm_zone->shm.log, 0,
                          "autocert: runtime request \"%V\" evicted "
                          "(idle > %T s)", host, ttl);
        }
    }

    ngx_shmtx_unlock(&shpool->mutex);
    return evicted;
}


ngx_int_t
ngx_autocert_requests_set_state(ngx_shm_zone_t *shm_zone, ngx_str_t *host,
    ngx_uint_t state, time_t next_eligible)
{
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh;
    ngx_autocert_request_t      *rn;
    ngx_str_t                    norm;
    u_char                       buf[NGX_AUTOCERT_REQUEST_NAME_MAX];
    uint32_t                     hash;
    time_t                       backoff;

    /* UNKNOWN (0) is the "no node" sentinel and is never stored; storing it
     * would leave a live node that reads as absent yet still consumes the cap.
     * Reject it along with out-of-range states. */
    if (shm_zone == NULL || shm_zone->shm.addr == NULL
        || state <= NGX_AUTOCERT_REQ_UNKNOWN
        || state > NGX_AUTOCERT_REQ_DENIED)
    {
        return NGX_ERROR;
    }

    norm.len = ngx_autocert_requests_normalize(host, buf);
    if (norm.len == 0) {
        return NGX_ERROR;
    }
    norm.data = buf;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;

    if (sh == NULL || sh->api_version != NGX_AUTOCERT_API_VERSION) {
        return NGX_ERROR;
    }

    hash = ngx_crc32_long(norm.data, norm.len);

    ngx_shmtx_lock(&shpool->mutex);

    rn = ngx_autocert_requests_lookup(sh, &norm, hash);
    if (rn == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_OK;                       /* absent: nothing to update */
    }

    rn->state = state;
    rn->last_attempt = ngx_time();

    /* Idle-TTL keep-alive: any driver-side transition (issuance outcome,
     * renewal re-queue, rate-cap release) is activity — refresh last_seen so
     * a live-but-low-traffic host is kept alive by its own renewal cycle,
     * not only by consumer ensure() hits. */
    rn->last_seen = rn->last_attempt;

    if (state == NGX_AUTOCERT_REQ_FAILED) {
        ngx_uint_t  n;

        rn->fail_count++;
        if (next_eligible == 0) {
            /* base doubled (fail_count - 1) times, clamped. Iterated (not a
             * single shift) so a large fail_count can't overflow time_t. */
            backoff = NGX_AUTOCERT_REQ_BACKOFF_BASE;
            for (n = rn->fail_count; n > 1; n--) {
                backoff <<= 1;
                if (backoff >= NGX_AUTOCERT_REQ_BACKOFF_MAX) {
                    backoff = NGX_AUTOCERT_REQ_BACKOFF_MAX;
                    break;
                }
            }
            next_eligible = ngx_time() + backoff;
        }
        rn->next_eligible = next_eligible;

    } else {
        rn->next_eligible = next_eligible;   /* 0 = eligible now */
    }

    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;
}
