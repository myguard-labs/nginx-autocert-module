/*
 * ngx_autocert_requests — shared-memory runtime cert-request registry (autolabel A1).
 * See the header for the cross-module contract. An rbtree of host->state in a slab
 * zone, keyed by crc32(host) with the full host compared on collision. Compiled
 * into both the autocert modules AND (verbatim, via the shared header) the consumer,
 * all operating on the same slab addressed through the named zone.
 */

#include "ngx_autocert_requests.h"


/* Retry backoff: base doubled per failure, clamped. Used by set_state(FAILED)
 * only when the caller passes next_eligible == 0 (0 => "compute it for me"). */
#define NGX_AUTOCERT_REQ_BACKOFF_BASE   300      /* 5 min */
#define NGX_AUTOCERT_REQ_BACKOFF_MAX    86400    /* 1 day */


static ngx_autocert_request_t *ngx_autocert_requests_lookup(
    ngx_autocert_requests_sh_t *sh, ngx_str_t *host, uint32_t hash);


/*
 * Validate + normalize a runtime host into `buf` (caller supplies
 * NGX_AUTOCERT_REQUEST_NAME_MAX bytes). Rules: non-empty, within cap, LDH per
 * label (letters/digits/hyphen), dot-separated, no leading/trailing dot, no
 * wildcard, no empty label. Lowercases into buf. Returns the length, or 0 on
 * reject. This is the single gate both ensure() and state() share so a stored
 * key and a lookup key always normalize identically.
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
 * Shared init body. `api_version` selects the stamp: the OWNER (autocert) passes
 * NGX_AUTOCERT_API_VERSION, a CONSUMER-first creation passes 0 ("layout exists but
 * autocert is not managing it"). Owner/consumer is decided by WHICH init callback
 * runs (the two thin wrappers below), never by the `data` argument.
 *
 * RELOAD HANDOFF. nginx's zone-reuse path (ngx_cycle.c) copies the old mapping's
 * shm.addr onto the new zone and calls init(new_zone, old_zone->data) WITHOUT
 * setting shm.exists — that flag only covers the platform/named-shm case. So
 * `data` (the old cycle's shm_zone->data, which is exactly the header we publish
 * below) is the reliable reuse signal, and shm.exists alone is not: relying on it
 * re-allocated a fresh header on every reload and orphaned the whole request tree.
 * Adopt `data` when present, re-publish it on this cycle's zone, and RE-STAMP the
 * inherited header with this cycle's api_version — in both directions. The callback
 * that runs is the claim, so the stamp always reflects whether autocert is actually
 * managing the zone in THIS cycle (see the adopt branch below).
 */
static ngx_int_t
ngx_autocert_requests_init_body(ngx_shm_zone_t *shm_zone, ngx_uint_t api_version)
{
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    /* Reuse across reload: adopt the existing header, never re-allocate. The
     * header lives at shpool->data, i.e. INSIDE the arena that the reuse path
     * carries over untouched — so a non-NULL shpool->data is itself the reliable
     * reuse signal, and a fresh arena (mmap'd zero-filled) gives NULL. This is
     * the same test the alpn and challenge zones use. */
    sh = shpool->data;

    if (sh != NULL) {
        /*
         * RE-STAMP to whatever THIS cycle's callback says, in both directions.
         * The callback that runs IS the claim: the owner callback runs only when
         * autocert's postconfig installed it (autocert enabled with issuable
         * names), the consumer callback only when it did not.
         *
         * So a reload that DISABLES autocert (names removed, or its load_module
         * dropped) leaves only the consumer callback, which must stamp the
         * inherited header back to 0 — otherwise the stamp still says "autocert
         * is managing this zone" while no driver exists to drain it: ensure()
         * would keep returning REQUESTED, nodes would pile up to the cap, and
         * serve.c would admit an SNI whose state can never advance. Re-stamping
         * keeps the feature FAIL-SAFE (inert) exactly as it was before the zone
         * was ever owned.
         */
        sh->api_version = api_version;

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: requests zone inherited (api_version %ui)",
                       sh->api_version);
        return NGX_OK;
    }

    sh = ngx_slab_alloc(shpool, sizeof(ngx_autocert_requests_sh_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    shpool->data = sh;

    sh->api_version = api_version;
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
    return ngx_autocert_requests_init_body(shm_zone, NGX_AUTOCERT_API_VERSION);
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
