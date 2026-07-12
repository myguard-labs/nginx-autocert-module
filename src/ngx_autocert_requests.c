/*
 * ngx_autocert_requests — shared-memory runtime cert-request registry (autolabel A1).
 * See the header for the cross-module contract. An rbtree of host->state in a slab
 * zone, keyed by crc32(host) with the full host compared on collision. Compiled
 * into both the autocert modules AND (verbatim, via the shared header) the consumer,
 * all operating on the same slab addressed through the named zone.
 */

#include "ngx_autocert_requests.h"


/* Its own address is the zone tag; the value is never read. */
ngx_uint_t  ngx_autocert_requests_zone_tag;


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


ngx_int_t
ngx_autocert_requests_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh;

    /* Inherit the previous incarnation's tree across reload. */
    if (shm_zone->shm.exists) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: requests zone inherited from old cycle");
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    sh = ngx_slab_alloc(shpool, sizeof(ngx_autocert_requests_sh_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    shpool->data = sh;

    /* data != NULL => the OWNER (autocert) is initializing: stamp the real
     * version. data == NULL => a consumer created the zone before autocert
     * attached (autocert absent or later in load order): stamp 0 so the version
     * check reports "not managed" and the feature stays off. */
    sh->api_version = (data != NULL) ? NGX_AUTOCERT_API_VERSION : 0;
    sh->count = 0;

    ngx_rbtree_init(&sh->rbtree, &sh->sentinel,
                    ngx_autocert_requests_insert_value);

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                   "autocert: requests zone initialized (api_version %ui)",
                   sh->api_version);

    return NGX_OK;
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
    hash = ngx_crc32_long(norm.data, norm.len);

    ngx_shmtx_lock(&shpool->mutex);
    rn = ngx_autocert_requests_lookup(sh, &norm, hash);
    state = (rn != NULL) ? (ngx_int_t) rn->state : NGX_AUTOCERT_REQ_UNKNOWN;
    ngx_shmtx_unlock(&shpool->mutex);

    return state;
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

    if (shm_zone == NULL || shm_zone->shm.addr == NULL
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
