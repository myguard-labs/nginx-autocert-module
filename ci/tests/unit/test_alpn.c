/*
 * Unit tests for ngx_autocert_alpn (M10b) — the tls-alpn-01 challenge cert
 * store. Sibling of test_challenge: same in-process slab arena, same forced
 * crc32 collision (see test_slab.h), but a two-part {cert,key} value.
 *
 * Verifies:
 *   - set -> get round-trips both cert and key
 *   - set on an existing domain replaces both values
 *   - remove -> get returns NGX_DECLINED; remove of an absent domain is OK
 *   - bounds: domain / cert / key each rejected at len 0 and len > MAX
 *   - three domains incl. a forced crc32 collision pair, all retrievable
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include "test_slab.h"

#include "../../../src/ngx_autocert_alpn.h"

#include <stdio.h>
#include <string.h>


static int          failures;
static ngx_pool_t  *pool;
/* Pass a zero-initialised log (log_level 0) so ngx_log_debug*() stay no-ops
 * in --with-debug builds instead of dereferencing a NULL log (segfault). */
static ngx_log_t   test_log;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


static ngx_str_t
S(const char *lit)
{
    ngx_str_t s;
    s.data = (u_char *) lit;
    s.len = ngx_strlen(lit);
    return s;
}

static ngx_str_t
SL(u_char *data, size_t len)
{
    ngx_str_t s;
    s.data = data;
    s.len = len;
    return s;
}

static int
eq(ngx_str_t *s, ngx_str_t *lit)
{
    return s->len == lit->len && ngx_memcmp(s->data, lit->data, s->len) == 0;
}


static void
test_roundtrip(ngx_shm_zone_t *zone)
{
    ngx_str_t  dom  = S("le.example.com");
    ngx_str_t  cert = S("-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n");
    ngx_str_t  key  = S("-----BEGIN PRIVATE KEY-----\nMIGH...\n-----END PRIVATE KEY-----\n");
    ngx_str_t  oc, ok;

    CHECK(ngx_autocert_alpn_set(zone, &dom, &cert, &key) == NGX_OK, "set domain");

    oc.len = 0; oc.data = NULL; ok.len = 0; ok.data = NULL;
    CHECK(ngx_autocert_alpn_get(zone, &dom, pool, &oc, &ok) == NGX_OK
          && eq(&oc, &cert) && eq(&ok, &key),
          "get returns the stored cert + key");
}


static void
test_replace(ngx_shm_zone_t *zone)
{
    ngx_str_t  dom = S("replace.example.org");
    ngx_str_t  c1 = S("cert-v1");
    ngx_str_t  k1 = S("key-v1");
    ngx_str_t  c2 = S("cert-version-two-longer");
    ngx_str_t  k2 = S("key-version-two-longer");
    ngx_str_t  oc, ok;

    CHECK(ngx_autocert_alpn_set(zone, &dom, &c1, &k1) == NGX_OK, "set v1");
    CHECK(ngx_autocert_alpn_set(zone, &dom, &c2, &k2) == NGX_OK,
          "set v2 (replace)");

    oc.len = 0; oc.data = NULL; ok.len = 0; ok.data = NULL;
    CHECK(ngx_autocert_alpn_get(zone, &dom, pool, &oc, &ok) == NGX_OK
          && eq(&oc, &c2) && eq(&ok, &k2),
          "get returns the replacement cert + key");
}


static void
test_remove(ngx_shm_zone_t *zone)
{
    ngx_str_t  dom = S("remove.example.net");
    ngx_str_t  c = S("c");
    ngx_str_t  k = S("k");
    ngx_str_t  oc, ok;

    CHECK(ngx_autocert_alpn_set(zone, &dom, &c, &k) == NGX_OK, "set");
    CHECK(ngx_autocert_alpn_remove(zone, &dom) == NGX_OK, "remove present");
    CHECK(ngx_autocert_alpn_get(zone, &dom, pool, &oc, &ok) == NGX_DECLINED,
          "get after remove -> DECLINED");

    {
        ngx_str_t absent = S("never.example");
        CHECK(ngx_autocert_alpn_remove(zone, &absent) == NGX_OK,
              "remove absent -> OK");
    }
}


static void
test_bounds(ngx_shm_zone_t *zone)
{
    ngx_str_t  dom = S("bounds.example");
    ngx_str_t  c = S("c");
    ngx_str_t  k = S("k");
    ngx_str_t  empty = SL((u_char *) "x", 0);
    ngx_str_t  oc, ok;
    u_char     dbuf[NGX_AUTOCERT_ALPN_DOMAIN_MAX + 8];
    u_char     cbuf[NGX_AUTOCERT_ALPN_CERT_MAX + 8];
    u_char     kbuf[NGX_AUTOCERT_ALPN_KEY_MAX + 8];
    ngx_str_t  overd, overc, overk;

    CHECK(ngx_autocert_alpn_set(zone, &empty, &c, &k) == NGX_ERROR,
          "set rejects empty domain");
    CHECK(ngx_autocert_alpn_set(zone, &dom, &empty, &k) == NGX_ERROR,
          "set rejects empty cert");
    CHECK(ngx_autocert_alpn_set(zone, &dom, &c, &empty) == NGX_ERROR,
          "set rejects empty key");

    memset(dbuf, 'd', sizeof(dbuf));
    memset(cbuf, 'c', sizeof(cbuf));
    memset(kbuf, 'k', sizeof(kbuf));
    overd = SL(dbuf, NGX_AUTOCERT_ALPN_DOMAIN_MAX + 1);
    overc = SL(cbuf, NGX_AUTOCERT_ALPN_CERT_MAX + 1);
    overk = SL(kbuf, NGX_AUTOCERT_ALPN_KEY_MAX + 1);

    CHECK(ngx_autocert_alpn_set(zone, &overd, &c, &k) == NGX_ERROR,
          "set rejects over-long domain");
    CHECK(ngx_autocert_alpn_set(zone, &dom, &overc, &k) == NGX_ERROR,
          "set rejects over-long cert");
    CHECK(ngx_autocert_alpn_set(zone, &dom, &c, &overk) == NGX_ERROR,
          "set rejects over-long key");

    /* get/remove of an over-long domain bounce too */
    CHECK(ngx_autocert_alpn_get(zone, &overd, pool, &oc, &ok) == NGX_DECLINED,
          "get rejects over-long domain");
    CHECK(ngx_autocert_alpn_remove(zone, &overd) == NGX_OK,
          "remove of over-long domain -> OK (no-op)");

    /* Exact boundary: a domain of exactly NGX_AUTOCERT_ALPN_DOMAIN_MAX bytes
     * is still IN bounds ("len > MAX" rejects, not "len >= MAX"). */
    {
        ngx_str_t  at_max = SL(dbuf, NGX_AUTOCERT_ALPN_DOMAIN_MAX);

        CHECK(ngx_autocert_alpn_set(zone, &at_max, &c, &k) == NGX_OK,
              "set accepts a domain of exactly NGX_AUTOCERT_ALPN_DOMAIN_MAX bytes");
        CHECK(ngx_autocert_alpn_remove(zone, &at_max) == NGX_OK,
              "cleanup: remove the exact-max domain");
    }
}


static void
test_three_and_collision(ngx_shm_zone_t *zone)
{
    u_char     a[NGX_AUTOCERT_TEST_COLL_LEN], b[NGX_AUTOCERT_TEST_COLL_LEN];
    ngx_str_t  d1 = S("first.example");
    ngx_str_t  c1 = S("cert-1");
    ngx_str_t  k1 = S("key-1");
    ngx_str_t  da, db, ca, ka, cb, kb, oc, ok;

    /* A plain third domain plus the two colliding ones => >= 3 entries. */
    CHECK(ngx_autocert_alpn_set(zone, &d1, &c1, &k1) == NGX_OK, "set domain 1");

    if (!ngx_autocert_test_crc32_collision(a, b)) {
        CHECK(0, "could not find a crc32 collision (unexpected)");
        return;
    }

    da = SL(a, NGX_AUTOCERT_TEST_COLL_LEN);
    db = SL(b, NGX_AUTOCERT_TEST_COLL_LEN);
    ca = S("cert-A"); ka = S("key-A");
    cb = S("cert-B-different"); kb = S("key-B-different");

    CHECK(ngx_crc32_long(a, NGX_AUTOCERT_TEST_COLL_LEN)
          == ngx_crc32_long(b, NGX_AUTOCERT_TEST_COLL_LEN),
          "two domains share a crc32 (forced collision)");

    CHECK(ngx_autocert_alpn_set(zone, &da, &ca, &ka) == NGX_OK,
          "collision: set domain A");
    CHECK(ngx_autocert_alpn_set(zone, &db, &cb, &kb) == NGX_OK,
          "collision: set domain B");

    oc.len = 0; oc.data = NULL; ok.len = 0; ok.data = NULL;
    CHECK(ngx_autocert_alpn_get(zone, &da, pool, &oc, &ok) == NGX_OK
          && eq(&oc, &ca) && eq(&ok, &ka),
          "collision: A retrievable with its own cert/key");

    oc.len = 0; oc.data = NULL; ok.len = 0; ok.data = NULL;
    CHECK(ngx_autocert_alpn_get(zone, &db, pool, &oc, &ok) == NGX_OK
          && eq(&oc, &cb) && eq(&ok, &kb),
          "collision: B retrievable with its own cert/key");

    /* first domain still intact alongside the collision pair */
    oc.len = 0; oc.data = NULL; ok.len = 0; ok.data = NULL;
    CHECK(ngx_autocert_alpn_get(zone, &d1, pool, &oc, &ok) == NGX_OK
          && eq(&oc, &c1) && eq(&ok, &k1),
          "third domain unaffected by the collision pair");
}


/*
 * RELOAD. nginx's zone-REUSE path copies the old arena onto the new cycle's zone
 * and calls init() WITHOUT setting shm.exists (that flag only covers the
 * platform/named-shm case, and is always 0 on Linux). init_zone used to key off
 * shm.exists, so EVERY reload re-allocated the header and orphaned the tree: an
 * `nginx -s reload` during an in-flight order dropped the tls-alpn-01 challenge
 * cert, the CA's validation handshake then found nothing, and the order failed.
 */
/* Portable substring search over a possibly non-terminated buffer; avoids
 * needing _GNU_SOURCE for memmem() in this standalone harness. */
static int
buf_has(const u_char *buf, size_t len, const char *needle)
{
    size_t  n = strlen(needle);
    size_t  i;

    if (n > len) {
        return 0;
    }
    for (i = 0; i + n <= len; i++) {
        if (memcmp(buf + i, needle, n) == 0) {
            return 1;
        }
    }
    return 0;
}


/*
 * Local mirror of the static ngx_autocert_alpn_lookup() in ngx_autocert_alpn.c
 * (same hash-then-domain-compare walk) -- the only way to reach the node's
 * slab-allocated an->key.data pointer from outside the TU, needed below to
 * check what the freed key block contains after remove.
 */
static ngx_autocert_alpn_node_t *
test_alpn_lookup(ngx_autocert_alpn_sh_t *sh, ngx_str_t *domain, uint32_t hash)
{
    ngx_rbtree_node_t         *node, *sentinel;
    ngx_autocert_alpn_node_t  *an;
    ngx_int_t                  rc;

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

        an = (ngx_autocert_alpn_node_t *) node;

        if (domain->len != an->domain_len) {
            node = (domain->len < an->domain_len) ? node->left : node->right;
            continue;
        }

        rc = ngx_memcmp(domain->data, an->domain, domain->len);
        if (rc == 0) {
            return an;
        }
        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


/*
 * Coverage for the wipe-at-call-sites fix (issues.md Security): set() and
 * remove() must cleanse an->key.data before it goes back to the slab, or the
 * next allocation of that size reads the challenge private key back. The
 * primitive (ngx_http_autocert_cleanse) already has unit coverage in
 * test_crypto.c; this asserts the CALL SITE actually invokes it, which a
 * primitive-only test cannot -- reverting either wipe call left the primitive
 * test green.
 *
 * Strategy: stash the key block's address and length under the lock (private
 * API mirror above), remove the node (frees that block back to the slab
 * WITHOUT reallocating it), then read the same address directly and assert
 * the key PEM marker is gone. Nothing else touches the arena between remove
 * and the check, so the block's content at that address is exactly what
 * remove() left behind.
 */
static void
test_remove_wipes_key(ngx_shm_zone_t *zone)
{
    ngx_slab_pool_t           *shpool;
    ngx_autocert_alpn_sh_t    *sh;
    ngx_autocert_alpn_node_t  *an;
    ngx_str_t   dom = S("wipe.example.com");
    ngx_str_t   c = S("-----BEGIN CERTIFICATE-----wipeme");
    ngx_str_t   k = S("-----BEGIN PRIVATE KEY-----wipeme-secret");
    u_char     *key_data;
    size_t      key_len;
    uint32_t    hash;

    CHECK(ngx_autocert_alpn_set(zone, &dom, &c, &k) == NGX_OK,
          "wipe: set");

    shpool = (ngx_slab_pool_t *) zone->shm.addr;
    sh = shpool->data;
    hash = ngx_crc32_long(dom.data, dom.len);

    an = test_alpn_lookup(sh, &dom, hash);
    CHECK(an != NULL, "wipe: node present before remove");
    if (an == NULL) {
        return;
    }

    key_data = an->key.data;
    key_len = an->key.len;
    CHECK(buf_has(key_data, key_len, "BEGIN PRIVATE KEY"),
          "wipe: key block holds the PEM before remove (sanity)");

    CHECK(ngx_autocert_alpn_remove(zone, &dom) == NGX_OK, "wipe: remove");

    /* The block was freed, not reallocated -- nothing ran in between that
     * would touch this address, so reading it directly observes exactly what
     * remove() left there. Assert ALL-ZERO rather than merely "lacks the PEM
     * marker": under NGX_DEBUG_MALLOC ngx_slab_junk() fills a freed block with
     * 0xA5, which would satisfy a marker-absence check whether or not the
     * cleanse ran, silently turning this detector into a tautology. */
    {
        size_t  i, nonzero = 0;

        for (i = 0; i < key_len; i++) {
            if (key_data[i] != 0) {
                nonzero++;
            }
        }
        CHECK(nonzero == 0,
              "wipe: freed key block is all-zero after remove");
    }
    CHECK(!buf_has(key_data, key_len, "BEGIN PRIVATE KEY"),
          "wipe: freed key block no longer contains the PEM after remove");
}


static void
test_reload_preserves_certs(void)
{
    ngx_shm_zone_t          *old, *new_zone;
    ngx_autocert_alpn_sh_t  *sh_before, *sh_after;
    ngx_str_t                d = S("inflight.example.com");
    ngx_str_t                c = S("-----BEGIN CERTIFICATE-----inflight");
    ngx_str_t                k = S("-----BEGIN PRIVATE KEY-----inflight");
    ngx_str_t                oc, ok;

    old = ngx_autocert_test_zone_create();
    CHECK(old != NULL, "reload: zone create");
    CHECK(ngx_autocert_alpn_init_zone(old, NULL) == NGX_OK,
          "reload: init (fresh start)");

    sh_before = ((ngx_slab_pool_t *) old->shm.addr)->data;
    CHECK(sh_before != NULL, "reload: fresh init allocates the header");

    CHECK(ngx_autocert_alpn_set(old, &d, &c, &k) == NGX_OK,
          "reload: challenge cert stored before the reload");

    /* --- the reload --- */
    new_zone = ngx_autocert_test_zone_reload(old);
    CHECK(ngx_autocert_alpn_init_zone(new_zone, NULL) == NGX_OK,
          "reload: init on the reused zone");

    sh_after = ((ngx_slab_pool_t *) new_zone->shm.addr)->data;
    CHECK(sh_after == sh_before,
          "reload: header ADOPTED, not re-allocated (no orphaned tree, no leak)");

    oc.len = 0; oc.data = NULL; ok.len = 0; ok.data = NULL;
    CHECK(ngx_autocert_alpn_get(new_zone, &d, pool, &oc, &ok) == NGX_OK
          && eq(&oc, &c) && eq(&ok, &k),
          "reload: in-flight tls-alpn-01 cert still served after reload");

    ngx_autocert_test_zone_destroy();
}


int
main(void)
{
    ngx_shm_zone_t  *zone;

    ngx_time_init();
    ngx_autocert_test_globals();   /* pid + pagesize + cacheline + slab sizes */

    if (ngx_crc32_table_init() != NGX_OK) {
        fprintf(stderr, "FAIL: crc32 table init\n");
        return 2;
    }

    pool = ngx_create_pool(16 * 1024, &test_log);
    if (pool == NULL) {
        fprintf(stderr, "FAIL: pool\n");
        return 2;
    }

    zone = ngx_autocert_test_zone_create();
    if (zone == NULL) {
        fprintf(stderr, "FAIL: slab zone create\n");
        return 2;
    }

    if (ngx_autocert_alpn_init_zone(zone, NULL) != NGX_OK) {
        fprintf(stderr, "FAIL: alpn init zone\n");
        return 2;
    }

    test_roundtrip(zone);
    test_replace(zone);
    test_remove(zone);
    test_bounds(zone);
    test_three_and_collision(zone);
    test_remove_wipes_key(zone);

    ngx_autocert_test_zone_destroy();

    test_reload_preserves_certs();   /* owns its own zone */

    ngx_destroy_pool(pool);

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
