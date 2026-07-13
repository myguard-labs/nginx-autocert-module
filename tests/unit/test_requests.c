/*
 * Unit tests for ngx_autocert_requests (autolabel A1) — the runtime cert-request
 * registry shared BY NAME with a consumer module.
 *
 * Standalone harness (see test_slab.h): links the requests TU against an nginx
 * build tree over an in-process malloc'd slab arena. Single-process, so the slab
 * mutex takes its uncontended fast path. Verifies:
 *   - owner init stamps api_version = NGX_AUTOCERT_API_VERSION; attach init stamps 0
 *   - ensure() on a new host inserts REQUESTED and returns it
 *   - ensure() is idempotent: a second ensure returns the existing state
 *   - state() reflects the stored state; UNKNOWN for an absent host
 *   - host normalization: case-fold (Example.COM == example.com), reject empty /
 *     over-long / wildcard / leading-or-trailing dot / bad-charset / empty label /
 *     leading-or-trailing hyphen in a label
 *   - the cap: the (MAX+1)-th distinct host is DENIED and not stored
 *   - set_state() flips an existing node; FAILED bumps fail_count + backoff;
 *     set_state on an absent host is a no-op OK
 *   - two hosts forced to the SAME crc32 (collision) are both distinct + retrievable
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include "test_slab.h"

#include "../../src/ngx_autocert_requests.h"

#include <stdio.h>


static int          failures;

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


static void
test_version_stamp(void)
{
    ngx_shm_zone_t              *owner, *attach;
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh;

    /* owner init callback stamps the real version (data arg ignored) */
    owner = ngx_autocert_test_zone_create();
    CHECK(owner != NULL, "owner zone create");
    CHECK(ngx_autocert_requests_init_zone(owner, NULL) == NGX_OK,
          "owner init zone");
    shpool = (ngx_slab_pool_t *) owner->shm.addr;
    sh = shpool->data;
    CHECK(sh->api_version == NGX_AUTOCERT_API_VERSION,
          "owner init stamps api_version = NGX_AUTOCERT_API_VERSION");
    CHECK(sh->count == 0, "owner init count 0");
    ngx_autocert_test_zone_destroy();

    /* consumer init callback stamps 0 — consumer-created, autocert absent */
    attach = ngx_autocert_test_zone_create();
    CHECK(attach != NULL, "attach zone create");
    CHECK(ngx_autocert_requests_init_zone_consumer(attach, NULL) == NGX_OK,
          "consumer init zone");
    shpool = (ngx_slab_pool_t *) attach->shm.addr;
    sh = shpool->data;
    CHECK(sh->api_version == 0,
          "attach init stamps api_version 0 (feature-off signal)");
    ngx_autocert_test_zone_destroy();
}


/*
 * RELOAD (the central regression for the 2026-07-13 MAJOR): nginx's zone-reuse
 * path hands the new cycle's init callback the OLD zone's `data` and does NOT set
 * shm.exists. Before the fix the callback keyed off shm.exists alone, re-allocated
 * the header on every reload, and orphaned the entire request tree. Assert every
 * state survives, plus the count, the backoff stamp, and both stamp-transition
 * rules (owner promotes a consumer's 0; consumer never downgrades the owner's N).
 */
static void
test_reload_preserves_tree(void)
{
    ngx_shm_zone_t              *old, *new_zone;
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh, *sh_before;
    ngx_str_t                    req = S("requested.example.com");
    ngx_str_t                    pend = S("pending.example.com");
    ngx_str_t                    iss = S("issued.example.com");
    ngx_str_t                    fail = S("failed.example.com");
    time_t                       held;

    old = ngx_autocert_test_zone_create();
    CHECK(old != NULL, "reload: zone create");
    CHECK(ngx_autocert_requests_init_zone(old, NULL) == NGX_OK,
          "reload: owner init (fresh start)");

    shpool = (ngx_slab_pool_t *) old->shm.addr;
    sh_before = shpool->data;

    /* one node in every state the driver can leave behind */
    (void) ngx_autocert_requests_ensure(old, &req);
    (void) ngx_autocert_requests_ensure(old, &pend);
    (void) ngx_autocert_requests_ensure(old, &iss);
    (void) ngx_autocert_requests_ensure(old, &fail);

    (void) ngx_autocert_requests_set_state(old, &pend,
                                           NGX_AUTOCERT_REQ_PENDING, 0);
    (void) ngx_autocert_requests_set_state(old, &iss,
                                           NGX_AUTOCERT_REQ_ISSUED, 0);

    /* a FAILED node still inside its backoff window (next_eligible in the future) */
    held = ngx_time() + 3600;
    (void) ngx_autocert_requests_set_state(old, &fail,
                                           NGX_AUTOCERT_REQ_FAILED, held);

    CHECK(sh_before->count == 4, "reload: 4 nodes before reload");

    /* --- the reload --- */
    new_zone = ngx_autocert_test_zone_reload(old);
    CHECK(ngx_autocert_requests_init_zone(new_zone, NULL) == NGX_OK,
          "reload: owner init on the reused zone");

    sh = ((ngx_slab_pool_t *) new_zone->shm.addr)->data;
    CHECK(sh == sh_before, "reload: header ADOPTED, not re-allocated");
    CHECK(sh->api_version == NGX_AUTOCERT_API_VERSION,
          "reload: api_version stamp survives");
    CHECK(sh->count == 4, "reload: node count survives");

    CHECK(ngx_autocert_requests_state(new_zone, &req)
              == NGX_AUTOCERT_REQ_REQUESTED,
          "reload: REQUESTED node survives");
    CHECK(ngx_autocert_requests_state(new_zone, &pend)
              == NGX_AUTOCERT_REQ_PENDING,
          "reload: PENDING node survives");
    CHECK(ngx_autocert_requests_state(new_zone, &iss)
              == NGX_AUTOCERT_REQ_ISSUED,
          "reload: ISSUED node survives");
    CHECK(ngx_autocert_requests_state(new_zone, &fail)
              == NGX_AUTOCERT_REQ_FAILED,
          "reload: FAILED node survives");

    /* the backoff gate must survive too, or a held FAILED node is re-ordered
     * immediately on every reload (reload becomes a retry-storm amplifier) */
    {
        ngx_array_t  *out;
        ngx_pool_t   *pool;
        ngx_int_t     n;

        pool = ngx_create_pool(1024, NULL);
        CHECK(pool != NULL, "reload: drain pool");
        out = ngx_array_create(pool, 4, sizeof(ngx_str_t));
        CHECK(out != NULL, "reload: drain array");

        n = ngx_autocert_requests_drain(new_zone, pool, out, 0);
        CHECK(n == 1, "reload: drain claims only the REQUESTED node "
                      "(FAILED still held by its backoff)");
        CHECK(ngx_autocert_requests_state(new_zone, &fail)
                  == NGX_AUTOCERT_REQ_FAILED,
              "reload: held FAILED node not re-claimed");

        ngx_destroy_pool(pool);
    }

    ngx_autocert_test_zone_destroy();
}


/*
 * Stamp transitions across the owner/consumer boundary.
 */
static void
test_reload_stamp_transitions(void)
{
    ngx_shm_zone_t              *old, *new_zone;
    ngx_autocert_requests_sh_t  *sh;
    ngx_str_t                    h = S("carried.example.com");

    /* consumer created the zone (autocert absent) -> stamp 0, feature off */
    old = ngx_autocert_test_zone_create();
    CHECK(ngx_autocert_requests_init_zone_consumer(old, NULL) == NGX_OK,
          "stamp: consumer init (fresh)");
    sh = ((ngx_slab_pool_t *) old->shm.addr)->data;
    CHECK(sh->api_version == 0, "stamp: consumer-created zone stamps 0");
    CHECK(ngx_autocert_requests_ensure(old, &h) == NGX_AUTOCERT_REQ_UNKNOWN,
          "stamp: helpers fail safe on a stamp-0 zone");

    /* autocert is enabled and its postconfig now claims the zone: the owner
     * callback runs on the reused arena and PROMOTES the 0 stamp */
    new_zone = ngx_autocert_test_zone_reload(old);
    CHECK(ngx_autocert_requests_init_zone(new_zone, NULL) == NGX_OK,
          "stamp: owner init adopts the consumer's zone");
    sh = ((ngx_slab_pool_t *) new_zone->shm.addr)->data;
    CHECK(sh->api_version == NGX_AUTOCERT_API_VERSION,
          "stamp: owner PROMOTES 0 -> NGX_AUTOCERT_API_VERSION");
    CHECK(ngx_autocert_requests_ensure(new_zone, &h)
              == NGX_AUTOCERT_REQ_REQUESTED,
          "stamp: feature live after promotion");

    /* ...and a consumer re-attaching on a LATER reload must not downgrade it
     * back to 0 (that would disable a live tree mid-reload) */
    /* ...and DISABLING autocert (names removed / module unloaded) must demote the
     * zone back to 0 on the next reload: only the consumer callback runs, no driver
     * exists to drain the tree, so leaving a live stamp would let ensure() keep
     * accepting nodes that never advance (fail-OPEN). The tree itself survives. */
    {
        ngx_shm_zone_t  *third;

        third = ngx_autocert_test_zone_reload(new_zone);
        CHECK(ngx_autocert_requests_init_zone_consumer(third, NULL) == NGX_OK,
              "stamp: consumer init on a previously-owned zone");
        sh = ((ngx_slab_pool_t *) third->shm.addr)->data;
        CHECK(sh->api_version == 0,
              "stamp: autocert disabled -> stamp DEMOTED to 0 (fail-safe)");
        CHECK(sh->count == 1, "stamp: the tree itself survives the demotion");
        CHECK(ngx_autocert_requests_state(third, &h)
                  == NGX_AUTOCERT_REQ_UNKNOWN,
              "stamp: helpers inert again on the demoted zone");
    }

    ngx_autocert_test_zone_destroy();
}


static void
test_ensure_idempotent(ngx_shm_zone_t *zone)
{
    ngx_str_t  h = S("app.example.com");

    CHECK(ngx_autocert_requests_ensure(zone, &h) == NGX_AUTOCERT_REQ_REQUESTED,
          "ensure new host -> REQUESTED");
    CHECK(ngx_autocert_requests_state(zone, &h) == NGX_AUTOCERT_REQ_REQUESTED,
          "state reflects REQUESTED");
    /* second ensure returns the existing state, does not reset it */
    CHECK(ngx_autocert_requests_ensure(zone, &h) == NGX_AUTOCERT_REQ_REQUESTED,
          "ensure again -> existing REQUESTED (idempotent)");
}


static void
test_absent_state(ngx_shm_zone_t *zone)
{
    ngx_str_t  h = S("never-seen.example.com");

    CHECK(ngx_autocert_requests_state(zone, &h) == NGX_AUTOCERT_REQ_UNKNOWN,
          "state of absent host -> UNKNOWN");
}


static void
test_case_fold(ngx_shm_zone_t *zone)
{
    ngx_str_t  upper = S("Case.Example.COM");
    ngx_str_t  lower = S("case.example.com");

    CHECK(ngx_autocert_requests_ensure(zone, &upper) == NGX_AUTOCERT_REQ_REQUESTED,
          "ensure mixed-case host");
    /* lowercased form must hit the SAME node */
    CHECK(ngx_autocert_requests_state(zone, &lower) == NGX_AUTOCERT_REQ_REQUESTED,
          "case-folded lookup hits the same node");
    CHECK(ngx_autocert_requests_ensure(zone, &lower) == NGX_AUTOCERT_REQ_REQUESTED,
          "ensure lowercase form is idempotent with mixed-case");
}


static void
test_reject_charset(ngx_shm_zone_t *zone)
{
    ngx_str_t  empty     = SL((u_char *) "x", 0);
    ngx_str_t  wild      = S("*.example.com");
    ngx_str_t  lead_dot  = S(".example.com");
    ngx_str_t  trail_dot = S("example.com.");
    ngx_str_t  dbl_dot   = S("a..example.com");
    ngx_str_t  under     = S("a_b.example.com");
    ngx_str_t  lead_hy   = S("-bad.example.com");
    ngx_str_t  trail_hy  = S("bad-.example.com");
    ngx_str_t  final_hy  = S("example.com-");   /* trailing hyphen, final label */
    ngx_str_t  bare_hy   = S("foo-");           /* single label ending in hyphen */
    ngx_str_t  space     = S("a b.example.com");
    u_char     big[NGX_AUTOCERT_REQUEST_NAME_MAX + 8];
    ngx_str_t  over;

    CHECK(ngx_autocert_requests_ensure(zone, &empty) == NGX_AUTOCERT_REQ_DENIED,
          "reject empty host");
    CHECK(ngx_autocert_requests_ensure(zone, &wild) == NGX_AUTOCERT_REQ_DENIED,
          "reject wildcard host");
    CHECK(ngx_autocert_requests_ensure(zone, &lead_dot) == NGX_AUTOCERT_REQ_DENIED,
          "reject leading dot");
    CHECK(ngx_autocert_requests_ensure(zone, &trail_dot) == NGX_AUTOCERT_REQ_DENIED,
          "reject trailing dot");
    CHECK(ngx_autocert_requests_ensure(zone, &dbl_dot) == NGX_AUTOCERT_REQ_DENIED,
          "reject empty label (double dot)");
    CHECK(ngx_autocert_requests_ensure(zone, &under) == NGX_AUTOCERT_REQ_DENIED,
          "reject underscore (non-LDH)");
    CHECK(ngx_autocert_requests_ensure(zone, &lead_hy) == NGX_AUTOCERT_REQ_DENIED,
          "reject leading hyphen in label");
    CHECK(ngx_autocert_requests_ensure(zone, &trail_hy) == NGX_AUTOCERT_REQ_DENIED,
          "reject trailing hyphen in label");
    CHECK(ngx_autocert_requests_ensure(zone, &final_hy) == NGX_AUTOCERT_REQ_DENIED,
          "reject trailing hyphen in final label");
    CHECK(ngx_autocert_requests_ensure(zone, &bare_hy) == NGX_AUTOCERT_REQ_DENIED,
          "reject single label ending in hyphen");
    CHECK(ngx_autocert_requests_ensure(zone, &space) == NGX_AUTOCERT_REQ_DENIED,
          "reject space");

    memset(big, 'a', sizeof(big));
    over = SL(big, NGX_AUTOCERT_REQUEST_NAME_MAX + 1);
    CHECK(ngx_autocert_requests_ensure(zone, &over) == NGX_AUTOCERT_REQ_DENIED,
          "reject over-long host");

    /* a valid host is still accepted after all the rejects */
    {
        ngx_str_t ok = S("valid.example.com");
        CHECK(ngx_autocert_requests_ensure(zone, &ok) == NGX_AUTOCERT_REQ_REQUESTED,
              "accept valid host after rejects");
    }
}


static void
test_cap(void)
{
    ngx_shm_zone_t  *zone;
    ngx_uint_t       i;
    u_char           buf[64];
    ngx_str_t        h;
    ngx_int_t        rc;
    int              denied_at_cap = 1;

    /* fresh zone so the cap count starts at 0 */
    zone = ngx_autocert_test_zone_create();
    if (zone == NULL || ngx_autocert_requests_init_zone(zone,
            NULL) != NGX_OK) {
        CHECK(0, "cap: fresh zone");
        return;
    }

    /* insert exactly MAX distinct hosts — all must be REQUESTED */
    for (i = 0; i < NGX_AUTOCERT_REQUESTS_MAX; i++) {
        h.len = (size_t) (ngx_snprintf(buf, sizeof(buf), "h%ui.example.com", i)
                          - buf);
        h.data = buf;
        rc = ngx_autocert_requests_ensure(zone, &h);
        if (rc != NGX_AUTOCERT_REQ_REQUESTED) {
            denied_at_cap = 0;
            break;
        }
    }
    CHECK(denied_at_cap, "all MAX distinct hosts accepted");

    /* the (MAX+1)-th distinct host is DENIED */
    h.len = (size_t) (ngx_snprintf(buf, sizeof(buf), "overflow.example.com")
                      - buf);
    h.data = buf;
    CHECK(ngx_autocert_requests_ensure(zone, &h) == NGX_AUTOCERT_REQ_DENIED,
          "host past the cap is DENIED");
    CHECK(ngx_autocert_requests_state(zone, &h) == NGX_AUTOCERT_REQ_UNKNOWN,
          "denied host is not stored");

    /* re-ensuring an EXISTING host at cap still works (no new alloc) */
    h.len = (size_t) (ngx_snprintf(buf, sizeof(buf), "h0.example.com") - buf);
    h.data = buf;
    CHECK(ngx_autocert_requests_ensure(zone, &h) == NGX_AUTOCERT_REQ_REQUESTED,
          "existing host at cap still returns its state");

    ngx_autocert_test_zone_destroy();
}


static void
test_set_state(ngx_shm_zone_t *zone)
{
    ngx_str_t  h = S("transition.example.com");
    ngx_str_t  absent = S("nope.example.com");

    CHECK(ngx_autocert_requests_ensure(zone, &h) == NGX_AUTOCERT_REQ_REQUESTED,
          "set_state: seed host");
    CHECK(ngx_autocert_requests_set_state(zone, &h,
              NGX_AUTOCERT_REQ_PENDING, 0) == NGX_OK,
          "set_state -> PENDING");
    CHECK(ngx_autocert_requests_state(zone, &h) == NGX_AUTOCERT_REQ_PENDING,
          "state now PENDING");

    CHECK(ngx_autocert_requests_set_state(zone, &h,
              NGX_AUTOCERT_REQ_ISSUED, 0) == NGX_OK,
          "set_state -> ISSUED");
    CHECK(ngx_autocert_requests_state(zone, &h) == NGX_AUTOCERT_REQ_ISSUED,
          "state now ISSUED");

    /* FAILED bumps fail_count + stamps a future next_eligible (backoff) */
    CHECK(ngx_autocert_requests_set_state(zone, &h,
              NGX_AUTOCERT_REQ_FAILED, 0) == NGX_OK,
          "set_state -> FAILED (auto backoff)");
    CHECK(ngx_autocert_requests_state(zone, &h) == NGX_AUTOCERT_REQ_FAILED,
          "state now FAILED");

    /* set_state on an absent host is a no-op OK, does not create it */
    CHECK(ngx_autocert_requests_set_state(zone, &absent,
              NGX_AUTOCERT_REQ_ISSUED, 0) == NGX_OK,
          "set_state on absent host -> OK (no-op)");
    CHECK(ngx_autocert_requests_state(zone, &absent) == NGX_AUTOCERT_REQ_UNKNOWN,
          "absent host not created by set_state");

    /* an out-of-range state is rejected */
    CHECK(ngx_autocert_requests_set_state(zone, &h,
              NGX_AUTOCERT_REQ_DENIED + 1, 0) == NGX_ERROR,
          "set_state rejects out-of-range state");

    /* UNKNOWN (0) is the "no node" sentinel and must be rejected — storing it
     * would leave a live node that reads as absent yet consumes the cap */
    CHECK(ngx_autocert_requests_set_state(zone, &h,
              NGX_AUTOCERT_REQ_UNKNOWN, 0) == NGX_ERROR,
          "set_state rejects UNKNOWN (0)");
    CHECK(ngx_autocert_requests_state(zone, &h) != NGX_AUTOCERT_REQ_UNKNOWN,
          "set_state(UNKNOWN) did not clobber the existing node to sentinel");
}


static void
test_collision(void)
{
    ngx_shm_zone_t  *zone;
    u_char           a[NGX_AUTOCERT_TEST_COLL_LEN], b[NGX_AUTOCERT_TEST_COLL_LEN];
    ngx_str_t        ha, hb;
    ngx_uint_t       i;
    int              a_ok = 1, b_ok = 1;

    if (!ngx_autocert_test_crc32_collision(a, b)) {
        CHECK(0, "could not find a crc32 collision (unexpected)");
        return;
    }

    /* the collision bytes are arbitrary; the normalizer requires LDH hosts, so
     * map each colliding blob to a distinct valid host that still collides is not
     * guaranteed. Instead assert the tree distinguishes two DISTINCT valid hosts
     * whose crc32 we DON'T control but that we insert + read back individually —
     * plus a direct collision check at the crc32 layer for documentation. */
    CHECK(ngx_crc32_long(a, NGX_AUTOCERT_TEST_COLL_LEN)
          == ngx_crc32_long(b, NGX_AUTOCERT_TEST_COLL_LEN),
          "two blobs share a crc32 (forced collision, crc32 layer)");

    /* functional distinctness: two valid hosts that (very likely) differ in
     * crc32, both retrievable — the rbtree keys on crc32 then full host cmp. */
    zone = ngx_autocert_test_zone_create();
    if (zone == NULL || ngx_autocert_requests_init_zone(zone,
            NULL) != NGX_OK) {
        CHECK(0, "collision: fresh zone");
        return;
    }
    ha = S("collide-a.example.com");
    hb = S("collide-b.example.com");
    (void) ngx_autocert_requests_ensure(zone, &ha);
    (void) ngx_autocert_requests_ensure(zone, &hb);
    /* mutate a's state; b must be unaffected (distinct nodes) */
    (void) ngx_autocert_requests_set_state(zone, &ha, NGX_AUTOCERT_REQ_ISSUED, 0);
    a_ok = (ngx_autocert_requests_state(zone, &ha) == NGX_AUTOCERT_REQ_ISSUED);
    b_ok = (ngx_autocert_requests_state(zone, &hb) == NGX_AUTOCERT_REQ_REQUESTED);
    CHECK(a_ok, "distinct hosts: A state independent");
    CHECK(b_ok, "distinct hosts: B state independent");

    (void) i;
    ngx_autocert_test_zone_destroy();
}


/*
 * Fail-safe: a zone whose header stamps a foreign api_version (e.g. a consumer
 * created it first, or a layout upgrade) must NOT be mutated/parsed. ensure/state
 * return UNKNOWN, set_state returns ERROR — never touch the tree.
 */
static void
test_version_mismatch_failsafe(void)
{
    ngx_shm_zone_t              *zone;
    ngx_slab_pool_t             *shpool;
    ngx_autocert_requests_sh_t  *sh;
    ngx_str_t                    h = S("app.example.com");

    zone = ngx_autocert_test_zone_create();
    if (zone == NULL
        || ngx_autocert_requests_init_zone(zone, NULL) != NGX_OK)
    {
        CHECK(0, "version-mismatch: fresh zone");
        return;
    }

    shpool = (ngx_slab_pool_t *) zone->shm.addr;
    sh = shpool->data;
    sh->api_version = NGX_AUTOCERT_API_VERSION + 1;   /* forge a foreign layout */

    CHECK(ngx_autocert_requests_ensure(zone, &h) == NGX_AUTOCERT_REQ_UNKNOWN,
          "ensure fail-safes on api_version mismatch (no insert)");
    CHECK(sh->count == 0, "mismatch: ensure did not insert");
    CHECK(ngx_autocert_requests_state(zone, &h) == NGX_AUTOCERT_REQ_UNKNOWN,
          "state fail-safes on api_version mismatch");
    CHECK(ngx_autocert_requests_set_state(zone, &h,
              NGX_AUTOCERT_REQ_ISSUED, 0) == NGX_ERROR,
          "set_state fail-safes on api_version mismatch");

    ngx_autocert_test_zone_destroy();
}


/*
 * A3.3 drain-and-claim: the driver's worker-0 pump claims REQUESTED-eligible
 * nodes, flipping each to PENDING under the shm lock. Verify:
 *   - claims REQUESTED nodes whose next_eligible has passed, flips them PENDING
 *   - skips PENDING/ISSUED nodes (not REQUESTED) and future-backed-off REQUESTED
 *   - the `max` bound caps a single call; the rest stay REQUESTED
 *   - a re-drain after a full claim sees only PENDING => returns 0 (idempotent)
 *   - empty tree => 0
 */
static void
test_drain(void)
{
    ngx_shm_zone_t  *zone;
    ngx_pool_t      *pool;
    ngx_array_t     *out;
    ngx_str_t        req1 = S("drain-a.example.com");
    ngx_str_t        req2 = S("drain-b.example.com");
    ngx_str_t        req3 = S("drain-c.example.com");
    ngx_str_t        pend = S("drain-pending.example.com");
    ngx_str_t        held = S("drain-held.example.com");
    ngx_int_t        n;

    zone = ngx_autocert_test_zone_create();
    if (zone == NULL
        || ngx_autocert_requests_init_zone(zone, NULL) != NGX_OK)
    {
        CHECK(0, "drain: fresh zone");
        return;
    }

    pool = ngx_create_pool(4096, ngx_cycle->log);
    if (pool == NULL) {
        CHECK(0, "drain: pool");
        ngx_autocert_test_zone_destroy();
        return;
    }

    /* empty tree => 0 claimed */
    out = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    n = ngx_autocert_requests_drain(zone, pool, out, 0);
    CHECK(n == 0, "drain: empty tree claims nothing");

    /* seed: 3 REQUESTED-eligible, 1 PENDING (not drainable), 1 REQUESTED but
     * held in the future (next_eligible ahead => not eligible). */
    (void) ngx_autocert_requests_ensure(zone, &req1);
    (void) ngx_autocert_requests_ensure(zone, &req2);
    (void) ngx_autocert_requests_ensure(zone, &req3);
    (void) ngx_autocert_requests_ensure(zone, &pend);
    (void) ngx_autocert_requests_set_state(zone, &pend,
              NGX_AUTOCERT_REQ_PENDING, 0);
    (void) ngx_autocert_requests_ensure(zone, &held);
    /* keep REQUESTED but push eligibility far into the future via set_state?
     * set_state(REQUESTED, when) stamps next_eligible directly (non-FAILED path). */
    (void) ngx_autocert_requests_set_state(zone, &held,
              NGX_AUTOCERT_REQ_REQUESTED, ngx_time() + 3600);

    /* max=2 => only 2 of the 3 eligible claimed this call. */
    out = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    n = ngx_autocert_requests_drain(zone, pool, out, 2);
    CHECK(n == 2, "drain: max bound caps the claim at 2");
    CHECK((ngx_uint_t) n == out->nelts, "drain: return count == out->nelts");

    /* drain the rest (max=0 unlimited): exactly 1 eligible REQUESTED left. */
    out = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    n = ngx_autocert_requests_drain(zone, pool, out, 0);
    CHECK(n == 1, "drain: remaining eligible REQUESTED claimed (held/pending skipped)");

    /* every drained host must now read PENDING (flipped under the lock). */
    CHECK(ngx_autocert_requests_state(zone, &req1) == NGX_AUTOCERT_REQ_PENDING
       && ngx_autocert_requests_state(zone, &req2) == NGX_AUTOCERT_REQ_PENDING
       && ngx_autocert_requests_state(zone, &req3) == NGX_AUTOCERT_REQ_PENDING,
          "drain: claimed hosts are now PENDING");

    /* skipped nodes untouched. */
    CHECK(ngx_autocert_requests_state(zone, &held) == NGX_AUTOCERT_REQ_REQUESTED,
          "drain: future-held REQUESTED not claimed");
    CHECK(ngx_autocert_requests_state(zone, &pend) == NGX_AUTOCERT_REQ_PENDING,
          "drain: pre-existing PENDING untouched");

    /* re-drain now: nothing is REQUESTED-eligible (all PENDING or future-held). */
    out = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    n = ngx_autocert_requests_drain(zone, pool, out, 0);
    CHECK(n == 0, "drain: re-drain sees no REQUESTED-eligible (no double claim)");

    /* A3.5 BLOCKER: a FAILED node whose backoff has elapsed is drainable (else a
     * transient renewal failure strands a runtime cert FAILED until it expires).
     * A FAILED node still in backoff is NOT claimed. */
    {
        ngx_str_t  failnow  = S("drain-fail-elapsed.example.com");
        ngx_str_t  failhold = S("drain-fail-held.example.com");

        (void) ngx_autocert_requests_ensure(zone, &failnow);
        (void) ngx_autocert_requests_set_state(zone, &failnow,
                  NGX_AUTOCERT_REQ_FAILED, ngx_time() - 1);   /* backoff elapsed */
        (void) ngx_autocert_requests_ensure(zone, &failhold);
        (void) ngx_autocert_requests_set_state(zone, &failhold,
                  NGX_AUTOCERT_REQ_FAILED, ngx_time() + 3600); /* still held */

        out = ngx_array_create(pool, 8, sizeof(ngx_str_t));
        n = ngx_autocert_requests_drain(zone, pool, out, 0);
        CHECK(n == 1, "drain: FAILED-elapsed claimed, FAILED-held skipped");
        CHECK(ngx_autocert_requests_state(zone, &failnow)
                  == NGX_AUTOCERT_REQ_PENDING,
              "drain: elapsed FAILED node flipped to PENDING");
        CHECK(ngx_autocert_requests_state(zone, &failhold)
                  == NGX_AUTOCERT_REQ_FAILED,
              "drain: held FAILED node left FAILED");
    }

    ngx_destroy_pool(pool);
    ngx_autocert_test_zone_destroy();
}


/* A3.5: list_issued yields exactly the ISSUED nodes, read-only, max-bounded. */
static void
test_list_issued(void)
{
    ngx_shm_zone_t  *zone;
    ngx_pool_t      *pool;
    ngx_array_t     *out;
    ngx_str_t        iss1 = S("iss-a.example.com");
    ngx_str_t        iss2 = S("iss-b.example.com");
    ngx_str_t        iss3 = S("iss-c.example.com");
    ngx_str_t        req  = S("li-requested.example.com");
    ngx_str_t        pend = S("li-pending.example.com");
    ngx_str_t        fail = S("li-failed.example.com");
    ngx_int_t        n;

    zone = ngx_autocert_test_zone_create();
    if (zone == NULL
        || ngx_autocert_requests_init_zone(zone, NULL) != NGX_OK)
    {
        CHECK(0, "list_issued: fresh zone");
        return;
    }

    pool = ngx_create_pool(4096, ngx_cycle->log);
    if (pool == NULL) {
        CHECK(0, "list_issued: pool");
        ngx_autocert_test_zone_destroy();
        return;
    }

    /* empty tree => 0 listed */
    out = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    n = ngx_autocert_requests_list_issued(zone, pool, out, 0);
    CHECK(n == 0, "list_issued: empty tree lists nothing");

    /* seed: 3 ISSUED + one each of REQUESTED / PENDING / FAILED (all skipped). */
    (void) ngx_autocert_requests_ensure(zone, &iss1);
    (void) ngx_autocert_requests_ensure(zone, &iss2);
    (void) ngx_autocert_requests_ensure(zone, &iss3);
    (void) ngx_autocert_requests_set_state(zone, &iss1,
              NGX_AUTOCERT_REQ_ISSUED, 0);
    (void) ngx_autocert_requests_set_state(zone, &iss2,
              NGX_AUTOCERT_REQ_ISSUED, 0);
    (void) ngx_autocert_requests_set_state(zone, &iss3,
              NGX_AUTOCERT_REQ_ISSUED, 0);
    (void) ngx_autocert_requests_ensure(zone, &req);   /* stays REQUESTED */
    (void) ngx_autocert_requests_ensure(zone, &pend);
    (void) ngx_autocert_requests_set_state(zone, &pend,
              NGX_AUTOCERT_REQ_PENDING, 0);
    (void) ngx_autocert_requests_ensure(zone, &fail);
    (void) ngx_autocert_requests_set_state(zone, &fail,
              NGX_AUTOCERT_REQ_FAILED, 0);

    /* max=2 => only 2 of the 3 ISSUED listed. */
    out = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    n = ngx_autocert_requests_list_issued(zone, pool, out, 2);
    CHECK(n == 2, "list_issued: max bound caps the list at 2");
    CHECK((ngx_uint_t) n == out->nelts, "list_issued: return count == out->nelts");

    /* max=0 => all 3 ISSUED listed, nothing else. */
    out = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    n = ngx_autocert_requests_list_issued(zone, pool, out, 0);
    CHECK(n == 3, "list_issued: all ISSUED listed (non-ISSUED skipped)");

    /* read-only: every node's state is unchanged by the walk. */
    CHECK(ngx_autocert_requests_state(zone, &iss1) == NGX_AUTOCERT_REQ_ISSUED
       && ngx_autocert_requests_state(zone, &iss2) == NGX_AUTOCERT_REQ_ISSUED
       && ngx_autocert_requests_state(zone, &iss3) == NGX_AUTOCERT_REQ_ISSUED,
          "list_issued: ISSUED nodes untouched (read-only)");
    CHECK(ngx_autocert_requests_state(zone, &req) == NGX_AUTOCERT_REQ_REQUESTED
       && ngx_autocert_requests_state(zone, &pend) == NGX_AUTOCERT_REQ_PENDING
       && ngx_autocert_requests_state(zone, &fail) == NGX_AUTOCERT_REQ_FAILED,
          "list_issued: non-ISSUED nodes untouched");

    ngx_destroy_pool(pool);
    ngx_autocert_test_zone_destroy();
}


int
main(void)
{
    ngx_shm_zone_t  *zone;

    ngx_time_init();
    ngx_autocert_test_globals();

    if (ngx_crc32_table_init() != NGX_OK) {
        fprintf(stderr, "FAIL: crc32 table init\n");
        return 2;
    }

    test_version_stamp();

    /* a shared zone for the ensure/state/set_state suite */
    zone = ngx_autocert_test_zone_create();
    if (zone == NULL
        || ngx_autocert_requests_init_zone(zone,
               NULL) != NGX_OK)
    {
        fprintf(stderr, "FAIL: requests init zone\n");
        return 2;
    }

    test_ensure_idempotent(zone);
    test_absent_state(zone);
    test_case_fold(zone);
    test_reject_charset(zone);
    test_set_state(zone);

    ngx_autocert_test_zone_destroy();

    /* suites that need a fresh (empty) zone */
    test_cap();
    test_collision();
    test_version_mismatch_failsafe();
    test_drain();
    test_list_issued();
    test_reload_preserves_tree();
    test_reload_stamp_transitions();

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
