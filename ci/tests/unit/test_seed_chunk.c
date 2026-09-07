/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the A6 chunked runtime-marker store walk
 * (ngx_autocert_driver.c, audit MINOR/Performance).
 *
 * ngx_autocert_runtime_seed() used to fdopendir() the store container and
 * readdir() the WHOLE top level synchronously, inline on worker 0's event
 * loop, with an openat/fstat/read per entry — from BOTH init_process and the
 * relock handler. On a large multi-tenant store that stalls worker 0 at
 * exactly the moment an operator reloads. The walk is now bounded: at most
 * NGX_AUTOCERT_SEED_CHUNK entries per event-loop tick, then a 0 ms yield,
 * resuming from the live DIR* cursor.
 *
 * The correctness risk a chunked walk introduces is that the ENTRY SET it
 * visits stops matching the one-shot walk's — an entry dropped at a chunk
 * boundary, or a cursor reset that re-walks (or skips) a chunk. That is what
 * these tests pin, against a real on-disk store:
 *
 *   1. every marker in a store LARGER than one chunk is recovered, and the
 *      recovered host set is exactly the one-shot walk's — so at least one
 *      yield genuinely happens and no boundary entry is lost;
 *   2. the result is independent of the chunk size: walking the same store at
 *      several different chunk budgets (1, 2, 7, CHUNK, CHUNK+1, huge)
 *      recovers an identical set, so no boundary is special;
 *   3. the DIR* cursor is not reset by a yield — resuming reads the NEXT
 *      entry, never the first one again. The negative control drives the same
 *      shipped loop with the cursor dropped at each yield, runs it to an
 *      OBSERVED fixed point (a full chunk adding no new host) rather than a
 *      tick cap, and asserts its reach equals an independent enumeration of
 *      what one chunk actually covers;
 *   4. non-runtime entries (dotfile, plain file, marker-less dir, empty
 *      marker, oversized marker, FIFO marker, symlinked entry) are skipped
 *      exactly as the one-shot walk skipped them, and skips do NOT consume a
 *      wrong slot in the recovered set;
 *   5. closedir() on the DIR* releases the container fd — mid-walk abort
 *      (the shutdown path) leaks neither the DIR* nor the fd. Checked by
 *      counting live fds around an aborted walk, and under ASan/LSan in the
 *      sanitized lane.
 *
 * THE LOOP UNDER TEST IS THE SHIPPED ONE. ngx_autocert_seed_walk_chunk() —
 * the budget accounting, the readdir cursor advance and the exhaustion check
 * — is sliced out of ngx_autocert_driver.c by
 * ci/tests/unit/extract_seedchunk.sh and executed here, alongside
 * NGX_AUTOCERT_SEED_CHUNK and ngx_autocert_seed_read_marker(). The tests
 * supply the DIR*, the budget and the per-entry handler exactly as
 * ngx_autocert_runtime_seed_step() does in production; they do not
 * re-implement the loop. A cursor bug introduced in driver.c — an exhaustion
 * check moved so a chunk's last entry is dropped, an off-by-one in the budget
 * — therefore fails this suite. The primitives are static in the driver (the
 * whole ACME driver, far too heavy to include-shim), hence the slice rather
 * than a link; it is locked to production code, with no copy drift.
 *
 * WHAT THIS DOES NOT COVER: ngx_autocert_runtime_seed_step()'s wrapper around
 * the loop — the shutdown guard, the per-tick config re-fetch and the
 * ngx_add_timer re-arm — and the shm half of each entry's decision
 * (ngx_autocert_name_is_config / ngx_autocert_name_due /
 * ngx_autocert_requests_ensure), which sits behind the loop's handler hook in
 * the driver's ngx_autocert_seed_restore_entry(). Those need a live cycle, an
 * initialized requests zone and the nginx event loop, which this suite has no
 * harness for; they are exercised by ci/tests/e2e/runtime-issue.sh.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "src/ngx_autocert_shared.h"
#include "src/ngx_autocert_requests.h"   /* NGX_AUTOCERT_REQUEST_NAME_MAX */

#include "generated_seedchunk.inc"


/*
 * ngx_string.o is linked as a whole object for ngx_snprintf/ngx_strlchr (which
 * ngx_autocert_shared.h's path helpers use). Other functions in that same
 * object reference ngx_alloc/ngx_pnalloc/ngx_cycle, which this TU never calls
 * — the sliced walk primitives touch no pool and no cycle. Same stub-link
 * idiom as test_ratecap.c / test_orphan_reap.c: define them so the link
 * resolves, and abort loudly if anything ever actually calls one, so a future
 * slice that quietly grows a pool dependency fails here instead of running
 * against a fake allocator.
 */
volatile ngx_cycle_t  *ngx_cycle;

void *ngx_alloc(size_t size, ngx_log_t *log);
void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) size; (void) log;
    fprintf(stderr, "ngx_alloc called: the sliced walk must not allocate\n");
    abort();
}

void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool; (void) size;
    fprintf(stderr, "ngx_pnalloc called: the sliced walk must not allocate\n");
    abort();
}


static int failures;

static void
ok(int cond, const char *what)
{
    if (cond) {
        printf("ok:   %s\n", what);
    } else {
        printf("FAIL: %s\n", what);
        failures++;
    }
}


/* ---------------------------------------------------------------- fixture */

/*
 * Fixture capacity. Derived from NGX_AUTOCERT_SEED_CHUNK rather than fixed,
 * because the store this suite plants is deliberately larger than one chunk:
 * a hard-coded ceiling would turn a raised chunk constant into a fixture
 * overflow ("one-shot walk failed") instead of a meaningful test run, which
 * would quietly cost the cursor negative control its ability to discriminate.
 */
#define MAX_HOSTS  (NGX_AUTOCERT_SEED_CHUNK + 64)

typedef struct {
    char    host[MAX_HOSTS][64];
    size_t  n;
} host_set_t;


static int
host_set_has(const host_set_t *s, const char *h)
{
    size_t  i;

    for (i = 0; i < s->n; i++) {
        if (strcmp(s->host[i], h) == 0) {
            return 1;
        }
    }
    return 0;
}


static int
host_set_cmp(const void *a, const void *b)
{
    return strcmp((const char *) a, (const char *) b);
}


static void
host_set_sort(host_set_t *s)
{
    qsort(s->host, s->n, sizeof(s->host[0]), host_set_cmp);
}


static int
host_set_equal(const host_set_t *a, const host_set_t *b)
{
    size_t  i;

    if (a->n != b->n) {
        return 0;
    }
    for (i = 0; i < a->n; i++) {
        if (strcmp(a->host[i], b->host[i]) != 0) {
            return 0;
        }
    }
    return 1;
}


/* Write <root>/<dir>/.autocert-runtime containing `content` (content == NULL
 * makes the entry directory with no marker at all). */
static int
plant_entry(const char *root, const char *dir, const char *content,
    size_t content_len)
{
    char  path[512];
    int   fd;

    if (snprintf(path, sizeof(path), "%s/%s", root, dir) >= (int) sizeof(path)) {
        return -1;
    }
    if (mkdir(path, 0700) == -1) {
        return -1;
    }

    if (content == NULL) {
        return 0;
    }

    if (snprintf(path, sizeof(path), "%s/%s/%s", root, dir,
                 NGX_AUTOCERT_RUNTIME_MARKER) >= (int) sizeof(path))
    {
        return -1;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        return -1;
    }
    if (content_len > 0 && write(fd, content, content_len)
        != (ssize_t) content_len)
    {
        (void) close(fd);
        return -1;
    }
    return close(fd);
}


/*
 * Per-entry sink handed to the SHIPPED chunk loop. Mirrors the driver's
 * ngx_autocert_seed_restore_entry() in shape; here it just records the host
 * into a set, because the cycle-bound decisions the driver makes at this
 * point (name_is_config / name_due / requests_ensure) need an event loop and
 * an shm zone this suite has no harness for.
 *
 * Records a SET, not a bag: the production walk visits each entry exactly
 * once, so dedup is a no-op for it, but it matters for the cursor-reset
 * mutation below, whose re-reads would otherwise inflate the count with
 * duplicates and let a "recovered fewer hosts" assertion pass for the wrong
 * reason. `*added` counts entries this call newly inserted, which is what the
 * fixed-point detection in walk_chunked() observes.
 */
typedef struct {
    host_set_t  *out;
    size_t       added;
    int          overflow;
} collect_ctx_t;


static ngx_int_t
collect_host(void *data, ngx_str_t *host)
{
    collect_ctx_t  *ctx = data;
    char            h[64];

    if (ctx->out->n >= MAX_HOSTS || host->len >= sizeof(ctx->out->host[0])) {
        ctx->overflow = 1;
        return NGX_DECLINED;
    }

    memcpy(h, host->data, host->len);
    h[host->len] = '\0';

    if (host_set_has(ctx->out, h)) {
        return NGX_DECLINED;
    }

    memcpy(ctx->out->host[ctx->out->n], h, host->len + 1);
    ctx->out->n++;
    ctx->added++;

    return NGX_OK;
}


/*
 * Drive the SHIPPED chunk loop, ngx_autocert_seed_walk_chunk(), sliced out of
 * ngx_autocert_driver.c. This function supplies only what
 * ngx_autocert_runtime_seed_step() supplies in production — the DIR*, the
 * budget, the scratch buffer, the handler — and the yield/resume decision
 * driven by the loop's own NGX_DONE / NGX_AGAIN verdict. The cursor
 * discipline under test is the shipped code's, not a re-implementation.
 *
 * `chunk` is the per-tick budget (NGX_AUTOCERT_SEED_CHUNK in production; the
 * tests vary it to prove no boundary is special). `*ticks` receives how many
 * chunks were consumed, so a test can assert a yield ACTUALLY happened rather
 * than assuming it.
 *
 * `reset_cursor` models the mutation this walk must not have: re-opening the
 * directory at every yield instead of resuming from the live DIR* cursor.
 * It is NOT bounded by a tick cap — that would make the mutated walk's
 * inability to advance an artefact of the test rather than a measured
 * property. Instead it terminates on an OBSERVED FIXED POINT: a full chunk
 * that adds no new host to the set. WALK_SPIN_LIMIT is a runaway guard only;
 * hitting it is a FAILURE (returns -2), never a silent pass.
 */
#define WALK_SPIN_LIMIT  1024

static int
walk_chunked(const char *root, size_t chunk, host_set_t *out, size_t *ticks,
    int reset_cursor)
{
    DIR            *dh;
    int             cfd;
    u_char          buf[NGX_AUTOCERT_REQUEST_NAME_MAX];
    collect_ctx_t   ctx;
    ngx_int_t       rc;

    out->n = 0;
    *ticks = 0;

    ctx.out = out;
    ctx.overflow = 0;

    cfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cfd == -1) {
        return -1;
    }
    dh = fdopendir(cfd);
    if (dh == NULL) {
        (void) close(cfd);
        return -1;
    }

    for ( ;; ) {
        (*ticks)++;

        ctx.added = 0;

        /* THE SHIPPED LOOP. Budget accounting, readdir cursor advance and
         * the exhaustion check all live in driver.c. */
        rc = ngx_autocert_seed_walk_chunk(dh, cfd, (ngx_uint_t) chunk, buf,
                                          collect_host, &ctx);

        if (ctx.overflow) {
            (void) closedir(dh);
            return -1;
        }

        if (rc == NGX_DONE) {
            (void) closedir(dh);         /* also closes cfd */
            return 0;                    /* enumeration exhausted */
        }

        /* Yield boundary. */
        if (reset_cursor) {
            /*
             * MUTATION MODEL: drop the resume cursor. A walk that re-opens
             * the container at every yield re-reads the same reachable
             * entries forever and never advances past them.
             *
             * Terminate on the OBSERVED fixed point: this chunk consumed its
             * whole budget and contributed nothing new, so no further
             * identical chunk ever will. That the mutated walk cannot make
             * progress is thus measured here, not imposed by a tick cap.
             */
            if (ctx.added == 0) {
                (void) closedir(dh);
                return 0;
            }

            if (*ticks >= WALK_SPIN_LIMIT) {
                /* Not a fixed point after a very generous number of chunks:
                 * the mutation model no longer behaves as described. Fail
                 * loudly rather than returning a set the caller would treat
                 * as meaningful. */
                (void) closedir(dh);
                return -2;
            }

            (void) closedir(dh);
            cfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (cfd == -1) {
                return -1;
            }
            dh = fdopendir(cfd);
            if (dh == NULL) {
                (void) close(cfd);
                return -1;
            }
        }
    }
}


/*
 * How many DISTINCT hosts a single chunk of `chunk` entries can reach from a
 * fresh cursor, enumerated directly rather than assumed from
 * NGX_AUTOCERT_SEED_CHUNK. This is the oracle the cursor-reset negative
 * control is asserted against: it is derived from what one chunk of this
 * store actually yields (entries that are not runtime markers consume budget
 * without contributing a host), so raising NGX_AUTOCERT_SEED_CHUNK moves both
 * the mutated walk's reach and this expectation together, and the assertion
 * keeps discriminating instead of going vacuous.
 */
static int
first_chunk_hosts(const char *root, size_t chunk, host_set_t *out)
{
    DIR            *dh;
    int             cfd;
    u_char          buf[NGX_AUTOCERT_REQUEST_NAME_MAX];
    collect_ctx_t   ctx;

    out->n = 0;

    ctx.out = out;
    ctx.added = 0;
    ctx.overflow = 0;

    cfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cfd == -1) {
        return -1;
    }
    dh = fdopendir(cfd);
    if (dh == NULL) {
        (void) close(cfd);
        return -1;
    }

    (void) ngx_autocert_seed_walk_chunk(dh, cfd, (ngx_uint_t) chunk, buf,
                                        collect_host, &ctx);
    (void) closedir(dh);

    return ctx.overflow ? -1 : 0;
}


/* One-shot walk: the pre-change behaviour, as the oracle. */
static int
walk_oneshot(const char *root, host_set_t *out)
{
    size_t  ticks;

    /* An unbounded chunk IS the one-shot walk: the inner loop never hits its
     * budget, so it runs the whole enumeration in a single pass with no
     * yield. Same code path, same primitives — the difference is only the
     * bound, which is exactly the variable under test. */
    return walk_chunked(root, (size_t) -1, out, &ticks, 0);
}


/*
 * Remove the fixture store. Deliberately NOT system("rm -rf ..."): handing a
 * path to a shell is the exact pattern the repo's SAST gates flag, and it is
 * avoidable here — the fixture is two levels deep by construction (entry dirs
 * each holding at most one marker file), so an explicit unlink walk is both
 * shorter to reason about and free of any shell at all.
 */
static void
remove_store(const char *root)
{
    DIR            *d;
    struct dirent  *e;
    char            path[600];

    d = opendir(root);
    if (d == NULL) {
        return;
    }

    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
            continue;
        }

        if (snprintf(path, sizeof(path), "%s/%s/%s", root, e->d_name,
                     NGX_AUTOCERT_RUNTIME_MARKER) < (int) sizeof(path))
        {
            (void) unlink(path);         /* marker, if any */
        }

        if (snprintf(path, sizeof(path), "%s/%s", root, e->d_name)
            < (int) sizeof(path))
        {
            /* entry is a dir, a plain file or a symlink — try both removals,
             * whichever applies succeeds and the other fails harmlessly. */
            if (rmdir(path) == -1) {
                (void) unlink(path);
            }
        }
    }

    (void) closedir(d);
    (void) rmdir(root);
}


/* Count this process's open fds, to catch a leaked DIR* or container fd. */
static int
count_open_fds(void)
{
    DIR            *d;
    struct dirent  *e;
    int             n = 0;

    d = opendir("/proc/self/fd");
    if (d == NULL) {
        return -1;                       /* no procfs: caller skips the check */
    }
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] != '.') {
            n++;
        }
    }
    (void) closedir(d);
    return n;
}


int
main(void)
{
    char        root[] = "/tmp/ac_seed_chunk_XXXXXX";
    char        name[64], content[64];
    host_set_t  oneshot, chunked, mutated, sized;
    size_t      ticks, i;
    /* Deliberately more than one chunk, and not a multiple of it, so the last
     * chunk is partial and at least one boundary falls mid-store. */
    const size_t  n_entries = NGX_AUTOCERT_SEED_CHUNK + 7;
    int         fds_before, fds_after, cfd;
    DIR        *dh;

    if (mkdtemp(root) == NULL) {
        fprintf(stderr, "mkdtemp failed\n");
        return 2;
    }

    /* --- plant a store larger than one chunk ------------------------- */
    for (i = 0; i < n_entries; i++) {
        (void) snprintf(name, sizeof(name), "e%03zu.example.com", i);
        (void) snprintf(content, sizeof(content), "e%03zu.example.com", i);
        if (plant_entry(root, name, content, strlen(content)) != 0) {
            fprintf(stderr, "plant_entry failed for %s\n", name);
            return 2;
        }
    }

    /* --- 1. chunked walk recovers the whole store -------------------- */
    if (walk_oneshot(root, &oneshot) != 0) {
        fprintf(stderr, "one-shot walk failed\n");
        return 2;
    }
    host_set_sort(&oneshot);
    ok(oneshot.n == n_entries,
       "one-shot walk recovers every planted marker");

    if (walk_chunked(root, NGX_AUTOCERT_SEED_CHUNK, &chunked, &ticks, 0) != 0) {
        fprintf(stderr, "chunked walk failed\n");
        return 2;
    }
    host_set_sort(&chunked);

    ok(ticks > 1,
       "chunked walk actually yielded (store exceeds one chunk)");
    ok(chunked.n == n_entries,
       "chunked walk recovers every planted marker");
    ok(host_set_equal(&oneshot, &chunked),
       "chunked walk recovers the SAME host set as the one-shot walk");

    /* --- 2. outcome is independent of the chunk boundary ------------- */
    {
        const size_t  sizes[] = {
            1, 2, 7,
            NGX_AUTOCERT_SEED_CHUNK - 1,
            NGX_AUTOCERT_SEED_CHUNK,
            NGX_AUTOCERT_SEED_CHUNK + 1,
            n_entries, n_entries + 1, 4096
        };
        size_t  s;
        int     all_equal = 1;

        for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
            if (walk_chunked(root, sizes[s], &sized, &ticks, 0) != 0) {
                all_equal = 0;
                break;
            }
            host_set_sort(&sized);
            if (!host_set_equal(&oneshot, &sized)) {
                printf("      chunk=%zu recovered %zu of %zu\n",
                       sizes[s], sized.n, oneshot.n);
                all_equal = 0;
            }
        }
        ok(all_equal,
           "recovered host set is identical at every chunk size "
           "(no boundary is special)");
    }

    /* --- 3. NEGATIVE CONTROL: a walk that drops the resume cursor ---- */
    {
        int  mrc = walk_chunked(root, NGX_AUTOCERT_SEED_CHUNK, &mutated,
                                &ticks, 1);

        /* -2 is the runaway guard: the cursor-reset walk kept finding new
         * hosts for WALK_SPIN_LIMIT chunks, so it never reached a fixed
         * point and the mutation model no longer describes the code. That is
         * a test failure, not a reason to accept whatever set came back. */
        ok(mrc != -2,
           "cursor-reset walk reaches a fixed point (runaway guard not hit)");
        if (mrc != 0) {
            fprintf(stderr, "mutated walk failed (rc=%d)\n", mrc);
            return 2;
        }
    }
    host_set_sort(&mutated);
    ok(!host_set_equal(&oneshot, &mutated),
       "dropping the resume cursor loses entries (negative control diverges)");

    /*
     * Pin the SPECIFIC property, not merely "the sets differ". Set inequality
     * alone would also be satisfied by the mutated walk merely duplicating
     * hosts, which is a different (and weaker) failure.
     *
     * The expectation is ENUMERATED, not derived from NGX_AUTOCERT_SEED_CHUNK:
     * first_chunk_hosts() runs one chunk of the shipped loop over this same
     * store from a fresh cursor and reports what it actually reaches. A walk
     * that re-opens the container at every yield can never reach more than
     * that, and the walk above terminated on an observed fixed point rather
     * than a tick cap — so this compares two measurements of the code under
     * test, and raising NGX_AUTOCERT_SEED_CHUNK moves both together instead of
     * making the assertion vacuous.
     *
     * Asserted as a count rather than against one named entry: readdir order
     * is not specified, so WHICH hosts land in the reachable first chunk is
     * filesystem-dependent, but HOW MANY can ever be reached is not.
     */
    if (first_chunk_hosts(root, NGX_AUTOCERT_SEED_CHUNK, &sized) != 0) {
        fprintf(stderr, "first_chunk_hosts failed\n");
        return 2;
    }
    ok(mutated.n == sized.n,
       "the resume-cursor mutation reaches exactly the hosts one chunk "
       "enumerates, and no more");
    ok(mutated.n < oneshot.n,
       "the resume-cursor mutation never reaches the whole store");

    /* --- 4. non-runtime entries are skipped -------------------------- */
    {
        char    path[512];
        int     fd;
        size_t  before = oneshot.n;

        /* dotfile dir, marker-less dir, plain file, empty marker */
        (void) plant_entry(root, ".hidden.example.com", "x", 1);
        (void) plant_entry(root, "nomarker.example.com", NULL, 0);
        (void) plant_entry(root, "empty.example.com", "", 0);

        (void) snprintf(path, sizeof(path), "%s/plainfile", root);
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd != -1) {
            (void) close(fd);
        }

        /* oversized marker (> NGX_AUTOCERT_REQUEST_NAME_MAX) */
        {
            static char  big[NGX_AUTOCERT_REQUEST_NAME_MAX + 32];

            memset(big, 'a', sizeof(big));
            (void) plant_entry(root, "big.example.com", big, sizeof(big));
        }

        /* symlinked entry: O_NOFOLLOW must refuse it */
        (void) snprintf(path, sizeof(path), "%s/symlinked.example.com", root);
        (void) symlink("e000.example.com", path);

        /* FIFO where the marker should be */
        (void) snprintf(path, sizeof(path), "%s/fifo.example.com", root);
        if (mkdir(path, 0700) == 0) {
            (void) snprintf(path, sizeof(path), "%s/fifo.example.com/%s",
                            root, NGX_AUTOCERT_RUNTIME_MARKER);
            (void) mkfifo(path, 0600);
        }

        if (walk_chunked(root, NGX_AUTOCERT_SEED_CHUNK, &chunked, &ticks, 0)
            != 0)
        {
            fprintf(stderr, "skip walk failed\n");
            return 2;
        }
        host_set_sort(&chunked);

        ok(chunked.n == before,
           "dotfile/marker-less/plain-file/empty/oversized/symlink/FIFO "
           "entries are all skipped");
        ok(host_set_equal(&oneshot, &chunked),
           "skips do not perturb the recovered host set");
        ok(!host_set_has(&chunked, "x"),
           "a dotfile entry's marker content never enters the set");
    }

    /* --- 5. mid-walk abort releases the DIR* and its container fd ---- */
    fds_before = count_open_fds();
    if (fds_before < 0) {
        printf("ok:   (skipped) /proc/self/fd unavailable, fd-leak check "
               "not run\n");
    } else {
        cfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (cfd == -1) {
            fprintf(stderr, "open store for abort test failed\n");
            return 2;
        }
        dh = fdopendir(cfd);
        if (dh == NULL) {
            (void) close(cfd);
            fprintf(stderr, "fdopendir for abort test failed\n");
            return 2;
        }

        /* consume one chunk, then abort as the shutdown guard does */
        for (i = 0; i < NGX_AUTOCERT_SEED_CHUNK; i++) {
            if (readdir(dh) == NULL) {
                break;
            }
        }
        (void) closedir(dh);             /* the ONLY release, closes cfd too */

        fds_after = count_open_fds();
        ok(fds_after == fds_before,
           "aborting the walk mid-enumeration leaks neither the DIR* nor "
           "the container fd");
    }

    /* --- cleanup ----------------------------------------------------- */
    remove_store(root);

    if (failures) {
        printf("\n%d test(s) failed\n", failures);
        return 1;
    }
    printf("\nall tests passed\n");
    return 0;
}
