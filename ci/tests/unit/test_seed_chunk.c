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
 *   5. closedir() on a DIR* abandoned mid-enumeration releases the container
 *      fd it was handed — the OWNERSHIP CONTRACT that
 *      ngx_autocert_runtime_seed_stop() relies on. Checked by counting live
 *      fds around a chunk driven through the shipped loop, and under ASan/LSan
 *      in the sanitized lane. NOTE: seed_stop() itself is NOT executed here —
 *      it touches file-scope seed state and a timer, neither of which is
 *      sliced. This pins the contract, not that call site.
 *
 *   6. a genuine mid-walk readdir() failure is reported as NGX_ERROR, not the
 *      NGX_DONE clean-exhaustion verdict a readdir() NULL also produces on
 *      the success path (audit MINOR/Lifecycle, A6 store-walk errno
 *      diagnosability). A linker --wrap=readdir64 interposer forces the
 *      SHIPPED ngx_autocert_readdir() -> readdir64() call to fail with EIO on
 *      its second invocation; the walk must return NGX_ERROR, distinct from
 *      the NGX_DONE a clean, errno-untouched NULL still produces right after
 *      (exhaustion side of the same wrapper). Both are asserted. The fix is
 *      proven with a negative control: reverting the errno check (mapping
 *      NGX_ERROR back to NGX_DONE) makes the "distinguishable" assertion go
 *      red -- see the REVERT NOTE near test_readdir_error() below.
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
#include <errno.h>
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
 * that adds no new host to the set. WALK_SPIN_LIMIT is a runaway guard on
 * EVERY walk (resuming and cursor-reset alike); hitting it is a FAILURE
 * (returns -2), never a silent pass and never a hang.
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

        /* Yield boundary.
         *
         * The runaway guard bounds EVERY walk, not just the cursor-reset
         * one. A shipped-loop bug that returns NGX_AGAIN without consuming
         * an entry (a budget off-by-one, or NGX_DONE remapped to NGX_AGAIN)
         * makes the resuming walk spin forever too; without this the test
         * hangs until the CI job timeout instead of failing by name.
         */
        if (*ticks >= WALK_SPIN_LIMIT) {
            (void) closedir(dh);
            return -2;                   /* runaway: no walk should need this */
        }

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


/*
 * ---------------------------------------------------------------- item 6
 *
 * Linker-level readdir() interposer (-Wl,--wrap=readdir64 in run.sh's
 * compile line for this binary; glibc's <dirent.h> resolves the plain
 * readdir() symbol ngx_autocert_readdir() calls to readdir64() under the
 * _FILE_OFFSET_BITS/_GNU_SOURCE combination this TU builds with, so that is
 * the symbol the wrap must target -- confirmed with objdump against the
 * built binary). Disarmed by default: __wrap_readdir64() forwards straight
 * to __real_readdir64() and every call above this point (including
 * count_open_fds()'s own readdir() loop, and this file's other readdir()
 * calls, which resolve to the same libc symbol) is unaffected.
 *
 * Armed via readdir_fail_arm(n): the interposer forwards the first `n` calls
 * transparently, then fails EVERY call from the (n+1)-th onward with EIO and
 * errno left set (mirroring what a real readdir() failure looks like) instead
 * of forwarding. It is deliberately NOT one-shot: the counter only advances on
 * the forwarding branch, so once armed the failure is sticky until
 * readdir_fail_disarm(). That is what a walk needs -- a single transient NULL
 * would be indistinguishable from end-of-directory to the loop under test.
 * This targets the SHIPPED ngx_autocert_readdir() -> readdir()
 * call inside the sliced ngx_autocert_seed_walk_chunk() the same way a real
 * ENOMEM/EBADF from the kernel would: the wrapped symbol is the one the
 * static inline in generated_seedchunk.inc actually calls, so this is not a
 * re-implementation of the walk's failure path -- it makes the real syscall
 * boundary fail.
 */
extern struct dirent *__real_readdir64(DIR *dirp);

static int  readdir_calls;
static int  readdir_fail_at = -1;          /* -1 = disarmed */

struct dirent *
__wrap_readdir64(DIR *dirp)
{
    if (readdir_fail_at >= 0 && readdir_calls >= readdir_fail_at) {
        errno = EIO;
        return NULL;
    }
    readdir_calls++;
    return __real_readdir64(dirp);
}

static void
readdir_fail_arm(int after_n_calls)
{
    readdir_calls = 0;
    readdir_fail_at = after_n_calls;
}

static void
readdir_fail_disarm(void)
{
    readdir_fail_at = -1;
    readdir_calls = 0;
}


/*
 * Drive ONE ngx_autocert_seed_walk_chunk() call directly (not the
 * yield/resume loop walk_chunked() drives) so the single verdict it returns
 * -- NGX_ERROR vs NGX_DONE vs NGX_AGAIN -- can be asserted precisely. Returns
 * that raw ngx_int_t.
 */
static ngx_int_t
walk_one_chunk(const char *root, size_t chunk, host_set_t *out)
{
    DIR            *dh;
    int             cfd;
    u_char          buf[NGX_AUTOCERT_REQUEST_NAME_MAX];
    collect_ctx_t   ctx;
    ngx_int_t       rc;

    out->n = 0;
    ctx.out = out;
    ctx.added = 0;
    ctx.overflow = 0;

    cfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cfd == -1) {
        return NGX_ERROR;
    }
    dh = fdopendir(cfd);
    if (dh == NULL) {
        (void) close(cfd);
        return NGX_ERROR;
    }

    rc = ngx_autocert_seed_walk_chunk(dh, cfd, (ngx_uint_t) chunk, buf,
                                      collect_host, &ctx);
    (void) closedir(dh);

    return rc;
}


/*
 * REVERT NOTE for the negative control this item's done-criterion requires:
 * comment out the `(ngx_errno == 0) ? NGX_DONE : NGX_ERROR` line in the
 * shipped ngx_autocert_seed_walk_chunk() (src/ngx_autocert_driver.c) and
 * replace it with the pre-fix `return NGX_DONE;`, re-run
 * extract_seedchunk.sh, rebuild and re-run this binary: the
 * "mid-walk readdir() failure is reported as NGX_ERROR, not NGX_DONE"
 * assertion below goes red because the mutated walk cannot return anything
 * but NGX_DONE/NGX_AGAIN. Observed and logged separately from this source
 * comment -- see the worker banner / PR body for the actual command and
 * output.
 */
static void
test_readdir_error(const char *root)
{
    host_set_t  out;
    ngx_int_t   rc_err, rc_done;

    /* Plant TWO fresh marker entries so the failure can be forced to land
     * GENUINELY MID-WALK -- after at least one entry has been consumed and its
     * marker read -- rather than on the very first readdir() call.
     *
     * That distinction is the whole point of this test. The marker read is
     * openat/fstat/read/close (ngx_autocert_seed_read_marker()), every one of
     * which can leave errno set on a perfectly successful entry. A failure on
     * the FIRST call never exercises that: nothing has clobbered the error
     * state yet, so the walk would return NGX_ERROR even with a broken error
     * channel. Only a failure AFTER a successful marker read proves the
     * channel reports THIS readdir()'s outcome and not the marker read's
     * leftovers.
     *
     * The directory is enumerated as "." + ".." + the two planted entries in
     * unspecified order, so arming after 3 calls guarantees at least one real
     * entry was returned and consumed before the failure, whatever that order
     * is -- and out.n below asserts a marker was actually read, so the test
     * fails loudly rather than silently degrading to the first-call case if
     * that ever stops holding. */
    (void) plant_entry(root, "errprobe1.example.com", "errprobe1.example.com",
                        strlen("errprobe1.example.com"));
    (void) plant_entry(root, "errprobe2.example.com", "errprobe2.example.com",
                        strlen("errprobe2.example.com"));

    /* --- error path: readdir() fails after 3 successful calls ---------- */
    readdir_fail_arm(3);
    rc_err = walk_one_chunk(root, NGX_AUTOCERT_SEED_CHUNK, &out);
    readdir_fail_disarm();

    ok(out.n >= 1,
       "the forced failure landed MID-walk: at least one marker was read "
       "(and clobbered errno) before readdir() failed");

    ok(rc_err == NGX_ERROR,
       "mid-walk readdir() failure is reported as NGX_ERROR, not NGX_DONE");

    /* --- exhaustion path: same store, undisturbed readdir() ------------- */
    rc_done = walk_one_chunk(root, NGX_AUTOCERT_SEED_CHUNK, &out);

    ok(rc_done == NGX_DONE,
       "clean enumeration exhaustion (no interposer) still reports NGX_DONE");
    ok(rc_err != rc_done,
       "error and clean exhaustion are DISTINGUISHABLE verdicts");

    /*
     * --- THE CLOBBER CASE -------------------------------------------------
     *
     * The two assertions above do not actually exercise why the errno clear
     * has to be per-call rather than hoisted once before the loop, because
     * the interposer sets errno itself on the call it fails -- so the error
     * verdict is reached whether or not anything cleared errno earlier.
     *
     * What the clear really protects is the OPPOSITE verdict: a walk that
     * ends CLEANLY after a marker read left errno set. ngx_autocert_seed_
     * read_marker() is openat/fstat/read/close, and a directory with no
     * runtime marker fails its openat() with ENOENT -- a completely normal,
     * already-handled skip that leaves errno nonzero. readdir() then reaches
     * end-of-directory and returns NULL WITHOUT touching errno (that is
     * exactly readdir(3)'s contract). A walk that inferred its verdict from
     * an errno cleared only once before the loop would read that leftover
     * ENOENT and report NGX_ERROR for a perfectly clean enumeration --
     * truncating the seed and logging a failure that never happened.
     *
     * So: plant a marker-less directory (openat -> ENOENT on every visit),
     * pre-dirty errno, and require the undisturbed walk to still say
     * NGX_DONE. This is the assertion that goes red when the per-call clear
     * is hoisted out of ngx_autocert_readdir() to before the loop.
     */
    (void) plant_entry(root, "nomarker.example.com", NULL, 0);

    errno = EIO;                 /* stale value from unrelated earlier work */

    rc_done = walk_one_chunk(root, NGX_AUTOCERT_SEED_CHUNK, &out);

    ok(rc_done == NGX_DONE,
       "a clean walk whose marker reads left errno set STILL reports "
       "NGX_DONE (the per-call errno clear, not a hoisted one)");
}


/*
 * TRAP guard for this item's done criterion: a sliced-function test proves
 * only the HELPER, never that any caller invokes it. This asserts the CALL
 * SITE the fix also touches -- ngx_autocert_runtime_seed_step() in
 * driver.c -- actually branches on NGX_ERROR and logs before stopping,
 * rather than silently falling through to the NGX_DONE branch. A grep-based
 * guard rather than an executed caller test: ngx_autocert_runtime_seed_step()
 * needs a live cycle, an initialized requests zone and the nginx event loop,
 * which this suite has no harness for (same limitation the file banner
 * already states for the wrapper as a whole).
 *
 * DELIBERATELY NARROW. This checks ONE structural fact -- that the call site
 * tests the walk's verdict against NGX_ERROR at all -- and nothing else. It
 * used to additionally require the literal log message
 * ("A6 store enumeration failed mid-walk") to appear on a later line, which
 * was the least stable half of the guard by a wide margin: rewording the
 * operator-facing string, or merely reflowing it across lines differently,
 * broke CI with zero behaviour change, and the ordering requirement rode on
 * the incidental fact that the branch happens to be formatted above the log
 * call today. A guard that fires on cosmetic edits has negative expected
 * value -- maintainers learn to weaken it rather than trust it.
 *
 * The residual limitation is stated plainly rather than papered over with a
 * second fragile string match: a grep cannot tell a live branch from a
 * commented-out one, and it does not verify that the branch LOGS. Those are
 * established by the sliced-helper test above (which executes the real
 * verdict logic) plus review of the diff, not by this guard.
 */
static void
test_readdir_error_call_site_wired(const char *workspace_driver_c)
{
    FILE  *f;
    char   line[512];
    int    saw_error_branch = 0;

    f = fopen(workspace_driver_c, "r");
    if (f == NULL) {
        ok(0, "call-site guard: could not open ngx_autocert_driver.c "
              "(WORKSPACE wrong?)");
        return;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        /* The walk's verdict local compared against NGX_ERROR. Matching the
         * local's name is unavoidable for a source-grep guard -- but it is a
         * private identifier in one function, not operator-facing text, so a
         * rename is a deliberate edit to this call site and re-reading this
         * guard is the right cost. Whitespace between the tokens is not
         * assumed: the two substrings are matched independently on the line. */
        if (strstr(line, "wrc") != NULL
            && strstr(line, "NGX_ERROR") != NULL)
        {
            saw_error_branch = 1;
            break;
        }
    }
    (void) fclose(f);

    ok(saw_error_branch,
       "ngx_autocert_runtime_seed_step() branches on the walk's NGX_ERROR "
       "verdict (call site is wired, not just the sliced helper)");
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
    int         fds_before, fds_after, cfd, crc;
    DIR        *dh;

    if (mkdtemp(root) == NULL) {
        fprintf(stderr, "mkdtemp failed\n");
        goto fail;
    }

    /* --- plant a store larger than one chunk ------------------------- */
    for (i = 0; i < n_entries; i++) {
        (void) snprintf(name, sizeof(name), "e%03zu.example.com", i);
        (void) snprintf(content, sizeof(content), "e%03zu.example.com", i);
        if (plant_entry(root, name, content, strlen(content)) != 0) {
            fprintf(stderr, "plant_entry failed for %s\n", name);
            goto fail;
        }
    }

    /* --- 1. chunked walk recovers the whole store -------------------- */
    if (walk_oneshot(root, &oneshot) != 0) {
        fprintf(stderr, "one-shot walk failed\n");
        goto fail;
    }
    host_set_sort(&oneshot);
    ok(oneshot.n == n_entries,
       "one-shot walk recovers every planted marker");

    crc = walk_chunked(root, NGX_AUTOCERT_SEED_CHUNK, &chunked, &ticks, 0);
    ok(crc != -2,
       "chunked walk advances its cursor (runaway guard not hit)");
    if (crc != 0) {
        fprintf(stderr, "chunked walk failed (rc=%d)\n", crc);
        goto fail;
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
            int  src = walk_chunked(root, sizes[s], &sized, &ticks, 0);

            if (src == -2) {
                printf("      chunk=%zu runaway: cursor never advanced\n",
                       sizes[s]);
            }
            if (src != 0) {
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
            goto fail;
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
        goto fail;
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

        int  krc = walk_chunked(root, NGX_AUTOCERT_SEED_CHUNK, &chunked,
                                &ticks, 0);

        ok(krc != -2,
           "skip-fixture walk advances its cursor (runaway guard not hit)");
        if (krc != 0) {
            fprintf(stderr, "skip walk failed (rc=%d)\n", krc);
            goto fail;
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
            goto fail;
        }
        dh = fdopendir(cfd);
        if (dh == NULL) {
            (void) close(cfd);
            fprintf(stderr, "fdopendir for abort test failed\n");
            goto fail;
        }

        /*
         * Consume one chunk through the SHIPPED loop, then release exactly as
         * ngx_autocert_runtime_seed_stop() does: closedir() alone, which owns
         * the container fd it was handed (shared.h's fdopendir contract).
         *
         * This pins the OWNERSHIP CONTRACT the driver's shutdown path relies
         * on -- that a DIR* abandoned mid-enumeration needs no separate
         * close(cfd). It does NOT execute ngx_autocert_runtime_seed_stop()
         * itself: that function touches the file-scope seed state and a timer,
         * neither of which is sliced here.
         */
        {
            u_char         abuf[NGX_AUTOCERT_REQUEST_NAME_MAX];
            collect_ctx_t  actx;
            host_set_t     aset;

            aset.n = 0;
            actx.out = &aset;
            actx.added = 0;
            actx.overflow = 0;

            (void) ngx_autocert_seed_walk_chunk(dh, cfd,
                       NGX_AUTOCERT_SEED_CHUNK, abuf, collect_host, &actx);
        }
        (void) closedir(dh);             /* the ONLY release, closes cfd too */

        fds_after = count_open_fds();
        ok(fds_after == fds_before,
           "closedir() on a mid-enumeration DIR* releases the container fd "
           "(the ownership contract seed_stop() depends on)");
    }

    /* --- 6. mid-walk readdir() failure is distinct from exhaustion --- */
    {
        char        errroot[] = "/tmp/ac_seed_chunk_err_XXXXXX";
        const char *ws;
        char        driver_path[600];

        if (mkdtemp(errroot) == NULL) {
            fprintf(stderr, "mkdtemp (errroot) failed\n");
            goto fail;
        }

        test_readdir_error(errroot);
        remove_store(errroot);

        /* WORKSPACE is exported by run.sh (absolutized) for exactly this
         * kind of source-relative check; when run standalone (outside
         * run.sh) default to the repo layout relative to this binary's
         * usual build dir ($WORKSPACE/.build/unit). */
        ws = getenv("WORKSPACE");
        if (ws == NULL) {
            ws = "../..";
        }
        if (snprintf(driver_path, sizeof(driver_path),
                     "%s/src/ngx_autocert_driver.c", ws) >= (int) sizeof(driver_path))
        {
            ok(0, "call-site guard: WORKSPACE path too long");
        } else {
            test_readdir_error_call_site_wired(driver_path);
        }
    }

    /* --- cleanup ----------------------------------------------------- */
    remove_store(root);

    if (failures) {
        printf("\n%d test(s) failed\n", failures);
        return 1;
    }
    printf("\nall tests passed\n");
    return 0;

    /*
     * Harness bail-out (setup/syscall failure, not an assertion failure).
     * Every such path routes here so the mkdtemp'd store is removed instead of
     * being left behind in /tmp on each run.
     */
fail:
    remove_store(root);
    return 2;
}
