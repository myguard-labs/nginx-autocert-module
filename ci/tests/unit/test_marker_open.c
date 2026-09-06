/*
 * Unit tests for the A6 runtime-marker OPEN SEMANTICS (src/ngx_autocert_driver.c,
 * ngx_autocert_runtime_mark / ngx_autocert_runtime_seed).
 *
 * The store is worker-owned, but this code's threat model already assumes a
 * hostile filesystem underneath it (that is why every store path is opened
 * fd-pinned with openat + O_NOFOLLOW). A pre-planted NON-REGULAR leaf at
 * <store>/<seg>/.autocert-runtime must therefore never be able to hurt us.
 *
 * The bug this guards (2026-07-13 audit, MAJOR): the write side opened the leaf
 * O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW and only THEN fstat()ed it. O_NOFOLLOW
 * rejects a symlink but NOT a FIFO planted directly at that name, and opening a
 * FIFO for writing BLOCKS in openat() until a reader appears (POSIX). The
 * S_ISREG check was therefore unreachable: the open wedged the sole ACME driver
 * event loop — and the nginx worker hosting it — indefinitely, right after a
 * successful runtime issuance. O_TRUNC compounded it by acting on the leaf
 * before its type was ever established.
 *
 * These tests assert the OPEN FLAGS the driver now uses, against real planted
 * leaves in a temp dir. They are deliberately about the syscall contract rather
 * than the driver function (which is static and needs a full cycle/store); a
 * regression in the flags is exactly what broke, and it is what this catches.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#define _GNU_SOURCE

#include <ngx_config.h>
#include <ngx_core.h>

#include "../../../src/ngx_autocert_shared.h"

#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


/*
 * MARKER_NAME / MARKER_OPEN_WRITE / MARKER_OPEN_READ used to be this file's
 * own copy of the driver's constants, so the test passed no matter what
 * production's flags actually were. They now alias the single definition in
 * ngx_autocert_shared.h that src/ngx_autocert_driver.c also consumes, so a
 * regression in the production flags shows up here too.
 */
#define MARKER_NAME        NGX_AUTOCERT_RUNTIME_MARKER
#define MARKER_OPEN_WRITE  NGX_AUTOCERT_MARKER_OPEN_WRITE
#define MARKER_OPEN_READ   NGX_AUTOCERT_MARKER_OPEN_READ


static int   failures;
static char  tmpdir[] = "/tmp/ac-marker-XXXXXX";

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


static void
unplant(void)
{
    char path[512];

    snprintf(path, sizeof(path), "%s/%s", tmpdir, MARKER_NAME);
    (void) unlink(path);
}


static int
plant_fifo(void)
{
    char path[512];

    unplant();
    snprintf(path, sizeof(path), "%s/%s", tmpdir, MARKER_NAME);
    return mkfifo(path, 0644);
}


static int
plant_symlink(const char *target)
{
    char path[512];

    unplant();
    snprintf(path, sizeof(path), "%s/%s", tmpdir, MARKER_NAME);
    return symlink(target, path);
}


static int
open_dir(void)
{
    return open(tmpdir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}


/*
 * The core regression. Open the planted FIFO with the driver's WRITE flags in a
 * CHILD process under an alarm: if the open blocks (the pre-fix behaviour) the
 * child is killed by SIGALRM and we can see it, instead of hanging the suite the
 * way the bug hung the worker.
 *
 * Returns: 0 = open failed fast (correct), 1 = open succeeded, 2 = BLOCKED.
 */
static int
try_open_write(void)
{
    pid_t  pid;
    int    status;

    fflush(stderr);

    pid = fork();
    if (pid == -1) {
        return -1;
    }

    if (pid == 0) {
        int dfd, fd;

        alarm(3);   /* the pre-fix flags block forever; bound it */

        dfd = open_dir();
        if (dfd == -1) {
            _exit(3);
        }

        fd = openat(dfd, MARKER_NAME, MARKER_OPEN_WRITE, 0644);
        if (fd == -1) {
            _exit(0);          /* refused, fast — what the driver needs */
        }
        (void) close(fd);
        _exit(1);              /* opened it */
    }

    if (waitpid(pid, &status, 0) == -1) {
        return -1;
    }

    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM) {
        return 2;              /* still inside openat() after 3s => blocked */
    }
    if (!WIFEXITED(status)) {
        return -1;
    }

    return WEXITSTATUS(status);
}


static void
test_fifo_write_does_not_block(void)
{
    int rc;

    CHECK(plant_fifo() == 0, "fifo: planted a FIFO at the marker leaf");

    rc = try_open_write();

    /* THE regression: pre-fix (O_WRONLY|O_TRUNC, no O_NONBLOCK) this returns 2. */
    CHECK(rc != 2,
          "fifo: marker write open does NOT block on a planted FIFO "
          "(pre-fix it wedged the driver + worker 0 forever)");
    CHECK(rc == 0,
          "fifo: marker write open is REFUSED (ENXIO), so the driver logs it "
          "and keeps running");

    unplant();
}


static void
test_fifo_read_does_not_block(void)
{
    pid_t  pid;
    int    status;

    CHECK(plant_fifo() == 0, "fifo: planted a FIFO for the read side");

    pid = fork();
    if (pid == 0) {
        int dfd, fd;
        struct stat st;

        alarm(3);

        dfd = open_dir();
        if (dfd == -1) {
            _exit(3);
        }

        /* O_RDONLY|O_NONBLOCK on a FIFO SUCCEEDS immediately (unlike O_WRONLY);
         * the S_ISREG gate is what must then refuse it. */
        fd = openat(dfd, MARKER_NAME, MARKER_OPEN_READ);
        if (fd == -1) {
            _exit(0);
        }
        if (fstat(fd, &st) == 0 && !S_ISREG(st.st_mode)) {
            (void) close(fd);
            _exit(0);          /* type gate refused it — correct */
        }
        (void) close(fd);
        _exit(1);              /* would have READ from a FIFO */
    }

    (void) waitpid(pid, &status, 0);

    CHECK(!(WIFSIGNALED(status) && WTERMSIG(status) == SIGALRM),
          "fifo: marker read open does not block");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "fifo: marker read refuses the FIFO on the S_ISREG gate");

    unplant();
}


static void
test_symlink_refused(void)
{
    int dfd, fd;

    CHECK(plant_symlink("/etc/passwd") == 0,
          "symlink: planted a symlink at the marker leaf");

    dfd = open_dir();
    CHECK(dfd != -1, "symlink: store dir pinned");

    fd = openat(dfd, MARKER_NAME, MARKER_OPEN_WRITE, 0644);
    CHECK(fd == -1 && errno == ELOOP,
          "symlink: O_NOFOLLOW refuses a symlinked marker (ELOOP)");
    if (fd != -1) {
        (void) close(fd);
    }
    (void) close(dfd);

    unplant();
}


/*
 * The happy path must still work: a fresh leaf is created, and an EXISTING
 * regular marker is truncated before the rewrite (the driver dropped O_TRUNC and
 * now ftruncate()s the fd once it has proven it is a plain file, so a shorter
 * host must not leave a tail of the longer previous one behind).
 */
static void
test_regular_file_roundtrip(void)
{
    int          dfd, fd;
    struct stat  st;
    char         buf[64];
    ssize_t      n;

    unplant();

    dfd = open_dir();
    CHECK(dfd != -1, "regular: store dir pinned");

    /* first write: creates the leaf */
    fd = openat(dfd, MARKER_NAME, MARKER_OPEN_WRITE, 0644);
    CHECK(fd != -1, "regular: fresh marker created");
    CHECK(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1,
          "regular: fresh marker is a single-linked regular file");
    CHECK(ftruncate(fd, 0) == 0, "regular: ftruncate ok");
    CHECK(write(fd, "a-very-long-runtime-host.example.com", 36) == 36,
          "regular: long host written");
    (void) close(fd);

    /* rewrite with a SHORTER host: the ftruncate must clear the old tail */
    fd = openat(dfd, MARKER_NAME, MARKER_OPEN_WRITE, 0644);
    CHECK(fd != -1, "regular: existing marker reopened");
    CHECK(fstat(fd, &st) == 0 && S_ISREG(st.st_mode),
          "regular: existing marker still a regular file");
    CHECK(ftruncate(fd, 0) == 0, "regular: ftruncate clears the old contents");
    CHECK(write(fd, "short.example.com", 17) == 17,
          "regular: short host written");
    (void) close(fd);

    fd = openat(dfd, MARKER_NAME, MARKER_OPEN_READ);
    CHECK(fd != -1, "regular: marker reopened for read");
    n = read(fd, buf, sizeof(buf));
    (void) close(fd);
    (void) close(dfd);

    CHECK(n == 17 && memcmp(buf, "short.example.com", 17) == 0,
          "regular: no stale tail from the longer previous host "
          "(ftruncate replaced O_TRUNC correctly)");

    unplant();
}


int
main(void)
{
    if (mkdtemp(tmpdir) == NULL) {
        fprintf(stderr, "FAIL: mkdtemp\n");
        return 2;
    }

    test_fifo_write_does_not_block();
    test_fifo_read_does_not_block();
    test_symlink_refused();
    test_regular_file_roundtrip();

    (void) rmdir(tmpdir);

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
