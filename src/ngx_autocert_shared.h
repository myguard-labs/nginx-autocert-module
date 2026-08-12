/*
 * ngx_autocert_shared — the narrow interface the CORE helper process uses to
 * read the HTTP module's configuration without depending on the HTTP module's
 * private conf struct. The helper is an NGX_CORE_MODULE; it cannot use
 * ngx_http_conf_get_module_main_conf, and the autocert main-conf struct is
 * file-private to ngx_http_autocert_module.c. So the HTTP module exports one
 * accessor that copies the few fields the helper needs into this flat struct.
 */

#ifndef _NGX_AUTOCERT_SHARED_H_INCLUDED_
#define _NGX_AUTOCERT_SHARED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_autocert_win32.h"   /* win32 shim types; empty on POSIX builds */

#include <fcntl.h>
#include <errno.h>


/*
 * ngx_autocert_mode_t — POSIX side. The win32 side is typedef'd in
 * ngx_autocert_win32.h (unsigned int; see its comment for why it cannot be
 * `#define mode_t`, and for the security-descriptor translation W5b owns).
 * On POSIX it is exactly mode_t, so this line is the only difference from the
 * pre-shim signatures.
 */
#if !(NGX_WIN32)
typedef mode_t  ngx_autocert_mode_t;
#endif


/*
 * ngx_autocert_stat_t — POSIX side. The win32 side is defined in
 * ngx_autocert_win32.h (its own struct, not UCRT's `struct stat`; see that
 * file's W5d comment for why `<sys/stat.h>` cannot be used at all under
 * MSVC). On POSIX it is exactly `struct stat`, so no call site or field
 * access differs from the pre-shim code. Included here directly rather than
 * relying on ngx_posix_config.h to have pulled `<sys/stat.h>` in already, so
 * this typedef is self-sufficient.
 */
#if !(NGX_WIN32)
#include <sys/stat.h>
typedef struct stat  ngx_autocert_stat_t;
#endif


typedef struct {
    ngx_uint_t       configured;     /* 0 => autocert not present in http{} */
    ngx_str_t        email;          /* account contact email, "" if none */
    ngx_resolver_t  *resolver;       /* may be NULL if autocert_resolver unset */
    time_t           resolver_timeout;
    /*
     * M5: the CA-identifying knobs (directory URL, trust bundle, EAB) are no
     * longer flat — they live per-CA in each ca_list entry's ca_conf. The driver
     * iterates ca_list and reads entry->ca_conf directly (see driver.c). The flat
     * `ca`/`ca_certificate`/`eab_*` fields the M4 bridge populated from ca_list[0]
     * are gone.
     */
    ngx_str_t        dns_hook_add;     /* M16 dns-01 publish-TXT exec, "" */
    ngx_str_t        dns_hook_remove;  /* M16 dns-01 remove-TXT exec, "" */
    time_t           dns_propagation_delay;  /* M16 seconds after publish */
    time_t           dns_hook_timeout;  /* M16 seconds to wait for a hook exec */
    ngx_uint_t       key_type;       /* ngx_http_autocert_key_type_e; == cert_key_types[0],
                                        kept for not-yet-array-aware consumers */
    ngx_array_t     *cert_key_types; /* dual-cert (Phase B): ngx_uint_t list of leaf
                                        key types to issue per name. 1 or 2 entries:
                                        at most one EC and at most one RSA (the parser
                                        rejects a duplicate family). The ACME
                                        account/challenge keys stay EC regardless. */
    ngx_uint_t       store;          /* ngx_http_autocert_store_e (disk layout) */
    ngx_str_t        path;           /* cert store dir (holds the account key) */
    time_t           renew_before;   /* M8: seconds before notAfter to renew */
    ngx_uint_t       challenge;      /* M10c: ngx_http_autocert_challenge_e */
    ngx_str_t        profile;        /* ACME Profiles: newOrder profile, "" = omit
                                        ("shortlived" for LE IP certs) */

    /* M5: the challenge token store the helper writes (NULL if not set up). */
    ngx_shm_zone_t  *challenge_zone;
    /* M6a: the collected enabled server names (ngx_str_t array, NULL/empty if
     * none). The order flow issues for the first name for now; multi-name
     * iteration is later (M6+). Points into the HTTP main-conf pool, which
     * outlives the helper run. */
    ngx_array_t     *names;
    /* M2: names grouped by CA (ngx_autocert_ca_entry_t array). One entry until
     * M4 adds per-vhost CAs; the driver (M5) iterates this. NULL/empty = none. */
    ngx_array_t     *ca_list;
    /* M5 test seed (token.len == 0 when unset). */
    ngx_str_t        test_token;
    ngx_str_t        test_keyauth;

    /* M10b: the tls-alpn-01 challenge cert store the helper writes (NULL if not
     * set up). */
    ngx_shm_zone_t  *alpn_zone;
    /* M10b test seed (domain.len == 0 when unset). */
    ngx_str_t        test_alpn_domain;
    ngx_str_t        test_alpn_keyauth;

    /* A3 (autolabel): the runtime request zone the driver drains to issue certs
     * for names enqueued at runtime (label-autoconf). NULL when no autocert
     * server names are configured (zone only created then). */
    ngx_shm_zone_t  *requests_zone;

    /* autolabel C test seed: autocert_test_runtime_request <host>; the driver's
     * kick handler inserts this host into requests_zone as REQUESTED once
     * (host.len == 0 when unset). Lets the Pebble e2e exercise the runtime
     * issuance lifecycle without a real label-autoconf consumer. */
    ngx_str_t        test_runtime_host;

    /* autolabel GC: idle TTL (seconds) for runtime registry nodes; the sched
     * tick evicts nodes idle past it. 0 = GC off. */
    time_t           runtime_ttl;
} ngx_autocert_conf_t;


/*
 * Fill *out from the running cycle's HTTP autocert main conf. Returns NGX_OK
 * with out->configured set appropriately (0 if the http{} block has no
 * autocert main conf, e.g. no http{} at all), NGX_ERROR only on a NULL out.
 * Safe to call from the helper (CORE) process against its own cycle.
 */
ngx_int_t ngx_autocert_get_conf(ngx_cycle_t *cycle, ngx_autocert_conf_t *out);


/*
 * NGX_EINTR retry predicate, POSIX side. See ngx_autocert_win32.h for the
 * win32 side (a compile-time-constant false there, since win32 has no
 * signal-interrupted-syscall outcome for these calls) and the rationale for
 * why the two need a shared name at all. Defined as a macro expanding to the
 * exact same comparison the call sites used before this shim existed, so
 * POSIX object code is unchanged.
 */
#if !(NGX_WIN32)
#define ngx_autocert_err_is_intr(err)   ((err) == NGX_EINTR)
#endif


/*
 * ngx_autocert_close/read/write/ftruncate/geteuid — POSIX side. The win32
 * side is defined in ngx_autocert_win32.h on the MSVCRT int-fd API (_close,
 * _read, _write, _chsize_s); see that file's W7 comment for why the fd stays
 * a plain CRT int rather than a HANDLE. Defined here as thin macros to the
 * POSIX call so every call site goes through one shim spelling regardless of
 * platform, with POSIX object code unchanged.
 */
#if !(NGX_WIN32)
#define ngx_autocert_close(fd)          close(fd)
#define ngx_autocert_read(fd, b, n)     read(fd, b, n)
#define ngx_autocert_write(fd, b, n)    write(fd, b, n)
#define ngx_autocert_ftruncate(fd, len) ftruncate(fd, len)
#define ngx_autocert_geteuid()          geteuid()
#endif


/*
 * ngx_autocert_flock_ex_nb — non-blocking exclusive interprocess lock, POSIX
 * side. The win32 side is defined in ngx_autocert_win32.h's W13 primitives
 * region (LockFileEx). Returns 0 on success, -1 on failure with errno set —
 * the same convention flock(2) already uses, so the single call site at
 * driver.c keeps its `== 0` / `-1` tests unchanged.
 */
#if !(NGX_WIN32)
#define ngx_autocert_flock_ex_nb(fd)    flock(fd, LOCK_EX | LOCK_NB)
#endif


/*
 * renameat2(2) wrapper, shared by the store commit (order.c) and the account-key
 * migration (driver.c) — both fd-pinned, security-sensitive renames that must
 * not drift. Called via syscall() so the build needs no glibc renameat2 wrapper.
 * Returns NGX_OK on success; NGX_DECLINED when the syscall/flag is unsupported
 * (caller falls back or defers); NGX_ERROR otherwise with ngx_errno set (incl.
 * EEXIST for RENAME_NOREPLACE against an existing destination — caller inspects).
 */
#if defined(__linux__)
#include <sys/syscall.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif
#endif


/*
 * The dir-fd operation family. Every call site below takes a `dfd` that came
 * from ngx_autocert_open_dir_path(), i.e. a directory whose every ancestor was
 * pinned during the walk. Routing them through the seam means the win32 port
 * (W5) touches this header instead of the four .c files.
 *
 * The flags parameters stay explicit rather than being folded into the helper:
 * AT_REMOVEDIR and AT_SYMLINK_NOFOLLOW are load-bearing at their call sites,
 * and a helper that silently picked one would be a security change disguised as
 * a refactor.
 *
 * POSIX bodies below are guarded #if !(NGX_WIN32); the win32 bodies live in
 * ngx_autocert_win32.h (W5c). Public signatures are byte-identical on both
 * platforms — see DESIGN-win32-store-io.md § W1.
 */

#if !(NGX_WIN32)

static ngx_inline int
ngx_autocert_openat(int dfd, const char *name, int flags)
{
    return openat(dfd, name, flags);
}


/*
 * O_CREAT variant. Split from the 3-argument form rather than made variadic:
 * a variadic wrapper cannot portably forward its mode to openat(), and the
 * win32 branch needs the creation mode as a distinct parameter anyway (it maps
 * to a security descriptor, not to a mode_t).
 */
static ngx_inline int
ngx_autocert_openat_mode(int dfd, const char *name, int flags,
    ngx_autocert_mode_t mode)
{
    return openat(dfd, name, flags, mode);
}


static ngx_inline int
ngx_autocert_mkdirat(int dfd, const char *name, ngx_autocert_mode_t mode)
{
    return mkdirat(dfd, name, mode);
}


static ngx_inline int
ngx_autocert_unlinkat(int dfd, const char *name, int flags)
{
    return unlinkat(dfd, name, flags);
}


static ngx_inline int
ngx_autocert_fstatat(int dfd, const char *name, ngx_autocert_stat_t *st, int flags)
{
    return fstatat(dfd, name, st, flags);
}


/*
 * linkat(2) wrapper — the store-seed hardlink at order.c's staging step. Both
 * fds are dir fds from the same pinned-walk family as the rest of this
 * region. flags is forwarded as-is (the sole call site always passes 0, i.e.
 * "fail EEXIST rather than replace" — see the win32 body's doc comment for
 * why that MUST stay true there too).
 */
static ngx_inline int
ngx_autocert_linkat(int oldfd, const char *oldpath, int newfd,
    const char *newpath, int flags)
{
    return linkat(oldfd, oldpath, newfd, newpath, flags);
}


/*
 * fstat(2) on an already-open int fd from this family (ngx_autocert_open_file_path,
 * ngx_autocert_openat_mode, ...). Kept distinct from ngx_autocert_fstatat above:
 * that one stats a NAME relative to a pinned dir fd, this one stats the fd
 * itself once it is already open — the two call sites never overlap.
 */
static ngx_inline int
ngx_autocert_fstat(int fd, ngx_autocert_stat_t *st)
{
    return fstat(fd, st);
}


static ngx_inline ngx_int_t
ngx_autocert_renameat2(int oldfd, const char *oldp, int newfd,
    const char *newp, unsigned int flags)
{
#if defined(__linux__) && defined(SYS_renameat2)
    if (syscall(SYS_renameat2, oldfd, oldp, newfd, newp, flags) == 0) {
        return NGX_OK;
    }
    if (ngx_errno == NGX_ENOSYS || ngx_errno == EINVAL
        || ngx_errno == ENOTTY || ngx_errno == EOPNOTSUPP)
    {
        return NGX_DECLINED;
    }
    return NGX_ERROR;
#else
    (void) oldfd; (void) oldp; (void) newfd; (void) newp; (void) flags;
    return NGX_DECLINED;
#endif
}

/*
 * Store-scan directory enumeration (W12). Every call site takes the fd from
 * ngx_autocert_open_dir_path()/ngx_autocert_openat(dfd, ..., O_DIRECTORY) — an
 * already-pinned directory — and enumerates it via fd, never by re-deriving
 * and re-opening a path (that would reintroduce the TOCTOU the pinning walk
 * exists to defeat). The win32 bodies (W12) resolve this to
 * NtQueryDirectoryFile on the same handle rather than FindFirstFileW/
 * FindNextFileW, which only take a path — see DESIGN-win32-store-io.md § W1.
 * Public signatures are byte-identical on both platforms.
 *
 * Ownership: ngx_autocert_closedir(dh) closes the fd that was handed to
 * ngx_autocert_fdopendir(fd) — the caller must not close it separately. If
 * ngx_autocert_fdopendir() fails, ownership does NOT transfer: the caller
 * still owns and must close the fd itself (see driver.c's A6 store scan,
 * the only caller, for the exact failure-path contract this preserves).
 */
#include <dirent.h>

typedef DIR            ngx_autocert_dir_t;
typedef struct dirent  ngx_autocert_dirent_t;


static ngx_inline ngx_autocert_dir_t *
ngx_autocert_fdopendir(int fd)
{
    return fdopendir(fd);
}


static ngx_inline ngx_autocert_dirent_t *
ngx_autocert_readdir(ngx_autocert_dir_t *dh)
{
    return readdir(dh);
}


static ngx_inline int
ngx_autocert_closedir(ngx_autocert_dir_t *dh)
{
    return closedir(dh);
}

#endif /* !(NGX_WIN32) */


/*
 * Open a directory without trusting any component of `path`. O_NOFOLLOW on a
 * single open(path) protects only the leaf; this walk pins every ancestor with
 * openat() before descending into the next component. If `create` is set,
 * missing components are made relative to the already-pinned parent. `path`
 * must be NUL-terminated. Returns an owned directory fd, or -1 with errno set.
 */
static ngx_inline int
ngx_autocert_open_dir_path(const char *path, ngx_uint_t create,
    ngx_autocert_mode_t mode)
{
    char         name[NGX_MAX_PATH];
    const char  *p, *q;
    size_t       len;
    int          dfd, nfd, err;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (path[0] == '/') {
        dfd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        p = path + 1;
    } else {
        dfd = open(".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        p = path;
    }
    if (dfd == -1) {
        return -1;
    }

    while (*p) {
        q = p;
        while (*q && *q != '/') {
            q++;
        }
        len = q - p;

        if (len == 0 || (len == 1 && p[0] == '.')) {
            p = (*q == '/') ? q + 1 : q;
            continue;
        }
        if ((len == 2 && p[0] == '.' && p[1] == '.')
            || len >= sizeof(name))
        {
            err = (len >= sizeof(name)) ? ENAMETOOLONG : EINVAL;
            (void) ngx_autocert_close(dfd);
            errno = err;
            return -1;
        }

        ngx_memcpy(name, p, len);
        name[len] = '\0';
        nfd = ngx_autocert_openat(dfd, name,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (nfd == -1 && create && errno == ENOENT) {
            if (ngx_autocert_mkdirat(dfd, name, mode) == -1 && errno != EEXIST) {
                err = errno;
                (void) ngx_autocert_close(dfd);
                errno = err;
                return -1;
            }
            nfd = ngx_autocert_openat(dfd, name,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (nfd == -1) {
            err = errno;
            (void) ngx_autocert_close(dfd);
            errno = err;
            return -1;
        }

        (void) ngx_autocert_close(dfd);
        dfd = nfd;
        p = (*q == '/') ? q + 1 : q;
    }

    return dfd;
}


/*
 * Open a regular leaf relative to a parent directory whose every component was
 * pinned by ngx_autocert_open_dir_path(). The final leaf is also O_NOFOLLOW.
 */
static ngx_inline int
ngx_autocert_open_file_path(const char *path, int flags)
{
    char         parent[NGX_MAX_PATH];
    const char  *p, *slash, *leaf;
    size_t       len;
    int          dfd, fd, err;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    slash = NULL;
    for (p = path; *p; p++) {
        if (*p == '/') {
            slash = p;
        }
    }

    if (slash == NULL) {
        dfd = ngx_autocert_open_dir_path(".", 0, 0);
        leaf = path;
    } else if (slash == path) {
        dfd = ngx_autocert_open_dir_path("/", 0, 0);
        leaf = slash + 1;
    } else {
        len = slash - path;
        if (len >= sizeof(parent)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        ngx_memcpy(parent, path, len);
        parent[len] = '\0';
        dfd = ngx_autocert_open_dir_path(parent, 0, 0);
        leaf = slash + 1;
    }

    if (leaf[0] == '\0' || (leaf[0] == '.' && leaf[1] == '\0')
        || (leaf[0] == '.' && leaf[1] == '.' && leaf[2] == '\0'))
    {
        if (dfd != -1) {
            (void) ngx_autocert_close(dfd);
        }
        errno = EINVAL;
        return -1;
    }
    if (dfd == -1) {
        return -1;
    }

    fd = ngx_autocert_openat(dfd, leaf, flags | O_NOFOLLOW | O_CLOEXEC);
    err = errno;
    (void) ngx_autocert_close(dfd);
    errno = err;

    return fd;
}


#endif /* _NGX_AUTOCERT_SHARED_H_INCLUDED_ */
