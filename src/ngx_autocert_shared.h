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
 * ngx_autocert_fsync / ngx_autocert_fsync_dir (W5i) — POSIX side. The win32
 * side is defined in ngx_autocert_win32.h's W5i primitives region
 * (FlushFileBuffers). Both take an already-open fd from this family and
 * return 0 on success, -1 on failure with errno set, matching fsync(2)'s own
 * convention so the account.c/order.c call sites keep their `!= 0`/`== -1`
 * tests unchanged.
 *
 * Split in two because a directory fd has no win32 analogue:
 * FlushFileBuffers() fails outright on a directory handle. Every dir-fsync
 * call site here is already best-effort by design (durability nicety, never
 * a correctness requirement — see the doc comments at its call sites), so
 * ngx_autocert_fsync_dir() is the seam that is allowed to be a real fsync on
 * POSIX and a documented no-op on win32; ngx_autocert_fsync() itself stays a
 * real flush on both platforms and must never be widened to swallow a
 * directory's failure too, or a genuine file-flush failure would go silently
 * unreported.
 */
#if !(NGX_WIN32)
#define ngx_autocert_fsync(fd)          fsync(fd)
#define ngx_autocert_fsync_dir(fd)      fsync(fd)
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
 * ngx_autocert_split_root() — classify and open the ROOT of `path`, and hand
 * back the remaining component walk in `*rest`. This runs BEFORE the
 * component walk in ngx_autocert_open_dir_path() below; the walk itself
 * stays byte-identical on both platforms (`/`-separated, `..`/`.`/empty
 * rejected, per-component O_NOFOLLOW pinning) once it has a root fd to
 * start from. Replaces the raw open("/")/open(".") bootstrap that used to
 * sit at the top of the walk (MSVC C4996 on `open`, and the C2220 that
 * `-WX` promotes it to) — those calls are gone here, not suppressed.
 *
 * On POSIX this is a thin passthrough: `/` opens "/", anything else opens
 * "." and is walked from `path` unchanged (the `norm`/`norm_cap` params are
 * unused on this side — POSIX has no `\`-vs-`/` ambiguity to normalise).
 * On win32, `path` may additionally use `\` as a separator; it is normalised
 * to `/` into the caller-owned `norm` buffer (size `norm_cap`) BEFORE
 * classification AND before `*rest` is handed to the walk, so the walk's
 * own `..`/`.`/empty-component rejection runs on the normalised form (a
 * `..\` that survived un-normalised would slip past the `../` check).
 * `norm` must outlive the caller's walk — `*rest` points inside it, never
 * into a buffer local to this function. Recognised win32 roots, all
 * case-insensitive:
 *
 *   C:/... or C:\...          drive-absolute -> root "\??\C:\", rest "..."
 *   //server/share/...        UNC (either sep) -> root "\??\UNC\server\share\",
 *   \\server\share/...        rest "..."; server+share are consumed TOGETHER
 *                              as the root, never walked component-wise
 *   /... or \... (no drive)   drive-relative -> EINVAL (no current-drive guess)
 *   C:foo (no sep after ':')  drive-relative -> EINVAL
 *   anything else             relative -> root ".", rest = path unchanged
 *
 * Returns an owned root dir fd with `*rest` pointing at the remaining
 * component string, or -1 with errno set.
 */
static ngx_inline int
ngx_autocert_win32_is_alpha(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}


/*
 * Fold '\' to '/' into `norm` (size `norm_cap`), the same '\'-vs-'/'
 * normalisation ngx_autocert_win32_classify_root() does as the FIRST step
 * before it looks at root syntax at all. Split out on its own because a
 * caller that only wants "give me a '/'-only string to walk" -- like
 * ngx_autocert_open_file_path()'s parent/leaf split below -- must NOT go
 * through the root classifier itself: that half also REJECTS a bare
 * '/'-rooted path as win32 drive-relative (EINVAL, "do not guess the
 * current drive"), which is exactly the ordinary absolute-path spelling
 * every POSIX caller in this module uses. Compiled unconditionally, like
 * ngx_autocert_win32_classify_root() above: no OS/CRT call, so the Linux
 * unit suite exercises the real function directly rather than a stand-in.
 * Returns 0 on success, or -1 with errno set (ENAMETOOLONG).
 */
static ngx_inline int
ngx_autocert_normalize_seps(const char *path, char *norm, size_t norm_cap)
{
    const char  *p;
    size_t       len;

    len = ngx_strlen(path);
    if (len >= norm_cap) {
        errno = ENAMETOOLONG;
        return -1;
    }

    for (p = path; *p; p++) {
        norm[p - path] = (*p == '\\') ? '/' : *p;
    }
    norm[len] = '\0';

    return 0;
}


/*
 * Pure path-syntax half of ngx_autocert_split_root(): normalises separators
 * and classifies the root, writing the NT object-name form ("\??\C:\...",
 * "\??\UNC\server\share") into `root` (size `root_cap`) and pointing `*rest`
 * at the remaining component string inside `norm` (size `norm_cap`, filled
 * in by this function — caller owns the buffer so this half stays free of
 * any OS/CRT call and is directly unit-testable on any host). Returns 0 with
 * `root`/`*rest` set for a recognised root, or -1 with errno set (EINVAL for
 * a drive-relative path, ENAMETOOLONG for an oversized input). `*rest` never
 * points outside `norm`.
 *
 * Compiled unconditionally (not #if NGX_WIN32-guarded) even though only the
 * win32 ngx_autocert_split_root() below calls it in production: it has no
 * win32-header dependency (ngx_strlen/ngx_strlchr/ngx_snprintf are pure
 * nginx-core), so keeping it outside the guard lets the unit suite compile
 * and exercise the real function on Linux — the only host these tests can
 * run on — rather than a hand-copied stand-in.
 */
static ngx_inline int
ngx_autocert_win32_classify_root(const char *path, char *norm,
    size_t norm_cap, char *root, size_t root_cap, const char **rest)
{
    const char  *p, *server, *share_end;
    size_t       len, server_len, share_len;

    /* Normalise \ to / BEFORE any classification or the walk sees it — the
     * walk's "..", ".", empty-component rejection must run on this form. */
    if (ngx_autocert_normalize_seps(path, norm, norm_cap) != 0) {
        return -1;
    }
    len = ngx_strlen(norm);

    if (len >= 2 && ngx_autocert_win32_is_alpha(norm[0]) && norm[1] == ':') {
        if (len >= 3 && norm[2] == '/') {
            /* C:/... (was C:\...) -> drive-absolute */
            if (root_cap < sizeof("\\??\\C:\\")) {
                errno = ENAMETOOLONG;
                return -1;
            }
            (void) ngx_snprintf((u_char *) root, root_cap,
                                 "\\??\\%c:\\%Z", norm[0]);
            *rest = norm + 3;
            return 0;
        }

        /* "C:foo" (drive-relative, no separator after the colon) -> reject;
         * do not guess the current drive. */
        errno = EINVAL;
        return -1;
    }

    if (len >= 2 && norm[0] == '/' && norm[1] == '/') {
        /* //server/share/... (was \\server\share\...) -> UNC. server+share
         * form the root TOGETHER; never walk the UNC prefix component-wise. */
        server = norm + 2;
        p = (const char *) ngx_strlchr((u_char *) server,
                                        (u_char *) norm + len, '/');
        if (p == NULL || p == server) {
            errno = EINVAL;
            return -1;
        }
        server_len = p - server;

        share_end = (const char *) ngx_strlchr((u_char *) (p + 1),
                                                (u_char *) norm + len, '/');
        if (share_end == NULL) {
            share_end = norm + len;
        }
        share_len = share_end - (p + 1);
        if (share_len == 0) {
            errno = EINVAL;
            return -1;
        }

        if (server_len + share_len + sizeof("\\??\\UNC\\\\") >= root_cap) {
            errno = ENAMETOOLONG;
            return -1;
        }

        (void) ngx_snprintf((u_char *) root, root_cap,
                             "\\??\\UNC\\%*s\\%*s\\%Z",
                             server_len, server, share_len, p + 1);
        *rest = (share_end == norm + len) ? share_end : share_end + 1;
        return 0;
    }

    if (norm[0] == '/') {
        /* leading separator, no drive: drive-relative -> reject; do not
         * guess the current drive. */
        errno = EINVAL;
        return -1;
    }

    /* No root marker: relative, root "." -- existing behaviour. */
    if (root_cap < sizeof(".")) {
        errno = ENAMETOOLONG;
        return -1;
    }
    root[0] = '.';
    root[1] = '\0';
    *rest = norm;
    return 0;
}


/*
 * win32 command-line quoting for one argv element, per the CommandLineToArgvW
 * rules (the same parser CreateProcessW's child uses to split back apart
 * whatever lpCommandLine string it was given): wrap the argument in double
 * quotes; a run of backslashes only needs doubling when it is immediately
 * followed by a quote (either an embedded `"` or the closing quote this
 * function appends), otherwise backslashes pass through literally; an
 * embedded `"` becomes `\"`. Appends a single leading space before the
 * quoted argument so callers can concatenate several results directly into
 * one lpCommandLine (the first argument's leading space is harmless —
 * CreateProcessW/the CRT parser skip leading whitespace).
 *
 * Writes into `out` (size `out_cap`) starting at offset `off`, returns the
 * new offset (== the string length so far) on success, or -1 with errno set
 * (ENAMETOOLONG) if `out` is too small. Never partially writes past `out_cap`
 * — on overflow the caller must treat `out` as undefined and abort, not use
 * a truncated command line.
 *
 * Compiled unconditionally (not #if NGX_WIN32-guarded), same reasoning as
 * ngx_autocert_win32_classify_root() above: pure string logic, no win32-header
 * dependency, so the Linux unit suite can call the real production function
 * instead of a hand-copied stand-in that could drift from it. This is the
 * injection surface for the dns-01 hook spawn (W8) — CreateProcessW takes one
 * flat command-line string, not an argv array, so getting this wrong is a
 * command-injection bug, not a cosmetic one.
 */
static ngx_inline ngx_int_t
ngx_autocert_win32_quote_arg(const char *arg, char *out, size_t out_cap,
    size_t off)
{
    size_t  len, need, i, backslashes;

#define NGX_AUTOCERT_QA_PUT(ch)                                              \
    do {                                                                     \
        if (off >= out_cap) {                                                \
            errno = ENAMETOOLONG;                                            \
            return -1;                                                       \
        }                                                                    \
        out[off++] = (ch);                                                   \
    } while (0)

    len = ngx_strlen(arg);

    /* Worst case: every input byte becomes two ('\' doubling or '"' -> '\"')
     * plus a leading space, two wrapping quotes and the NUL. Cheap upper
     * bound checked once so the per-byte loop below never re-checks. */
    need = off + 1 /* space */ + 1 /* opening quote */
           + (len * 2) + 1 /* closing quote */ + 1 /* NUL */;
    if (need > out_cap) {
        errno = ENAMETOOLONG;
        return -1;
    }

    NGX_AUTOCERT_QA_PUT(' ');
    NGX_AUTOCERT_QA_PUT('"');

    backslashes = 0;
    for (i = 0; i < len; i++) {
        if (arg[i] == '\\') {
            backslashes++;
            continue;
        }

        if (arg[i] == '"') {
            /* Every pending backslash doubles, THEN escape the quote. */
            while (backslashes > 0) {
                NGX_AUTOCERT_QA_PUT('\\');
                NGX_AUTOCERT_QA_PUT('\\');
                backslashes--;
            }
            NGX_AUTOCERT_QA_PUT('\\');
            NGX_AUTOCERT_QA_PUT('"');
            continue;
        }

        /* Ordinary byte: any pending backslashes were NOT before a quote,
         * so they pass through undoubled. */
        while (backslashes > 0) {
            NGX_AUTOCERT_QA_PUT('\\');
            backslashes--;
        }
        NGX_AUTOCERT_QA_PUT(arg[i]);
    }

    /* Trailing backslashes sit immediately before the closing quote this
     * function appends, so they double too. */
    while (backslashes > 0) {
        NGX_AUTOCERT_QA_PUT('\\');
        NGX_AUTOCERT_QA_PUT('\\');
        backslashes--;
    }

    NGX_AUTOCERT_QA_PUT('"');
    out[off] = '\0';

#undef NGX_AUTOCERT_QA_PUT

    return (ngx_int_t) off;
}


#if !(NGX_WIN32)

static ngx_inline int
ngx_autocert_split_root(const char *path, char *norm, size_t norm_cap,
    const char **rest)
{
    (void) norm; (void) norm_cap;

    if (path[0] == '/') {
        *rest = path + 1;
        return open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }

    *rest = path;
    return open(".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

#else /* NGX_WIN32 */

static ngx_inline int
ngx_autocert_split_root(const char *path, char *norm, size_t norm_cap,
    const char **rest)
{
    char  root[NGX_MAX_PATH];

    if (ngx_autocert_win32_classify_root(path, norm, norm_cap,
                                          root, sizeof(root), rest) != 0)
    {
        return -1;
    }

    return ngx_autocert_win32_ntopen(NGX_AUTOCERT_INVALID_DIRFD, root,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
        NGX_AUTOCERT_FILE_OPEN,
        NGX_AUTOCERT_FILE_DIRECTORY_FILE | NGX_AUTOCERT_FILE_OPEN_FOR_BACKUP_INTENT,
        _O_RDONLY);
}

#endif /* NGX_WIN32 */


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
    char         norm[NGX_MAX_PATH];
    const char  *p, *q;
    size_t       len;
    int          dfd, nfd, err;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    dfd = ngx_autocert_split_root(path, norm, sizeof(norm), &p);
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
 *
 * The parent/leaf split below scans for '/' only, exactly like
 * ngx_autocert_open_dir_path()'s component walk once it has a normalised
 * string to walk. On win32 a caller-supplied path may use '\' instead: a
 * bare "C:\store\key.pem" then contains no '/' at all (splits as
 * parent=".", leaf=the whole string -- a relative open of a literally-named
 * file, not the intended absolute one), and a mixed "C:/store\key.pem"
 * splits at the '/' and hands the un-normalised "store\key.pem" on as a
 * leaf. Fold '\' to '/' first with ngx_autocert_normalize_seps() -- the
 * same separator fold ngx_autocert_win32_classify_root() applies as its
 * own first step on the directory side, split out on its own here because
 * this function must NOT also run root classification: that half rejects
 * a bare '/'-rooted path as win32 drive-relative (EINVAL), which is the
 * ordinary absolute-path spelling every POSIX caller uses. The substring
 * handed to ngx_autocert_open_dir_path() as the parent is always '/'-only;
 * open_dir_path() (via ngx_autocert_split_root()) classifies that root
 * itself, exactly as it would for any other caller -- this function never
 * invents its own root spelling.
 */
static ngx_inline int
ngx_autocert_open_file_path(const char *path, int flags)
{
    char         norm[NGX_MAX_PATH];
    char         parent[NGX_MAX_PATH];
    const char  *p, *slash, *leaf;
    size_t       len;
    int          dfd, fd, err;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (ngx_autocert_normalize_seps(path, norm, sizeof(norm)) != 0) {
        return -1;
    }

    /* norm is the whole original path with separators folded to '/'; split
     * it the same way ngx_autocert_open_dir_path()'s walk would -- on the
     * LAST '/', everything before it is the parent to open. This mirrors
     * the pre-existing POSIX cases (no separator / leading separator /
     * interior separator) exactly, now operating on the normalised string
     * instead of the raw caller input. */
    slash = NULL;
    for (p = norm; *p; p++) {
        if (*p == '/') {
            slash = p;
        }
    }

    if (slash == NULL) {
        dfd = ngx_autocert_open_dir_path(".", 0, 0);
        leaf = norm;
    } else if (slash == norm) {
        dfd = ngx_autocert_open_dir_path("/", 0, 0);
        leaf = slash + 1;
    } else {
        len = slash - norm;
        if (len >= sizeof(parent)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        ngx_memcpy(parent, norm, len);
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
