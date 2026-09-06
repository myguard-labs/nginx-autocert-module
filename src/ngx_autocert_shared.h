/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
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

#include <stddef.h>   /* offsetof — NGX_AUTOCERT_FILE_NAME_INFO_OFF below */


/*
 * FILE_RENAME_INFORMATION / FILE_LINK_INFORMATION trailing-array layout —
 * the pure arithmetic half of ngx_autocert_renameat2()/ngx_autocert_linkat()
 * (src/ngx_autocert_win32.h), extracted here so it is ONE definition both
 * functions call and the unit suite can bind to directly, following the same
 * pure-core pattern as ngx_autocert_win32_classify_root() below. Defined
 * BEFORE the ngx_autocert_win32.h include just below, because that header's
 * renameat2()/linkat() bodies use this macro at compile time -- the macro
 * must already be visible when their text is pasted in.
 *
 * Both NT structs share the identical header shape:
 *
 *     struct { BOOLEAN ReplaceIfExists; HANDLE RootDirectory;
 *              ULONG FileNameLength; } *hdr;
 *
 * and the trailing FileName[] array starts, ON THE WIRE, at
 * offsetof(FileNameLength) + sizeof(ULONG) -- immediately after the ULONG,
 * with NO padding. A compiler is free to pad the OVERALL struct size up to
 * its widest member's alignment (HANDLE, 8 bytes on LLP64/64-bit Windows),
 * so sizeof(hdr) rounds up PAST that true offset (24 vs. the true 20 for
 * this field layout) -- copying/sizing off sizeof(*hdr) instead of this
 * offset writes the filename 4 bytes late, corrupting the trailing
 * FileNameLength bytes and the first wchar_t's of the name (observed on
 * MSVC/x64 as NtSetInformationFile failing with a generic status, surfaced
 * to the caller as ERROR_GEN_FAILURE). NEVER "simplify" a caller back to
 * sizeof(*hdr) -- that is the exact bug this macro exists to prevent.
 *
 * `hdr_type` is the real win32 struct tag (ngx_autocert_rename_hdr_s /
 * ngx_autocert_link_hdr_s) on win32, or NGX_AUTOCERT_TEST_RENAME_HDR_T
 * defined below on any other host, so this macro is usable unconditionally
 * (it needs only <stddef.h>'s offsetof and the ULONG width, no win32
 * header), letting the unit suite assert against the SAME symbol production
 * code uses instead of a hand-copied stand-in that could silently drift.
 */
#if NGX_WIN32

#define NGX_AUTOCERT_FILE_NAME_INFO_OFF(hdr_type) \
    (offsetof(hdr_type, FileNameLength) + sizeof(ULONG))

#else /* !NGX_WIN32 */

/*
 * Linux/POSIX has no <windows.h>, so ULONG/HANDLE/BOOLEAN do not exist here.
 * Stand-in typedefs matching the win32 ABI widths this code targets (LLP64,
 * 1-byte BOOLEAN, 8-byte HANDLE, 4-byte ULONG) let the SAME macro, on the
 * SAME field layout, be evaluated on Linux -- this is what makes the layout
 * arithmetic unit-testable on the only host these tests run on, instead of
 * being asserted only via a test-local reimplementation that proves nothing
 * about the production header.
 */
typedef unsigned char   ngx_autocert_test_boolean_t;
typedef void            *ngx_autocert_test_handle_t;
typedef unsigned int    ngx_autocert_test_ulong_t;

struct ngx_autocert_test_rename_hdr_s {
    ngx_autocert_test_boolean_t  ReplaceIfExists;
    ngx_autocert_test_handle_t   RootDirectory;
    ngx_autocert_test_ulong_t    FileNameLength;
};

#define NGX_AUTOCERT_TEST_RENAME_HDR_T struct ngx_autocert_test_rename_hdr_s

#define NGX_AUTOCERT_FILE_NAME_INFO_OFF(hdr_type) \
    (offsetof(hdr_type, FileNameLength) + sizeof(ngx_autocert_test_ulong_t))

#endif /* NGX_WIN32 */


#include "ngx_autocert_win32.h"   /* win32 shim types; empty on POSIX builds */

#include <fcntl.h>
#include <errno.h>


/*
 * A6 runtime marker: filename and open-flag contract shared between the
 * driver (production, ngx_autocert_driver.c) and its unit test
 * (ci/tests/unit/test_marker_open.c). Defined exactly once here so the test
 * cannot silently drift from production by keeping its own copy — that used
 * to be possible and made the test pass regardless of what the driver did.
 *
 * WRITE flags: O_NONBLOCK is REQUIRED (a planted FIFO must fail fast with
 * ENXIO instead of blocking openat() forever) and O_TRUNC must NOT be set
 * (truncation happens only after the fd is proven to be a regular file, via
 * ftruncate()). O_NOFOLLOW rejects a symlinked leaf.
 *
 * READ flags: O_NONBLOCK for the same FIFO reason (a FIFO opened O_RDONLY
 * with no writer would otherwise be free to hang under some conditions);
 * O_NOFOLLOW rejects a symlinked leaf. The S_ISREG + st_nlink check at each
 * call site is the actual type gate — these flags only remove the blocking
 * possibility before that check runs.
 */
#define NGX_AUTOCERT_RUNTIME_MARKER    ".autocert-runtime"

#define NGX_AUTOCERT_MARKER_OPEN_WRITE \
    (O_WRONLY | O_CREAT | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)

#define NGX_AUTOCERT_MARKER_OPEN_READ \
    (O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)


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
    ngx_resolver_t  *resolver; /* may be NULL if autocert_resolver unset */
    time_t           resolver_timeout;
    /*
     * M5: the CA-identifying knobs (directory URL, trust bundle, EAB) are no
     * longer flat — they live per-CA in each ca_list entry's ca_conf. The
     * driver iterates ca_list and reads entry->ca_conf directly (see driver.c).
     * The flat `ca`/`ca_certificate`/`eab_*` fields the M4 bridge populated
     * from ca_list[0] are gone.
     */
    ngx_str_t        dns_hook_add;     /* M16 dns-01 publish-TXT exec, "" */
    ngx_str_t        dns_hook_remove;  /* M16 dns-01 remove-TXT exec, "" */
    time_t           dns_propagation_delay;  /* M16 seconds after publish */
    time_t           dns_hook_timeout; /* M16 seconds to wait for a hook exec */
    ngx_uint_t key_type; /* ngx_http_autocert_key_type_e; == cert_key_types[0],
                            kept for not-yet-array-aware consumers */
    ngx_array_t
        *cert_key_types;    /* dual-cert (Phase B): ngx_uint_t list of leaf
                               key types to issue per name. 1 or 2 entries:
                               at most one EC and at most one RSA (the parser
                               rejects a duplicate family). The ACME
                               account/challenge keys stay EC regardless. */
    ngx_uint_t       store; /* ngx_http_autocert_store_e (disk layout) */
    ngx_str_t        path;  /* cert store dir (holds the account key) */
    time_t           renew_before;   /* M8: seconds before notAfter to renew */
    ngx_uint_t       challenge;      /* M10c: ngx_http_autocert_challenge_e */
    ngx_str_t        profile; /* ACME Profiles: newOrder profile, "" = omit
                                 ("shortlived" for LE IP certs) */

    /* M5: the challenge token store the helper writes (NULL if not set up). */
    ngx_shm_zone_t  *challenge_zone;
    /* M6a: the collected enabled server names (ngx_str_t array, NULL/empty if
     * none). The order flow issues for the first name for now; multi-name
     * iteration is later (M6+). Points into the HTTP main-conf pool, which
     * outlives the helper run. */
    ngx_array_t     *names;
    /* M2: names grouped by CA (ngx_autocert_ca_entry_t array). One entry until
     * M4 adds per-vhost CAs; the driver (M5) iterates this. NULL/empty = none.
     */
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
 * ngx_autocert_close/read/write/ftruncate/geteuid/fchmod — POSIX side. The
 * win32 side is defined in ngx_autocert_win32.h on the MSVCRT int-fd API
 * (_close, _read, _write, _chsize_s); see that file's W7 comment for why the
 * fd stays a plain CRT int rather than a HANDLE. Defined here as thin macros
 * to the POSIX call so every call site goes through one shim spelling
 * regardless of platform, with POSIX object code unchanged.
 *
 * ngx_autocert_fchmod (W11) is the last of this family: win32 has no chmod
 * analogue at all (permission bits are a DACL, not a mode word), so its
 * win32 side in ngx_autocert_win32.h translates the POSIX bitmask into an
 * owner-only DACL rather than calling anything named "chmod". See that
 * file's W11 comment for the translation and why PROTECTED_DACL_SECURITY_
 * INFORMATION is mandatory there.
 */
#if !(NGX_WIN32)
#define ngx_autocert_close(fd)          close(fd)
#define ngx_autocert_read(fd, b, n)     read(fd, b, n)
#define ngx_autocert_write(fd, b, n)    write(fd, b, n)
#define ngx_autocert_ftruncate(fd, len) ftruncate(fd, len)
#define ngx_autocert_geteuid()          geteuid()
#define ngx_autocert_fchmod(fd, m)      fchmod(fd, (mode_t) (m))
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
 * FlushFileBuffers() fails outright on a directory handle. Callers differ
 * in how much they rely on the directory fsync succeeding — account.c's key
 * save treats it as a best-effort durability nicety (the key file itself is
 * already fsynced + closed first), while order.c's commit-rename call sites
 * treat it as a hard correctness requirement and abort the renewal on
 * failure, because that fsync is what makes the just-committed rename
 * durable — see the doc comments at each call site for which applies.
 * ngx_autocert_fsync_dir() is the seam that is allowed to be a real fsync on
 * POSIX and a documented no-op on win32 (win32 callers get an unconditional
 * success since FlushFileBuffers cannot target a directory at all);
 * ngx_autocert_fsync() itself stays a real flush on both platforms and must
 * never be widened to swallow a directory's failure too, or a genuine
 * file-flush failure would go silently unreported.
 */
#if !(NGX_WIN32)
#define ngx_autocert_fsync(fd)          fsync(fd)
#define ngx_autocert_fsync_dir(fd)      fsync(fd)
#endif

/*
 * renameat2(2) wrapper, shared by the store commit (order.c) and the
 * account-key migration (driver.c) — both fd-pinned, security-sensitive renames
 * that must not drift. Called via syscall() so the build needs no glibc
 * renameat2 wrapper. Returns NGX_OK on success; NGX_DECLINED when the
 * syscall/flag is unsupported (caller falls back or defers); NGX_ERROR
 * otherwise with ngx_errno set (incl. EEXIST for RENAME_NOREPLACE against an
 * existing destination — caller inspects).
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

static ngx_inline int ngx_autocert_fstatat( int dfd, const char *name,
                                            ngx_autocert_stat_t *st, int flags )
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
 * fstat(2) on an already-open int fd from this family
 * (ngx_autocert_open_file_path, ngx_autocert_openat_mode, ...). Kept distinct
 * from ngx_autocert_fstatat above: that one stats a NAME relative to a pinned
 * dir fd, this one stats the fd itself once it is already open — the two call
 * sites never overlap.
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
 * Whether a configured dns-01 hook names a fully-qualified executable path.
 * POSIX has one absolute form, rooted at '/'.  On win32, a leading separator
 * alone is rooted at the current drive and C:foo is relative to C:'s current
 * directory, so neither is safe for a worker whose CWD is unspecified.  Take
 * only a drive root (C:/... or C:\\...) or a UNC server/share root.
 */
static ngx_inline ngx_int_t
ngx_autocert_dns_hook_path_is_absolute(ngx_str_t *path)
{
#if (NGX_WIN32)
    u_char  *p, *end, *share;

    if (path->len >= 3 && ngx_autocert_win32_is_alpha(path->data[0])
        && path->data[1] == ':'
        && (path->data[2] == '/' || path->data[2] == '\\'))
    {
        return 1;
    }

    if (path->len < 5
        || (path->data[0] != '/' && path->data[0] != '\\')
        || (path->data[1] != '/' && path->data[1] != '\\'))
    {
        return 0;
    }

    p = path->data + 2;
    end = path->data + path->len;
    while (p < end && *p != '/' && *p != '\\') {
        p++;
    }
    if (p == path->data + 2 || p == end) {
        return 0;
    }

    share = ++p;
    while (p < end && *p != '/' && *p != '\\') {
        p++;
    }

    return p != share;
#else
    return path->len != 0 && path->data[0] == '/';
#endif
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


/*
 * W9 — named-mutex singleton name construction (win32 interprocess ACME
 * driver gate, DESIGN-win32-store-io.md § W2). Takes the CANONICALIZED
 * absolute store path (the caller must have resolved it via
 * GetFinalPathNameByHandleW first -- this function does no canonicalisation
 * of its own, so case / trailing-slash / 8.3-form differences on the same
 * directory must already be folded before it is called) and writes
 * "Global\ngx_autocert_singleton_<hash>" into `out` (size `out_cap`), where
 * <hash> is a stable hash of `path` rendered as lowercase hex.
 *
 * `Global\` (not `Local\`) is load-bearing: `Local\` is per-session, so a
 * Windows service instance and a console instance of the same nginx build
 * would each get their own namespace and both arm the ACME engine --
 * exactly the bug this mutex exists to close.
 *
 * FNV-1a, not ngx_crc32_short/long: the crc32 tables need
 * ngx_crc32_init(cf->pool) before first use (pool-allocated, cycle-scoped),
 * which is unavailable at the point ngx_autocert_driver_trylock() calls
 * this (worker init_process, no pool handy) and would make the Linux unit
 * test drag in ngx_crc32_init's pool machinery for no benefit -- FNV-1a is
 * self-contained, allocation-free, and only needs to be stable and
 * well-distributed, not cryptographically strong.
 *
 * Pure string+hash logic with no win32-header dependency, compiled
 * unconditionally like ngx_autocert_win32_classify_root() and
 * ngx_autocert_win32_quote_arg() above: the Linux unit suite calls the real
 * production function directly. Caller-supplied out buffer + capacity, no
 * allocation, same signature shape as its precedents. Returns 0 on success,
 * or -1 with errno set (ENAMETOOLONG) if `out` is too small; `out` is left
 * unmodified on failure -- no partial/truncated name is ever produced.
 */
static ngx_inline int
ngx_autocert_win32_singleton_name(const char *path, char *out, size_t out_cap)
{
    static const char  hexdigits[] = "0123456789abcdef";
    uint32_t            hash;
    size_t              i, len, need;
    const char          prefix[] = "Global\\ngx_autocert_singleton_";

    /* FNV-1a, 32-bit. Offset basis and prime are the published constants;
     * nothing here needs to match any other hash in this codebase. */
    hash = 2166136261u;
    len = ngx_strlen(path);
    for (i = 0; i < len; i++) {
        hash ^= (unsigned char) path[i];
        hash *= 16777619u;
    }

    /* prefix + 8 hex digits + NUL, computed rather than sizeof()'d so the
     * bound stays correct if the prefix text above ever changes. */
    need = (sizeof(prefix) - 1) + 8 + 1;
    if (need > out_cap) {
        errno = ENAMETOOLONG;
        return -1;
    }

    ngx_memcpy(out, prefix, sizeof(prefix) - 1);

    for (i = 0; i < 8; i++) {
        out[sizeof(prefix) - 1 + i] =
            hexdigits[(hash >> (28 - 4 * i)) & 0xF];
    }
    out[sizeof(prefix) - 1 + 8] = '\0';

    return 0;
}


/*
 * W9 — WaitForSingleObject() result -> singleton-acquisition verdict.
 *
 * This is the exact rule a plausible win32 port gets backwards: WAIT_ABANDONED
 * means a previous holder exited (crashed, killed, whatever) WITHOUT releasing
 * -- but the kernel has already transferred ownership to THIS caller. It is a
 * SUCCESS, not an error. Treating it as failure means no worker ever acquires
 * the singleton again after one crash, which silently and permanently stops
 * certificate issuance/renewal on that store. NGX_LOG_NOTICE is the caller's
 * job (this function is pure and does no logging), but the caller MUST log
 * when this returns NGX_OK for WAIT_ABANDONED specifically, since it is
 * diagnostically significant (something died holding the lock).
 *
 * WAIT_TIMEOUT (used with a zero timeout, per this gate's never-block rule)
 * means another process currently holds it -> NGX_AGAIN, mirroring the POSIX
 * flock() EAGAIN path exactly so both feed the same relock-timer retry in
 * ngx_autocert_relock_handler().
 *
 * Anything else (WAIT_FAILED, or an unrecognised code) -> NGX_ERROR.
 *
 * Takes a plain uint32_t rather than DWORD so this stays win32-header-free
 * and Linux-unit-testable; the four named constants below are numerically
 * identical to the WinBase.h macros of the same name (0, 0x80, 0x102,
 * 0xFFFFFFFF), so a win32 caller passes WaitForSingleObject()'s return value
 * straight through with no translation.
 */
#define NGX_AUTOCERT_WAIT_OBJECT_0    0x00000000u
#define NGX_AUTOCERT_WAIT_ABANDONED   0x00000080u
#define NGX_AUTOCERT_WAIT_TIMEOUT     0x00000102u
#define NGX_AUTOCERT_WAIT_FAILED      0xFFFFFFFFu

static ngx_inline ngx_int_t
ngx_autocert_win32_mutex_wait_verdict(uint32_t wait_rc)
{
    switch (wait_rc) {

    case NGX_AUTOCERT_WAIT_OBJECT_0:
        return NGX_OK;

    case NGX_AUTOCERT_WAIT_ABANDONED:
        /* Ownership transferred to us; treat exactly like WAIT_OBJECT_0. */
        return NGX_OK;

    case NGX_AUTOCERT_WAIT_TIMEOUT:
        return NGX_AGAIN;

    default:
        return NGX_ERROR;
    }
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

    return ngx_autocert_win32_ntopen(
        NGX_AUTOCERT_INVALID_DIRFD, root,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
        NGX_AUTOCERT_FILE_OPEN,
        NGX_AUTOCERT_FILE_DIRECTORY_FILE |
            NGX_AUTOCERT_FILE_OPEN_FOR_BACKUP_INTENT,
        _O_RDONLY );
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
            if ( ngx_autocert_mkdirat( dfd, name, mode ) == -1 &&
                 errno != EEXIST ) {
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


/*
 * ngx_autocert_win32_dacl_mode (W11) — pure DACL-ACE-tuple -> POSIX
 * group/other permission-bit decision core.
 *
 * The win32 side of ngx_autocert_fstat/fstatat (ngx_autocert_win32.h)
 * fabricates st_mode for account.c's "reject a key with group/other bits"
 * guard (ngx_autocert_account.c:276-283). Before W11 that guard was a
 * tautology on win32: the fabricated mode was always S_IFREG|0600 regardless
 * of the file's real DACL, so a world-readable account key passed. This
 * function is the decision this repo actually needs walking the real DACL
 * to get right, extracted out of the win32-only ACE-walk loop so it has a
 * Linux test oracle (the win32 side cannot be exercised or fuzzed here at
 * all; this function can).
 *
 * Contract: the caller has already walked every ACE in the file's DACL and
 * reduced each one to a (is_owner, is_allow, is_tolerated) tuple:
 *   - is_owner:     the ACE's SID equals the file owner's SID (EqualSid).
 *   - is_allow:     the ACE type is ACCESS_ALLOWED_ACE_TYPE (a DENY ACE
 *                    grants nothing and is not evidence of exposure).
 *   - is_tolerated: the ACE's SID is SYSTEM or the local Administrators
 *                    group (CreateWellKnownSid WinLocalSystemSid /
 *                    WinBuiltinAdministratorsSid) — DECIDED, not discovered:
 *                    an admin/SYSTEM principal can read any file on the box
 *                    regardless of this DACL, so flagging them would make
 *                    the guard permanently unusable (every Windows file has
 *                    an implicit Administrators/SYSTEM grant somewhere)
 *                    without adding any real security. Nothing else is
 *                    tolerated: a non-owner, non-tolerated ALLOW ace is
 *                    exactly the exposure account.c's guard exists to catch.
 *
 * Returns the POSIX group/other bits that should be OR'd into st_mode
 * (S_IRWXG|S_IRWXO when any ACE is a non-owner, non-tolerated ALLOW; 0 when
 * every ALLOW ace is owner-only or tolerated). Callers combine this with
 * S_IFREG and the fixed owner bits (0600) the way the win32 fstat bodies
 * already build st_mode; this function decides only the group/other half,
 * which is the half account.c's guard actually reads.
 *
 * n == 0 (a DACL with no ACEs at all, i.e. NULL DACL / everyone denied by
 * default, or the caller passing an empty walk) is NOT "no exposure found":
 * treat it the same as the fail-closed caller contract in
 * ngx_autocert_win32.h's W11 comment — the caller is expected to have
 * already fail-closed on any API error before calling this, but an
 * unexpectedly empty ACE list from a live DACL is itself worth flagging
 * rather than silently returning "safe", so it also returns the flagged
 * bits. A real owner-only DACL always has at least the owner's ACE.
 */
static ngx_inline ngx_autocert_mode_t
ngx_autocert_win32_dacl_mode(const ngx_int_t *is_owner,
    const ngx_int_t *is_allow, const ngx_int_t *is_tolerated, ngx_uint_t n)
{
    ngx_uint_t  i;

    if (n == 0) {
        return (ngx_autocert_mode_t) (S_IRWXG | S_IRWXO);
    }

    for (i = 0; i < n; i++) {
        if (!is_allow[i]) {
            continue;
        }
        if (is_owner[i] || is_tolerated[i]) {
            continue;
        }
        return (ngx_autocert_mode_t) (S_IRWXG | S_IRWXO);
    }

    return 0;
}


/*
 * Refuse an already-open directory or file fd unless it is owned by our own
 * euid and cannot be modified by anyone else. ngx_autocert_fstat()
 * fabricates a POSIX-shaped st_mode/st_uid on both platforms (win32's side
 * walks the real DACL via ngx_autocert_win32_dacl_mode() above), so this one
 * check is portable without an #ifdef.
 *
 * Both the store directory (adopted, not created, whenever it already
 * exists — driver.c's trylock) and the stored serving key (serve.c's cache
 * reload) are read from a filesystem the threat model treats as
 * attacker-writable by another local user: ngx_autocert_open_dir_path()
 * pins every path component against a planted symlink, but says nothing
 * about who owns the inode it lands on or what it is writable by. Without
 * this a directory or key pre-created (or substituted) by another local
 * user is adopted silently.
 *
 * `secret` picks WHICH permissions are disqualifying, and the distinction is
 * load-bearing:
 *
 *   secret=1 (a private key): any group/other bit is refused, READ included.
 *     A key another user can read is already compromised, so this matches
 *     account.c's account-key load path exactly.
 *
 *   secret=0 (the store directory): only group/other WRITE is refused. The
 *     threat this closes is another user planting or swapping certificate
 *     material, which needs write. Refusing group/other READ as well would
 *     reject a store directory created by a plain `mkdir -p` under the
 *     default 0022 umask (0755) — an ordinary, safe deployment and the
 *     shape every e2e test uses. The directory being listable is not a
 *     vulnerability: it holds public certificates, and each private key
 *     inside is checked in its own right with secret=1. Conflating the two
 *     turned a hardening check into a false refusal that takes the whole
 *     module down on a correctly-configured host.
 *
 * `what` names the object in the log line ("store directory", "serving
 * key"); the caller owns and closes fd. Returns NGX_OK when the check
 * passes, NGX_ERROR (with a log line already emitted) otherwise.
 */
static ngx_inline ngx_int_t
ngx_autocert_check_owner_mode(int fd, ngx_log_t *log, const char *what,
    ngx_uint_t secret)
{
    ngx_autocert_stat_t  st;
    ngx_autocert_mode_t  bad;

    if (ngx_autocert_fstat(fd, &st) == -1) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "autocert: fstat(%s) failed", what);
        return NGX_ERROR;
    }

    bad = secret ? (S_IRWXG | S_IRWXO) : (S_IWGRP | S_IWOTH);

    if (st.st_mode & bad) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "autocert: %s is %s by group/other "
                      "(refusing to adopt it)", what,
                      secret ? "accessible" : "writable");
        return NGX_ERROR;
    }

    if (st.st_uid != ngx_autocert_geteuid()) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "autocert: %s is not owned by the worker euid "
                      "(refusing to adopt it)", what);
        return NGX_ERROR;
    }

    return NGX_OK;
}


#endif /* _NGX_AUTOCERT_SHARED_H_INCLUDED_ */
