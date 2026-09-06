/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (C) 2026 Thijs Eilander
 *
 * ngx_autocert_win32 — win32 support skeleton for the store-IO shim.
 *
 * Everything here is inside #if (NGX_WIN32), so a POSIX build sees an empty
 * header and its object code is byte-identical with or without this file.
 *
 * This header declares types and toolchain detection only; the implementations
 * land in ngx_autocert_shared.h alongside their POSIX counterparts, so callers
 * keep one signature per operation and never learn the platform.
 *
 * The contract these types serve is DESIGN-win32-store-io.md in this module's
 * memory mirror. Two decisions from it shape everything below and are repeated
 * here because getting either wrong compiles cleanly and fails in production:
 *
 *   1. CreateFileW has NO relative-open parameter. Real openat()-style
 *      semantics require NtCreateFile with RootDirectory in OBJECT_ATTRIBUTES.
 *      Deriving a path from a handle and re-opening it reintroduces exactly the
 *      TOCTOU that ngx_autocert_open_dir_path() exists to defeat.
 *
 *   2. FILE_SHARE_DELETE must be set on every open. POSIX unlinks still-open
 *      files freely and the cert store relies on it; without this flag unlink
 *      fails with ERROR_SHARING_VIOLATION only under concurrency.
 */

#ifndef _NGX_AUTOCERT_WIN32_H_INCLUDED_
#define _NGX_AUTOCERT_WIN32_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_WIN32)

/*
 * Toolchain detection. MinGW-w64 ships dirent.h/unistd.h and a POSIX-ish CRT;
 * MSVC ships neither (verified by W0a). Code that can use a POSIX spelling on
 * MinGW still goes through the shim — the seam must serve both toolchains
 * identically, otherwise the win32 branch is only ever tested on one of them.
 */
#if defined(_MSC_VER)
#define NGX_AUTOCERT_MSVC     1
#define NGX_AUTOCERT_MINGW    0
#elif defined(__MINGW32__)
#define NGX_AUTOCERT_MSVC     0
#define NGX_AUTOCERT_MINGW    1
#else
#error "ngx_autocert: unsupported win32 toolchain (expected MSVC or MinGW-w64)"
#endif

#include <aclapi.h> /* GetSecurityInfo/SetSecurityInfo/SetEntriesInAclW — W11 */
#include <errno.h>
#include <fcntl.h>  /* _O_RDONLY and friends for _open_osfhandle */
#include <io.h>     /* _open_osfhandle, _get_osfhandle, _close */
#include <limits.h> /* INT_MAX — W9 canon-path WideCharToMultiByte clamp */
#include <stddef.h> /* offsetof — ngx_autocert_readdir (W12) */
#include <stdlib.h> /* malloc/free — ngx_autocert_dir_t (W12) */
#include <windows.h>
#include <winioctl.h> /* IO_REPARSE_TAG_*; needs windows.h first */

/*
 * Share mode used for every open in the shim.
 *
 * FILE_SHARE_DELETE is load-bearing, not defensive: a pinned directory handle
 * without it blocks the store commit's own rename (order.c RENAME_EXCHANGE
 * site), i.e. the module deadlocks against itself. Kept as one constant so no
 * call site can quietly omit it.
 */
#define NGX_AUTOCERT_SHARE_ALL                                                \
    (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)


/*
 * Reparse-point policy — the O_NOFOLLOW analogue.
 *
 * Opens use FILE_FLAG_OPEN_REPARSE_POINT so the link itself is opened rather
 * than its target. But win32 reparse points are a wider category than symlinks:
 * dedup and cloud-sync tags also live here, and rejecting all of them would
 * break stores on ordinary deduplicated volumes. So the tag is inspected and
 * only the two that actually redirect to another location are refused, mapping
 * to ELOOP the way O_NOFOLLOW does.
 */
#define ngx_autocert_reparse_is_link(tag)                                     \
    ((tag) == IO_REPARSE_TAG_SYMLINK || (tag) == IO_REPARSE_TAG_MOUNT_POINT)


/*
 * mode_t shim. MSVC's CRT does not define mode_t at all (a bare `mode_t`
 * parameter is a hard parse error there); MinGW-w64's CRT DOES define it, so
 * this must never `#define mode_t` — that would collide and fail to build on
 * MinGW specifically. A distinct name sidesteps both problems and is usable
 * from either toolchain.
 *
 * The value carried in this type is still a POSIX permission bitmask (e.g.
 * 0600, 0700) exactly as the POSIX call sites already spell it — this header
 * does not reinterpret it. W5b's win32 branch is what translates that
 * bitmask into a security descriptor when it implements the shim bodies;
 * nothing in W5a applies it to anything.
 */
typedef unsigned int  ngx_autocert_mode_t;


/*
 * ngx_autocert_stat_t (W5d) and the `<sys/stat.h>` macros the call sites use.
 *
 * `<sys/stat.h>` cannot be included in ANY nginx TU under MSVC: nginx's
 * ngx_win32_config.h does `typedef __int64 off_t;` then `#define
 * _OFF_T_DEFINED`. That guard covers BOTH `off_t` and `_off_t` in UCRT, so
 * `_off_t` is never typedef'd, and UCRT's `<sys/stat.h>` — whose `struct
 * _stat32` has an `_off_t st_size` member — fails to parse. This is not an
 * include-order or `_WIN32_WINNT` problem; the header is simply unusable
 * here. So this struct and these macros are our own, not UCRT's.
 *
 * Six members: st_mode, st_nlink, st_size, st_mtime, st_uid, st_ino are the
 * only fields any call site in this repo reads (grepped for every
 * `\.st_[a-z]+`/`->st_[a-z]+` against a `struct stat`/`ngx_autocert_stat_t`
 * in src/ — account.c's ownership check reads st_uid,
 * ngx_http_autocert_cache_reload's and ngx_http_autocert_read_file's
 * freshness logic in serve.c reads st_mtime and (audit MINOR) st_ino). st_size
 * is `off_t` — nginx's own `__int64` typedef on win32 — so the existing
 * `<= 0` / `> NGX_AUTOCERT_REQUEST_NAME_MAX` checks keep 64-bit semantics; a
 * `_off_t` (32-bit on UCRT, and undefined here regardless) would silently
 * truncate them. st_mode uses ngx_autocert_mode_t, matching the POSIX side.
 * st_mtime is populated via nginx's own `ngx_file_mtime()` FILETIME
 * conversion (ngx_files.h), the same one the core win32 file-info path
 * already uses — like the POSIX `time_t st_mtime`, this is WHOLE-SECOND
 * resolution only: nginx defines no portable sub-second accessor on either
 * platform (`ngx_file_mtime()` divides FILETIME's 100ns ticks down to whole
 * seconds; POSIX `st_mtime` is itself second-granular, `st_mtim.tv_nsec` is
 * a distinct, non-portable field nginx's own file-info layer never exposes).
 * st_ino is nginx's own `ngx_file_uniq_t` (uint64_t on win32, ino_t on
 * POSIX) — populated here from `BY_HANDLE_FILE_INFORMATION`'s
 * nFileIndexHigh/nFileIndexLow via `ngx_file_uniq()`, the exact same macro
 * ngx_open_file_cache already uses for this purpose. Note NTFS file IDs are
 * not stable across a volume format-and-restore the way an inode number
 * mostly is, but they ARE stable across the rename+replace an ACME renewal
 * performs, which is what this guards. st_uid has no win32 meaning, same as
 * ngx_autocert_geteuid() above (W7): the shim bodies set it to the identical
 * placeholder ngx_autocert_geteuid() returns, so account.c's
 * `st.st_uid != ngx_autocert_geteuid()` ownership check keeps compiling and
 * takes the same "always unprivileged, always safe default" branch geteuid()
 * already documents — this is not a new privilege decision, real ownership
 * verification is still W11 (key ACL) as already noted above.
 *
 * The `S_IF*`/`S_IS*`/`S_IRWX*` macros are `#ifndef`-guarded rather than
 * defined unconditionally: MinGW-w64's own headers may already supply some
 * of these transitively, and its definitions must win where present so both
 * toolchains see one set of values.
 */
typedef struct {
    ngx_autocert_mode_t  st_mode;
    short                st_nlink;
    off_t                st_size;
    time_t               st_mtime;
    ngx_uid_t            st_uid;
    ngx_file_uniq_t      st_ino;
} ngx_autocert_stat_t;

#ifndef S_IFMT
#define S_IFMT   0170000
#endif
#ifndef S_IFDIR
#define S_IFDIR  0040000
#endif
#ifndef S_IFREG
#define S_IFREG  0100000
#endif
#ifndef S_ISDIR
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#endif
#ifndef S_IRWXG
#define S_IRWXG  0000070
#endif
#ifndef S_IRWXO
#define S_IRWXO  0000007
#endif
/* The individual WRITE bits, needed separately from the S_IRWX* groups:
 * ngx_autocert_check_owner_mode() refuses only group/other WRITE on a
 * non-secret path (a store directory), while still refusing every group/other
 * bit on a secret. MSVC's <sys/stat.h> defines neither, so both are ours. */
#ifndef S_IWGRP
#define S_IWGRP  0000020
#endif
#ifndef S_IWOTH
#define S_IWOTH  0000002
#endif
/* The individual READ bits: ngx_autocert_win32_dacl_mode() maps a read-only
 * foreign ACE to exactly these so a secret still refuses it while a store
 * directory accepts it. MSVC defines neither. */
#ifndef S_IRGRP
#define S_IRGRP  0000040
#endif
#ifndef S_IROTH
#define S_IROTH  0000004
#endif


/*
 * POSIX open() flags the call sites spell (O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC,
 * O_NONBLOCK, ...) so the shared call sites in ngx_autocert_shared.h keep
 * exactly one spelling on both platforms. On win32 these are NOT passed to a
 * CRT _open()/_sopen_s() — the win32 branch of the shim (W5b) interprets each
 * bit itself (e.g. O_NOFOLLOW selects FILE_FLAG_OPEN_REPARSE_POINT) and never
 * forwards the raw flag word to the CRT or to CreateFileW/NtCreateFile. A call
 * site's O_NOFOLLOW therefore remains meaningful on win32 even though there is
 * no CRT-level equivalent of the flag itself.
 *
 * MinGW-w64's <fcntl.h> defines some of these already (its O_RDONLY etc. are
 * CRT-meaningful and must be left alone); each shim-only flag is guarded with
 * #ifndef so MinGW's own definition always wins where one exists, and MSVC
 * (which defines none of them) picks up the shim value. Bits are placed at
 * 0x01000000 and up specifically so they cannot collide with any low-bit flag
 * either CRT already assigns to _O_* / O_* constants.
 */
#ifndef O_DIRECTORY
#define O_DIRECTORY   0x01000000
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW    0x02000000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC     0x04000000
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK    0x08000000
#endif


/*
 * A pinned directory. The shim's public signatures stay int-fd-typed on both
 * platforms (see the helpers in ngx_autocert_shared.h): on win32 the int is a
 * CRT fd from _open_osfhandle(), and the HANDLE underneath is recovered with
 * _get_osfhandle() when a Win32/NT call needs it. Keeping the public type
 * identical is what lets W4's POSIX-only refactor stand unchanged.
 *
 * Ownership matches POSIX exactly: the fd owns the handle, and _close(fd)
 * closes it. Callers must not CloseHandle() a handle obtained from
 * _get_osfhandle() — that would close it twice.
 */
typedef int  ngx_autocert_dirfd_t;

#define NGX_AUTOCERT_INVALID_DIRFD  (-1)


/*
 * Recover the HANDLE backing a shim fd. Returns INVALID_HANDLE_VALUE for a
 * closed or non-file fd. Borrowed, never owned — see the note above.
 */
#define ngx_autocert_fd_handle(fd)                                            \
    ((HANDLE) _get_osfhandle(fd))


/*
 * W7 — the trivial primitives.
 *
 * Only the mappings that are genuinely one-to-one live here. Anything with a
 * semantic gap is deliberately absent and belongs to its own step: fchmod is
 * W11 (no NTFS analogue without an ACL), flock is W13 (LockFileEx), fork/execve
 * are W8 (CreateProcess + Job Object), fdopendir is W12.
 *
 * MinGW-w64 supplies POSIX spellings for several of these, but they are mapped
 * unconditionally on win32 anyway: if the two toolchains take different code
 * paths, only one of them is ever exercised by whichever CI lane runs, and the
 * other rots silently.
 */

#define ngx_autocert_close(fd)          _close(fd)
#define ngx_autocert_read(fd, b, n)     _read(fd, b, (unsigned int) (n))
#define ngx_autocert_write(fd, b, n)    _write(fd, b, (unsigned int) (n))

/*
 * ftruncate -> _chsize_s. Note the return convention differs: ftruncate()
 * returns -1 and sets errno, _chsize_s() RETURNS the errno value directly and
 * leaves errno alone. Normalised here so callers keep their -1 test.
 */
#define ngx_autocert_ftruncate(fd, len)                                       \
    (_chsize_s(fd, (__int64) (len)) == 0 ? 0 : -1)

/*
 * geteuid() has no win32 meaning. The POSIX callers use it only for a
 * "are we root?" style check; on win32 that question is answered by token
 * elevation, not a uid. Returning a non-zero constant makes the caller take
 * the unprivileged branch, which is the safe default. W11 revisits privilege
 * checks properly when it implements the key ACL.
 */
#define ngx_autocert_geteuid()          ((ngx_uid_t) 1)

/*
 * nanosleep -> Sleep. The POSIX call takes ns, Sleep takes whole ms; a sub-ms
 * request must not become a busy-spin of Sleep(0), so it rounds UP to 1ms.
 */
#define ngx_autocert_sleep_ns(ns)                                             \
    Sleep((DWORD) (((ns) + 999999LL) / 1000000LL))

/*
 * Monotonic milliseconds, for the dns-01 hook wait deadline.
 *
 * Mapped at the millisecond level rather than as a clock_gettime() shim: the
 * only caller (ngx_autocert_dns_monotonic) immediately reduces a timespec to
 * ms, so synthesising a struct timespec just to divide it again would add a
 * conversion without adding fidelity.
 *
 * GetTickCount64, NOT QueryPerformanceCounter: the deadline needs a clock that
 * is monotonic and cheap, not one that is high-resolution. QPC would also need
 * a frequency division per call. GetTickCount64 is 64-bit, so it does not wrap
 * (the 32-bit GetTickCount wraps after 49.7 days, which would silently expire
 * a hook wait on a long-lived worker).
 *
 * GetTickCount64 is a Vista+ kernel32 export whose prototype the SDK headers
 * gate behind the same _WIN32_WINNT floor that is a dead end here (see the
 * GetFileInformationByHandleEx note below: <ngx_config.h> has already fully
 * expanded <windows.h> at nginx's own 0x0501, so a later #define changes
 * nothing). Declare it ourselves, same minimal-surface style — kernel32 is
 * always already linked, so this resolves at link time without GetProcAddress.
 * Without the declaration MinGW emits an implicit-declaration error under
 * -Werror, and an implicit int return would truncate the 64-bit tick count.
 */
#ifndef NGX_AUTOCERT_HAVE_GETTICKCOUNT64
#define NGX_AUTOCERT_HAVE_GETTICKCOUNT64  1
WINBASEAPI ULONGLONG WINAPI GetTickCount64(void);
#endif

#define ngx_autocert_monotonic_ms()     ((uint64_t) GetTickCount64())

/*
 * Map GetLastError()/NTSTATUS to the errno values the seam's callers already
 * branch on (EEXIST, ENOENT, EAGAIN, ENOTEMPTY, ELOOP...).
 *
 * Deliberately not _doserrno / _get_errno: the CRT's mapping is narrower and
 * collapses distinctions the callers depend on — notably
 * ERROR_SHARING_VIOLATION, which must surface as EAGAIN so the lock path
 * retries rather than failing hard.
 *
 * Declared here, ahead of the first body that calls it; defined below with the
 * other shim bodies. static ngx_inline, like every other body in this header: a
 * non-static definition in a header included by six translation units is a
 * duplicate-symbol link error at win32 link time.
 */
static ngx_inline int ngx_autocert_win32_errno(DWORD err);

/*
 * ngx_autocert_win32_dacl_mode (W11) — the pure ACE-tuple -> POSIX
 * group/other bits decision core. Defined in ngx_autocert_shared.h (which
 * includes THIS header before its own body, so a forward declaration here is
 * required for the same MinGW use-before-declaration reason as
 * ngx_autocert_win32_errno above) so it has a Linux unit-test oracle; see
 * that definition's comment for the full contract. Only
 * ngx_autocert_win32_mode_from_dacl() below calls it.
 */
static ngx_inline ngx_autocert_mode_t
ngx_autocert_win32_dacl_mode(const ngx_int_t *is_owner,
    const ngx_int_t *is_allow, const ngx_int_t *is_tolerated,
    const ngx_int_t *is_write, ngx_uint_t n);
static ngx_inline ngx_int_t ngx_autocert_win32_mask_is_write(uint32_t mask);

/*
 * W13 — flock(fd, LOCK_EX | LOCK_NB) -> LockFileEx.
 *
 * The POSIX side locks the whole file with a single flock() call; the win32
 * analogue locks a byte range, so the whole conceptual file is locked with
 * the standard 0..0xFFFFFFFFFFFFFFFF idiom (offset 0, length as large as the
 * OVERLAPPED's two DWORD halves can express). LOCKFILE_FAIL_IMMEDIATELY is
 * what makes this non-blocking, matching LOCK_NB; LOCKFILE_EXCLUSIVE_LOCK
 * matches LOCK_EX.
 *
 * Same return convention as flock(): 0 on success, -1 on failure with errno
 * set. Contention (another process already holds the lock) must surface as
 * EAGAIN — the sole caller (driver.c's singleton-gate trylock) branches on
 * exactly that to tell "another process holds it, retry later" apart from a
 * hard failure. LockFileEx failing immediately for that reason sets
 * ERROR_LOCK_VIOLATION or ERROR_SHARING_VIOLATION; ngx_autocert_win32_errno()
 * maps both to EAGAIN, so SetLastError() of the mapped value is what makes
 * the caller's `ngx_errno == EWOULDBLOCK` test (EAGAIN and EWOULDBLOCK are
 * the same CRT constant) succeed. errno is set explicitly too, per the W5h
 * pattern of failure paths setting both errno and SetLastError, since a
 * caller may read either.
 *
 * ngx_autocert_win32_errno() is forward-declared just above rather than left to
 * its declaration further down: this body CALLS it, and a call that precedes
 * any declaration is an implicit-declaration error under MinGW's C99 (and then
 * a "static declaration follows non-static declaration" error when the real
 * declaration is reached). MSVC does not diagnose it, so the ordering must be
 * kept correct here rather than trusted to one compiler.
 */
static ngx_inline int
ngx_autocert_flock_ex_nb(int fd)
{
    HANDLE      h;
    OVERLAPPED  ov;
    int         mapped;

    h = ngx_autocert_fd_handle(fd);
    if (h == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        errno = EBADF;
        return -1;
    }

    ngx_memzero(&ov, sizeof(OVERLAPPED));

    if (LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0, 0xFFFFFFFF, 0xFFFFFFFF, &ov))
    {
        return 0;
    }

    mapped = ngx_autocert_win32_errno(GetLastError());
    SetLastError(mapped);
    errno = mapped;
    return -1;
}


/*
 * W5i — fsync(fd) -> FlushFileBuffers.
 *
 * Same return convention as fsync(2): 0 on success, -1 on failure with errno
 * set. On failure both errno and SetLastError() are set explicitly, per the
 * W13 pattern above (not W5f/linkat's SetLastError-only shape, which is a
 * known inconsistency tracked separately as W5h) — a caller may read either.
 *
 * ngx_autocert_win32_errno() is forward-declared above this shim's first use,
 * same ordering requirement as ngx_autocert_flock_ex_nb(): MSVC does not
 * diagnose use-before-declaration of a static ngx_inline function but MinGW
 * does, so the declaration must precede every caller in this header's
 * textual order regardless of which compiler happens to validate it.
 */
static ngx_inline int
ngx_autocert_fsync(int fd)
{
    HANDLE  h;
    int     mapped;

    h = ngx_autocert_fd_handle(fd);
    if (h == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        errno = EBADF;
        return -1;
    }

    if (FlushFileBuffers(h)) {
        return 0;
    }

    mapped = ngx_autocert_win32_errno(GetLastError());
    SetLastError(mapped);
    errno = mapped;
    return -1;
}


/*
 * W5i — directory fsync has no win32 analogue: FlushFileBuffers() fails
 * outright on a directory handle (ERROR_INVALID_FUNCTION / equivalent). Every
 * call site that fsyncs a directory fd through this seam already treats it as
 * best-effort durability, not a correctness requirement (see the doc comments
 * at ngx_autocert_account.c's key-dir fsync and ngx_autocert_order.c's
 * ngx_autocert_order_fsync_dirfd()) — those callers exist to make an already-
 * complete, already-fsynced file's directory entry durable sooner, and a
 * filesystem that simply cannot fsync a directory (several do not) must not
 * turn into a hard failure there.
 *
 * On win32 this is therefore a documented no-op that reports success. Note
 * what this does and does not buy: NTFS's metadata journal gives crash
 * *consistency* for directory entries, NOT the persistent-media guarantee a
 * POSIX fsync(dfd) provides — directory-entry durability here is best effort,
 * and this shim deliberately does not claim parity with fsync(dfd). Reporting
 * success is still correct rather than a silently-swallowed failure, because
 * the operation requested genuinely does not exist on this platform
 * (FlushFileBuffers is documented for file and volume handles only), and the
 * callers are best-effort by construction. This must stay
 * a SEPARATE shim from ngx_autocert_fsync() above — folding the two together
 * would make a real file-flush failure disappear the same way, which is not
 * acceptable on any platform.
 */
static ngx_inline int
ngx_autocert_fsync_dir(int fd)
{
    (void) fd;
    return 0;
}


/*
 * W11 — fchmod(fd, mode) -> owner-only DACL.
 *
 * win32 has no permission-bit file mode at all; the ACL IS the permission
 * model. This does not attempt to emulate a mode word — it grants access to
 * the file's OWNER ONLY, driven by which of the POSIX owner-bits in `mode`
 * are set, and strips every other principal's access outright. Group/other
 * bits in `mode` are deliberately ignored: on win32 there is no "group" or
 * "other" class to grant into, and granting one would defeat the entire
 * point of this shim (the sole caller, ngx_autocert_order_write_tmp_at(),
 * calls it with 0600 — owner read/write, nothing else — specifically to keep
 * the ACME account/cert private keys off disk in a world-readable form; see
 * ngx_autocert_account.c's DACL-derived mode check, which is what actually
 * verifies this on read-back).
 *
 * The DACL itself is built by ngx_autocert_win32_build_owner_dacl() below
 * (shared with ngx_autocert_mkdirat()'s 0700 directory arm, which hands it
 * to the kernel at creation) and applied by
 * ngx_autocert_win32_set_owner_dacl(): it grants the owner SID and the
 * process token user SID and strips inheritance
 * (PROTECTED_DACL_SECURITY_INFORMATION — see that helper for why the flag
 * is load-bearing).
 *
 * Return convention matches fchmod(2) and the rest of this shim family: 0 on
 * success, -1 on failure with SetLastError() carrying the raw Win32 error
 * code and errno carrying the mapped POSIX code. This deliberately does NOT
 * follow ngx_autocert_flock_ex_nb()'s mapped-value inversion above: that
 * shim exists to satisfy a caller with an EWOULDBLOCK-style contract, and
 * fchmod has no such caller.
 */
/*
 * A SID off the process token: the token USER (win32's nearest analogue of
 * geteuid()) or the token's default OWNER (the SID a new object will be
 * owned by — BUILTIN\Administrators for an elevated administrator, the user
 * itself otherwise). On Windows the OWNER of an object an administrator
 * creates is the Administrators group, not the administrator's own account,
 * so an ACE naming the account nginx runs as is NOT the owner's ACE and
 * would read as a foreign grant. Both the DACL writer and the DACL reader
 * below treat the token user as "us" alongside the owner. Fills `buf`
 * (SECURITY_MAX_SID_SIZE bytes); returns ERROR_SUCCESS or the Win32 error,
 * never a mapped errno.
 */
static ngx_inline DWORD
ngx_autocert_win32_token_sid(TOKEN_INFORMATION_CLASS cls, BYTE *buf,
    DWORD buf_len)
{
    HANDLE  tok;
    DWORD   need, err;
    PSID    sid;
    /* GetTokenInformation() writes a TOKEN_USER / TOKEN_OWNER (a pointer
     * member) followed by the SID it points into; a bare BYTE array has no
     * alignment guarantee for that pointer read, so force the struct's. */
    union {
        BYTE         bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
        TOKEN_USER   align_user;
        TOKEN_OWNER  align_owner;
    } raw;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        return GetLastError();
    }

    need = 0;
    if (!GetTokenInformation(tok, cls, raw.bytes, sizeof(raw.bytes), &need)) {
        err = GetLastError();
        CloseHandle(tok);
        return err;
    }

    CloseHandle(tok);

    if (cls == TokenUser) {
        sid = raw.align_user.User.Sid;
    } else if (cls == TokenOwner) {
        sid = raw.align_owner.Owner;
    } else {
        return ERROR_INVALID_PARAMETER;
    }

    if (sid == NULL || !IsValidSid(sid) || GetLengthSid(sid) > buf_len) {
        return ERROR_INVALID_SID;
    }

    if (!CopySid(buf_len, (PSID) buf, sid)) {
        return GetLastError();
    }

    return ERROR_SUCCESS;
}


/*
 * Build a DACL that grants `mask` to `owner` and to the process token user
 * (one ACE when they are the same SID, two when an administrator created the
 * object and the owner is therefore BUILTIN\Administrators) and nothing to
 * anyone else. `inherit` is the EXPLICIT_ACCESS inheritance word:
 * NO_INHERITANCE for a file, SUB_CONTAINERS_AND_OBJECTS_INHERIT for a
 * directory so what the module creates inside it starts owner-only too.
 * *out is LocalAlloc'd; the caller LocalFree()s it. Returns ERROR_SUCCESS or
 * the raw Win32 error.
 */
static ngx_inline DWORD
ngx_autocert_win32_build_owner_dacl(PSID owner, DWORD mask, DWORD inherit,
    PACL *out)
{
    PSID               user;
    EXPLICIT_ACCESS_W  ea[2];
    BYTE               user_buf[SECURITY_MAX_SID_SIZE];
    ULONG              n;
    DWORD              err;

    *out = NULL;

    err = ngx_autocert_win32_token_sid(TokenUser, user_buf, sizeof(user_buf));
    if (err != ERROR_SUCCESS) {
        return err;
    }
    user = (PSID) user_buf;

    ngx_memzero(ea, sizeof(ea));
    ea[0].grfAccessPermissions = mask;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = inherit;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea[0].Trustee.ptstrName = (LPWSTR) owner;
    n = 1;

    if (!EqualSid(owner, user)) {
        ea[1] = ea[0];
        ea[1].Trustee.ptstrName = (LPWSTR) user;
        n = 2;
    }

    return SetEntriesInAclW(n, ea, NULL, out);
}


/*
 * Replace an existing object's DACL with the owner-only one above.
 *
 * PROTECTED_DACL_SECURITY_INFORMATION is the load-bearing flag here, not an
 * optional hardening extra: SetSecurityInfo() without it MERGES the new DACL
 * with inherited ACEs from the parent directory rather than replacing them,
 * and a parent commonly carries an inherited grant to Users or Authenticated
 * Users (every stock volume root grants Authenticated Users Modify). Omitting
 * it would leave the object open to exactly the principals this exists to
 * lock out, while every other part of the call appears to succeed. Setting
 * it strips inheritance and makes the DACL built here the ENTIRE effective
 * DACL.
 *
 * Returns ERROR_SUCCESS or the raw Win32 error; callers map to errno.
 */
static ngx_inline DWORD
ngx_autocert_win32_set_owner_dacl(HANDLE h, DWORD mask, DWORD inherit)
{
    PSID                  owner;
    PSECURITY_DESCRIPTOR  owner_sd;
    PACL                  new_dacl;
    DWORD                 err;

    owner = NULL;
    owner_sd = NULL;

    err = GetSecurityInfo(h, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
                           &owner, NULL, NULL, NULL, &owner_sd);
    if (err != ERROR_SUCCESS) {
        return err;
    }

    if (owner == NULL) {
        LocalFree(owner_sd);
        return ERROR_INVALID_OWNER;
    }

    err = ngx_autocert_win32_build_owner_dacl(owner, mask, inherit, &new_dacl);
    if (err != ERROR_SUCCESS) {
        LocalFree(owner_sd);
        return err;
    }

    err = SetSecurityInfo(h, SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                NULL, NULL, new_dacl, NULL);

    LocalFree(owner_sd);
    LocalFree(new_dacl);

    return err;
}


static ngx_inline int
ngx_autocert_fchmod(int fd, ngx_autocert_mode_t mode)
{
    HANDLE  h;
    DWORD   mask, err;

    h = ngx_autocert_fd_handle(fd);
    if (h == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        errno = EBADF;
        return -1;
    }

    /* Access mask from the owner bits only — group/other bits in `mode` are
     * intentionally never consulted; see the function comment above. DELETE
     * is granted unconditionally so the owner can always remove the file it
     * owns (matching the POSIX shim's callers, which unlink on their own
     * failure paths through ngx_autocert_unlinkat(), a directory-fd-scoped
     * operation that does not itself need this, but a bare owner-only ACL
     * with no DELETE would otherwise surprise a future caller that opens the
     * file directly and tries to remove it). No FILE_DELETE_CHILD: that bit
     * only has meaning on a directory, and this shim is file-only (the sole
     * caller passes a file fd; ngx_autocert_order_write_tmp_at() never calls
     * this on a directory handle). */
    mask = DELETE;
    if (mode & 0400) {
        mask |= FILE_GENERIC_READ;
    }
    if (mode & 0200) {
        mask |= FILE_GENERIC_WRITE;
    }
    if (mode & 0100) {
        mask |= FILE_GENERIC_EXECUTE;
    }

    err = ngx_autocert_win32_set_owner_dacl(h, mask, NO_INHERITANCE);
    if (err != ERROR_SUCCESS) {
        SetLastError(err);
        errno = ngx_autocert_win32_errno(err);
        return -1;
    }

    return 0;
}

/*
 * NGX_EINTR retry predicate.
 *
 * nginx core does not define NGX_EINTR on win32 at all
 * (src/os/win32/ngx_errno.h has no entry for it) — a bare `ngx_errno ==
 * NGX_EINTR` is therefore a hard compile error on win32, not merely a wrong
 * answer. The retry loops that test it (e.g. the flock() spin at driver.c)
 * exist because a POSIX blocking syscall can be interrupted by a caught signal
 * mid-wait and must be retried. Win32 has no analogous "signal arrived during
 * this syscall" outcome for these calls, so the predicate is a
 * compile-time-constant false here: the branch it guards is simply unreachable
 * on win32, which is the correct behaviour, not a gap being papered over.
 */
#define ngx_autocert_err_is_intr(err)   0

/*
 * AT_SYMLINK_NOFOLLOW / AT_REMOVEDIR — the flag words ngx_autocert_fstatat()
 * and ngx_autocert_unlinkat() call sites pass explicitly
 * (DESIGN-win32-store-io.md says these stay call-site params rather than being
 * folded into a helper, on both platforms). Neither exists in any win32 header;
 * the shim bodies below interpret the bits themselves, so the exact numeric
 * value only has to be distinct from the other bit in this pair. Bit 0/1 keep
 * them out of the O_* shim range (0x01000000+) with room to spare.
 */
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW  0x0001
#endif
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR         0x0002
#endif


/*
 * RENAME_NOREPLACE / RENAME_EXCHANGE — ngx_autocert_renameat2()'s flags word.
 * order.c and driver.c only #define these under `#if defined(__linux__)`, so
 * on win32 the identifiers are genuinely undeclared at their call sites
 * (confirmed against W5-win32-diagnostics.md's MinGW list). Values only need
 * to be distinct from each other and from the AT_* pair above; they are never
 * forwarded to a real syscall, ngx_autocert_renameat2()'s win32 body switches
 * on them directly.
 */
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE  0x0004
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE   0x0008
#endif


/*
 * ntdll entry points used for the RootDirectory-relative opens that reproduce
 * openat() pinning (DESIGN-win32-store-io.md § W1: CreateFileW has no
 * relative-open parameter, so this is not optional). Resolved via
 * GetProcAddress against a load-time-linked ntdll.dll — no import lib, per the
 * design. ntdll.dll is always already loaded in a win32 process, so
 * GetModuleHandleW cannot fail here in practice; NULL is still checked because
 * a NULL function pointer must never be called silently.
 *
 * Minimal NT type surface: only what the shim bodies below actually touch.
 * Deliberately not the "real" <winternl.h>/<ntstatus.h> (not shipped by
 * either toolchain in a usable form here); redeclared to the ABI both MSVC
 * and MinGW-w64 agree on.
 */

/*
 * NTSTATUS is part of that minimal surface and must be declared here: neither
 * toolchain defines it from <windows.h> alone (it lives in <winternl.h> /
 * <ntdef.h>, which this header deliberately does not pull in). It is a plain
 * signed 32-bit status in the NT ABI, which MSVC and MinGW-w64 agree on.
 * Guarded so that a TU which already included <winternl.h> for other reasons
 * keeps the SDK's own typedef.
 */
#ifndef NGX_AUTOCERT_HAVE_NTSTATUS
#define NGX_AUTOCERT_HAVE_NTSTATUS  1
typedef LONG  NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status)  (((NTSTATUS) (status)) >= 0)
#endif

#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND     ((NTSTATUS) 0xC0000034L)
#endif
#ifndef STATUS_OBJECT_PATH_NOT_FOUND
#define STATUS_OBJECT_PATH_NOT_FOUND     ((NTSTATUS) 0xC000003AL)
#endif
#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION     ((NTSTATUS) 0xC0000035L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED             ((NTSTATUS) 0xC0000022L)
#endif
#ifndef STATUS_SHARING_VIOLATION
#define STATUS_SHARING_VIOLATION         ((NTSTATUS) 0xC0000043L)
#endif
#ifndef STATUS_DIRECTORY_NOT_EMPTY
#define STATUS_DIRECTORY_NOT_EMPTY       ((NTSTATUS) 0xC0000101L)
#endif
#ifndef STATUS_NOT_A_DIRECTORY
#define STATUS_NOT_A_DIRECTORY           ((NTSTATUS) 0xC0000103L)
#endif
#ifndef STATUS_FILE_IS_A_DIRECTORY
#define STATUS_FILE_IS_A_DIRECTORY       ((NTSTATUS) 0xC00000BAL)
#endif
#ifndef STATUS_TOO_MANY_LINKS
#define STATUS_TOO_MANY_LINKS            ((NTSTATUS) 0xC0000265L)
#endif
#ifndef STATUS_REPARSE_POINT_ENCOUNTERED
#define STATUS_REPARSE_POINT_ENCOUNTERED ((NTSTATUS) 0xC0000280L)
#endif
/*
 * STATUS_NO_MORE_FILES — NtQueryDirectoryFile's clean-end-of-enumeration
 * status (W12). A warning-severity code (top two bits 10), so NT_SUCCESS()
 * on it is false; it is not routed through
 * ngx_autocert_win32_errno_from_ntstatus below because it is not an error —
 * ngx_autocert_readdir() checks for it explicitly and maps it to POSIX
 * readdir()'s "NULL, errno left alone" end-of-directory contract, never to a
 * mapped ERROR_* code.
 */
#ifndef STATUS_NO_MORE_FILES
#define STATUS_NO_MORE_FILES             ((NTSTATUS) 0x80000006L)
#endif

/*
 * FILE_ATTRIBUTE_TAG_INFO / FileAttributeTagInfo / GetFileInformationByHandleEx
 * are Vista+ API gated behind _WIN32_WINNT in the SDK headers. Raising that
 * floor here is a dead end: <ngx_config.h> above has already pulled in and
 * fully expanded <windows.h> at whatever _WIN32_WINNT nginx's own
 * src/os/win32/ngx_win32_config.h set (0x0501), so a later #define in this
 * header changes nothing (confirmed against CI run 31548004561 — a
 * _WIN32_WINNT floor here produced a byte-identical error set). Declare the
 * pieces ourselves instead, same minimal-NT-surface style as NTSTATUS above.
 *
 * FileAttributeTagInfo is normally a FILE_INFO_BY_HANDLE_CLASS enumerator,
 * not a macro, so it cannot be probed or guarded with #ifndef without risking
 * a redefinition against a real enum constant of the same name. Use a
 * private macro name instead and pass it at the (single) call site; its
 * value (9) is fixed by the win32 ABI, identical to the SDK's own
 * FileAttributeTagInfo.
 */
#define NGX_AUTOCERT_FileAttributeTagInfo  9

#ifndef NGX_AUTOCERT_HAVE_FILE_ATTRIBUTE_TAG_INFO
#define NGX_AUTOCERT_HAVE_FILE_ATTRIBUTE_TAG_INFO  1
typedef struct {
    DWORD  FileAttributes;
    DWORD  ReparseTag;
} NGX_AUTOCERT_FILE_ATTRIBUTE_TAG_INFO;
#endif

#ifndef NGX_AUTOCERT_HAVE_GETFILEINFORMATIONBYHANDLEEX
#define NGX_AUTOCERT_HAVE_GETFILEINFORMATIONBYHANDLEEX  1
/* kernel32 export, present on every supported OS; not declared by the SDK
 * headers reachable here because they gate the prototype on the same
 * _WIN32_WINNT floor that is a dead end above. Plain extern declaration —
 * kernel32 is always already linked, so this resolves at link time without
 * GetProcAddress. */
WINBASEAPI BOOL WINAPI GetFileInformationByHandleEx(HANDLE FileHandle,
    int FileInformationClass, LPVOID FileInformation,
    DWORD BufferSize);
#endif

/*
 * FileDirectoryInformation / FILE_DIRECTORY_INFORMATION (W12) — the
 * NtQueryDirectoryFile counterpart to FileAttributeTagInfo above. Same
 * minimal-NT-surface style: FileInformationClass value 1 is ABI-fixed (ntddk.h
 * FILE_INFORMATION_CLASS enumerator), not probed or guarded against a real
 * enum constant for the same reason NGX_AUTOCERT_FileAttributeTagInfo isn't.
 * The struct is variable-length in the real ABI (FileName is a trailing
 * array whose size is FileNameLength bytes, NOT NUL-terminated); FileName[1]
 * here is only a placement anchor for pointer arithmetic, never indexed past
 * FileNameLength bytes. NextEntryOffset chains consecutive entries inside one
 * query's buffer; 0 marks the last entry in the buffer (not necessarily the
 * last entry in the directory — the caller re-queries when the buffer drains).
 */
#define NGX_AUTOCERT_FileDirectoryInformation  1

#ifndef NGX_AUTOCERT_HAVE_FILE_DIRECTORY_INFORMATION
#define NGX_AUTOCERT_HAVE_FILE_DIRECTORY_INFORMATION  1
typedef struct {
    ULONG          NextEntryOffset;
    ULONG          FileIndex;
    LARGE_INTEGER  CreationTime;
    LARGE_INTEGER  LastAccessTime;
    LARGE_INTEGER  LastWriteTime;
    LARGE_INTEGER  ChangeTime;
    LARGE_INTEGER  EndOfFile;
    LARGE_INTEGER  AllocationSize;
    ULONG          FileAttributes;
    ULONG          FileNameLength;
    WCHAR          FileName[1];
} NGX_AUTOCERT_FILE_DIRECTORY_INFORMATION;
#endif

typedef struct {
    USHORT  Length;
    USHORT  MaximumLength;
    PWSTR   Buffer;
} NGX_AUTOCERT_UNICODE_STRING;

typedef struct {
    ULONG                         Length;
    HANDLE                        RootDirectory;
    NGX_AUTOCERT_UNICODE_STRING  *ObjectName;
    ULONG                         Attributes;
    PVOID                         SecurityDescriptor;
    PVOID                         SecurityQualityOfService;
} NGX_AUTOCERT_OBJECT_ATTRIBUTES;

typedef struct {
    union {
        NTSTATUS  Status;
        PVOID     Pointer;
    } u;
    ULONG_PTR  Information;
} NGX_AUTOCERT_IO_STATUS_BLOCK;

/* OBJ_CASE_INSENSITIVE only — deliberately NOT OBJ_INHERIT (settled decision
 * 8: handles must not be inheritable, the O_CLOEXEC analogue). */
#define NGX_AUTOCERT_OBJ_CASE_INSENSITIVE  0x00000040L

#define NGX_AUTOCERT_FILE_OPEN              0x00000001
#define NGX_AUTOCERT_FILE_CREATE            0x00000002
#define NGX_AUTOCERT_FILE_OPEN_IF           0x00000003
#define NGX_AUTOCERT_FILE_DIRECTORY_FILE       0x00000001
#define NGX_AUTOCERT_FILE_NON_DIRECTORY_FILE   0x00000040
#define NGX_AUTOCERT_FILE_SYNCHRONOUS_IO_NONALERT  0x00000020
#define NGX_AUTOCERT_FILE_OPEN_FOR_BACKUP_INTENT   0x00004000
#define NGX_AUTOCERT_FILE_OPEN_REPARSE_POINT       0x00200000
#define NGX_AUTOCERT_FILE_DELETE_ON_CLOSE          0x00001000

#define NGX_AUTOCERT_FILE_DISPOSITION_DELETE 0x00000001
#define NGX_AUTOCERT_FILE_RENAME_REPLACE_IF_EXISTS 0x00000001

typedef NTSTATUS (NTAPI *ngx_autocert_pfn_NtCreateFile_t)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    NGX_AUTOCERT_OBJECT_ATTRIBUTES *ObjectAttributes,
    NGX_AUTOCERT_IO_STATUS_BLOCK *IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
    ULONG EaLength);

typedef NTSTATUS (NTAPI *ngx_autocert_pfn_NtSetInformationFile_t)(
    HANDLE FileHandle, NGX_AUTOCERT_IO_STATUS_BLOCK *IoStatusBlock,
    PVOID FileInformation, ULONG Length, ULONG FileInformationClass);

typedef NTSTATUS (NTAPI *ngx_autocert_pfn_NtQueryInformationFile_t)(
    HANDLE FileHandle, NGX_AUTOCERT_IO_STATUS_BLOCK *IoStatusBlock,
    PVOID FileInformation, ULONG Length, ULONG FileInformationClass);

/*
 * NtQueryDirectoryFile (W12) — ApcRoutine/ApcContext/FileName are always NULL
 * at our call site (no APC completion, no wildcard filter: the shim reads
 * every entry and lets the caller filter), so they are typed PVOID rather
 * than pulling in PIO_APC_ROUTINE/PUNICODE_STRING from the headers this file
 * deliberately does not include. FileInformationClass is ULONG, matching the
 * bare-int style already used for GetFileInformationByHandleEx's class param
 * above, rather than declaring the real FILE_INFORMATION_CLASS enum.
 */
typedef NTSTATUS (NTAPI *ngx_autocert_pfn_NtQueryDirectoryFile_t)(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    NGX_AUTOCERT_IO_STATUS_BLOCK *IoStatusBlock, PVOID FileInformation,
    ULONG Length, ULONG FileInformationClass, BOOLEAN ReturnSingleEntry,
    PVOID FileName, BOOLEAN RestartScan);

/*
 * Lazily resolved once per process. ngx_autocert_pfn_NtCreateFile is both the
 * fast-path gate below AND one of the four pointers published here, so the
 * publication order is load-bearing, not benign: it is stored LAST, after a
 * MemoryBarrier(), specifically so that a second thread observing it non-NULL
 * through the gate is guaranteed to also observe
 * ngx_autocert_pfn_NtSetInformationFile,
 * ngx_autocert_pfn_NtQueryInformationFile and
 * ngx_autocert_pfn_NtQueryDirectoryFile already published. Any writer racing to
 * resolve stores the same values (GetProcAddress is idempotent for a given
 * (module, symbol)), so the only thing that needs ordering is which pointer
 * becomes visible first — publish the three non-gate pointers, THEN the gate
 * pointer, never the other way round. Getting this backwards (or reasoning
 * about each pointer as independently benign) is exactly the bug this comment
 * used to describe as safe: a torn read on any one pointer is impossible, but a
 * reader is not limited to reading only the gate.
 */
static ngx_autocert_pfn_NtCreateFile_t
    ngx_autocert_pfn_NtCreateFile = NULL;
static ngx_autocert_pfn_NtSetInformationFile_t
    ngx_autocert_pfn_NtSetInformationFile = NULL;
static ngx_autocert_pfn_NtQueryInformationFile_t
    ngx_autocert_pfn_NtQueryInformationFile = NULL;
static ngx_autocert_pfn_NtQueryDirectoryFile_t
    ngx_autocert_pfn_NtQueryDirectoryFile = NULL;

static ngx_inline ngx_int_t
ngx_autocert_win32_resolve_ntdll(void)
{
    HMODULE  ntdll;
    ngx_autocert_pfn_NtCreateFile_t            create_fn;
    ngx_autocert_pfn_NtSetInformationFile_t    set_fn;
    ngx_autocert_pfn_NtQueryInformationFile_t  query_fn;
    ngx_autocert_pfn_NtQueryDirectoryFile_t    querydir_fn;

    if (ngx_autocert_pfn_NtCreateFile != NULL) {
        return NGX_OK;
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return NGX_ERROR;
    }

    create_fn = (ngx_autocert_pfn_NtCreateFile_t)
        (void *) GetProcAddress(ntdll, "NtCreateFile");
    set_fn = (ngx_autocert_pfn_NtSetInformationFile_t)
        (void *) GetProcAddress(ntdll, "NtSetInformationFile");
    query_fn = (ngx_autocert_pfn_NtQueryInformationFile_t)
        (void *) GetProcAddress(ntdll, "NtQueryInformationFile");
    querydir_fn = (ngx_autocert_pfn_NtQueryDirectoryFile_t)
        (void *) GetProcAddress(ntdll, "NtQueryDirectoryFile");

    if (create_fn == NULL || set_fn == NULL || query_fn == NULL
        || querydir_fn == NULL)
    {
        return NGX_ERROR;
    }

    /* Publish the three non-gate pointers first, then the gate pointer last,
     * with a barrier between so no reader can observe the gate non-NULL
     * before the other three stores are visible. */
    ngx_autocert_pfn_NtSetInformationFile = set_fn;
    ngx_autocert_pfn_NtQueryInformationFile = query_fn;
    ngx_autocert_pfn_NtQueryDirectoryFile = querydir_fn;
    MemoryBarrier();
    ngx_autocert_pfn_NtCreateFile = create_fn;

    return NGX_OK;
}


/*
 * NTSTATUS -> Win32 error code (an ERROR_* value, the same domain ngx_errno
 * reads on win32 since ngx_errno == GetLastError()). Kept in the ERROR_*
 * domain rather than mapping straight to NGX_E*-or-CRT errno names: callers
 * compare ngx_errno against NGX_ENOENT and similar, and NGX_ENOENT is itself
 * defined as ERROR_FILE_NOT_FOUND (src/os/win32/ngx_errno.h) so mapping to
 * that same domain lets SetLastError(this return value) make ngx_errno
 * compare equal to the right NGX_E* macro without a second translation step.
 * Only the statuses NtCreateFile/NtSetInformationFile can plausibly return
 * for these operations are mapped; anything else falls back to
 * ERROR_GEN_FAILURE, matching the callers that treat an unrecognised error as
 * "do not treat this as absent".
 *
 * ENOTEMPTY and ELOOP have no NGX_E* macro of their own (nginx defines
 * NGX_ELOOP as the literal 0 on win32, which is unusable as a sentinel).
 * Grepping this repo found no live call site that branches on either name,
 * so they fall back to a distinct, still-meaningful ERROR_* code for a future
 * caller or for logging, rather than colliding with 0 or an unrelated NGX_E*.
 */
static ngx_inline DWORD
ngx_autocert_win32_errno_from_ntstatus(NTSTATUS status)
{
    switch (status) {
    case STATUS_OBJECT_NAME_NOT_FOUND:
    case STATUS_OBJECT_PATH_NOT_FOUND:
        return ERROR_FILE_NOT_FOUND;           /* -> NGX_ENOENT */
    case STATUS_OBJECT_NAME_COLLISION:
        return ERROR_ALREADY_EXISTS;           /* -> NGX_EEXIST */
    case STATUS_ACCESS_DENIED:
        return ERROR_ACCESS_DENIED;            /* -> NGX_EACCES */
    case STATUS_SHARING_VIOLATION:
        return ERROR_SHARING_VIOLATION;        /* -> NGX_EAGAIN */
    case STATUS_DIRECTORY_NOT_EMPTY:
        return ERROR_DIR_NOT_EMPTY;            /* -> ENOTEMPTY (see above) */
    case STATUS_NOT_A_DIRECTORY:
        return ERROR_DIRECTORY;                /* -> NGX_ENOTDIR */
    case STATUS_FILE_IS_A_DIRECTORY:
        return ERROR_CANNOT_MAKE;              /* -> NGX_EISDIR */
    case STATUS_TOO_MANY_LINKS:
    case STATUS_REPARSE_POINT_ENCOUNTERED:
        return ERROR_TOO_MANY_LINKS;           /* -> ELOOP (see above) */
    default:
        return ERROR_GEN_FAILURE;
    }
}

/*
 * GetLastError() -> the errno-family value this seam's callers who compare
 * against plain <errno.h> names (not ngx_errno/NGX_E*) would want — kept for
 * exactly that group and for logging. Per DESIGN-win32-store-io.md's mapping
 * table.
 *
 * Deliberately not _doserrno/_get_errno: the CRT's mapping is narrower and
 * collapses distinctions callers depend on, notably ERROR_SHARING_VIOLATION,
 * which must surface as EAGAIN so the lock path retries rather than failing
 * hard.
 */
static ngx_inline int
ngx_autocert_win32_errno(DWORD err)
{
    switch (err) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        return ENOENT;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
        return EEXIST;
    case ERROR_ACCESS_DENIED:
        return EACCES;
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:
        return EAGAIN;
    case ERROR_DIR_NOT_EMPTY:
        return ENOTEMPTY;
    case ERROR_TOO_MANY_LINKS:
        return ELOOP;
    default:
        return EIO;
    }
}


/*
 * Build an OBJECT_ATTRIBUTES + UNICODE_STRING pair for a relative NtCreateFile
 * call: RootDirectory = the pinned dir handle, ObjectName = the single path
 * component being opened underneath it (never a multi-component path — every
 * caller here already walked to the parent via ngx_autocert_open_dir_path()
 * on the POSIX side, or is about to on this one).
 *
 * `wname` must outlive the NtCreateFile call — callers pass a caller-owned
 * stack buffer, not something this function allocates, so there is no cleanup
 * path to get wrong.
 */
static ngx_inline ngx_int_t
ngx_autocert_win32_oa(NGX_AUTOCERT_OBJECT_ATTRIBUTES *oa,
    NGX_AUTOCERT_UNICODE_STRING *us, HANDLE root, const char *name,
    wchar_t *wname, int wname_cap)
{
    int  n;

    n = MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, wname_cap);
    if (n <= 0) {
        SetLastError(ERROR_BAD_PATHNAME);
        errno = ngx_autocert_win32_errno(ERROR_BAD_PATHNAME);
        return NGX_ERROR;
    }

    us->Length = (USHORT) ((n - 1) * sizeof(wchar_t));
    us->MaximumLength = (USHORT) (wname_cap * sizeof(wchar_t));
    us->Buffer = wname;

    oa->Length = sizeof(*oa);
    oa->RootDirectory = root;
    oa->ObjectName = us;
    oa->Attributes = NGX_AUTOCERT_OBJ_CASE_INSENSITIVE;
    oa->SecurityDescriptor = NULL;
    oa->SecurityQualityOfService = NULL;

    return NGX_OK;
}


/*
 * Shared open path for both the directory-open and the leaf-open shims below.
 * `dfd` may be NGX_AUTOCERT_INVALID_DIRFD to mean "root" (absolute/rooted
 * open, mirroring the POSIX helpers' "/" and "." bootstrap opens); every other
 * caller in this header already has a real pinned dfd by the time it opens
 * anything relative.
 *
 * Returns a CRT int fd (via _open_osfhandle) on success, -1 with
 * GetLastError() set on failure. `create_disposition` /
 * `create_options_extra` let the two public wrappers below (dir-open,
 * leaf-open incl. O_CREAT) share this without duplicating the NT call.
 */
static ngx_inline int
ngx_autocert_win32_ntopen_sd(int dfd, const char *name, ULONG desired_access,
    ULONG create_disposition, ULONG create_options_extra, int crt_flags,
    PSECURITY_DESCRIPTOR sd)
{
    NGX_AUTOCERT_OBJECT_ATTRIBUTES  oa;
    NGX_AUTOCERT_UNICODE_STRING     us;
    NGX_AUTOCERT_IO_STATUS_BLOCK    iosb;
    wchar_t                         wname[NGX_MAX_PATH];
    HANDLE                          root, h;
    NTSTATUS                        status;
    int                             fd;

    if (ngx_autocert_win32_resolve_ntdll() != NGX_OK) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        errno = ngx_autocert_win32_errno(ERROR_PROC_NOT_FOUND);
        return -1;
    }

    root = (dfd == NGX_AUTOCERT_INVALID_DIRFD)
           ? NULL : ngx_autocert_fd_handle(dfd);

    if (ngx_autocert_win32_oa(&oa, &us, root, name, wname,
                              (int) (sizeof(wname) / sizeof(wname[0])))
        != NGX_OK)
    {
        return -1;
    }

    /* A caller-supplied security descriptor is applied by the kernel AT
     * creation, so a new directory never exists for a moment with the
     * parent's inherited DACL (ngx_autocert_mkdirat below). NULL keeps the
     * default: inherit from the parent. */
    oa.SecurityDescriptor = sd;

    ngx_memzero(&iosb, sizeof(iosb));

    status = ngx_autocert_pfn_NtCreateFile(&h, desired_access, &oa, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL, NGX_AUTOCERT_SHARE_ALL,
        create_disposition,
        NGX_AUTOCERT_FILE_SYNCHRONOUS_IO_NONALERT | create_options_extra,
        NULL, 0);

    if (!NT_SUCCESS(status)) {
        DWORD  mapped = ngx_autocert_win32_errno_from_ntstatus(status);
        SetLastError(mapped);
        errno = ngx_autocert_win32_errno(mapped);
        return -1;
    }

    fd = _open_osfhandle((intptr_t) h, crt_flags);
    if (fd == -1) {
        CloseHandle(h);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        errno = ngx_autocert_win32_errno(ERROR_NOT_ENOUGH_MEMORY);
        return -1;
    }

    return fd;
}


static ngx_inline int
ngx_autocert_win32_ntopen(int dfd, const char *name, ULONG desired_access,
    ULONG create_disposition, ULONG create_options_extra, int crt_flags)
{
    return ngx_autocert_win32_ntopen_sd(dfd, name, desired_access,
                                        create_disposition,
                                        create_options_extra, crt_flags,
                                        NULL);
}


/*
 * Reparse-point policy enforcement: called after a FILE_OPEN_REPARSE_POINT
 * open succeeds, when the caller asked for no-follow semantics. Queries the
 * reparse tag off the just-opened handle; if it is a symlink or mount point
 * (ngx_autocert_reparse_is_link), the open is unwound and ELOOP is reported,
 * matching O_NOFOLLOW. Any other tag (dedup, cloud placeholder, ...) is left
 * alone so ordinary dedup-enabled volumes keep working (DESIGN § gap 3).
 */
static ngx_inline int
ngx_autocert_win32_check_reparse(HANDLE h)
{
    NGX_AUTOCERT_FILE_ATTRIBUTE_TAG_INFO  info;

    if (!GetFileInformationByHandleEx(h, NGX_AUTOCERT_FileAttributeTagInfo,
                                       &info, sizeof(info)))
    {
        /* The handle was opened with FILE_OPEN_REPARSE_POINT, so it may BE
         * the reparse point/link itself; an undeterminable tag is not proof
         * the object is not a link. Callers (e.g. the account private-key
         * open in ngx_autocert_account.c) rely on O_NOFOLLOW actually
         * refusing a planted link, so fail closed the same way the
         * confirmed-link branch below does rather than letting an
         * unreadable tag silently pass the open through. */
        SetLastError(ERROR_TOO_MANY_LINKS);
        errno = ngx_autocert_win32_errno(ERROR_TOO_MANY_LINKS);
        return NGX_ERROR;
    }

    if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        && ngx_autocert_reparse_is_link(info.ReparseTag))
    {
        SetLastError(ERROR_TOO_MANY_LINKS);
        errno = ngx_autocert_win32_errno(ERROR_TOO_MANY_LINKS);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * ngx_autocert_openat — directory-relative open, no O_CREAT. Interprets the
 * O_* bits from ngx_autocert_win32.h itself (never forwarded to the CRT or to
 * NtCreateFile as a raw flag word, per that header's comment).
 */
static ngx_inline int
ngx_autocert_openat(int dfd, const char *name, int flags)
{
    ULONG    desired_access, options;
    int      fd, crt_flags;
    HANDLE   h;

    desired_access = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    options = 0;
    crt_flags = 0;

    if (flags & O_DIRECTORY) {
        /* READ_CONTROL is required for GetSecurityInfo() to read the DACL.
         * The file arm below gets it implicitly via GENERIC_READ; a directory
         * handle does not, and ngx_autocert_fstat() now walks the DACL for
         * directories too (the store-directory permission guard depends on
         * it). Without this the walk fails with ERROR_ACCESS_DENIED and the
         * fail-closed contract turns every store directory into a refusal. */
        desired_access |= FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL;
        options |= NGX_AUTOCERT_FILE_DIRECTORY_FILE
                 | NGX_AUTOCERT_FILE_OPEN_FOR_BACKUP_INTENT;
    } else {
        desired_access |= GENERIC_READ | (flags & O_WRONLY ? GENERIC_WRITE : 0)
                | (flags & O_RDWR ? GENERIC_WRITE : 0);
        options |= NGX_AUTOCERT_FILE_NON_DIRECTORY_FILE;
        crt_flags |= (flags & (O_WRONLY | O_RDWR)) ? _O_RDWR : _O_RDONLY;
    }

    if (flags & O_NOFOLLOW) {
        options |= NGX_AUTOCERT_FILE_OPEN_REPARSE_POINT;
    }

    fd = ngx_autocert_win32_ntopen(dfd, name, desired_access,
                                    NGX_AUTOCERT_FILE_OPEN, options,
                                    crt_flags);
    if (fd == -1) {
        return -1;
    }

    if (flags & O_NOFOLLOW) {
        h = ngx_autocert_fd_handle(fd);
        if (ngx_autocert_win32_check_reparse(h) != NGX_OK) {
            DWORD  err = GetLastError();
            _close(fd);
            SetLastError(err);
            errno = ngx_autocert_win32_errno(err);
            return -1;
        }
    }

    return fd;
}


/*
 * O_CREAT variant used for leaf opens (ngx_autocert_open_file_path()'s
 * openat(dfd, leaf, flags|O_NOFOLLOW|O_CLOEXEC) call, and any other
 * create-capable call site). O_EXCL maps to FILE_CREATE (atomic
 * create-or-fail, matching the POSIX O_CREAT|O_EXCL contract); otherwise
 * FILE_OPEN_IF (create-or-open, matching plain O_CREAT).
 */
static ngx_inline int
ngx_autocert_openat_mode(int dfd, const char *name, int flags,
    ngx_autocert_mode_t mode)
{
    ULONG    desired_access, options, disposition;
    int      fd, crt_flags;
    HANDLE   h;

    /*
     * `mode` is not applied at creation time: NtCreateFile takes a security
     * descriptor, not a POSIX bitmask, and the file is created with the
     * parent's inherited DACL. ngx_autocert_fchmod() is what translates the
     * bitmask into an owner-only DACL, and every caller here that passes a
     * mode calls it immediately after (the POSIX side does the same, because
     * O_CREAT honours umask and so cannot be trusted either).
     *
     * WRITE_DAC is therefore requested on any writable open: SetSecurityInfo()
     * inside ngx_autocert_fchmod() needs it on THIS handle, and without it
     * that call fails ERROR_ACCESS_DENIED at runtime with no compile-time
     * symptom — the key would be left with the parent's inherited DACL while
     * the write path unlinks the file and reports failure. GENERIC_READ
     * already implies READ_CONTROL, which is all GetSecurityInfo() needs, so
     * only the write side has to be widened. Read-only opens do not ask for
     * WRITE_DAC: they never chmod, and requesting DAC-write privilege they
     * cannot use would fail on a key the worker is only allowed to read.
     */
    desired_access = FILE_READ_ATTRIBUTES | SYNCHRONIZE | GENERIC_READ
           | (flags & (O_WRONLY | O_RDWR) ? GENERIC_WRITE | WRITE_DAC : 0);
    options = NGX_AUTOCERT_FILE_NON_DIRECTORY_FILE;
    crt_flags = (flags & (O_WRONLY | O_RDWR)) ? _O_RDWR : _O_RDONLY;

    if (flags & O_NOFOLLOW) {
        options |= NGX_AUTOCERT_FILE_OPEN_REPARSE_POINT;
    }

    disposition = (flags & O_EXCL)
                  ? NGX_AUTOCERT_FILE_CREATE
                  : NGX_AUTOCERT_FILE_OPEN_IF;

    fd = ngx_autocert_win32_ntopen( dfd, name, desired_access, disposition,
                                    options, crt_flags );
    if (fd == -1) {
        return -1;
    }

    if (flags & O_NOFOLLOW) {
        h = ngx_autocert_fd_handle(fd);
        if (ngx_autocert_win32_check_reparse(h) != NGX_OK) {
            DWORD  err = GetLastError();
            _close(fd);
            SetLastError(err);
            errno = ngx_autocert_win32_errno(err);
            return -1;
        }
    }

    return fd;
}


/*
 * mkdirat -> NtCreateFile(FILE_CREATE|FILE_DIRECTORY_FILE). Atomic
 * create-or-EEXIST, matching mkdirat()'s contract (callers here test
 * ngx_errno == NGX_EEXIST on failure, never fall through on a pre-existing
 * dir). No handle is kept open — the directory is created, not opened for
 * later use, so it is closed immediately.
 */
static ngx_inline int
ngx_autocert_mkdirat(int dfd, const char *name, ngx_autocert_mode_t mode)
{
    SECURITY_DESCRIPTOR   sd;
    PSECURITY_DESCRIPTOR  psd;
    PACL                  dacl;
    BYTE                  owner_buf[SECURITY_MAX_SID_SIZE];
    DWORD                 err;
    int                   fd;

    psd = NULL;
    dacl = NULL;

    /* A 0700 mkdir on POSIX yields a directory nobody else can enter or
     * write. NtCreateFile instead INHERITS the parent's DACL, and every stock
     * volume root grants Authenticated Users Modify, so without this the
     * store directory this module creates for itself would be refused by
     * its own ngx_autocert_check_owner_mode() guard a moment later — and,
     * worse, genuinely be plantable by any local user. Hand the kernel an
     * owner-only, SE_DACL_PROTECTED descriptor AT creation: the directory
     * then never exists, even for an instant, with the inherited DACL that a
     * concurrent foreign open could have used to obtain a handle it keeps
     * after a later re-permissioning. The owner is the token's default
     * owner, which is what the kernel will stamp on the new object; the
     * token user is granted alongside it (they differ for an elevated
     * administrator). Inheritable, so what the module creates inside starts
     * owner-only as well. Modes that grant group/other bits (the 0755
     * `live` dir) keep the inherited DACL, which inside a 0700 store is
     * already the owner-only one. */
    if ((mode & (S_IRWXG | S_IRWXO)) == 0) {
        err = ngx_autocert_win32_token_sid(TokenOwner, owner_buf,
                                           sizeof(owner_buf));
        if (err != ERROR_SUCCESS) {
            SetLastError(err);
            errno = ngx_autocert_win32_errno(err);
            return -1;
        }

        err = ngx_autocert_win32_build_owner_dacl((PSID) owner_buf,
                  FILE_ALL_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                  &dacl);
        if (err != ERROR_SUCCESS) {
            SetLastError(err);
            errno = ngx_autocert_win32_errno(err);
            return -1;
        }

        /* SE_DACL_PROTECTED is what stops the kernel from ADDING the
         * parent's inheritable ACEs to the explicit DACL during creation;
         * without it the descriptor is merged, not applied, and the
         * Authenticated Users grant is right back. */
        if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)
            || !SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE)
            || !SetSecurityDescriptorControl(&sd, SE_DACL_PROTECTED,
                                             SE_DACL_PROTECTED))
        {
            err = GetLastError();
            LocalFree(dacl);
            SetLastError(err);
            errno = ngx_autocert_win32_errno(err);
            return -1;
        }

        psd = &sd;
    }

    fd = ngx_autocert_win32_ntopen_sd(dfd, name,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
        NGX_AUTOCERT_FILE_CREATE,
        NGX_AUTOCERT_FILE_DIRECTORY_FILE
        | NGX_AUTOCERT_FILE_OPEN_FOR_BACKUP_INTENT,
        _O_RDONLY, psd);

    err = GetLastError();
    if (dacl != NULL) {
        LocalFree(dacl);
    }

    if (fd == -1) {
        SetLastError(err);
        return -1;
    }

    _close(fd);
    return 0;
}


/*
 * unlinkat -> open the target (no-follow, matching POSIX unlink's refusal to
 * traverse a symlink as the thing being removed... actually POSIX unlink()
 * removes the symlink itself, never follows; FILE_OPEN_REPARSE_POINT mirrors
 * that) then FILE_DISPOSITION_INFORMATION. AT_REMOVEDIR selects the directory
 * open options so a non-empty directory reports ENOTEMPTY instead of a
 * generic failure. FILE_SHARE_DELETE (always on, via NGX_AUTOCERT_SHARE_ALL)
 * is what makes this work against a file another handle still has open —
 * the settled decision 4 unlink-while-open case.
 */
static ngx_inline int
ngx_autocert_unlinkat(int dfd, const char *name, int flags)
{
    NGX_AUTOCERT_IO_STATUS_BLOCK  iosb;
    HANDLE                        h;
    NTSTATUS                      status;
    int                           fd;
    ULONG                         desired_access, options;
    struct {
        BOOLEAN  DeleteFile;
    } disp;

    desired_access = DELETE | SYNCHRONIZE;
    options = NGX_AUTOCERT_FILE_OPEN_REPARSE_POINT;

    if (flags & AT_REMOVEDIR) {
        options |= NGX_AUTOCERT_FILE_DIRECTORY_FILE
                 | NGX_AUTOCERT_FILE_OPEN_FOR_BACKUP_INTENT;
    } else {
        options |= NGX_AUTOCERT_FILE_NON_DIRECTORY_FILE;
    }

    fd = ngx_autocert_win32_ntopen(
        dfd, name, desired_access, NGX_AUTOCERT_FILE_OPEN, options, _O_RDONLY );
    if (fd == -1) {
        return -1;
    }

    h = ngx_autocert_fd_handle(fd);
    disp.DeleteFile = TRUE;
    ngx_memzero(&iosb, sizeof(iosb));

    status = ngx_autocert_pfn_NtSetInformationFile(h, &iosb, &disp,
        sizeof(disp), 13 /* FileDispositionInformation */);

    if (!NT_SUCCESS(status)) {
        DWORD  mapped = ngx_autocert_win32_errno_from_ntstatus(status);
        _close(fd);
        SetLastError(mapped);
        errno = ngx_autocert_win32_errno(mapped);
        return -1;
    }

    _close(fd);
    return 0;
}


/*
 * W11 — ngx_autocert_win32_mode_from_dacl(HANDLE) — real DACL -> POSIX
 * group/other permission bits.
 *
 * ngx_autocert_fstat/fstatat below used to fabricate st_mode as a constant
 * S_IFREG|0600 regardless of the file's actual ACL, which made account.c's
 * "reject a key with group/other bits" guard (ngx_autocert_account.c:276-283)
 * a tautology on win32 — a world-readable account key always passed. This
 * reads the real DACL and reduces it to the (is_owner, is_allow, is_tolerated)
 * tuples ngx_autocert_win32_dacl_mode() (ngx_autocert_shared.h, unit-tested
 * on Linux) decides from.
 *
 * Bounded to NGX_AUTOCERT_DACL_WALK_MAX ACEs on the stack — a private key's
 * DACL is never attacker-sized (this module writes it itself via
 * ngx_autocert_fchmod() above, one ACE), and a fixed bound keeps this
 * allocation-free and keeps the fail-closed contract below simple: an ACE
 * count that would overflow the bound is treated the same as any other
 * enumeration failure, not silently truncated into a false "safe" reading.
 *
 * FAIL-CLOSED CONTRACT: every error return sets *mode_bits to
 * (S_IRWXG | S_IRWXO) — the guard must reject rather than silently pass when
 * this cannot determine the truth. This is the opposite default of a normal
 * "return -1 on error" API and is deliberate; callers must not reinterpret a
 * -1 return here as "leave st_mode alone".
 *
 * Each ALLOW ACE's access Mask is classified too (is_write): a read-only
 * grant to a foreign SID — the Users/Authenticated Users read ACE every
 * directory under a stock Windows tree inherits — maps to the READ bits
 * only, so a secret still refuses it and the store directory accepts it.
 * Without the mask the walk could not tell a read grant from full control
 * and refused every ordinary store.
 */
#define NGX_AUTOCERT_DACL_WALK_MAX  32

static ngx_inline int
ngx_autocert_win32_mode_from_dacl(HANDLE h, ngx_autocert_mode_t *mode_bits)
{
    PSID                   owner, system_sid, admins_sid;
    PACL                   dacl;
    PSECURITY_DESCRIPTOR   sd;
    ACL_SIZE_INFORMATION   size_info;
    ngx_int_t              is_owner[NGX_AUTOCERT_DACL_WALK_MAX];
    ngx_int_t              is_allow[NGX_AUTOCERT_DACL_WALK_MAX];
    ngx_int_t              is_tolerated[NGX_AUTOCERT_DACL_WALK_MAX];
    ngx_int_t              is_write[NGX_AUTOCERT_DACL_WALK_MAX];
    BYTE                   system_buf[SECURITY_MAX_SID_SIZE];
    BYTE                   admins_buf[SECURITY_MAX_SID_SIZE];
    BYTE                   user_buf[SECURITY_MAX_SID_SIZE];
    BYTE                   creator_buf[SECURITY_MAX_SID_SIZE];
    PSID                   user_sid, creator_sid;
    DWORD                  creator_len;
    DWORD                  system_len, admins_len, i, err;
    ngx_uint_t             n;

    /* Fail closed on the earliest possible error: every path below that
     * returns before the walk completes must have already set the flagged
     * bits, so a `goto fail`-free straight-line set of early returns below
     * is safe by construction rather than by remembering to set it at each
     * site — set it once, up front, and only clear it on the one path that
     * proves the DACL is owner-only. */
    *mode_bits = (ngx_autocert_mode_t) (S_IRWXG | S_IRWXO);

    owner = NULL;
    dacl = NULL;
    sd = NULL;

    /* Zeroed up front: an empty-but-non-NULL DACL (AceCount == 0, distinct
     * from the NULL-DACL early return below) leaves the walk loop not
     * executing at all, so n stays 0 and these are passed to
     * ngx_autocert_win32_dacl_mode() unwritten on that path. n == 0 makes
     * that function return its flagged value without reading them either
     * way, but passing uninitialized arrays into a call, even one that
     * provably does not read them here, is exactly what a later edit to
     * either function could turn into a real bug silently — zero them so
     * there is nothing to get wrong. */
    ngx_memzero(is_owner, sizeof(is_owner));
    ngx_memzero(is_allow, sizeof(is_allow));
    ngx_memzero(is_tolerated, sizeof(is_tolerated));
    ngx_memzero(is_write, sizeof(is_write));

    err = GetSecurityInfo(h, SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &owner, NULL, &dacl, NULL, &sd);
    if (err != ERROR_SUCCESS) {
        SetLastError(err);
        errno = ngx_autocert_win32_errno(err);
        return -1;
    }

    if (dacl == NULL) {
        /* NULL DACL means "everyone has full access" (no DACL at all, not
         * an empty one) — the most exposed state a Windows object can be
         * in. Fail closed; *mode_bits is already set above. */
        LocalFree(sd);
        return 0;
    }

    system_len = sizeof(system_buf);
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, system_buf, &system_len)) {
        err = GetLastError();
        LocalFree(sd);
        SetLastError(err);
        errno = ngx_autocert_win32_errno(err);
        return -1;
    }
    system_sid = (PSID) system_buf;

    admins_len = sizeof(admins_buf);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admins_buf,
                             &admins_len))
    {
        err = GetLastError();
        LocalFree(sd);
        SetLastError(err);
        errno = ngx_autocert_win32_errno(err);
        return -1;
    }
    admins_sid = (PSID) admins_buf;

    /* The process token user is "us" exactly as the owner is: an
     * administrator's objects are owned by BUILTIN\Administrators, so the
     * ACE that names the account nginx actually runs as is not the owner's
     * ACE and would otherwise count as a foreign write grant on the store
     * the module created for itself. Fail closed if the token cannot be
     * read, like every other error on this path. */
    err = ngx_autocert_win32_token_sid(TokenUser, user_buf, sizeof(user_buf));
    if (err != ERROR_SUCCESS) {
        LocalFree(sd);
        SetLastError(err);
        errno = ngx_autocert_win32_errno(err);
        return -1;
    }
    user_sid = (PSID) user_buf;

    /* CREATOR OWNER (S-1-3-0) is a placeholder, not a principal: an
     * inherit-only ACE naming it means "whoever creates a child owns that
     * child's copy". It grants nothing on this object and, on a child, only
     * to the child's creator — who needed write on this directory already.
     * Every stock directory carries one; tolerate it by SID rather than
     * skipping inherit-only ACEs wholesale, because an inherit-only ACE for
     * a REAL foreign principal does become effective on the children the
     * module creates without re-permissioning them (the 0755 `live` dir),
     * and must keep flagging the store. */
    creator_len = sizeof(creator_buf);
    if (!CreateWellKnownSid(WinCreatorOwnerSid, NULL, creator_buf,
                             &creator_len))
    {
        err = GetLastError();
        LocalFree(sd);
        SetLastError(err);
        errno = ngx_autocert_win32_errno(err);
        return -1;
    }
    creator_sid = (PSID) creator_buf;

    ngx_memzero(&size_info, sizeof(size_info));
    if (!GetAclInformation(dacl, &size_info, sizeof(size_info),
                            AclSizeInformation))
    {
        err = GetLastError();
        LocalFree(sd);
        SetLastError(err);
        errno = ngx_autocert_win32_errno(err);
        return -1;
    }

    if (size_info.AceCount > NGX_AUTOCERT_DACL_WALK_MAX) {
        /* Bound exceeded — fail closed rather than read a truncated view of
         * the DACL and risk missing an exposing ACE past the cutoff. */
        LocalFree(sd);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        errno = ngx_autocert_win32_errno(ERROR_INSUFFICIENT_BUFFER);
        return -1;
    }

    n = 0;

    for (i = 0; i < size_info.AceCount; i++) {
        ACE_HEADER  *hdr;
        PSID         ace_sid;
        ACCESS_MASK  mask;
        int          allow;

        if (!GetAce(dacl, i, (LPVOID *) &hdr)) {
            err = GetLastError();
            LocalFree(sd);
            SetLastError(err);
            errno = ngx_autocert_win32_errno(err);
            return -1;
        }

        /* Only the two ACE types this DACL can actually contain matter:
         * ALLOW grants access (the exposure this guard looks for), DENY
         * grants nothing so it is never evidence of exposure. Anything else
         * (object-specific / callback ACE types) is conservatively treated
         * as neither owner nor tolerated AND as write-granting, so a
         * non-owner one still flags with the full bits — fail closed rather
         * than assume a type this shim does not recognise is benign. */
        if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ace_sid = (PSID) &((ACCESS_ALLOWED_ACE *) hdr)->SidStart;
            mask = ((ACCESS_ALLOWED_ACE *) hdr)->Mask;
            allow = 1;
        } else if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) {
            ace_sid = (PSID) &((ACCESS_DENIED_ACE *) hdr)->SidStart;
            mask = ((ACCESS_DENIED_ACE *) hdr)->Mask;
            allow = 0;
        } else {
            is_owner[n] = 0;
            is_allow[n] = 1;
            is_tolerated[n] = 0;
            is_write[n] = 1;
            n++;
            continue;
        }

        is_allow[n] = allow;
        is_owner[n] = ((owner != NULL && EqualSid(ace_sid, owner))
                       || EqualSid(ace_sid, user_sid)) ? 1 : 0;
        is_tolerated[n] = (EqualSid(ace_sid, system_sid)
                            || EqualSid(ace_sid, admins_sid)
                            || EqualSid(ace_sid, creator_sid)) ? 1 : 0;
        is_write[n] = ngx_autocert_win32_mask_is_write((uint32_t) mask);
        n++;
    }

    LocalFree(sd);

    *mode_bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow,
                                               is_tolerated, is_write, n);
    return 0;
}


/*
 * fstatat -> open no-follow (mirroring AT_SYMLINK_NOFOLLOW when given; POSIX
 * fstatat() without that flag follows a symlink, so its absence opens without
 * FILE_OPEN_REPARSE_POINT here too) then GetFileInformationByHandleEx.
 * st_mode/st_nlink/st_size are the only fields any call site in this repo
 * reads (verified against S_ISDIR/S_ISREG/st_nlink/st_size uses in
 * driver.c/order.c). st_mode's directory bit and owner bits (0700/0600) are
 * still the documented DESIGN approximation; its group/other bits, as of
 * W11, are no longer a fixed constant — they come from
 * ngx_autocert_win32_mode_from_dacl() below, the real DACL on the file. See
 * that function's comment for the fail-closed contract and for why st_uid
 * (unlike st_mode) stays the placeholder ngx_autocert_geteuid() always
 * returned: the ownership half of account.c's guard is still not
 * meaningful on win32, only the permission half is now real.
 *
 * The target's file-vs-directory type is not known up front, so the first
 * open is directory-agnostic: plain ngx_autocert_openat() sets
 * NGX_AUTOCERT_FILE_NON_DIRECTORY_FILE, which makes NtCreateFile reject any
 * directory with STATUS_FILE_IS_A_DIRECTORY (mapped to ERROR_CANNOT_MAKE by
 * ngx_autocert_win32_errno_from_ntstatus) before the S_IFDIR branch below
 * ever gets a chance to run. Retrying with O_DIRECTORY added on exactly that
 * error — rather than changing ngx_autocert_win32_ntopen's signature to pass
 * neither FILE_DIRECTORY_FILE nor FILE_NON_DIRECTORY_FILE — keeps this
 * function's O_NOFOLLOW handling identical on both opens without touching the
 * shared open helper's contract for every other caller.
 */
static ngx_inline int ngx_autocert_fstatat( int dfd, const char *name,
                                            ngx_autocert_stat_t *st, int flags )
{
    BY_HANDLE_FILE_INFORMATION  info;
    HANDLE                      h;
    ngx_autocert_mode_t         dacl_bits;
    int                         fd, ntflags;
    ngx_uint_t                  is_dir;

    ntflags = O_RDONLY;
    if (flags & AT_SYMLINK_NOFOLLOW) {
        ntflags |= O_NOFOLLOW;
    }

    fd = ngx_autocert_openat(dfd, name, ntflags);
    if (fd == -1 && GetLastError() == ERROR_CANNOT_MAKE) {
        fd = ngx_autocert_openat(dfd, name, ntflags | O_DIRECTORY);
    }
    if (fd == -1) {
        return -1;
    }

    h = ngx_autocert_fd_handle(fd);

    if (!GetFileInformationByHandle(h, &info)) {
        DWORD  err = GetLastError();
        _close(fd);
        SetLastError(err);
        errno = ngx_autocert_win32_errno(err);
        return -1;
    }

    is_dir = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;

    {
        /* Walk the DACL for DIRECTORIES TOO, not just regular files.
         *
         * This used to be `if (!is_dir)`, on the reasoning that the only
         * consumer was the account-key guard, which rejects a directory via
         * S_ISREG before ever reading the mode. That is no longer true:
         * ngx_autocert_check_owner_mode() now stats the STORE DIRECTORY
         * (driver.c's trylock) to refuse one that group/other can write.
         * With the fixed S_IFDIR|0700 approximation those bits were never
         * set on win32, so that check passed unconditionally and a store
         * directory another local user could write was adopted silently —
         * exactly the case the guard exists to stop.
         *
         * The fail-closed contract carries over unchanged: on any error
         * mode_from_dacl() sets (S_IRWXG|S_IRWXO), which contains the write
         * bits, so an undeterminable DACL refuses rather than accepts. */
        if (ngx_autocert_win32_mode_from_dacl(h, &dacl_bits) == -1) {
            DWORD  err = GetLastError();
            _close(fd);
            SetLastError(err);
            errno = ngx_autocert_win32_errno(err);
            return -1;
        }
    }

    _close(fd);

    ngx_memzero(st, sizeof(*st));
    /* dacl_bits now comes from the real DACL for BOTH kinds, so a
     * group/other-writable directory is visible to the store-directory
     * guard instead of being masked by a hardcoded 0700. */
    st->st_mode = (ngx_autocert_mode_t)
                  ((is_dir ? (S_IFDIR | 0700) : (S_IFREG | 0600)) | dacl_bits);
    st->st_nlink = (short) (info.nNumberOfLinks > 0
                             ? info.nNumberOfLinks : 1);
    st->st_size = ngx_file_size(&info);
    st->st_mtime = ngx_file_mtime(&info);
    st->st_uid = ngx_autocert_geteuid();
    st->st_ino = ngx_file_uniq(&info);

    return 0;
}


/*
 * fstat(2) on an already-open shim fd. Distinct from ngx_autocert_fstatat
 * above for the same reason the POSIX side keeps them distinct: this stats
 * the fd itself, no name/dfd/no-follow involved (the file is already open,
 * so there is nothing left to resolve). Same W11 DACL-derived group/other
 * bits as ngx_autocert_fstatat above; see that function's comment.
 */
static ngx_inline int
ngx_autocert_fstat(int fd, ngx_autocert_stat_t *st)
{
    BY_HANDLE_FILE_INFORMATION  info;
    HANDLE                      h;
    ngx_autocert_mode_t         dacl_bits;
    ngx_uint_t                  is_dir;

    h = ngx_autocert_fd_handle(fd);
    if (h == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        errno = ngx_autocert_win32_errno(ERROR_INVALID_HANDLE);
        return -1;
    }

    if (!GetFileInformationByHandle(h, &info)) {
        errno = ngx_autocert_win32_errno(GetLastError());
        return -1;
    }

    is_dir = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;

    /* Directories walk the DACL too — see the matching comment in
     * ngx_autocert_fstat() above for why the old `if (!is_dir)` made the
     * store-directory guard vacuous on win32. */
    if (ngx_autocert_win32_mode_from_dacl(h, &dacl_bits) == -1) {
        errno = ngx_autocert_win32_errno(GetLastError());
        return -1;
    }

    ngx_memzero(st, sizeof(*st));
    /* dacl_bits now comes from the real DACL for BOTH kinds, so a
     * group/other-writable directory is visible to the store-directory
     * guard instead of being masked by a hardcoded 0700. */
    st->st_mode = (ngx_autocert_mode_t)
                  ((is_dir ? (S_IFDIR | 0700) : (S_IFREG | 0600)) | dacl_bits);
    st->st_nlink = (short) (info.nNumberOfLinks > 0
                             ? info.nNumberOfLinks : 1);
    st->st_size = ngx_file_size(&info);
    st->st_mtime = ngx_file_mtime(&info);
    st->st_uid = ngx_autocert_geteuid();
    st->st_ino = ngx_file_uniq(&info);

    return 0;
}


/*
 * ngx_autocert_dirent_t (W12) — the only member any call site reads is
 * d_name (grepped for every `->d_name`/`.d_name` in src/: the A6 store scan
 * in driver.c is the sole reader). Sized to NGX_MAX_PATH bytes of UTF-8,
 * always NUL-terminated by ngx_autocert_readdir() below — never a raw slice
 * of the NT UTF-16 buffer, which is neither NUL-terminated nor UTF-8.
 */
typedef struct {
    char  d_name[NGX_MAX_PATH];
} NGX_AUTOCERT_DIRENT;

typedef NGX_AUTOCERT_DIRENT  ngx_autocert_dirent_t;

/*
 * ngx_autocert_dir_t (W12) — a pinned directory handle plus the
 * NtQueryDirectoryFile batch-query state. `fd` is the same CRT int fd
 * ngx_autocert_fdopendir() was handed (not dup'd — ownership matches POSIX
 * fdopendir/closedir exactly, see the shared.h contract comment). `buf` holds
 * one FILE_DIRECTORY_INFORMATION batch; `pos` is the next unread entry inside
 * it (NULL when the batch is exhausted and a re-query is due); `eof` latches
 * once STATUS_NO_MORE_FILES has been seen so a caller that keeps calling
 * ngx_autocert_readdir() past the end keeps getting NULL without re-querying
 * the now-exhausted handle. `dirent` is the entry returned to the caller,
 * overwritten on each call — same single-buffer-reuse contract glibc's
 * readdir() has, so callers must not hold a `de` pointer across the next
 * ngx_autocert_readdir() call (the existing driver.c loop does not).
 *
 * Heap-allocated (ngx_autocert_fdopendir mallocs it) rather than a fixed-size
 * value type: the public shim signature mirrors POSIX's `DIR *`, an opaque
 * pointer the caller only ever holds, never copies or embeds by value.
 */
#define NGX_AUTOCERT_DIR_QUERY_BUF_SIZE  8192

typedef struct {
    int             fd;
    ngx_uint_t      eof;
    unsigned char  *pos;
    unsigned char  *end;
    /*
     * buf.bytes is the actual query output; buf.align_force is never read
     * or written — its only purpose is to force this member to 8-byte
     * alignment. FILE_DIRECTORY_INFORMATION contains LARGE_INTEGER members,
     * and NtQueryDirectoryFile needs an aligned output buffer (an unaligned
     * one can fail with STATUS_DATATYPE_MISALIGNMENT on some filesystem
     * drivers/architectures). A bare `unsigned char[]` has alignment 1; it
     * would only land on an 8-byte boundary here by accident, because the
     * pointer-sized members above it happen to sum to a multiple of 8 — a
     * later field reorder could silently break that. The union makes the
     * requirement explicit instead of incidental.
     */
    union {
        unsigned char  bytes[NGX_AUTOCERT_DIR_QUERY_BUF_SIZE];
        LARGE_INTEGER  align_force;
    } buf;
    ngx_autocert_dirent_t  dirent;
} NGX_AUTOCERT_DIR;

typedef NGX_AUTOCERT_DIR  ngx_autocert_dir_t;


/*
 * fdopendir(3) -> malloc the enumeration state, remember the fd. No NT call
 * happens here — the first ngx_autocert_readdir() call issues the first
 * NtQueryDirectoryFile, matching POSIX fdopendir()'s lazy-first-read
 * behaviour closely enough for this shim's one caller.
 *
 * On malloc failure, ownership of `fd` does NOT transfer (mirrors POSIX
 * fdopendir() failing without touching the fd): the caller still owns and
 * must close it. This function must never close `fd` itself on any path.
 */
static ngx_inline ngx_autocert_dir_t *
ngx_autocert_fdopendir(int fd)
{
    ngx_autocert_dir_t  *dh;

    dh = malloc(sizeof(ngx_autocert_dir_t)); /* NOLINT-nginx */
    if (dh == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        errno = ngx_autocert_win32_errno(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    dh->fd = fd;
    dh->eof = 0;
    dh->pos = NULL;
    dh->end = NULL;

    return dh;
}


/*
 * readdir(3) -> NtQueryDirectoryFile on the pinned handle (never
 * FindFirstFileW/FindNextFileW — see the file banner). Batches entries into
 * dh->buf (FILE_DIRECTORY_INFORMATION records chained by NextEntryOffset) and
 * re-queries only once the batch is drained, never ReturnSingleEntry — a
 * syscall per file would make a large store container's warm-start scan
 * (A6) pay one round trip per entry.
 *
 * "." and ".." are returned exactly as NtQueryDirectoryFile yields them
 * (unlike FindFirstFileW, it does not filter them out itself) — matching
 * POSIX readdir(), which also returns them. The existing driver.c call site
 * already skips any d_name[0] == '.' itself; filtering here instead would be
 * a silent behaviour difference between the two platform bodies of this
 * shim.
 *
 * An entry whose name cannot be converted to UTF-8, or does not fit in
 * NGX_MAX_PATH bytes including the NUL, is skipped — advance to the next
 * entry, never return a truncated name and never abort the scan. This is a
 * deliberate security-relevant choice, not an oversight: a name this shim
 * cannot represent cannot match any name the store creates (every name this
 * module writes to disk is a DNS label or a fixed literal it chose), so
 * skipping it costs nothing a real store scan needs and avoids feeding a
 * mangled or truncated name into the caller's marker-read/openat logic.
 * The same distrust applies to the record's own shape: the fixed header and
 * FileNameLength are bounds-checked against what NtQueryDirectoryFile
 * actually returned before anything reads through info->FileName, exactly
 * like the NextEntryOffset check below — a name isn't the only field a
 * malformed response can lie about.
 *
 * End-of-directory vs error: STATUS_NO_MORE_FILES is mapped to a clean NULL
 * return with the error channel left alone (matching POSIX readdir(), which
 * also returns NULL at end-of-directory without touching errno) — it is
 * deliberately not passed through ngx_autocert_win32_errno_from_ntstatus(),
 * which is reserved for genuine failures. Any other unsuccessful status maps
 * through that function and SetLastError(), the same as every other shim
 * body in this file.
 */
static ngx_inline ngx_autocert_dirent_t *
ngx_autocert_readdir(ngx_autocert_dir_t *dh)
{
    NGX_AUTOCERT_FILE_DIRECTORY_INFORMATION  *info;
    NGX_AUTOCERT_IO_STATUS_BLOCK              iosb;
    NTSTATUS                                  status;
    HANDLE                                    h;
    int                                       n;

    if (dh->eof) {
        return NULL;
    }

    for ( ;; ) {
        if (dh->pos == NULL) {
            if (ngx_autocert_win32_resolve_ntdll() != NGX_OK) {
                SetLastError(ERROR_PROC_NOT_FOUND);
                errno = ngx_autocert_win32_errno(ERROR_PROC_NOT_FOUND);
                dh->eof = 1;
                return NULL;
            }

            h = ngx_autocert_fd_handle(dh->fd);
            ngx_memzero(&iosb, sizeof(iosb));

            status = ngx_autocert_pfn_NtQueryDirectoryFile(h, NULL, NULL,
                NULL, &iosb, dh->buf.bytes, sizeof(dh->buf.bytes),
                NGX_AUTOCERT_FileDirectoryInformation, FALSE, NULL, FALSE);

            if (status == STATUS_NO_MORE_FILES) {
                dh->eof = 1;
                return NULL;                /* clean end: errno untouched */
            }

            if (!NT_SUCCESS(status)) {
                DWORD  mapped = ngx_autocert_win32_errno_from_ntstatus(status);
                SetLastError(mapped);
                errno = ngx_autocert_win32_errno(mapped);
                dh->eof = 1;
                return NULL;
            }

            /* iosb.Information is the check every other check in this
             * function depends on: dh->end is derived from it, and the
             * NextEntryOffset / FileNameLength bounds checks below all
             * compare against dh->end. If the kernel ever reported more
             * bytes than the buffer it was actually given, dh->end would
             * point past the real allocation and every check derived from
             * it would validate against the wrong boundary — silently
             * passing exactly the malformed input they exist to catch.
             * Clamp here, before dh->end is computed, not after. */
            if (iosb.Information > sizeof(dh->buf.bytes)) {
                SetLastError(ERROR_GEN_FAILURE);
                errno = ngx_autocert_win32_errno(ERROR_GEN_FAILURE);
                dh->eof = 1;
                return NULL;
            }

            dh->pos = dh->buf.bytes;
            dh->end = dh->buf.bytes + (size_t) iosb.Information;

            if (dh->pos >= dh->end) {
                /* Zero-byte success is not documented but not impossible;
                 * treat exactly like STATUS_NO_MORE_FILES rather than
                 * spinning. */
                dh->eof = 1;
                return NULL;
            }
        }

        info = (NGX_AUTOCERT_FILE_DIRECTORY_INFORMATION *) dh->pos;

        /* Distrust the record's shape before reading any field beyond the
         * pointer itself: the fixed header, up to and including
         * FileNameLength, must actually fit in what NtQueryDirectoryFile
         * returned. A batch too short for even one full header is treated
         * as end-of-batch, same rationale as the NextEntryOffset and
         * FileNameLength checks below. */
        if ((size_t) (dh->end - dh->pos)
            < offsetof(NGX_AUTOCERT_FILE_DIRECTORY_INFORMATION, FileName))
        {
            dh->pos = NULL;
            continue;
        }

        /* Advance the cursor for the NEXT call before any `continue` below,
         * so a skipped entry never gets re-read. NextEntryOffset == 0 marks
         * the last entry in THIS batch, not the last entry in the directory
         * — dh->pos == NULL makes the next call re-query.
         *
         * NextEntryOffset is NEVER trusted blindly: NTFS always terminates a
         * batch with NextEntryOffset == 0, so a nonzero offset that would
         * walk the cursor to or past dh->end can only come from a malformed
         * response (e.g. a third-party filesystem filter/redirector on the
         * store's volume) — treat that the same as end-of-batch rather than
         * dereferencing past dh->buf on the next call. The kernel's own scan
         * position inside the handle already advanced past whatever this
         * call returned regardless of how much of it we trust, so the next
         * re-query resumes cleanly; it does not re-read the entries we
         * declined to walk into. */
        dh->pos = (info->NextEntryOffset != 0
                   && dh->pos + info->NextEntryOffset < dh->end)
                  ? dh->pos + info->NextEntryOffset : NULL;

        /* FileNameLength is untrusted exactly like NextEntryOffset above: a
         * garbage value would otherwise make WideCharToMultiByte read past
         * dh->buf looking for wide chars that were never there. Compare via
         * subtraction against the bytes actually remaining after
         * info->FileName, not by adding FileNameLength to a pointer, so a
         * hostile length cannot overflow the comparison itself. `info` still
         * points at the current (unadvanced) record; dh->end is the current
         * batch's boundary and is untouched by the dh->pos advance above. */
        if (info->FileNameLength
            > (size_t) (dh->end - (unsigned char *) info->FileName))
        {
            continue;          /* untrusted length: skip, not abort */
        }

        n = WideCharToMultiByte(CP_UTF8, 0, info->FileName,
                (int) (info->FileNameLength / sizeof(WCHAR)),
                dh->dirent.d_name, (int) sizeof(dh->dirent.d_name) - 1,
                NULL, NULL);

        if (n <= 0 || (size_t) n >= sizeof(dh->dirent.d_name)) {
            continue;      /* unrepresentable or oversized: skip, not abort */
        }

        dh->dirent.d_name[n] = '\0';

        return &dh->dirent;
    }
}


/*
 * closedir(3) -> free the enumeration state and close the fd it owns — the
 * same fd ngx_autocert_fdopendir() was handed, per the ownership contract in
 * shared.h. Matches POSIX closedir(dh)'s "also closes the underlying fd"
 * behaviour exactly; the caller must not close that fd separately.
 */
static ngx_inline int
ngx_autocert_closedir(ngx_autocert_dir_t *dh)
{
    int  fd;

    fd = dh->fd;
    free(dh); /* NOLINT-nginx */

    return _close(fd);
}


/*
 * renameat2 -> FILE_RENAME_INFORMATION via NtSetInformationFile.
 *
 * RENAME_EXCHANGE has no win32 primitive (DESIGN § gap 1, W1's central review
 * question), and it cannot be emulated: NTFS cannot rename over an existing
 * DIRECTORY at all, so no sequence of win32 calls swaps two populated dirs.
 * We still return NGX_DECLINED here, but order.c no longer routes the win32
 * store commit through this flag — ngx_autocert_order_swap_dirs_at() takes a
 * win32-specific per-file publish path instead, because on POSIX declining
 * merely defers a renewal while on win32 it would block renewal permanently.
 *
 * RENAME_NOREPLACE IS expressible: FILE_RENAME_INFORMATION's
 * ReplaceIfExists=FALSE is atomic create-or-fail against the destination,
 * the same guarantee renameat2(RENAME_NOREPLACE) gives on Linux.
 */
static ngx_inline ngx_int_t
ngx_autocert_renameat2(int oldfd, const char *oldp, int newfd,
    const char *newp, unsigned int flags)
{
    NGX_AUTOCERT_IO_STATUS_BLOCK  iosb;
    HANDLE                        oldh, newdirh;
    NTSTATUS                      status;
    int                           fd;
    wchar_t                       wnewp[NGX_MAX_PATH];
    int                           n;
    size_t                        struct_len;
    size_t                        name_off;
    unsigned char
        buf[sizeof(NGX_AUTOCERT_FILE_ATTRIBUTE_TAG_INFO)
            + sizeof(wchar_t) * NGX_MAX_PATH + 32];

    if (flags & RENAME_EXCHANGE) {
        return NGX_DECLINED;
    }

    if (ngx_autocert_win32_resolve_ntdll() != NGX_OK) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        errno = ngx_autocert_win32_errno(ERROR_PROC_NOT_FOUND);
        return NGX_ERROR;
    }

    /* Open the source no-follow, non-directory-or-directory agnostic (a
     * rename can move either); DELETE access is what
     * FileRenameInformation needs. */
    fd = ngx_autocert_win32_ntopen(oldfd, oldp,
        DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
        NGX_AUTOCERT_FILE_OPEN,
        NGX_AUTOCERT_FILE_OPEN_REPARSE_POINT
        | NGX_AUTOCERT_FILE_OPEN_FOR_BACKUP_INTENT,
        _O_RDONLY);
    if (fd == -1) {
        return NGX_ERROR;
    }
    oldh = ngx_autocert_fd_handle(fd);

    newdirh = ngx_autocert_fd_handle(newfd);

    n = MultiByteToWideChar(CP_UTF8, 0, newp, -1, wnewp,
                             (int) (sizeof(wnewp) / sizeof(wnewp[0])));
    if (n <= 0) {
        _close(fd);
        SetLastError(ERROR_BAD_PATHNAME);
        errno = ngx_autocert_win32_errno(ERROR_BAD_PATHNAME);
        return NGX_ERROR;
    }

    {
        /*
         * FILE_RENAME_INFORMATION, laid out by hand (not declared as a C
         * struct with a trailing FileName[1] — MSVC and MinGW disagree on
         * whether that field is named FileName or a raw flexible array in
         * older SDK headers). ReplaceIfExists is the RENAME_NOREPLACE knob;
         * RootDirectory pins the destination the same way OBJECT_ATTRIBUTES
         * does for opens, keeping the rename inside the pinned dir tree
         * rather than trusting a path string.
         */
        struct ngx_autocert_rename_hdr_s {
            BOOLEAN  ReplaceIfExists;
            HANDLE   RootDirectory;
            ULONG    FileNameLength;
        } *hdr;

        /*
         * The FileName array starts at offsetof(FileNameLength) +
         * sizeof(ULONG) ON THE WIRE — the real kernel layout has no padding
         * between FileNameLength and FileName. sizeof(*hdr) is NOT that
         * offset: the compiler pads the struct's overall size up to
         * HANDLE's 8-byte alignment (24 on LLP64/64-bit vs. the true
         * 20-byte header), so copying/sizing off sizeof(*hdr) writes the
         * name 4 bytes past where NtSetInformationFile expects it, on top
         * of the ULONG FileNameLength that precedes it. The kernel then
         * reads padding as text and rejects the call. Do NOT "simplify"
         * this back to sizeof(*hdr) — that is the exact bug this comment is
         * warning about (diagnosed against MSVC/x64,
         * offsetof(RootDirectory)=8, offsetof(FileNameLength)=16,
         * sizeof(*hdr)=24, true FileName offset=20). offsetof() keeps this
         * correct on 32-bit too (FileName offset=12 there) without a magic
         * number.
         */
        name_off = NGX_AUTOCERT_FILE_NAME_INFO_OFF(
            struct ngx_autocert_rename_hdr_s);

        struct_len = name_off + (size_t) (n - 1) * sizeof(wchar_t);
        if (struct_len > sizeof(buf)) {
            _close(fd);
            SetLastError(ERROR_BUFFER_OVERFLOW);
            errno = ngx_autocert_win32_errno(ERROR_BUFFER_OVERFLOW);
            return NGX_ERROR;
        }

        hdr = (void *) buf;
        hdr->ReplaceIfExists = (flags & RENAME_NOREPLACE) ? FALSE : TRUE;
        hdr->RootDirectory = newdirh;
        hdr->FileNameLength = (ULONG) ((n - 1) * sizeof(wchar_t));
        ngx_memcpy(buf + name_off, wnewp, hdr->FileNameLength);

        ngx_memzero(&iosb, sizeof(iosb));
        status = ngx_autocert_pfn_NtSetInformationFile(oldh, &iosb, buf,
            (ULONG) struct_len, 10 /* FileRenameInformation */);
    }

    _close(fd);

    if (!NT_SUCCESS(status)) {
        /*
         * STATUS_OBJECT_NAME_COLLISION here is FILE_RENAME_INFORMATION
         * refusing to replace an existing destination (ReplaceIfExists ==
         * FALSE) — the RENAME_NOREPLACE-vs-existing-destination case the
         * seam's contract comment documents callers inspecting via
         * ngx_errno == NGX_EEXIST (ngx_autocert_shared.h's
         * ngx_autocert_renameat2 doc comment). The generic mapper already
         * sends that status to ERROR_ALREADY_EXISTS == NGX_EEXIST, so no
         * special case is needed beyond what the mapper already does.
         */
        DWORD  mapped = ngx_autocert_win32_errno_from_ntstatus(status);
        SetLastError(mapped);
        errno = ngx_autocert_win32_errno(mapped);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * linkat -> FILE_LINK_INFORMATION via NtSetInformationFile. Mirrors
 * ngx_autocert_renameat2 immediately above: same dfd-relative resolution,
 * same hand-laid variable-length buffer (FILE_LINK_INFORMATION has the
 * identical ReplaceIfExists/RootDirectory/FileNameLength/FileName shape as
 * FILE_RENAME_INFORMATION), same status-to-errno path.
 *
 * The sole call site (order.c's store-seed hardlink) always passes flags==0
 * and depends on ngx_errno == NGX_EEXIST when the destination is already
 * present, exactly like POSIX linkat(..., 0) — it must fail, never replace,
 * an existing staged file. ReplaceIfExists is therefore hardcoded FALSE, not
 * derived from `flags`; any nonzero flags value is rejected outright since
 * this shim has no primitive for AT_* link flags and silently ignoring one
 * would be a behavior change disguised as a passthrough.
 */
static ngx_inline int
ngx_autocert_linkat(int oldfd, const char *oldpath, int newfd,
    const char *newpath, int flags)
{
    NGX_AUTOCERT_IO_STATUS_BLOCK  iosb;
    HANDLE                        oldh, newdirh;
    NTSTATUS                      status;
    int                           fd;
    wchar_t                       wnewp[NGX_MAX_PATH];
    int                           n;
    size_t                        struct_len;
    size_t                        name_off;
    unsigned char
        buf[sizeof(NGX_AUTOCERT_FILE_ATTRIBUTE_TAG_INFO)
            + sizeof(wchar_t) * NGX_MAX_PATH + 32];

    if (flags != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        errno = ngx_autocert_win32_errno(ERROR_INVALID_PARAMETER);
        return -1;
    }

    if (ngx_autocert_win32_resolve_ntdll() != NGX_OK) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        errno = ngx_autocert_win32_errno(ERROR_PROC_NOT_FOUND);
        return -1;
    }

    /* Open the source no-follow; FILE_LINK_INFORMATION needs a handle with
     * access sufficient to create a hard link to it — the docs specify
     * DELETE, matching the rename path's access mask. */
    fd = ngx_autocert_win32_ntopen(oldfd, oldpath,
        DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
        NGX_AUTOCERT_FILE_OPEN,
        NGX_AUTOCERT_FILE_OPEN_REPARSE_POINT
        | NGX_AUTOCERT_FILE_OPEN_FOR_BACKUP_INTENT,
        _O_RDONLY);
    if (fd == -1) {
        return -1;
    }
    oldh = ngx_autocert_fd_handle(fd);

    newdirh = ngx_autocert_fd_handle(newfd);

    n = MultiByteToWideChar(CP_UTF8, 0, newpath, -1, wnewp,
                             (int) (sizeof(wnewp) / sizeof(wnewp[0])));
    if (n <= 0) {
        _close(fd);
        SetLastError(ERROR_BAD_PATHNAME);
        errno = ngx_autocert_win32_errno(ERROR_BAD_PATHNAME);
        return -1;
    }

    {
        /*
         * FILE_LINK_INFORMATION, laid out by hand for the same reason
         * FILE_RENAME_INFORMATION is above: SDK headers disagree on the
         * trailing FileName field's declared type. ReplaceIfExists is
         * hardcoded FALSE (see the function doc comment) — this is the one
         * field that must NOT mirror the rename body's flag-derived value.
         */
        struct ngx_autocert_link_hdr_s {
            BOOLEAN  ReplaceIfExists;
            HANDLE   RootDirectory;
            ULONG    FileNameLength;
        } *hdr;

        /*
         * Same tail-padding trap as ngx_autocert_renameat2 above (see that
         * comment): sizeof(*hdr) over-counts the struct's padded size, not
         * the true on-the-wire FileName offset. Derive it from the real
         * field offset instead of trusting sizeof().
         */
        name_off = NGX_AUTOCERT_FILE_NAME_INFO_OFF(
            struct ngx_autocert_link_hdr_s);

        struct_len = name_off + (size_t) (n - 1) * sizeof(wchar_t);
        if (struct_len > sizeof(buf)) {
            _close(fd);
            SetLastError(ERROR_BUFFER_OVERFLOW);
            errno = ngx_autocert_win32_errno(ERROR_BUFFER_OVERFLOW);
            return -1;
        }

        hdr = (void *) buf;
        hdr->ReplaceIfExists = FALSE;
        hdr->RootDirectory = newdirh;
        hdr->FileNameLength = (ULONG) ((n - 1) * sizeof(wchar_t));
        ngx_memcpy(buf + name_off, wnewp, hdr->FileNameLength);

        ngx_memzero(&iosb, sizeof(iosb));
        status = ngx_autocert_pfn_NtSetInformationFile(oldh, &iosb, buf,
            (ULONG) struct_len, 11 /* FileLinkInformation */);
    }

    _close(fd);

    if (!NT_SUCCESS(status)) {
        /*
         * STATUS_OBJECT_NAME_COLLISION -> ERROR_ALREADY_EXISTS -> NGX_EEXIST
         * via the generic mapper (same mapping ngx_autocert_renameat2 relies
         * on above) is exactly the case order.c's caller tolerates: the
         * ReplaceIfExists==FALSE destination-exists refusal.
         */
        DWORD  mapped = ngx_autocert_win32_errno_from_ntstatus(status);
        SetLastError(mapped);
        errno = ngx_autocert_win32_errno(mapped);
        return -1;
    }

    return 0;
}


/*
 * W9 — named-mutex interprocess singleton gate. DESIGN-win32-store-io.md § W2:
 * B2 is that ngx_worker is declared but never assigned on win32, so the
 * existing worker-0 gate in ngx_http_autocert_module.c fails OPEN on every
 * win32 worker, and the driver's own serializer (flock()) is POSIX-only. This
 * adds a named CreateMutexW gate IN FRONT of ngx_autocert_flock_ex_nb() inside
 * ngx_autocert_driver_trylock(), win32 only; the POSIX path is untouched.
 *
 * GetFinalPathNameByHandleW is Vista+, gated behind the same _WIN32_WINNT
 * floor that is a dead end here (see the GetTickCount64 / GetFileInformation-
 * ByHandleEx notes above: <ngx_config.h> already expanded <windows.h> at
 * nginx's own 0x0501, so a later #define is inert — proven twice). Declare it
 * ourselves; kernel32 is always linked so it resolves without GetProcAddress.
 * CreateMutexW / WaitForSingleObject / ReleaseMutex are pre-Vista exports the
 * SDK headers already declare unconditionally, so only this one needs the
 * hand-written prototype.
 */
#ifndef NGX_AUTOCERT_HAVE_GETFINALPATHNAMEBYHANDLEW
#define NGX_AUTOCERT_HAVE_GETFINALPATHNAMEBYHANDLEW  1
WINBASEAPI DWORD WINAPI GetFinalPathNameByHandleW(HANDLE hFile,
    LPWSTR lpszFilePath, DWORD cchFilePath, DWORD dwFlags);
#endif

#ifndef FILE_NAME_NORMALIZED
#define FILE_NAME_NORMALIZED  0x0
#endif

/*
 * Canonicalize the already-open store dir handle's path via
 * GetFinalPathNameByHandleW, UTF-8-encode it into `out` (size `out_cap`).
 * NOT the configured string: it differs in case / trailing slash / 8.3 form
 * for the same directory, which would make two nginx instances pointed at
 * "the same" store by different spellings each build a DIFFERENT mutex name
 * and both arm.
 *
 * Returns 0 on success, or -1 with errno set (ENAMETOOLONG for an oversized
 * result, or a mapped GetLastError() otherwise).
 */
static ngx_inline int
ngx_autocert_win32_canon_store_path(int dfd, char *out, size_t out_cap)
{
    HANDLE   h;
    wchar_t  wpath[NGX_MAX_PATH];
    DWORD    wlen, mapped;
    int      n;

    h = ngx_autocert_fd_handle(dfd);
    if (h == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        errno = EBADF;
        return -1;
    }

    wlen = GetFinalPathNameByHandleW(
        h, wpath, (DWORD) ( sizeof( wpath ) / sizeof( wpath[0] ) ),
        FILE_NAME_NORMALIZED );
    if (wlen == 0 || wlen >= sizeof(wpath) / sizeof(wpath[0])) {
        mapped = (wlen == 0) ? GetLastError() : ERROR_BUFFER_OVERFLOW;
        SetLastError(mapped);
        errno = ngx_autocert_win32_errno(mapped);
        return -1;
    }

    n = WideCharToMultiByte(CP_UTF8, 0, wpath, (int) wlen, out,
                             (out_cap > INT_MAX) ? INT_MAX : (int) out_cap,
                             NULL, NULL);
    if (n <= 0) {
        mapped = GetLastError();
        SetLastError(mapped);
        errno = (mapped == ERROR_INSUFFICIENT_BUFFER)
                ? ENAMETOOLONG : ngx_autocert_win32_errno(mapped);
        return -1;
    }
    if ((size_t) n >= out_cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    out[n] = '\0';

    return 0;
}

/*
 * Thin CreateMutexW wrapper: create/open the named mutex `wname` and take a
 * ZERO-TIMEOUT non-blocking wait on it — NEVER block; a blocking wait here
 * pins the calling worker's event loop. `*wait_rc` receives the raw
 * WaitForSingleObject() result (WAIT_OBJECT_0 / WAIT_ABANDONED /
 * WAIT_TIMEOUT / WAIT_FAILED) for the caller to feed to
 * ngx_autocert_win32_mutex_wait_verdict() in ngx_autocert_shared.h — the
 * WAIT_OBJECT_0-vs-WAIT_ABANDONED-vs-WAIT_TIMEOUT decision is deliberately
 * NOT made in this header (win32.h is included by shared.h before that
 * function's definition, so it cannot be called from here).
 *
 * Returns the mutex HANDLE on success (caller owns it: on any outcome other
 * than "acquired", the caller must CloseHandle it), or NULL with errno set
 * if CreateMutexW itself fails (a hard failure distinct from any wait
 * outcome).
 */
static ngx_inline HANDLE
ngx_autocert_win32_mutex_open_and_wait(const wchar_t *wname, DWORD *wait_rc)
{
    HANDLE  h;
    DWORD   err;

    h = CreateMutexW(NULL, FALSE, wname);
    if (h == NULL) {
        err = GetLastError();
        SetLastError(err);
        errno = ngx_autocert_win32_errno(err);
        return NULL;
    }

    *wait_rc = WaitForSingleObject(h, 0);
    return h;
}

/*
 * InitializeProcThreadAttributeList / UpdateProcThreadAttribute /
 * DeleteProcThreadAttributeList, plus the STARTUPINFOEXW extended
 * startup-info struct and the PROC_THREAD_ATTRIBUTE_HANDLE_LIST /
 * EXTENDED_STARTUPINFO_PRESENT constants they need (W8b), are Vista+ surface
 * gated behind the same _WIN32_WINNT floor that is a dead end here (see the
 * GetTickCount64 / GetFileInformationByHandleEx notes above: <ngx_config.h>
 * has already fully expanded <windows.h> at nginx's own 0x0501, so a later
 * #define changes nothing — confirmed against this file's own MinGW headers,
 * which gate the same three functions behind `#if _WIN32_WINNT >= 0x0600`).
 * Declare the pieces ourselves, same minimal-NT-surface style used above.
 *
 * The real SDK type for the attribute list is an opaque
 * `LPPROC_THREAD_ATTRIBUTE_LIST` (pointer to a forward-declared struct), and
 * that typedef itself is not consistently #ifndef-guarded across MinGW/MSVC
 * headers, so redeclaring it risks a collision. Sidestep the whole problem:
 * treat the attribute list as an opaque LPVOID blob everywhere in this
 * header and at the one call site (ngx_autocert_order.c) — the win32 ABI for
 * these three calls only ever dereferences it opaquely, never through the
 * named type, so LPVOID is a legal substitute for every parameter here.
 */
#ifndef NGX_AUTOCERT_HAVE_PROC_THREAD_ATTRIBUTE_LIST
#define NGX_AUTOCERT_HAVE_PROC_THREAD_ATTRIBUTE_LIST  1

#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT  0x00080000
#endif

#ifndef PROC_THREAD_ATTRIBUTE_HANDLE_LIST
/* ABI-fixed value: ProcThreadAttributeHandleList (2) with the THREAD (0x10000)
 * and INPUT (0x20000) flag bits OR'd in, matching every SDK's
 * ProcThreadAttributeValue(2, FALSE, TRUE, FALSE) expansion. */
#define PROC_THREAD_ATTRIBUTE_HANDLE_LIST  0x00020002
#endif

typedef struct {
    STARTUPINFOW  StartupInfo;
    LPVOID        lpAttributeList;
} NGX_AUTOCERT_STARTUPINFOEXW;

WINBASEAPI BOOL WINAPI InitializeProcThreadAttributeList(
    LPVOID lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags,
    PSIZE_T lpSize);

WINBASEAPI BOOL WINAPI UpdateProcThreadAttribute(LPVOID lpAttributeList,
    DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize,
    PVOID lpPreviousValue, PSIZE_T lpReturnSize);

WINBASEAPI VOID WINAPI DeleteProcThreadAttributeList(
    LPVOID lpAttributeList);

#endif /* NGX_AUTOCERT_HAVE_PROC_THREAD_ATTRIBUTE_LIST */

#endif /* NGX_WIN32 */


#endif /* _NGX_AUTOCERT_WIN32_H_INCLUDED_ */
