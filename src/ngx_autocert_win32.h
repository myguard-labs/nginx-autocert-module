/*
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


#include <windows.h>
#include <winioctl.h>          /* IO_REPARSE_TAG_*; needs windows.h first */
#include <io.h>                /* _open_osfhandle, _get_osfhandle, _close */
#include <fcntl.h>             /* _O_RDONLY and friends for _open_osfhandle */
#include <errno.h>


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
 * W11 (no NTFS analogue without an ACL), flock is W10 (LockFileEx), fork/execve
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
 */
#define ngx_autocert_monotonic_ms()     ((uint64_t) GetTickCount64())


/*
 * Map GetLastError()/NTSTATUS to the errno values the seam's callers already
 * branch on (EEXIST, ENOENT, EAGAIN, ENOTEMPTY, ELOOP...).
 *
 * Deliberately not _doserrno / _get_errno: the CRT's mapping is narrower and
 * collapses distinctions the callers depend on — notably ERROR_SHARING_VIOLATION,
 * which must surface as EAGAIN so the lock path retries rather than failing hard.
 *
 * Defined in ngx_autocert_shared.h with the other shim bodies.
 */
int ngx_autocert_win32_errno(DWORD err);


/*
 * NGX_EINTR retry predicate.
 *
 * nginx core does not define NGX_EINTR on win32 at all (src/os/win32/ngx_errno.h
 * has no entry for it) — a bare `ngx_errno == NGX_EINTR` is therefore a hard
 * compile error on win32, not merely a wrong answer. The retry loops that test
 * it (e.g. the flock() spin at driver.c) exist because a POSIX blocking syscall
 * can be interrupted by a caught signal mid-wait and must be retried. Win32 has
 * no analogous "signal arrived during this syscall" outcome for these calls, so
 * the predicate is a compile-time-constant false here: the branch it guards is
 * simply unreachable on win32, which is the correct behaviour, not a gap being
 * papered over.
 */
#define ngx_autocert_err_is_intr(err)   0

#endif /* NGX_WIN32 */


#endif /* _NGX_AUTOCERT_WIN32_H_INCLUDED_ */
