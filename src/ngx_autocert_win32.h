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

#endif /* NGX_WIN32 */


#endif /* _NGX_AUTOCERT_WIN32_H_INCLUDED_ */
