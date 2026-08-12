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
 * Defined below with the other shim bodies. static ngx_inline, like every
 * other body in this header: a non-static definition in a header included by
 * six translation units is a duplicate-symbol link error at win32 link time.
 */
static ngx_inline int ngx_autocert_win32_errno(DWORD err);


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


/*
 * AT_SYMLINK_NOFOLLOW / AT_REMOVEDIR — the flag words ngx_autocert_fstatat()
 * and ngx_autocert_unlinkat() call sites pass explicitly (DESIGN-win32-store-io.md
 * says these stay call-site params rather than being folded into a helper, on
 * both platforms). Neither exists in any win32 header; the shim bodies below
 * interpret the bits themselves, so the exact numeric value only has to be
 * distinct from the other bit in this pair. Bit 0/1 keep them out of the O_*
 * shim range (0x01000000+) with room to spare.
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
 * Lazily resolved once per process. A benign data race on first-use (two
 * workers resolving concurrently) is acceptable: GetProcAddress is idempotent
 * for a given (module, symbol) and every writer stores the same value, so a
 * torn read is impossible on a pointer-sized, naturally aligned store on
 * x86/x64. No lock is worth adding for that.
 */
static ngx_autocert_pfn_NtCreateFile_t
    ngx_autocert_pfn_NtCreateFile = NULL;
static ngx_autocert_pfn_NtSetInformationFile_t
    ngx_autocert_pfn_NtSetInformationFile = NULL;
static ngx_autocert_pfn_NtQueryInformationFile_t
    ngx_autocert_pfn_NtQueryInformationFile = NULL;

static ngx_inline ngx_int_t
ngx_autocert_win32_resolve_ntdll(void)
{
    HMODULE  ntdll;

    if (ngx_autocert_pfn_NtCreateFile != NULL) {
        return NGX_OK;
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return NGX_ERROR;
    }

    ngx_autocert_pfn_NtCreateFile =
        (ngx_autocert_pfn_NtCreateFile_t)
        (void *) GetProcAddress(ntdll, "NtCreateFile");
    ngx_autocert_pfn_NtSetInformationFile =
        (ngx_autocert_pfn_NtSetInformationFile_t)
        (void *) GetProcAddress(ntdll, "NtSetInformationFile");
    ngx_autocert_pfn_NtQueryInformationFile =
        (ngx_autocert_pfn_NtQueryInformationFile_t)
        (void *) GetProcAddress(ntdll, "NtQueryInformationFile");

    if (ngx_autocert_pfn_NtCreateFile == NULL
        || ngx_autocert_pfn_NtSetInformationFile == NULL
        || ngx_autocert_pfn_NtQueryInformationFile == NULL)
    {
        ngx_autocert_pfn_NtCreateFile = NULL;
        return NGX_ERROR;
    }

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
ngx_autocert_win32_ntopen(int dfd, const char *name, ULONG desired_access,
    ULONG create_disposition, ULONG create_options_extra, int crt_flags)
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

    ngx_memzero(&iosb, sizeof(iosb));

    status = ngx_autocert_pfn_NtCreateFile(&h, desired_access, &oa, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL, NGX_AUTOCERT_SHARE_ALL,
        create_disposition,
        NGX_AUTOCERT_FILE_SYNCHRONOUS_IO_NONALERT | create_options_extra,
        NULL, 0);

    if (!NT_SUCCESS(status)) {
        SetLastError(ngx_autocert_win32_errno_from_ntstatus(status));
        return -1;
    }

    fd = _open_osfhandle((intptr_t) h, crt_flags);
    if (fd == -1) {
        CloseHandle(h);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return -1;
    }

    return fd;
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
        /* Not a reparse point (or the query failed for an unrelated reason);
         * either way there is nothing to reject. */
        return NGX_OK;
    }

    if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        && ngx_autocert_reparse_is_link(info.ReparseTag))
    {
        SetLastError(ERROR_TOO_MANY_LINKS);
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
        desired_access |= FILE_LIST_DIRECTORY | FILE_TRAVERSE;
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
    int      crt_flags;

    (void) mode; /* W11 (ACL translation) owns applying this; not yet wired */

    desired_access = FILE_READ_ATTRIBUTES | SYNCHRONIZE | GENERIC_READ
           | (flags & (O_WRONLY | O_RDWR) ? GENERIC_WRITE : 0);
    options = NGX_AUTOCERT_FILE_NON_DIRECTORY_FILE;
    crt_flags = (flags & (O_WRONLY | O_RDWR)) ? _O_RDWR : _O_RDONLY;

    if (flags & O_NOFOLLOW) {
        options |= NGX_AUTOCERT_FILE_OPEN_REPARSE_POINT;
    }

    disposition = (flags & O_EXCL)
                  ? NGX_AUTOCERT_FILE_CREATE
                  : NGX_AUTOCERT_FILE_OPEN_IF;

    return ngx_autocert_win32_ntopen(dfd, name, desired_access, disposition, options,
                                      crt_flags);
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
    int  fd;

    (void) mode;

    fd = ngx_autocert_win32_ntopen(dfd, name,
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
        NGX_AUTOCERT_FILE_CREATE,
        NGX_AUTOCERT_FILE_DIRECTORY_FILE
        | NGX_AUTOCERT_FILE_OPEN_FOR_BACKUP_INTENT,
        _O_RDONLY);
    if (fd == -1) {
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

    fd = ngx_autocert_win32_ntopen(dfd, name, desired_access, NGX_AUTOCERT_FILE_OPEN,
                                    options, _O_RDONLY);
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
        return -1;
    }

    _close(fd);
    return 0;
}


/*
 * fstatat -> open no-follow (mirroring AT_SYMLINK_NOFOLLOW when given; POSIX
 * fstatat() without that flag follows a symlink, so its absence opens without
 * FILE_OPEN_REPARSE_POINT here too) then GetFileInformationByHandleEx.
 * st_mode/st_nlink/st_size are the only fields any call site in this repo
 * reads (verified against S_ISDIR/S_ISREG/st_nlink/st_size uses in
 * driver.c/order.c) — st_mode is approximated from the directory attribute
 * bit and a fixed permission mask, per DESIGN's documented approximation.
 */
static ngx_inline int
ngx_autocert_fstatat(int dfd, const char *name, struct stat *st, int flags)
{
    BY_HANDLE_FILE_INFORMATION  info;
    HANDLE                      h;
    int                         fd, ntflags;

    ntflags = O_RDONLY;
    if (flags & AT_SYMLINK_NOFOLLOW) {
        ntflags |= O_NOFOLLOW;
    }

    fd = ngx_autocert_openat(dfd, name, ntflags);
    if (fd == -1) {
        return -1;
    }

    h = ngx_autocert_fd_handle(fd);

    if (!GetFileInformationByHandle(h, &info)) {
        DWORD  err = GetLastError();
        _close(fd);
        SetLastError(err);
        return -1;
    }

    _close(fd);

    ngx_memzero(st, sizeof(*st));
    st->st_mode = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                  ? (S_IFDIR | 0700) : (S_IFREG | 0600);
    st->st_nlink = (short) (info.nNumberOfLinks > 0
                             ? info.nNumberOfLinks : 1);
    st->st_size = (info.nFileSizeHigh == 0)
                  ? (_off_t) info.nFileSizeLow : (_off_t) -1;

    return 0;
}


/*
 * fstat(2) on an already-open shim fd. Distinct from ngx_autocert_fstatat
 * above for the same reason the POSIX side keeps them distinct: this stats
 * the fd itself, no name/dfd/no-follow involved (the file is already open,
 * so there is nothing left to resolve).
 */
static ngx_inline int
ngx_autocert_fstat(int fd, struct stat *st)
{
    BY_HANDLE_FILE_INFORMATION  info;
    HANDLE                      h;

    h = ngx_autocert_fd_handle(fd);
    if (h == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return -1;
    }

    if (!GetFileInformationByHandle(h, &info)) {
        return -1;
    }

    ngx_memzero(st, sizeof(*st));
    st->st_mode = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                  ? (S_IFDIR | 0700) : (S_IFREG | 0600);
    st->st_nlink = (short) (info.nNumberOfLinks > 0
                             ? info.nNumberOfLinks : 1);
    st->st_size = (info.nFileSizeHigh == 0)
                  ? (_off_t) info.nFileSizeLow : (_off_t) -1;

    return 0;
}


/*
 * renameat2 -> FILE_RENAME_INFORMATION via NtSetInformationFile.
 *
 * RENAME_EXCHANGE has no win32 primitive (DESIGN § gap 1, W1's central review
 * question): returning NGX_DECLINED here runs the existing non-Linux fallback
 * unchanged (order.c already handles NGX_DECLINED for exactly this reason —
 * the fallback is not new code written for win32, it is the same path a
 * pre-3.15 Linux kernel already exercises).
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
    unsigned char
        buf[sizeof(NGX_AUTOCERT_FILE_ATTRIBUTE_TAG_INFO)
            + sizeof(wchar_t) * NGX_MAX_PATH + 32];

    if (flags & RENAME_EXCHANGE) {
        return NGX_DECLINED;
    }

    if (ngx_autocert_win32_resolve_ntdll() != NGX_OK) {
        SetLastError(ERROR_PROC_NOT_FOUND);
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
        struct {
            BOOLEAN  ReplaceIfExists;
            HANDLE   RootDirectory;
            ULONG    FileNameLength;
        } *hdr;

        struct_len = sizeof(*hdr) + (size_t) (n - 1) * sizeof(wchar_t);
        if (struct_len > sizeof(buf)) {
            _close(fd);
            SetLastError(ERROR_BUFFER_OVERFLOW);
            return NGX_ERROR;
        }

        hdr = (void *) buf;
        hdr->ReplaceIfExists = (flags & RENAME_NOREPLACE) ? FALSE : TRUE;
        hdr->RootDirectory = newdirh;
        hdr->FileNameLength = (ULONG) ((n - 1) * sizeof(wchar_t));
        ngx_memcpy(buf + sizeof(*hdr), wnewp, hdr->FileNameLength);

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
        SetLastError(ngx_autocert_win32_errno_from_ntstatus(status));
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif /* NGX_WIN32 */


#endif /* _NGX_AUTOCERT_WIN32_H_INCLUDED_ */
