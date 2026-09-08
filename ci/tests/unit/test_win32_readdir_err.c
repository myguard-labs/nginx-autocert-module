/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for the win32 store-scan enumeration's EXPLICIT error channel:
 * ngx_autocert_readdir_err() in src/ngx_autocert_win32.h (W12).
 *
 * THE DEFECT THIS PINS. ngx_autocert_readdir() returns NULL for both clean
 * end-of-directory and a genuine failure. Telling them apart by reading the
 * ambient process error state -- errno on POSIX, which is GetLastError() on
 * win32 -- is correct on the POSIX arm and WRONG on this one:
 *
 *   - ngx_autocert_readdir()'s own loop skips an entry whose name will not
 *     convert to UTF-8, or does not fit NGX_MAX_PATH, with a bare `continue`
 *     -- and WideCharToMultiByte() has already set LastError
 *     (ERROR_NO_UNICODE_TRANSLATION / ERROR_INSUFFICIENT_BUFFER) on exactly
 *     the failure that triggers that skip. The untrusted-FileNameLength
 *     `continue` above it is the same shape.
 *   - The loop then re-queries, hits STATUS_NO_MORE_FILES and returns NULL
 *     for a perfectly CLEAN end of directory -- with GetLastError() still
 *     nonzero from the skip.
 *   - More generally, Win32 APIs are permitted to set LastError even when
 *     they succeed; only a FAILING call's value is meaningful.
 *
 * So a caller that clears the global before each ngx_autocert_readdir() call
 * and inspects it after cannot work, because the clobber happens INSIDE the
 * shim, after that clear. On a real store, one directory whose name is not
 * representable in UTF-8 would make every A6 seed walk log an enumeration
 * failure and stop early at the END of the walk -- silent truncation plus a
 * misleading error, which is worse than the bug the error channel exists to
 * fix. dh->err is the fix: written on EVERY NULL-returning path, so it is
 * never stale and never ambiguous.
 *
 * WHY THIS RUNS ON LINUX. .github/workflows/windows-build.yml is build-only
 * and never runs the unit suite, so the platform where this bites has no test
 * coverage of its own. This TU therefore compiles the PRODUCTION source text
 * of the struct, fdopendir, the readdir loop and the accessor -- sliced by
 * ci/tests/unit/extract_win32_readdir.sh into generated_win32_readdir.inc --
 * against stand-in Windows types and a scripted NtQueryDirectoryFile defined
 * below. It is not a re-implementation: dropping `dh->err = 0` from the
 * STATUS_NO_MORE_FILES path, or forgetting to set it on a failure path,
 * recompiles into this test and fails it. Same slicing rationale as
 * extract_seedchunk.sh, same "bind to production, not a hand-copy"
 * requirement as test_win32_rename_info_layout.c.
 *
 * What it does NOT prove: that the real NtQueryDirectoryFile returns the
 * statuses scripted here, or that the real WideCharToMultiByte sets LastError
 * as documented. Those are platform contracts, asserted by the ABI/behaviour
 * of Windows itself, not by this suite.
 *
 * Exit 0 = pass; non-zero on first failure.
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ------------------------------------------------------------------ *
 * Stand-in Windows surface.
 *
 * Widths match the win32 ABI the production code is compiled against on
 * 64-bit Windows (LLP64: ULONG/DWORD 4 bytes, HANDLE 8, WCHAR 2), so the
 * sliced struct's layout arithmetic -- the offsetof(FileName) bounds check
 * and the FileNameLength/sizeof(WCHAR) division in particular -- is the same
 * arithmetic the shipped code performs. Only the FUNCTIONS are simulated.
 * ------------------------------------------------------------------ */

typedef unsigned int    ULONG;
typedef unsigned int    DWORD;
typedef unsigned short  USHORT;
typedef unsigned short  WCHAR;
typedef WCHAR          *PWSTR;
typedef void           *HANDLE;
typedef void           *LPVOID;
typedef int             NTSTATUS;
typedef int             BOOL;
typedef unsigned char   BOOLEAN;
typedef long long       LONGLONG;
typedef union { LONGLONG QuadPart; } LARGE_INTEGER;

#define NTAPI
#define FALSE  0
#define TRUE   1

#define NGX_MAX_PATH  260

#define ngx_inline    inline
#define ngx_uint_t    unsigned long
#define ngx_err_t     int
#define ngx_memzero(p, n)  memset(p, 0, n)

#define ERROR_NOT_ENOUGH_MEMORY   8
#define ERROR_PROC_NOT_FOUND      127
#define ERROR_GEN_FAILURE         31
#define ERROR_NO_UNICODE_TRANSLATION  1113

#define NT_SUCCESS(status)  (((NTSTATUS) (status)) >= 0)
#define STATUS_NO_MORE_FILES  ((NTSTATUS) 0x80000006L)
#define NGX_AUTOCERT_FileDirectoryInformation  1

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

typedef struct {
    union { NTSTATUS Status; void *Pointer; } u;
    unsigned long  Information;
} NGX_AUTOCERT_IO_STATUS_BLOCK;

/* --- the simulated ambient global, and the simulated NT/Win32 calls ---- */

static DWORD  fake_last_error;

static void   SetLastError(DWORD e) { fake_last_error = e; }
static DWORD  GetLastError(void)    { return fake_last_error; }

static int  ngx_autocert_win32_errno(DWORD e) { return (int) e; }
static DWORD
ngx_autocert_win32_errno_from_ntstatus(NTSTATUS s) { return (DWORD) -s; }

#define ngx_autocert_fd_handle(fd)  ((HANDLE) (size_t) (fd))

/*
 * Scripted NtQueryDirectoryFile. Each test sets `script_status` (returned as
 * the NTSTATUS) and, when that status is success, copies `script_batch` of
 * `script_batch_len` bytes into the caller's buffer. `resolve_ok` drives the
 * ntdll-resolution failure path.
 */
static NTSTATUS       script_status;
static unsigned char  script_batch[4096];
static size_t         script_batch_len;
static unsigned long  script_information;      /* overrides batch_len when set */
static int            resolve_ok = 1;
static int            query_calls;

static int
ngx_autocert_win32_resolve_ntdll(void)
{
    return resolve_ok ? 0 /* NGX_OK */ : -1;
}
#define NGX_OK  0

static NTSTATUS NTAPI
fake_NtQueryDirectoryFile(HANDLE h, void *ev, void *apc, void *apcctx,
    NGX_AUTOCERT_IO_STATUS_BLOCK *iosb, void *buf, unsigned long len,
    int cls, BOOL single, void *mask, BOOL restart)
{
    (void) h; (void) ev; (void) apc; (void) apcctx; (void) cls;
    (void) single; (void) mask; (void) restart;

    query_calls++;

    if (!NT_SUCCESS(script_status)) {
        return script_status;
    }

    /*
     * A scripted batch is delivered exactly ONCE, then the directory is
     * drained and every further query reports end-of-directory. This mirrors
     * a real handle: the kernel's scan position advances past what it
     * returned, so a re-query never re-delivers the same entries. Without
     * this the shim's own "batch exhausted -> re-query" loop would be fed the
     * same batch forever and spin.
     */
    if (script_batch_len == 0) {
        return STATUS_NO_MORE_FILES;
    }

    if (script_batch_len > len) {
        return (NTSTATUS) 0xC0000001L;
    }

    memcpy(buf, script_batch, script_batch_len);
    iosb->Information = script_information ? script_information
                                           : script_batch_len;
    script_batch_len   = 0;             /* consumed */
    script_information = 0;
    return 0;
}

#define ngx_autocert_pfn_NtQueryDirectoryFile  fake_NtQueryDirectoryFile

/*
 * WideCharToMultiByte stand-in. Converts the ASCII subset (which is all the
 * fixtures below need) and, when a wide char is outside it, FAILS exactly the
 * way the real one does for an unconvertible name: returns 0 and sets
 * LastError to ERROR_NO_UNICODE_TRANSLATION. That failure -> `continue` is
 * the precise clobber this test exists to prove is not misread as an error.
 */
#define CP_UTF8  65001

static int
WideCharToMultiByte(unsigned cp, DWORD flags, const WCHAR *in, int inlen,
    char *out, int outlen, const char *def, void *used)
{
    int  i;

    (void) cp; (void) flags; (void) def; (void) used;

    if (inlen > outlen) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return 0;
    }

    for (i = 0; i < inlen; i++) {
        if (in[i] > 0x7f) {
            /* Unconvertible in this stand-in: same observable as the real
             * WideCharToMultiByte failing on a name it cannot represent. */
            SetLastError(ERROR_NO_UNICODE_TRANSLATION);
            return 0;
        }
        out[i] = (char) in[i];
    }

    return inlen;
}

static int  fake_close_calls;
static int  _close(int fd) { (void) fd; fake_close_calls++; return 0; }

/* ------------------------------------------------------------------ *
 * The production code under test.
 * ------------------------------------------------------------------ */

#include "generated_win32_readdir.inc"

/* ------------------------------------------------------------------ */

static int  failures;

static void
ok(int cond, const char *what)
{
    printf("%s:   %s\n", cond ? "ok" : "FAIL", what);
    if (!cond) {
        failures++;
    }
}

/*
 * Build a one-entry FILE_DIRECTORY_INFORMATION batch into script_batch.
 * `name` is ASCII; when `wide_hi` is nonzero the first wide char is forced
 * above 0x7f so the stand-in WideCharToMultiByte fails on it, reproducing the
 * unrepresentable-name skip.
 */
static void
script_one_entry(const char *name, int wide_hi)
{
    NGX_AUTOCERT_FILE_DIRECTORY_INFORMATION  *info;
    size_t  n = strlen(name);
    size_t  i;

    memset(script_batch, 0, sizeof(script_batch));
    info = (NGX_AUTOCERT_FILE_DIRECTORY_INFORMATION *) script_batch;

    info->NextEntryOffset = 0;                 /* last entry in this batch */
    info->FileNameLength  = (ULONG) (n * sizeof(WCHAR));

    for (i = 0; i < n; i++) {
        info->FileName[i] = (WCHAR) (unsigned char) name[i];
    }
    if (wide_hi && n > 0) {
        info->FileName[0] = 0x00e9;            /* not representable here */
    }

    script_batch_len = offsetof(NGX_AUTOCERT_FILE_DIRECTORY_INFORMATION,
                                FileName)
                       + n * sizeof(WCHAR);
    script_information = 0;
}

static void
reset_script(void)
{
    script_status      = 0;
    script_batch_len   = 0;
    script_information = 0;
    resolve_ok         = 1;
    query_calls        = 0;
    fake_last_error    = 0;
}


/*
 * THE HEADLINE CASE. A store containing one non-representable directory name,
 * walked to completion with a DIRTY LastError pre-set (as any earlier Win32
 * call in the worker could leave it).
 *
 * The shim must skip the bad entry, reach STATUS_NO_MORE_FILES, and report
 * dh->err == 0 -- a CLEAN end of directory -- even though GetLastError() is
 * nonzero at that moment. Asserting the global is still nonzero is what makes
 * this a real discrimination test rather than a vacuous one: it proves the
 * accessor's answer is independent of the global, not merely equal to it in
 * a case where both happen to be zero.
 */
static void
test_eof_after_unrepresentable_name_is_clean(void)
{
    ngx_autocert_dir_t     *dh;
    ngx_autocert_dirent_t  *de;

    reset_script();

    dh = ngx_autocert_fdopendir(7);
    if (dh == NULL) {
        ok(0, "fdopendir returned NULL");
        return;
    }

    ok(ngx_autocert_readdir_err(dh) == 0,
       "a fresh handle starts with a clean error channel");

    /* Pre-dirty the ambient global, exactly as unrelated earlier Win32 work
     * in the same worker would leave it. */
    SetLastError(ERROR_GEN_FAILURE);

    /*
     * The one scripted batch holds a single entry whose name cannot be
     * represented. The shim's loop skips it via `continue` -- with
     * WideCharToMultiByte having set LastError on the way -- finds the batch
     * drained, re-queries, and the (now consumed) script reports
     * end-of-directory. So this single call walks the entire failure-then-EOF
     * sequence the defect lives in.
     */
    script_one_entry("bad", 1);

    de = ngx_autocert_readdir(dh);

    ok(de == NULL, "unrepresentable name is skipped, walk ends at EOF");

    ok(GetLastError() != 0,
       "the ambient global IS dirty at clean EOF (the trap this guards)");

    ok(ngx_autocert_readdir_err(dh) == 0,
       "clean end-of-directory reports err == 0 despite the dirty global "
       "(EOF is NOT misreported as an enumeration failure)");

    (void) ngx_autocert_closedir(dh);
}


/*
 * The other half of the discrimination: a GENUINE NtQueryDirectoryFile
 * failure must report a NONZERO err. Without this, a channel hardwired to 0
 * would pass the case above and silently swallow every real failure -- the
 * exact vacuous-control shape.
 */
static void
test_genuine_failure_reports_nonzero(void)
{
    ngx_autocert_dir_t     *dh;
    ngx_autocert_dirent_t  *de;
    ngx_err_t               err;

    reset_script();

    dh = ngx_autocert_fdopendir(9);
    if (dh == NULL) {
        ok(0, "fdopendir returned NULL");
        return;
    }

    /* Deliberately CLEAN global, so a nonzero verdict cannot have leaked in
     * from the ambient state -- it can only have come from dh->err. */
    SetLastError(0);

    script_status = (NTSTATUS) 0xC0000022L;      /* STATUS_ACCESS_DENIED */

    de = ngx_autocert_readdir(dh);
    err = ngx_autocert_readdir_err(dh);

    ok(de == NULL, "a failing query returns NULL");
    ok(err != 0,
       "a genuine enumeration failure reports err != 0 (not swallowed as EOF)");

    (void) ngx_autocert_closedir(dh);
}


/*
 * The ntdll-resolution failure path and the over-long-Information clamp are
 * the two remaining NULL-returning paths in the loop. Both are genuine
 * failures and both must set err, or a regression there degrades to a silent
 * truncated walk.
 */
static void
test_every_failure_path_sets_err(void)
{
    ngx_autocert_dir_t  *dh;

    /* --- ntdll resolution failure --- */
    reset_script();
    resolve_ok = 0;
    SetLastError(0);

    dh = ngx_autocert_fdopendir(11);
    if (dh != NULL) {
        (void) ngx_autocert_readdir(dh);
        ok(ngx_autocert_readdir_err(dh) != 0,
           "ntdll-resolution failure sets the error channel");
        (void) ngx_autocert_closedir(dh);
    } else {
        ok(0, "fdopendir returned NULL");
    }

    /* --- kernel reports more bytes than the buffer it was given --- */
    reset_script();
    SetLastError(0);
    script_one_entry("ok.example.com", 0);
    script_information = NGX_AUTOCERT_DIR_QUERY_BUF_SIZE + 1;

    dh = ngx_autocert_fdopendir(12);
    if (dh != NULL) {
        (void) ngx_autocert_readdir(dh);
        ok(ngx_autocert_readdir_err(dh) != 0,
           "an over-long reported Information sets the error channel");
        (void) ngx_autocert_closedir(dh);
    } else {
        ok(0, "fdopendir returned NULL");
    }
}


/*
 * A normal entry still reaches the caller, and a clean walk over it ends with
 * err == 0. Without this the suite could pass with a shim that skipped
 * everything.
 */
static void
test_good_entry_round_trips(void)
{
    ngx_autocert_dir_t     *dh;
    ngx_autocert_dirent_t  *de;

    reset_script();
    SetLastError(0);

    dh = ngx_autocert_fdopendir(13);
    if (dh == NULL) {
        ok(0, "fdopendir returned NULL");
        return;
    }

    script_one_entry("good.example.com", 0);
    de = ngx_autocert_readdir(dh);

    ok(de != NULL && strcmp(de->d_name, "good.example.com") == 0,
       "a representable entry is returned with its name intact");

    /* The batch is consumed; the next query reports end-of-directory. */
    de = ngx_autocert_readdir(dh);

    ok(de == NULL, "the walk then reaches end of directory");
    ok(ngx_autocert_readdir_err(dh) == 0,
       "a clean walk over a good entry ends with err == 0");

    (void) ngx_autocert_closedir(dh);
}


int
main(void)
{
    printf("== win32 store-scan enumeration: EOF vs error channel ==\n");

    test_good_entry_round_trips();
    test_eof_after_unrepresentable_name_is_clean();
    test_genuine_failure_reports_nonzero();
    test_every_failure_path_sets_err();

    if (failures) {
        printf("%d assertion(s) FAILED\n", failures);
        return 1;
    }

    return 0;
}
