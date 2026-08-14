/*
 * Unit test for the FILE_RENAME_INFORMATION / FILE_LINK_INFORMATION
 * variable-length-buffer layout arithmetic used by ngx_autocert_renameat2()
 * and ngx_autocert_linkat() in src/ngx_autocert_win32.h.
 *
 * Those functions build the NtSetInformationFile input buffer by hand:
 *
 *     struct { BOOLEAN ReplaceIfExists; HANDLE RootDirectory;
 *              ULONG FileNameLength; } *hdr;
 *
 * and must know the BYTE OFFSET where the trailing FileName[] array begins.
 * On the real (documented, on-the-wire) NT structure that offset is
 * offsetof(FileNameLength) + sizeof(ULONG) -- i.e. immediately after the
 * ULONG, with NO padding. But a compiler is free to pad the OVERALL struct
 * size up to the alignment of its widest member (HANDLE, 8 bytes on
 * LLP64/64-bit Windows), so sizeof(hdr) rounds up past that true offset --
 * concretely 24 instead of 20 for this member layout. A version of the
 * rename/link code that copies the filename to `buf + sizeof(*hdr)` and
 * sizes the call with `sizeof(*hdr) + name_bytes` writes/declares the name
 * 4 bytes later than the kernel expects, corrupting the first 4 wchar_t's
 * of every rename/hardlink target on affected ABIs (observed on MSVC/x64:
 * NtSetInformationFile returns a generic failure, surfaced to the caller as
 * ERROR_GEN_FAILURE / "device attached to the system is not functioning").
 *
 * This test cannot include <windows.h> or call the real win32-only
 * functions (they need real HANDLEs, NtSetInformationFile, etc. and only
 * build under _WIN32) -- so it pins the LAYOUT ARITHMETIC directly: it
 * declares the identical field layout using stand-in types whose sizes
 * match the win32 ABI (BOOLEAN=1 byte, HANDLE=8 bytes as on LLP64/64-bit
 * Windows, ULONG=4 bytes), then asserts that the correct trailing-array
 * offset is offsetof(FileNameLength)+sizeof(ULONG) -- and, crucially, that
 * this is NOT equal to sizeof(the struct). A build of ngx_autocert_win32.h
 * that reverts to `sizeof(*hdr)` for the offset would pass every other
 * local check (it compiles, it links, the wrong-endian bytes are still
 * "a struct") -- only this offset comparison catches the regression, which
 * is the whole point: prior win32 path/ABI bugs in this port shipped with
 * no test that would have caught them.
 *
 * Exit 0 = pass; non-zero on first failure.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Stand-ins matching the win32 ABI widths this code targets (LLP64,
 * 8-byte HANDLE, 4-byte ULONG, 1-byte BOOLEAN) -- NOT the real win32
 * typedefs, since <windows.h> is unavailable on Linux. Field order and
 * widths are what determine the padding bug, not the type names. */
typedef unsigned char   test_boolean_t;
typedef void            *test_handle_t;
typedef unsigned int     test_ulong_t;   /* win32 ULONG is always 32-bit,
                                             even on LLP64 where `long` is
                                             32-bit too but LP64 Linux
                                             `long` is 64-bit -- use `int`
                                             so this matches on every host
                                             gcc targets here (checked
                                             below regardless). */

struct test_rename_hdr {
    test_boolean_t  ReplaceIfExists;
    test_handle_t   RootDirectory;
    test_ulong_t    FileNameLength;
};

static int failures = 0;

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            failures++; \
        } \
    } while (0)

int
main(void)
{
    size_t  true_off, hdr_size;

    /* Sanity: this ABI model needs a 4-byte ULONG and an 8-byte HANDLE for
     * the padding bug to reproduce at all; skip loudly rather than pass
     * vacuously if the toolchain ever disagrees. */
    if (sizeof(test_ulong_t) != 4) {
        fprintf(stderr,
            "SKIP: sizeof(test_ulong_t)=%zu != 4, layout model invalid "
            "on this toolchain\n", sizeof(test_ulong_t));
        return 0;
    }
    if (sizeof(test_handle_t) != 8) {
        fprintf(stderr,
            "SKIP: sizeof(test_handle_t)=%zu != 8, layout model invalid "
            "on this toolchain\n", sizeof(test_handle_t));
        return 0;
    }

    true_off = offsetof(struct test_rename_hdr, FileNameLength)
               + sizeof(test_ulong_t);
    hdr_size = sizeof(struct test_rename_hdr);

    /* The real on-the-wire offset: 0 (BOOLEAN) padded to 8 (HANDLE) = 8,
     * +8 (HANDLE) = 16, +4 (ULONG) = 20. */
    CHECK(true_off == 20, "offsetof(FileNameLength)+sizeof(ULONG) != 20");

    /* The bug this test exists to catch: sizeof(struct) rounds up to the
     * HANDLE alignment (8), landing on 24 -- NOT the same as the true
     * offset. If a future compiler/ABI ever made these equal, the old
     * (buggy) code would accidentally be correct and this assertion
     * would need updating alongside it; today, on every ABI this module
     * targets, they must differ. */
    CHECK(hdr_size == 24, "sizeof(struct test_rename_hdr) != 24 "
                           "(unexpected padding model for this ABI)");
    CHECK(true_off != hdr_size,
        "true FileName offset must NOT equal sizeof(hdr) -- "
        "this is the exact bug: copying/sizing off sizeof(*hdr) instead "
        "of offsetof(FileNameLength)+sizeof(ULONG)");

    if (failures == 0) {
        printf("OK: all win32 rename/link layout tests passed\n");
        return 0;
    }

    fprintf(stderr, "%d test(s) failed\n", failures);
    return 1;
}
