/*
 * Unit tests for the win32 DACL-ACE-tuple -> POSIX group/other permission-bit
 * decision core (src/ngx_autocert_shared.h: ngx_autocert_win32_dacl_mode()),
 * the W11 pure core behind ngx_autocert_win32_mode_from_dacl() in
 * ngx_autocert_win32.h.
 *
 * Before W11, ngx_autocert_fstat()/ngx_autocert_fstatat() on win32 fabricated
 * st_mode as a CONSTANT S_IFREG|0600 regardless of the file's real ACL, which
 * made ngx_autocert_account.c's "reject an account key with group/other
 * permission bits" guard (account.c:276-283) a tautology on win32: a
 * world-readable private key always passed. This function is the security
 * decision that closes that gap -- given the caller's walk of every ACE in
 * the file's real DACL, reduced to (is_owner, is_allow, is_tolerated, is_write, is_write) tuples,
 * it decides whether the group/other bits the guard checks should be SET
 * (reject) or clear (accept).
 *
 * It has no win32-header dependency (plain ngx_int_t arrays and a count), so
 * it is compiled unconditionally in ngx_autocert_shared.h and this suite
 * calls the REAL production function on Linux -- the only host these tests
 * can run on -- exercising the exact decision the win32 build's ACE walk
 * feeds it, not a hand-copied stand-in that could silently drift from it.
 *
 * Exit 0 = all pass; non-zero on first failure count.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>

#include "../../../src/ngx_autocert_shared.h"


/* Link stub: ngx_core.h expects ngx_cycle to exist for anything that pulls
 * in ngx_log.h macros, even though this test never triggers a log call. */
volatile ngx_cycle_t  *ngx_cycle;


static int  failures;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


int
main(void)
{
    ngx_autocert_mode_t  bits;
    ngx_int_t             is_owner[4] = {0}, is_allow[4] = {0},
                           is_tolerated[4] = {0}, is_write[4] = {0};
    ngx_autocert_mode_t   full, rdonly;
    ngx_uint_t            i;

    full = (ngx_autocert_mode_t) (S_IRWXG | S_IRWXO);
    rdonly = (ngx_autocert_mode_t) (S_IRGRP | S_IROTH);

    /* Every legacy case below models the pre-mask world where a foreign
     * ALLOW was full control; is_write=1 keeps their expectations intact. */
    for (i = 0; i < 4; i++) {
        is_write[i] = 1;
    }

    /* 1. Empty ACE list (n == 0): NOT "no exposure found" -- treated as
     * unexpectedly empty and flagged, per the function's documented
     * "an unexpectedly empty ACE list from a live DACL is itself worth
     * flagging" contract. A real owner-only DACL always has at least the
     * owner's own ACE, so an empty walk here is itself suspicious. */
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, is_write, 0);
    CHECK(bits == (ngx_autocert_mode_t) (S_IRWXG | S_IRWXO),
          "empty ACE list -> flagged (fail closed, not treated as safe)");

    /* 2. Single ALLOW ACE, owner's own SID: the textbook safe case this
     * whole feature exists to recognise as SAFE -- ngx_autocert_fchmod()'s
     * owner-only DACL (0600) round-tripping through this decision core. */
    is_owner[0] = 1; is_allow[0] = 1; is_tolerated[0] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, is_write, 1);
    CHECK(bits == 0, "single owner ALLOW ace -> 0 (owner-only DACL, safe)");

    /* 3. Single ALLOW ACE, a non-owner, non-tolerated SID (e.g. "Users" or
     * "Everyone" inherited from the parent directory): THIS is the exposure
     * account.c's guard exists to catch -- a world-readable private key.
     * Must flag. */
    is_owner[0] = 0; is_allow[0] = 1; is_tolerated[0] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, is_write, 1);
    CHECK(bits == (ngx_autocert_mode_t) (S_IRWXG | S_IRWXO),
          "non-owner, non-tolerated ALLOW ace -> flagged (exposed key)");

    /* 4. Single DENY ACE for a non-owner SID: a DENY ace grants nothing, so
     * it is not evidence of exposure by itself -- must NOT flag on a DENY
     * alone. (A DACL consisting of only a DENY ace with no ALLOW ace grants
     * no access to anyone but the implicit owner outside the DACL, which
     * this decision core cannot see either way; the point of this case is
     * narrower: a DENY entry must never be misread as an ALLOW.) */
    is_owner[0] = 0; is_allow[0] = 0; is_tolerated[0] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, is_write, 1);
    CHECK(bits == 0, "non-owner DENY ace alone -> 0 (DENY grants nothing)");

    /* 5. Owner ALLOW plus a DENY for a stranger: still safe -- the DENY
     * changes nothing about what's granted, and the only ALLOW is the
     * owner's. */
    is_owner[0] = 1; is_allow[0] = 1; is_tolerated[0] = 0;
    is_owner[1] = 0; is_allow[1] = 0; is_tolerated[1] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, is_write, 2);
    CHECK(bits == 0, "owner ALLOW + stranger DENY -> 0 (still owner-only)");

    /* 6. Owner ALLOW plus SYSTEM/Administrators ALLOW (is_tolerated=1): the
     * DECIDED tolerance -- SYSTEM and local Administrators can read any file
     * on the box regardless of this DACL, so flagging them would make the
     * guard permanently unusable without adding real security. Must NOT
     * flag. */
    is_owner[0] = 1; is_allow[0] = 1; is_tolerated[0] = 0;
    is_owner[1] = 0; is_allow[1] = 1; is_tolerated[1] = 1;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, is_write, 2);
    CHECK(bits == 0,
          "owner ALLOW + tolerated (SYSTEM/Administrators) ALLOW -> 0");

    /* 7. Owner ALLOW plus one exposing stranger ALLOW among several
     * tolerated/owner entries: one bad ACE anywhere in the list must flag
     * the whole DACL -- this is a security property, not "flag only if
     * every ACE is bad". */
    is_owner[0] = 1; is_allow[0] = 1; is_tolerated[0] = 0;
    is_owner[1] = 0; is_allow[1] = 1; is_tolerated[1] = 1;
    is_owner[2] = 0; is_allow[2] = 1; is_tolerated[2] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, is_write, 3);
    CHECK(bits == (ngx_autocert_mode_t) (S_IRWXG | S_IRWXO),
          "one exposing ALLOW among otherwise-safe aces -> flagged (any bad "
          "ace flags the whole DACL)");

    /* 8. Tolerated ALLOW without any owner ACE at all (owner ACE absent,
     * only SYSTEM/Administrators grant access): still safe by the same
     * decided-tolerance rule -- is_owner is irrelevant once is_tolerated is
     * true. */
    is_owner[0] = 0; is_allow[0] = 1; is_tolerated[0] = 1;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, is_write, 1);
    CHECK(bits == 0, "tolerated ALLOW with no owner ace present -> 0");

    /* 9. THE #241 blocker: a foreign ALLOW that grants READ only (the
     * Users / Authenticated Users read ACE every directory under a stock
     * Windows tree inherits). Must map to the READ bits only — enough for
     * check_owner_mode(secret=1) to still refuse a readable KEY, and
     * exactly what check_owner_mode(secret=0) accepts for the store
     * DIRECTORY, the same way a 0755 directory is accepted on POSIX. Before
     * the mask was read this returned full bits and refused every store. */
    is_owner[0] = 1; is_allow[0] = 1; is_tolerated[0] = 0; is_write[0] = 1;
    is_owner[1] = 0; is_allow[1] = 1; is_tolerated[1] = 0; is_write[1] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated,
                                        is_write, 2);
    CHECK(bits == rdonly,
          "owner ALLOW + read-only foreign ALLOW -> read bits only");
    CHECK((bits & (S_IWGRP | S_IWOTH)) == 0,
          "read-only foreign ALLOW is accepted by the store-dir guard "
          "(secret=0)");
    CHECK((bits & (S_IRWXG | S_IRWXO)) != 0,
          "read-only foreign ALLOW is still refused by the secret guard "
          "(secret=1)");

    /* 10. Read-only foreign ALLOW followed by a WRITE foreign ALLOW: one
     * write grant anywhere escalates the whole DACL to the full bits; the
     * earlier read-only reading must not stick. */
    is_owner[0] = 0; is_allow[0] = 1; is_tolerated[0] = 0; is_write[0] = 0;
    is_owner[1] = 0; is_allow[1] = 1; is_tolerated[1] = 0; is_write[1] = 1;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated,
                                        is_write, 2);
    CHECK(bits == full, "read-only then write foreign ALLOW -> full bits");

    /* 11. Order reversed: write first, then read-only. Same answer. */
    is_write[0] = 1; is_write[1] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated,
                                        is_write, 2);
    CHECK(bits == full, "write then read-only foreign ALLOW -> full bits");

    /* 12. A DENY ACE carrying a write mask grants nothing: is_write on a
     * DENY must be ignored, not read as a write grant. */
    is_owner[0] = 1; is_allow[0] = 1; is_tolerated[0] = 0; is_write[0] = 1;
    is_owner[1] = 0; is_allow[1] = 0; is_tolerated[1] = 0; is_write[1] = 1;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated,
                                        is_write, 2);
    CHECK(bits == 0, "owner ALLOW + write-mask DENY -> 0 (DENY grants nothing)");

    /* 13. A tolerated (SYSTEM/Administrators) ALLOW with a write mask is
     * still tolerated: the decided tolerance is about the principal, not
     * the mask. */
    is_owner[0] = 1; is_allow[0] = 1; is_tolerated[0] = 0; is_write[0] = 1;
    is_owner[1] = 0; is_allow[1] = 1; is_tolerated[1] = 1; is_write[1] = 1;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated,
                                        is_write, 2);
    CHECK(bits == 0, "owner ALLOW + tolerated write ALLOW -> 0");

    /* 14. The mask classifier itself, against the stock Windows templates
     * and each individual write-ish right. Literal masks, since this test
     * has no <windows.h>; the win32 build static-asserts the literal
     * against the SDK constants. */
    CHECK(ngx_autocert_win32_mask_is_write(0x00120089u) == 0,
          "\"Read\" template (0x120089) -> not write");
    CHECK(ngx_autocert_win32_mask_is_write(0x001200A9u) == 0,
          "\"Read & execute\" template (0x1200A9) -> not write");
    CHECK(ngx_autocert_win32_mask_is_write(0x80000000u) == 0,
          "GENERIC_READ alone -> not write");
    CHECK(ngx_autocert_win32_mask_is_write(0x20000000u) == 0,
          "GENERIC_EXECUTE alone -> not write");
    CHECK(ngx_autocert_win32_mask_is_write(0x00100000u) == 0,
          "SYNCHRONIZE alone -> not write");
    CHECK(ngx_autocert_win32_mask_is_write(0u) == 0, "empty mask -> not write");
    CHECK(ngx_autocert_win32_mask_is_write(0x001301BFu) == 1,
          "\"Modify\" template (0x1301BF) -> write");
    CHECK(ngx_autocert_win32_mask_is_write(0x001F01FFu) == 1,
          "FILE_ALL_ACCESS (0x1F01FF) -> write");
    CHECK(ngx_autocert_win32_mask_is_write(0x00100116u) == 1,
          "\"Write\" template (0x100116) -> write");
    CHECK(ngx_autocert_win32_mask_is_write(0x00000002u) == 1,
          "FILE_WRITE_DATA / FILE_ADD_FILE alone -> write");
    CHECK(ngx_autocert_win32_mask_is_write(0x00000004u) == 1,
          "FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY alone -> write");
    CHECK(ngx_autocert_win32_mask_is_write(0x00000040u) == 1,
          "FILE_DELETE_CHILD alone -> write");
    CHECK(ngx_autocert_win32_mask_is_write(0x00010000u) == 1,
          "DELETE alone -> write");
    CHECK(ngx_autocert_win32_mask_is_write(0x00040000u) == 1,
          "WRITE_DAC alone -> write");
    CHECK(ngx_autocert_win32_mask_is_write(0x00080000u) == 1,
          "WRITE_OWNER alone -> write");
    CHECK(ngx_autocert_win32_mask_is_write(0x40000000u) == 1,
          "GENERIC_WRITE alone -> write");
    CHECK(ngx_autocert_win32_mask_is_write(0x10000000u) == 1,
          "GENERIC_ALL alone -> write");

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall win32 DACL-mode checks passed\n");
    return 0;
}
