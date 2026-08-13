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
 * the file's real DACL, reduced to (is_owner, is_allow, is_tolerated) tuples,
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
                           is_tolerated[4] = {0};

    /* 1. Empty ACE list (n == 0): NOT "no exposure found" -- treated as
     * unexpectedly empty and flagged, per the function's documented
     * "an unexpectedly empty ACE list from a live DACL is itself worth
     * flagging" contract. A real owner-only DACL always has at least the
     * owner's own ACE, so an empty walk here is itself suspicious. */
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, 0);
    CHECK(bits == (ngx_autocert_mode_t) (S_IRWXG | S_IRWXO),
          "empty ACE list -> flagged (fail closed, not treated as safe)");

    /* 2. Single ALLOW ACE, owner's own SID: the textbook safe case this
     * whole feature exists to recognise as SAFE -- ngx_autocert_fchmod()'s
     * owner-only DACL (0600) round-tripping through this decision core. */
    is_owner[0] = 1; is_allow[0] = 1; is_tolerated[0] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, 1);
    CHECK(bits == 0, "single owner ALLOW ace -> 0 (owner-only DACL, safe)");

    /* 3. Single ALLOW ACE, a non-owner, non-tolerated SID (e.g. "Users" or
     * "Everyone" inherited from the parent directory): THIS is the exposure
     * account.c's guard exists to catch -- a world-readable private key.
     * Must flag. */
    is_owner[0] = 0; is_allow[0] = 1; is_tolerated[0] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, 1);
    CHECK(bits == (ngx_autocert_mode_t) (S_IRWXG | S_IRWXO),
          "non-owner, non-tolerated ALLOW ace -> flagged (exposed key)");

    /* 4. Single DENY ACE for a non-owner SID: a DENY ace grants nothing, so
     * it is not evidence of exposure by itself -- must NOT flag on a DENY
     * alone. (A DACL consisting of only a DENY ace with no ALLOW ace grants
     * no access to anyone but the implicit owner outside the DACL, which
     * this decision core cannot see either way; the point of this case is
     * narrower: a DENY entry must never be misread as an ALLOW.) */
    is_owner[0] = 0; is_allow[0] = 0; is_tolerated[0] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, 1);
    CHECK(bits == 0, "non-owner DENY ace alone -> 0 (DENY grants nothing)");

    /* 5. Owner ALLOW plus a DENY for a stranger: still safe -- the DENY
     * changes nothing about what's granted, and the only ALLOW is the
     * owner's. */
    is_owner[0] = 1; is_allow[0] = 1; is_tolerated[0] = 0;
    is_owner[1] = 0; is_allow[1] = 0; is_tolerated[1] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, 2);
    CHECK(bits == 0, "owner ALLOW + stranger DENY -> 0 (still owner-only)");

    /* 6. Owner ALLOW plus SYSTEM/Administrators ALLOW (is_tolerated=1): the
     * DECIDED tolerance -- SYSTEM and local Administrators can read any file
     * on the box regardless of this DACL, so flagging them would make the
     * guard permanently unusable without adding real security. Must NOT
     * flag. */
    is_owner[0] = 1; is_allow[0] = 1; is_tolerated[0] = 0;
    is_owner[1] = 0; is_allow[1] = 1; is_tolerated[1] = 1;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, 2);
    CHECK(bits == 0,
          "owner ALLOW + tolerated (SYSTEM/Administrators) ALLOW -> 0");

    /* 7. Owner ALLOW plus one exposing stranger ALLOW among several
     * tolerated/owner entries: one bad ACE anywhere in the list must flag
     * the whole DACL -- this is a security property, not "flag only if
     * every ACE is bad". */
    is_owner[0] = 1; is_allow[0] = 1; is_tolerated[0] = 0;
    is_owner[1] = 0; is_allow[1] = 1; is_tolerated[1] = 1;
    is_owner[2] = 0; is_allow[2] = 1; is_tolerated[2] = 0;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, 3);
    CHECK(bits == (ngx_autocert_mode_t) (S_IRWXG | S_IRWXO),
          "one exposing ALLOW among otherwise-safe aces -> flagged (any bad "
          "ace flags the whole DACL)");

    /* 8. Tolerated ALLOW without any owner ACE at all (owner ACE absent,
     * only SYSTEM/Administrators grant access): still safe by the same
     * decided-tolerance rule -- is_owner is irrelevant once is_tolerated is
     * true. */
    is_owner[0] = 0; is_allow[0] = 1; is_tolerated[0] = 1;
    bits = ngx_autocert_win32_dacl_mode(is_owner, is_allow, is_tolerated, 1);
    CHECK(bits == 0, "tolerated ALLOW with no owner ace present -> 0");

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall win32 DACL-mode checks passed\n");
    return 0;
}
