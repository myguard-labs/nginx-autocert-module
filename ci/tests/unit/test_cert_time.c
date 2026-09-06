/*
 * Unit tests for the crypto TU's certificate-expiry helpers (M8 renewal):
 *   - ngx_http_autocert_cert_not_after(path, &out, &key_id, verify_name, &test_log) — read a
 *     leaf PEM's notAfter as a Unix epoch; ENOENT/ENOTDIR -> NGX_DECLINED, a
 *     symlinked path -> NGX_ERROR (O_NOFOLLOW), other failures -> NGX_ERROR; a
 *     non-NULL verify_name the leaf does not cover -> NGX_ABORT (M2).
 *   - ngx_autocert_timegm(struct tm*) — a self-contained, timezone-independent
 *     UTC tm -> time_t, exercised with a leap day and a year past 2038.
 *
 * ngx_autocert_timegm is static, so this TU include-shims the whole crypto .c
 * (the same source the server compiles) to reach it — no production hook and no
 * copy drift. The PEM fixture is ci/tests/unit/fixture_leaf.pem (notAfter 2099-12-31
 * 23:59:59Z, epoch 4102444799 — past 2038 to exercise 64-bit time_t).
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

/* Log + cycle stubs the crypto TU references; define BEFORE including it. */
volatile ngx_cycle_t  *ngx_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

/* Include-shim: pulls in the static ngx_autocert_timegm + the public
 * ngx_http_autocert_cert_not_after, compiled exactly as shipped. */
#include "../../../src/ngx_http_autocert_crypto.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>


static int  failures;

/* Minimal real ngx_log_t so ngx_log_error(...)'s (log)->log_level check
 * dereferences a valid object instead of NULL; ngx_log_error_core above is
 * stubbed to a no-op so nothing actually prints. */
static ngx_log_t  test_log = { .log_level = NGX_LOG_DEBUG_ALL };

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


/* The committed fixture; epoch of its notAfter (2099-12-31T23:59:59Z). */
#define FIXTURE_PATH   "ci/tests/unit/fixture_leaf.pem"
#define FIXTURE_EPOCH  ((time_t) 4102444799)


static void
test_timegm_vectors(void)
{
    struct tm  tm;

    struct {
        int  y, mon, mday, h, mi, s;
        time_t expect;
        const char *msg;
    } v[] = {
        /* epoch itself */
        { 1970,  1,  1,  0,  0,  0,          0, "timegm epoch 1970-01-01" },
        /* a known value: 2001-09-09T01:46:40Z == 1000000000 */
        { 2001,  9,  9,  1, 46, 40, 1000000000, "timegm 2001-09-09 == 1e9" },
        /* leap day 2024-02-29 (2024 IS a leap year) */
        { 2024,  2, 29, 12,  0,  0, 1709208000, "timegm leap day 2024-02-29" },
        /* A year past 2038: on a 64-bit time_t this must compute exactly (and
         * NOT be clamped to -1 by the 32-bit overflow guard); on a 32-bit
         * time_t the guard would return -1 instead of wrapping. 2099-12-31. */
        { 2099, 12, 31, 23, 59, 59, 4102444799, "timegm 2099 (> 2038)" },
    };
    size_t  i;

    for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        memset(&tm, 0, sizeof(tm));
        tm.tm_year = v[i].y - 1900;
        tm.tm_mon  = v[i].mon - 1;
        tm.tm_mday = v[i].mday;
        tm.tm_hour = v[i].h;
        tm.tm_min  = v[i].mi;
        tm.tm_sec  = v[i].s;
        CHECK(ngx_autocert_timegm(&tm) == v[i].expect, v[i].msg);
    }

    /* cross-check against libc timegm for a sweep of dates */
    {
        int  ok = 1;
        struct tm  t;
        time_t years[] = { 1971, 1999, 2000, 2016, 2038, 2040, 2100, 2400 };
        size_t k;
        for (k = 0; k < sizeof(years) / sizeof(years[0]); k++) {
            memset(&t, 0, sizeof(t));
            t.tm_year = (int) years[k] - 1900;
            t.tm_mon = 5; t.tm_mday = 15; t.tm_hour = 6;
            t.tm_min = 7; t.tm_sec = 8;
            if (ngx_autocert_timegm(&t) != timegm(&t)) {
                ok = 0;
            }
        }
        CHECK(ok, "timegm matches libc timegm across a year sweep");
    }

    /* out-of-range year => (time_t) -1 */
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = 10000 - 1900;     /* y == 10000 > 9999 */
    tm.tm_mon = 0; tm.tm_mday = 1;
    CHECK(ngx_autocert_timegm(&tm) == (time_t) -1,
          "timegm rejects out-of-range year");

    /* boundary: year == 9999 is IN range (the guard is "> 9999", not ">="),
     * and must match libc timegm exactly -- catches a mutation that widens
     * the rejection to ">= 9999".
     *
     * The comparison alone is NOT a sufficient oracle: where time_t is too
     * narrow to represent year 9999 (32-bit time_t), libc timegm also returns
     * (time_t) -1, so a ">= 9999" mutation would compare -1 == -1 and PASS.
     * Require the libc reference to be representable before asserting the
     * match; skip explicitly otherwise, rather than assert a tautology. */
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = 9999 - 1900;
    tm.tm_mon = 11; tm.tm_mday = 31; tm.tm_hour = 23; tm.tm_min = 59; tm.tm_sec = 59;
    {
        struct tm  ref = tm;
        time_t     libc_ref = timegm(&ref);

        if (libc_ref == (time_t) -1) {
            fprintf(stderr,
                    "skip: year 9999 not representable in time_t "
                    "(%zu-bit) -- boundary oracle would be a tautology\n",
                    sizeof(time_t) * 8);
        } else {
            time_t  got = ngx_autocert_timegm(&tm);

            CHECK(got != (time_t) -1 && got == libc_ref,
                  "timegm accepts year == 9999 (upper boundary is inclusive)");
        }
    }
}


static void
test_cert_not_after(void)
{
    time_t  out = 0;
    int     key_id = EVP_PKEY_NONE;

    CHECK(ngx_http_autocert_cert_not_after(FIXTURE_PATH, &out, &key_id, NULL, NULL, &test_log)
              == NGX_OK
          && out == FIXTURE_EPOCH,
          "cert_not_after reads the fixture's exact notAfter epoch");

    /* The fixture leaf is EC (id-ecPublicKey); the key_id out-param reports it. */
    CHECK(key_id == EVP_PKEY_EC,
          "cert_not_after reports the leaf key family (EC) via key_id");

    /* key_id is optional: a NULL pointer must be accepted. */
    out = 0;
    CHECK(ngx_http_autocert_cert_not_after(FIXTURE_PATH, &out, NULL, NULL, NULL, &test_log) == NGX_OK
          && out == FIXTURE_EPOCH,
          "cert_not_after accepts a NULL key_id out-param");

    /* M2 SAN/identity check. The fixture has CN=fixture.example, no SAN;
     * X509_check_host falls back to the CN. A matching verify_name passes; a
     * wrong name returns NGX_ABORT so the scheduler reissues. */
    {
        ngx_str_t  good = ngx_string("fixture.example");
        ngx_str_t  bad  = ngx_string("wrong.example");
        ngx_str_t  empty = ngx_null_string;

        out = 0;
        CHECK(ngx_http_autocert_cert_not_after(FIXTURE_PATH, &out, NULL, &good, NULL, &test_log)
                  == NGX_OK
              && out == FIXTURE_EPOCH,
              "cert_not_after accepts a leaf that covers verify_name");

        out = 0;
        CHECK(ngx_http_autocert_cert_not_after(FIXTURE_PATH, &out, NULL, &bad, NULL, &test_log)
                  == NGX_ABORT,
              "cert_not_after returns NGX_ABORT for a wrong-domain leaf");

        /* An empty verify_name is treated as "no check". */
        out = 0;
        CHECK(ngx_http_autocert_cert_not_after(FIXTURE_PATH, &out, NULL, &empty, NULL, &test_log)
                  == NGX_OK,
              "cert_not_after skips the identity check for an empty verify_name");
    }

    /* Missing file -> NGX_DECLINED (no cert stored yet). */
    out = 0;
    CHECK(ngx_http_autocert_cert_not_after("ci/tests/unit/does-not-exist.pem", &out, NULL, NULL, NULL, &test_log)
              == NGX_DECLINED,
          "cert_not_after missing file -> NGX_DECLINED");

    /* Symlink to the fixture -> NGX_ERROR (O_NOFOLLOW refuses to traverse). */
    {
        char  link[] = "/tmp/autocert_test_link_XXXXXX";
        int   fd = mkstemp(link);
        char  abs_target[4096];

        if (fd != -1) {
            close(fd);
            unlink(link);
            if (realpath(FIXTURE_PATH, abs_target) != NULL
                && symlink(abs_target, link) == 0)
            {
                out = 0;
                CHECK(ngx_http_autocert_cert_not_after(link, &out, NULL, NULL, NULL, &test_log) == NGX_ERROR,
                      "cert_not_after refuses to follow a symlink (O_NOFOLLOW)");
                unlink(link);
            } else {
                CHECK(0, "could not set up symlink fixture");
            }
        } else {
            CHECK(0, "could not create temp path for symlink fixture");
        }
    }
}


/*
 * serve.c and order.c both gate a loaded leaf's validity window with:
 *
 *   if (X509_cmp_current_time(notBefore) >= 0
 *       || X509_cmp_current_time(notAfter) <= 0)
 *       -> reject
 *
 * X509_cmp_current_time() returns 0 on a parse ERROR for the ASN1_TIME, not
 * "equal to now" -- a >0/<0-only check would silently treat a malformed
 * notBefore/notAfter as valid.
 *
 * The guard itself is inline in two large static server functions this TU
 * cannot reach, so it is mirrored here as two functions with the SHIPPED and
 * the PRE-FIX shapes, and both are driven with the same inputs. That makes the
 * negative control a real one: `window_pre_fix` is the code that used to ship,
 * and the test asserts it ACCEPTS the malformed time the fixed shape rejects.
 * If someone reverts serve.c/order.c to the >0/<0 spelling, the mirrored
 * `window_fixed` must be reverted with it or the two disagree here.
 */

/* The shape now shipping in serve.c:1268 and order.c:2236. */
static int
window_fixed(int nb, int na)
{
    return (nb >= 0 || na <= 0) ? 0 : 1;   /* 0 = reject, 1 = accept */
}


/* The shape that shipped before this fix. */
static int
window_pre_fix(int nb, int na)
{
    return (nb > 0 || na < 0) ? 0 : 1;
}


/*
 * Pair check (key_path): the freshness path must treat a stored chain whose
 * private key does not match as DUE, not fresh.
 *
 * This is the regression guard for a silent multi-week outage: the store
 * publishes privkey and fullchain as two files, so a crash mid-commit or a
 * partially restored backup can leave a NEW key beside an OLD-but-valid
 * chain. That chain parses, covers the name, has the right key family and is
 * not yet in its renew window, so before this check every freshness test read
 * it as fresh and no reissue was ever scheduled -- while the serve path
 * refused the mismatched pair on every handshake and served nothing.
 *
 * Both PEMs are generated here rather than committed so the test carries no
 * private key in the repo, and so the MATCHING and MISMATCHED cases come from
 * the same generator (a committed pair could drift out of sync silently).
 */
static int
write_pem_key(const char *path, EVP_PKEY *k)
{
    FILE *f = fopen(path, "wb");
    int   ok;

    if (f == NULL) {
        return 0;
    }
    ok = PEM_write_PrivateKey(f, k, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    return ok == 1;
}


static EVP_PKEY *
gen_ec_key(void)
{
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if (c == NULL) {
        return NULL;
    }
    if (EVP_PKEY_keygen_init(c) == 1
        && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, NID_X9_62_prime256v1) == 1)
    {
        (void) EVP_PKEY_keygen(c, &k);
    }
    EVP_PKEY_CTX_free(c);
    return k;
}


static void
test_cmp_current_time_zero_is_rejected(void)
{
    ASN1_TIME  *bad = ASN1_STRING_new();
    ASN1_TIME  *past = ASN1_TIME_new();
    ASN1_TIME  *future = ASN1_TIME_new();
    int         r_bad, r_past, r_future;

    CHECK(bad != NULL && past != NULL && future != NULL,
          "allocated the ASN1_TIME probes");
    if (bad == NULL || past == NULL || future == NULL) {
        return;
    }

    /* Not a valid UTCTime/GeneralizedTime payload -> parse failure. */
    ASN1_STRING_set(bad, "not-a-time", -1);
    ASN1_TIME_set(past, (time_t) 0);            /* 1970, well in the past */
    ASN1_TIME_set(future, (time_t) 4102444800); /* 2100, well in the future */

    r_bad = X509_cmp_current_time(bad);
    r_past = X509_cmp_current_time(past);
    r_future = X509_cmp_current_time(future);

    /* The premise the whole fix rests on: 0 means "could not parse", and a
     * parseable time never yields 0 -- not even one equal to now. */
    CHECK(r_bad == 0,
          "X509_cmp_current_time returns 0 on a malformed ASN1_TIME");
    CHECK(r_past < 0, "a past time compares < 0, never 0");
    CHECK(r_future > 0, "a future time compares > 0, never 0");

    /* A genuinely valid window (notBefore in the past, notAfter in the
     * future) must still be ACCEPTED -- the fix must not over-reject. */
    CHECK(window_fixed(r_past, r_future) == 1,
          "fixed guard still accepts a valid notBefore/notAfter window");

    /* A malformed notBefore is rejected by the fixed guard... */
    CHECK(window_fixed(r_bad, r_future) == 0,
          "fixed guard rejects a malformed notBefore");
    CHECK(window_fixed(r_past, r_bad) == 0,
          "fixed guard rejects a malformed notAfter");

    /* ...and NEGATIVE CONTROL: the pre-fix guard accepted both, which is the
     * exact gap this change closes. If these two go green-as-reject, the
     * control has stopped controlling and this test is worthless. */
    CHECK(window_pre_fix(r_bad, r_future) == 1,
          "NEGATIVE CONTROL: pre-fix guard ACCEPTED a malformed notBefore");
    CHECK(window_pre_fix(r_past, r_bad) == 1,
          "NEGATIVE CONTROL: pre-fix guard ACCEPTED a malformed notAfter");

    /* Both shapes must agree on unambiguous, parseable input, so the fix is
     * a strictly narrower accept -- not a behaviour change for good certs. */
    CHECK(window_fixed(r_past, r_future) == window_pre_fix(r_past, r_future),
          "fixed and pre-fix guards agree on a valid window");
    CHECK(window_fixed(r_future, r_future) == window_pre_fix(r_future, r_future),
          "fixed and pre-fix guards agree on a not-yet-valid certificate");
    CHECK(window_fixed(r_past, r_past) == window_pre_fix(r_past, r_past),
          "fixed and pre-fix guards agree on an expired certificate");

    ASN1_STRING_free(bad);
    ASN1_TIME_free(past);
    ASN1_TIME_free(future);
}


static void
test_cert_pair_check(void)
{
    EVP_PKEY  *key = gen_ec_key();
    EVP_PKEY  *other = gen_ec_key();
    X509      *leaf = NULL;
    char       cert_p[] = "/tmp/autocert_pair_cert_XXXXXX";
    char       key_p[]  = "/tmp/autocert_pair_key_XXXXXX";
    char       oth_p[]  = "/tmp/autocert_pair_oth_XXXXXX";
    int        fd_c, fd_k, fd_o;
    time_t     out = 0;
    FILE      *f;

    if (key == NULL || other == NULL) {
        CHECK(0, "could not generate EC keys for the pair fixture");
        goto cleanup;
    }

    fd_c = mkstemp(cert_p); fd_k = mkstemp(key_p); fd_o = mkstemp(oth_p);
    if (fd_c == -1 || fd_k == -1 || fd_o == -1) {
        CHECK(0, "could not create temp paths for the pair fixture");
        goto cleanup;
    }
    close(fd_c); close(fd_k); close(fd_o);

    /* Self-signed leaf bound to `key`, valid far in the future so nothing
     * except the pair check can make it read as due. */
    leaf = X509_new();
    if (leaf == NULL
        || X509_set_version(leaf, 2) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(leaf), 1) != 1
        || X509_gmtime_adj(X509_getm_notBefore(leaf), -3600) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(leaf), 365 * 24 * 3600) == NULL
        || X509_set_pubkey(leaf, key) != 1
        || X509_sign(leaf, key, EVP_sha256()) == 0)
    {
        CHECK(0, "could not build the self-signed pair fixture leaf");
        goto cleanup;
    }

    f = fopen(cert_p, "wb");
    if (f == NULL || PEM_write_X509(f, leaf) != 1) {
        if (f != NULL) { fclose(f); }
        CHECK(0, "could not write the pair fixture leaf");
        goto cleanup;
    }
    fclose(f);

    if (!write_pem_key(key_p, key) || !write_pem_key(oth_p, other)) {
        CHECK(0, "could not write the pair fixture keys");
        goto cleanup;
    }

    /* Matching pair: unchanged behaviour, still fresh (NGX_OK). This is the
     * control that keeps the check from reading as due for everyone. */
    out = 0;
    CHECK(ngx_http_autocert_cert_not_after(cert_p, &out, NULL, NULL, key_p, &test_log)
              == NGX_OK && out > 0,
          "cert_not_after accepts a chain whose stored key matches");

    /* Mismatched pair -> NGX_ABORT, which the scheduler routes to reissue. */
    out = 0;
    CHECK(ngx_http_autocert_cert_not_after(cert_p, &out, NULL, NULL, oth_p, &test_log)
              == NGX_ABORT,
          "cert_not_after returns NGX_ABORT for a mismatched key/chain pair");

    /* Absent key beside a valid chain is equally unserveable -> reissue. */
    out = 0;
    CHECK(ngx_http_autocert_cert_not_after(cert_p, &out, NULL, NULL,
                                           "/tmp/autocert-no-such-key.pem", &test_log)
              == NGX_ABORT,
          "cert_not_after returns NGX_ABORT when the stored key is missing");

    /* A NULL key_path skips the pair check entirely (back-compat). */
    out = 0;
    CHECK(ngx_http_autocert_cert_not_after(cert_p, &out, NULL, NULL, NULL, &test_log)
              == NGX_OK,
          "cert_not_after skips the pair check when key_path is NULL");

    /* A key_path that fails to open with a NON-ENOENT errno (here: EACCES
     * from a mode-0000 file) must NOT be treated as a torn pair. Before the
     * fix this collapsed every open() errno to NGX_ABORT, which on win32 is
     * reachable from the publish path itself (a sharing violation while a
     * rename is in flight) and would trigger a spurious real ACME reissue.
     * The correct outcome is the pair check being SKIPPED, so the overall
     * call still reports NGX_OK (the chain itself is fresh and valid). Skips
     * gracefully when running as root, where chmod 0000 does not deny
     * self-open. */
    if (geteuid() == 0) {
        fprintf(stderr,
                "skip: running as root, chmod 0000 would not deny open() -- "
                "non-ENOENT key_path errno test needs a non-root user\n");
    } else {
        char  noperm_p[] = "/tmp/autocert_pair_noperm_XXXXXX";
        int   fd_n = mkstemp(noperm_p);

        CHECK(fd_n != -1, "could not create the no-permission key fixture");
        if (fd_n != -1) {
            close(fd_n);
            CHECK(chmod(noperm_p, 0000) == 0,
                  "could not chmod the no-permission key fixture to 0000");

            out = 0;
            CHECK(ngx_http_autocert_cert_not_after(cert_p, &out, NULL, NULL,
                                                   noperm_p, &test_log)
                      == NGX_OK,
                  "cert_not_after does NOT abort on a non-ENOENT (EACCES) "
                  "key_path open failure -- the pair check is skipped, not "
                  "treated as a torn pair");

            chmod(noperm_p, 0600);
            unlink(noperm_p);
        }
    }

cleanup:
    /* Below the label so an early `goto cleanup` (failed keygen, failed leaf
     * build, failed PEM write) still removes whatever mkstemp() created. An
     * unexpanded XXXXXX template just yields ENOENT, which is harmless. */
    unlink(cert_p); unlink(key_p); unlink(oth_p);
    if (leaf != NULL)  { X509_free(leaf); }
    if (key != NULL)   { EVP_PKEY_free(key); }
    if (other != NULL) { EVP_PKEY_free(other); }
}


int
main(void)
{
    /* timegm path needs ngx_time initialised? It does not, but harmless. */
    ngx_time_init();

    test_timegm_vectors();
    test_cert_not_after();
    test_cmp_current_time_zero_is_rejected();
    test_cert_pair_check();

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
