/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the config-time name/contact validators (audit MINOR):
 *   - ngx_autocert_dns_name_valid() (ngx_autocert_ident.h) — LDH/length shape
 *     check for an issuable server_name/autocert_wildcard value, called from
 *     ngx_http_autocert_add_name() (ngx_http_autocert_module.c) before the
 *     name is embedded verbatim, unescaped, in the ACME newOrder JSON
 *     (ngx_autocert_order_new_order) and used as a filesystem path segment.
 *   - ngx_autocert_account_json_safe() (ngx_autocert_account.c, exposed via
 *     ngx_autocert_account.h) — reused here for the SAME config-time gate on
 *     autocert_contact, so a JSON-unsafe contact email fails `nginx -t`
 *     instead of surfacing only as a runtime newAccount POST error.
 *
 * Both a wildcard name ("*.example.com") and a punycode/IDNA label
 * ("xn--...") MUST still be accepted — that negative-space case is the one
 * an over-strict validator here would break, taking a working config down.
 *
 * ngx_autocert_dns_name_valid is `static ngx_inline` in a header shared
 * across the CORE/HTTP modules and the standalone crypto unit tests (same
 * file ngx_autocert_str_is_ip lives in, exercised by test_ipident.c) — no
 * extraction needed, this TU just includes it. ngx_autocert_account_json_safe
 * is declared non-static in ngx_autocert_account.h; this TU links its
 * definition via the same slice extract_jsonsafe.sh produces for
 * test_account_jsonsafe.c, rather than the whole account state machine.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

/* Log + cycle stubs referenced by the linked nginx string/inet objects and
 * by ngx_autocert_account.c's error paths (never exercised for real here). */
volatile ngx_cycle_t  *ngx_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

#include "src/ngx_http_autocert_conf.h"  /* ngx_autocert_ident.h */

/*
 * Only json_safe is used here. log_safe is `static` in production, so pulling
 * its slice in unused would trip -Werror=unused-function and would also drag
 * ngx_escape_json into the link, which this TU does not link ngx_string.o for.
 */
#define NGX_AUTOCERT_SLICE_SKIP_ngx_autocert_account_log_safe

#include "generated_jsonsafe.inc" /* ngx_autocert_account_json_safe */

#include <stdio.h>
#include <string.h>


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


#define STR(s)  { sizeof(s) - 1, (u_char *) (s) }


static int
name_ok(const char *lit)
{
    ngx_str_t  s;
    s.data = (u_char *) lit;
    s.len = ngx_strlen(lit);
    return (int) ngx_autocert_dns_name_valid(&s);
}

static int
email_ok(const char *lit)
{
    ngx_str_t  s;
    s.data = (u_char *) lit;
    s.len = ngx_strlen(lit);
    return (int) ngx_autocert_account_json_safe(&s);
}


int
main(void)
{
    /* --- accepted: ordinary concrete names --- */
    CHECK(name_ok("example.com") == 1, "accepts a plain domain");
    CHECK(name_ok("a.b.example.com") == 1, "accepts a multi-label domain");
    CHECK(name_ok("ex-ample.com") == 1, "accepts an internal hyphen");
    CHECK(name_ok("a.co") == 1, "accepts a short single-char label");

    /* --- accepted: the negative-space case the fix must NOT break --- */
    CHECK(name_ok("*.example.com") == 1,
          "REQUIRED: accepts a leading-label wildcard");
    CHECK(name_ok("*.a.example.com") == 1,
          "REQUIRED: accepts a wildcard over a multi-label rest");
    CHECK(name_ok("xn--fsq.example.com") == 1,
          "REQUIRED: accepts a punycode/IDNA label (plain LDH, not decoded)");
    CHECK(name_ok("*.xn--fsq.example.com") == 1,
          "REQUIRED: accepts a wildcard over a punycode rest");
    CHECK(name_ok("xn--80akhbyknj4f.xn--p1ai") == 1,
          "REQUIRED: accepts an all-punycode domain (both labels xn--)");

    /* --- rejected: would corrupt the ACME order JSON or the path segment --- */
    CHECK(name_ok("") == 0, "rejects the empty name");
    CHECK(name_ok(".example.com") == 0, "rejects a leading dot");
    CHECK(name_ok("example.com.") == 0, "rejects a trailing dot");
    CHECK(name_ok("example..com") == 0, "rejects an empty label");
    CHECK(name_ok("-example.com") == 0, "rejects a label starting with '-'");
    CHECK(name_ok("example-.com") == 0, "rejects a label ending with '-'");
    CHECK(name_ok("exa\"mple.com") == 0,
          "rejects a JSON-breaking double quote");
    CHECK(name_ok("exa\\mple.com") == 0, "rejects a JSON-breaking backslash");
    CHECK(name_ok("example.com\n") == 0,
          "rejects an embedded control byte (newline)");
    CHECK(name_ok("exa mple.com") == 0, "rejects an embedded space");
    CHECK(name_ok("exam*ple.com") == 0,
          "rejects a non-leading '*' (only the sole leading wildcard form "
          "reaches this check with a '*' at all)");

    /* label-length and total-length boundaries (RFC 1035/1123) */
    {
        char    label64[65];
        char    buf[300];
        size_t  i;

        memset(label64, 'a', 64);
        label64[64] = '\0';
        {
            char  name[80];
            snprintf(name, sizeof(name), "%s.com", label64);
            CHECK(name_ok(name) == 0, "rejects a 64-byte label (max is 63)");
        }
        {
            char  label63[64];
            char  name[80];
            memset(label63, 'a', 63);
            label63[63] = '\0';
            snprintf(name, sizeof(name), "%s.com", label63);
            CHECK(name_ok(name) == 1, "accepts a 63-byte label (boundary)");
        }

        /* 254 total bytes (one over the 253 RFC 1035 cap): a run of "a."
         * labels padded to exactly 254 chars. */
        for (i = 0; i < sizeof(buf) - 1; i++) {
            buf[i] = (i % 2 == 0) ? 'a' : '.';
        }
        buf[253] = '\0'; /* exactly 253 -- must still be accepted */
        CHECK(buf[252] != '.', "253-byte fixture does not end mid-label");
        CHECK(name_ok(buf) == 1, "accepts a name of exactly 253 bytes");

        buf[253] = 'a';
        buf[254] = '\0'; /* 254 bytes -- must be rejected */
        CHECK(name_ok(buf) == 0, "rejects a name of 254 bytes (over cap)");

        /*
         * The cap is on the WHOLE name, so a wildcard does not buy two extra
         * bytes: "*." plus a 253-byte suffix is 255 total and must be
         * rejected. Measuring only the post-"*." remainder accepted it.
         */
        {
            char  wild[sizeof(buf) + 2];

            buf[253] = '\0';                    /* back to a 253-byte name */
            snprintf(wild, sizeof(wild), "*.%s", buf);
            CHECK(strlen(wild) == 255, "wildcard fixture is 255 bytes total");
            CHECK(name_ok(wild) == 0,
                  "rejects a wildcard whose FULL length exceeds 253 "
                  "(the '*.' prefix buys no extra bytes)");
        }

        /* A wildcard at exactly the cap is still accepted -- the fix must not
         * over-tighten into rejecting a legal name. */
        {
            char  wild[sizeof(buf) + 2];

            buf[251] = '\0';                    /* 251 + "*." == 253 */
            snprintf(wild, sizeof(wild), "*.%s", buf);
            CHECK(strlen(wild) == 253, "wildcard boundary fixture is 253 bytes");
            CHECK(buf[250] != '.', "wildcard boundary fixture ends a label");
            CHECK(name_ok(wild) == 1,
                  "accepts a wildcard of exactly 253 bytes (boundary)");
        }
    }

    /* --- autocert_contact: reuse of ngx_autocert_account_json_safe --- */
    CHECK(email_ok("ops@example.com") == 1, "accepts an ordinary email");
    CHECK(email_ok("ops+tag@example.com") == 1,
          "accepts an email with a '+' tag");
    CHECK(email_ok("exa\"mple@example.com") == 0,
          "rejects a JSON-breaking double quote in the contact");
    CHECK(email_ok("exa\\mple@example.com") == 0,
          "rejects a JSON-breaking backslash in the contact");

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
