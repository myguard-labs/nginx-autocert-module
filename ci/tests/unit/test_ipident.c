/*
 * Unit tests for the IP-identifier helpers in ngx_http_autocert_conf.h:
 *   - ngx_autocert_str_is_ip(name, &out6) — classify an identifier as IPv4
 *     (AF_INET), IPv6 (AF_INET6, address written to out6), or a dns name (0).
 *   - ngx_autocert_fs_segment(buf, cap, name) — map an identifier to its
 *     on-disk store segment. Exercises the three branches: wildcard
 *     ("*.rest" -> "_wildcard_.rest"), IPv6 (normalized "_ip6_" + 8 hex groups
 *     joined by '-'), and the verbatim path (dns names AND IPv4 literals).
 *
 * Both helpers are `static ngx_inline` in the shared header, so this TU just
 * includes it and links the nginx string/inet objects the inlines call
 * (ngx_inet_addr / ngx_inet6_addr / ngx_sprintf).
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

/* Log + cycle stubs referenced by the linked nginx string/inet objects. */
volatile ngx_cycle_t  *ngx_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

#include "../../../src/ngx_http_autocert_conf.h"

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


static int
seg_is(ngx_str_t *name, const char *want)
{
    u_char  buf[NGX_AUTOCERT_DOMAIN_SEG_MAX];
    size_t  n;

    n = ngx_autocert_fs_segment(buf, sizeof(buf), name);
    return n == strlen(want) && ngx_memcmp(buf, want, n) == 0;
}


#define STR(s)  { sizeof(s) - 1, (u_char *) (s) }


int
main(void)
{
    ngx_str_t  v4      = STR("192.0.2.1");
    ngx_str_t  v4_max  = STR("255.255.255.255");
    ngx_str_t  v6      = STR("2001:db8::1");
    ngx_str_t  v6_loop = STR("::1");
    ngx_str_t  v6_full = STR("fe80:0:0:0:0:0:0:1");
    ngx_str_t  dns     = STR("example.com");
    ngx_str_t  wild    = STR("*.example.com");
    ngx_str_t  notip   = STR("999.1.1.1");

    /* --- classification --- */
    CHECK(ngx_autocert_str_is_ip(&v4_max, NULL) == AF_INET,  "255.255.255.255 -> AF_INET");
    CHECK(ngx_autocert_str_is_ip(&v4, NULL) == AF_INET,      "v4 -> AF_INET");
    CHECK(ngx_autocert_str_is_ip(&v6, NULL) == AF_INET6,     "v6 -> AF_INET6");
    CHECK(ngx_autocert_str_is_ip(&v6_loop, NULL) == AF_INET6, "::1 -> AF_INET6");
    CHECK(ngx_autocert_str_is_ip(&dns, NULL) == 0,           "dns -> 0");
    CHECK(ngx_autocert_str_is_ip(&wild, NULL) == 0,          "wildcard -> 0");
    CHECK(ngx_autocert_str_is_ip(&notip, NULL) == 0,         "999.1.1.1 -> 0");

    /* --- fs_segment: dns + IPv4 stored verbatim --- */
    CHECK(seg_is(&dns, "example.com"),      "dns verbatim");
    CHECK(seg_is(&v4, "192.0.2.1"),         "v4 verbatim");
    CHECK(seg_is(&v4_max, "255.255.255.255"), "v4 max verbatim");

    /* --- fs_segment: wildcard map --- */
    CHECK(seg_is(&wild, "_wildcard_.example.com"), "wildcard map");

    /* --- fs_segment: IPv6 normalized full-hex --- */
    CHECK(seg_is(&v6,
                 "_ip6_2001-0db8-0000-0000-0000-0000-0000-0001"),
          "v6 2001:db8::1 normalized");
    CHECK(seg_is(&v6_loop,
                 "_ip6_0000-0000-0000-0000-0000-0000-0000-0001"),
          "v6 ::1 normalized");
    /* compressed and fully-written forms of the same address collapse to the
     * same segment (no aliasing of one cert across two store keys). */
    CHECK(seg_is(&v6_full,
                 "_ip6_fe80-0000-0000-0000-0000-0000-0000-0001"),
          "v6 fe80:0:...:1 normalized");

    if (failures) {
        fprintf(stderr, "\n%d FAILURE(S)\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall passed\n");
    return 0;
}
