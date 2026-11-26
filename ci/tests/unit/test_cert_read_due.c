/* Focused renewal-policy test for the function sliced from driver.c. */
#include <ngx_config.h>
#include <ngx_core.h>

#include "generated_cert_read_due.inc"

#include <stdio.h>

static int failures;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                             \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                             \
        }                                                                     \
    } while (0)

int
main(void)
{
    CHECK(ngx_autocert_cert_read_due(NGX_DECLINED),
          "a missing stored chain remains due for issuance");
    CHECK(ngx_autocert_cert_read_due(NGX_ABORT),
          "an invalid or mismatched stored pair remains due for issuance");
    CHECK(!ngx_autocert_cert_read_due(NGX_ERROR),
          "an unreadable stored key or chain backs off without issuance");
    CHECK(!ngx_autocert_cert_read_due(NGX_OK),
          "a readable fresh pair remains not due");

    return failures ? 1 : 0;
}
