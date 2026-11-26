/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * The extracted production callback runs without any allocated srv_conf.
 * Real core headers define both the command ABI and compiled field offsets.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_ssl_module.h>

ngx_module_t ngx_http_ssl_module;
static unsigned errors;
static unsigned checks;
static unsigned failures;

void
ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t err,
    const char *fmt, ...)
{
    (void) cf;
    (void) err;
    if (level != NGX_LOG_EMERG
        || strstr(fmt, "autocert: ngx_http_ssl_srv_conf_t ABI mismatch") == NULL)
    {
        fprintf(stderr, "unexpected ABI diagnostic\n");
        exit(1);
    }
    errors++;
}

#include "ssl_abi.inc"

static ngx_command_t commands[] = {
    { ngx_string("ssl_certificate"), NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      NULL, NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificates), NULL },
    { ngx_string("ssl_certificate_key"), NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      NULL, NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate_keys), NULL },
    { ngx_string("unrelated"), 0, NULL, 0, 0, NULL },
    ngx_null_command
};

static void
check(const char *label, ngx_int_t expected)
{
    ngx_conf_t cf;
    ngx_int_t rc;

    memset(&cf, 0, sizeof(cf));
    errors = 0;
    rc = ngx_http_autocert_preconfig(&cf);
    if (rc != expected || errors != (unsigned) (expected == NGX_ERROR)) {
        fprintf(stderr, "FAIL %s: rc=%ld errors=%u (expected %ld)\n",
                label, (long) rc, errors, (long) expected);
        failures++;
    } else {
        printf("PASS %s\n", label);
    }
    checks++;
}

int
main(void)
{
    ngx_command_t saved[4], tmp;

    memcpy(saved, commands, sizeof(commands));
    ngx_http_ssl_module.commands = commands;
    check("matched layout", NGX_OK);
    commands[0].offset += 32;
    commands[1].offset += 32;
    check("A-into-B (+32 bytes)", NGX_ERROR);
    commands[0].offset -= 64;
    commands[1].offset -= 64;
    check("B-into-A (-32 bytes)", NGX_ERROR);
    memcpy(commands, saved, sizeof(commands));
    commands[1].offset++;
    check("key-only one-byte drift", NGX_ERROR);
    memcpy(commands, saved, sizeof(commands));
    commands[0].offset++;
    check("certificate-only one-byte drift", NGX_ERROR);
    memcpy(commands, saved, sizeof(commands));
    commands[0].conf = 0;
    check("wrong configuration offset", NGX_ERROR);
    memcpy(commands, saved, sizeof(commands));
    commands[1].type = NGX_CONF_TAKE1;
    check("wrong configuration scope", NGX_ERROR);
    memcpy(commands, saved, sizeof(commands));
    commands[0].name.len = 0;
    check("empty command table", NGX_ERROR);
    memcpy(commands, saved, sizeof(commands));
    commands[1].name.len = 0;
    check("missing key directive", NGX_ERROR);
    memcpy(commands, saved, sizeof(commands));
    commands[0].name.data = (u_char *) "ssl_certificatX";
    check("missing certificate directive", NGX_ERROR);
    memcpy(commands, saved, sizeof(commands));
    ngx_http_ssl_module.commands = NULL;
    check("absent command table", NGX_ERROR);
    ngx_http_ssl_module.commands = commands;
    tmp = commands[0];
    commands[0] = commands[1];
    commands[1] = tmp;
    check("reordered matched directives", NGX_OK);
    commands[0].type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12;
    commands[1].type = commands[0].type;
    check("matched multicert directive flags", NGX_OK);
    printf("SSL ABI guard: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
