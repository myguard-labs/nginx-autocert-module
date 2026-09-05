/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * ngx_autocert_serve — per-SNI certificate serving at the TLS handshake (M7).
 *
 * Lives in the HTTP module .so. Two halves:
 *
 *  - config time (ngx_http_autocert_serve_init, called from the HTTP module's
 *    postconfiguration): walk every autocert-enabled server, ensure it has a
 *    usable SSL_CTX (building one with a self-signed bootstrap cert when the
 *    operator gave no ssl_certificate), and install an OpenSSL cert_cb that
 *    swaps in the real certificate per-SNI at handshake.
 *
 *  - handshake time (the cert_cb): look the SNI host up in a per-worker cache
 *    keyed by name, (re)load <store>/<host>/{fullchain,privkey}.pem when the
 *    file mtime has changed, and attach it to the connection's SSL. A renewal
 *    therefore takes effect with no config reload (history.md hot-swap
 *    decision) — the next handshake sees the newer mtime and reloads.
 *
 * Why a self-built SSL_CTX instead of injecting a dummy cert before nginx's ssl
 * module runs: ngx_http_ssl_module is a built-in (low module index), so its
 * merge runs before any dynamic module's and it returns before ngx_ssl_create
 * when no ssl_certificate is configured (ctx stays NULL). autocert cannot hook
 * earlier without a core patch, so it builds the ctx itself in postconfig. See
 * history.md 2026-06-18 "M7 cert serving".
 */

#ifndef _NGX_AUTOCERT_SERVE_H_INCLUDED_
#define _NGX_AUTOCERT_SERVE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_autocert_conf.h"


/*
 * Set up per-SNI serving for every autocert-enabled server. Call from the HTTP
 * module's postconfiguration AFTER ngx_http_ssl_module has merged (i.e. it is
 * safe to read sscf->ssl.ctx). Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t ngx_http_autocert_serve_init(ngx_conf_t *cf,
    ngx_http_autocert_main_conf_t *amcf);


/*
 * `master_process off` reload: drop the per-worker cert cache + name-index gate
 * so they rebuild from the new config. Call from init_module (single-process
 * path only). No-op-safe before the first handshake builds anything.
 */
void ngx_autocert_serve_reload(void);

/*
 * ---------------------------------------------------------------------------
 * cert_cb delegation (autolabel B3) — the ONE exported symbol of this module.
 * ---------------------------------------------------------------------------
 *
 * THE PROBLEM. OpenSSL keeps exactly ONE cert_cb per SSL_CTX and
 * SSL_CTX_set_cert_cb() REPLACES it; there is no SSL_CTX_get_cert_cb() to chain
 * through (verified against OpenSSL 3.5.6 — only the setter exists;
 * SSL_CTX_get_client_cert_cb is a different callback). So when a second module
 * (nginx-label-autoconf-module, which serves per-container SNI certs) installs
 * its own cert_cb, autocert's is silently dropped and EVERY autocert name —
 * runtime AND ordinary config-time server_names — is served the M7 self-signed
 * bootstrap cert. Certs still order, issue and land in the store; only the
 * serve path dies, and it dies without a single log line.
 *
 * THE CONTRACT. autocert OWNS the OpenSSL slot: it is the only module that may
 * call SSL_CTX_set_cert_cb() on an autocert-enabled server. A consumer does NOT
 * install a cert_cb — it REGISTERS here, and autocert's cert_cb calls it FIRST,
 * falling back to the store lookup when the consumer declines.
 *
 * Consumer-first is deliberate: a consumer's cert is an explicit per-container
 * operator statement (`nda.tls.cert` / `nda.tls.key` — a filesystem path the
 * operator named), whereas autocert's is derived from the ACME store. The two
 * sets are disjoint by construction anyway (a host is either statically
 * certed by a label or handed to autocert via `nda.tls.auto`), so the ordering
 * only decides who wins a misconfiguration — and the explicit path should.
 *
 * `next` returns, and MUST return, one of:
 *
 *   NGX_OK        the consumer installed a certificate on this SSL. autocert
 *                 will NOT touch the connection's certs and returns 1 (proceed)
 *                 to OpenSSL.
 *   NGX_DECLINED  the consumer has nothing for this SNI. autocert proceeds with
 *                 its own store lookup exactly as if no consumer existed. This
 *                 is the common path and MUST be cheap.
 *   NGX_ERROR     fail the handshake (autocert returns 0 to OpenSSL).
 *
 * NGX_DECLINED, not OpenSSL's 1, because OpenSSL's "1" means only "continue the
 * handshake" and cannot distinguish "I installed a cert" from "I did nothing" —
 * and autocert must know which, or it would either clobber the consumer's cert
 * or skip its own lookup.
 *
 * LINKAGE. This is the module's only INTENDED cross-module entry point. It has
 * default visibility, like most of this module's internals (the .so exports
 * them because nothing hides them, not because they are API — do not call
 * those). The one deliberate exception runs the other way: the
 * ngx_autocert_requests_* shm helpers are explicitly HIDDEN (see
 * ngx_autocert_requests.h) because they are code-copied into each .so and share
 * state through shm rather than through the symbol table, and interposition
 * between the two copies would be a bug.
 *
 * Delegation cannot use that copy-the-code trick: the cert_cb's state is
 * autocert's private per-server sctx plus a process-static per-worker cert
 * cache, so a vendored copy compiled into the consumer's .so would hold its own
 * zeroed static variables and could never serve autocert's certs. A real
 * cross-.so call is required — and nginx dlopen()s modules
 * RTLD_NOW|RTLD_GLOBAL, so this symbol lands in the global namespace where a
 * consumer can reach it.
 *
 * A consumer MUST resolve it with dlsym(RTLD_DEFAULT, ...) at runtime rather
 * than referencing it directly: RTLD_NOW is EAGER, so a direct extern reference
 * would make nginx refuse to start whenever autocert is absent. A NULL dlsym
 * result simply means "autocert not loaded" and the consumer keeps its own
 * cert_cb.
 *
 * ORDER-INDEPENDENT. The registration is kept in a file-static slot that the
 * cert_cb reads at HANDSHAKE time, not one copied into sctx at install time, so
 * it does not matter whether the consumer's config phase runs before or after
 * autocert's serve_init. (Making this load-order dependent is exactly the trap
 * the shm-zone attach already had to dodge.)
 *
 * RELOAD-SAFE. The registration is stamped with the registering cycle; a
 * registration from a previous cycle is ignored, so a reload that drops the
 * consumer module cannot leave autocert calling into a stale function pointer.
 * The consumer re-registers from its config phase on every cycle.
 *
 * The callback returns ngx_int_t (NOT int): the values above are ngx_int_t
 * constants and ngx_int_t is intptr_t, so declaring the slot `int` would
 * truncate on LP64 and mismatch the ABI across the .so boundary.
 *
 * Returns NGX_OK, or NGX_ERROR if `next` is NULL.
 */
ngx_int_t ngx_autocert_cert_cb_register(
    ngx_int_t (*next)(SSL *ssl_conn, void *arg), void *arg);


#endif /* _NGX_AUTOCERT_SERVE_H_INCLUDED_ */
