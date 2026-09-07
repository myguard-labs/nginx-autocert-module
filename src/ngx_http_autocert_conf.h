/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * ngx_http_autocert_conf — the autocert HTTP module's config struct
 * definitions, shared between the HTTP module itself and the small accessor TU
 * (ngx_autocert_conf.c) that the CORE helper module links in.
 *
 * Why a shared header instead of a cross-.so symbol: the addon ships two
 * separate .so files (CORE process module, HTTP module) and nginx does not
 * guarantee their load order, so the CORE module must not depend on a symbol
 * defined in the HTTP module's .so (an unresolved direct call would make the
 * CORE .so fail to dlopen when it is loaded first, or the HTTP module absent).
 * The accessor is therefore compiled INTO the CORE module and reads the HTTP
 * main conf out of the shared cycle; both TUs must agree on the struct layout,
 * which lives here.
 */

#ifndef _NGX_HTTP_AUTOCERT_CONF_H_INCLUDED_
#define _NGX_HTTP_AUTOCERT_CONF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* http-free identifier + store-segment helpers (ngx_autocert_str_is_ip,
 * ngx_autocert_cert_covers, ngx_autocert_fs_segment) and their constants.
 * Split out so the crypto/cert-expiry unit builds can reach them without
 * pulling <ngx_http.h>. */
#include "ngx_autocert_ident.h"


typedef enum {
    NGX_HTTP_AUTOCERT_KEY_P256 = 0,
    NGX_HTTP_AUTOCERT_KEY_P384,
    NGX_HTTP_AUTOCERT_KEY_RSA2048,
    NGX_HTTP_AUTOCERT_KEY_RSA3072,
    NGX_HTTP_AUTOCERT_KEY_RSA4096
} ngx_http_autocert_key_type_e;

typedef enum {
    NGX_HTTP_AUTOCERT_STORE_SECURE = 0,
    NGX_HTTP_AUTOCERT_STORE_CERTBOT
} ngx_http_autocert_store_e;

typedef enum {
    NGX_HTTP_AUTOCERT_CHALLENGE_HTTP_01 = 0,
    NGX_HTTP_AUTOCERT_CHALLENGE_TLS_ALPN_01,
    NGX_HTTP_AUTOCERT_CHALLENGE_DNS_01
} ngx_http_autocert_challenge_e;

/*
 * multi-CA M1 (#15 residual): the CA-identifying knobs grouped into one struct
 * so they live per-server (autocert_ca / _staging / _ca_certificate / _eab_kid
 * / _eab_hmac_key). M4 gives srv_conf its own ca_conf and merges global→server;
 * M2 groups names by effective CA into main_conf.ca_list; M5's driver iterates
 * ca_list and drives one ACME engine per CA from each entry's ca_conf.
 */
typedef struct {
    ngx_str_t    ca;                /* ACME directory URL */
    ngx_flag_t   staging;           /* autocert_staging on|off */
    ngx_str_t    ca_certificate;    /* PEM trust bundle to verify the CA, "" */
    ngx_str_t    issuance_certificate;
                                    /* PEM trust anchor for the ISSUED chain,
                                     * "" = no chain verification. Distinct
                                     * from ca_certificate, which anchors the
                                     * CA's TLS endpoint: a CA may serve its
                                     * API under one root and sign end-entity
                                     * certificates under another. */
    ngx_str_t    eab_kid;           /* EAB key id (RFC 8555 §7.3.4), "" */
    ngx_str_t    eab_hmac_key;      /* base64url EAB HMAC key, "" */
} ngx_autocert_ca_conf_t;

/*
 * multi-CA M2: one entry per distinct CA the instance issues against. Built at
 * postconfig by grouping enabled server_names by their effective CA. In the
 * M1/M2 world (directives still http{}-global) there is exactly ONE entry
 * holding every name; M4 (SRV-scope) makes per-vhost CAs produce several.
 * ca_hash is the leading 64 bits of SHA-256(canonical CA URL) as 16 lowercase
 * hex + NUL, used by M3 for the per-CA account dir
 * (<path>/accounts/<hash>/account.key). account_key_path is filled by M3; "" in
 * M2. (Was crc32/hex8 — too short to rule out two distinct CA URLs aliasing
 * onto one account.key, which would break per-CA key isolation.)
 */
#define NGX_AUTOCERT_CA_HASH_HEX  16
typedef struct {
    ngx_autocert_ca_conf_t  ca_conf;          /* resolved CA config */
    ngx_array_t            *names;             /* ngx_str_t under this CA */
    u_char                  ca_hash[NGX_AUTOCERT_CA_HASH_HEX + 1];
    /* sha256(ca url)[:8] hex16 + NUL */
    ngx_str_t               account_key_path;  /* M3 fills; "" in M2 */
    /*
     * Per-CA account contact. Each CA has its own ACME account, so each gets
     * its own newAccount contact: the FIRST enabled vhost in this CA group with
     * a non-empty `autocert on <email>` supplies it; a second vhost in the same
     * group with a DIFFERENT non-empty email is rejected at postconfig (one CA
     * = one account = one contact). "" if no vhost in the group set an email.
     */
    ngx_str_t               email;
} ngx_autocert_ca_entry_t;


/* Per-server config: the on/off switch + optional contact (M0). */
typedef struct {
    ngx_flag_t   enable;    /* autocert on|off; NGX_CONF_UNSET until set */
    ngx_str_t    email;     /* optional ACME account contact, "" if absent */

    /* M4: per-server CA knobs. The CA directives are MAIN+SRV scope and write
     * here via SRV_CONF_OFFSET; merge_srv_conf folds the http{} default into
     * each server, postconfig resolves + validates each effective ca_conf and
     * groups names by CA URL into main_conf.ca_list. staging starts UNSET (set
     * in create_srv_conf) so merge can tell "not set" from "off". */
    ngx_autocert_ca_conf_t  ca_conf;

    /* D5 (#16): explicit wildcard SANs (autocert_wildcard *.example.com ...).
     * MAIN+SRV scope, stored here via SRV_CONF_OFFSET; merge_srv_conf folds the
     * http{} default into each server (http-level = inherited by all vhosts,
     * server-level = appended). Each is a sole-leading-label wildcard. At
     * postconfig they join the names/ca_list pipeline like any issuable name,
     * and a concrete server_name they cover is suppressed (served from the
     * wildcard cert, not issued separately). NGX_CONF_UNSET_PTR until set. Only
     * valid under autocert_challenge dns-01 (enforced at postconfig). */
    ngx_array_t            *wildcards;        /* ngx_str_t "*.rest" */
} ngx_http_autocert_srv_conf_t;


/*
 * Main (http{}-global) config: the autocert_* tuning knobs plus the shared
 * zone handle and the collected name set. Populated once, in the http{}
 * occurrence of create_main_conf, read by every server.
 */
typedef struct {
    ngx_str_t    email; /* account contact (1st enabled vhost), "" */
    time_t       renew_before;      /* seconds before notAfter to renew */
    ngx_uint_t   key_type;          /* ngx_http_autocert_key_type_e */
    ngx_array_t *key_types;         /* ngx_uint_t list (dual-cert, Phase B);
                                       key_type above == key_types[0] for the
                                       not-yet-array-aware consumers. */
    ngx_uint_t   store;             /* ngx_http_autocert_store_e */
    ngx_str_t    path;              /* cert store directory */
    ngx_uint_t   challenge;         /* ngx_http_autocert_challenge_e */

    /* ACME Profiles (draft-aaron-acme-profiles): the CA-defined issuance
     * profile requested in newOrder. Let's Encrypt requires the "shortlived"
     * profile for IP-address certs. "" = omit the field (CA default profile).
     */
    ngx_str_t    profile;

    /* M4b outbound-client knobs, read by the helper process. */
    ngx_resolver_t  *resolver;      /* built at config time, NULL if unset */
    time_t       resolver_timeout;  /* seconds */

    /* M16: dns-01 challenge. The driver publishes a TXT record by exec'ing an
     * operator hook (D3), waits dns_propagation_delay, then asks the CA to
     * validate. Hooks "" until set; delay defaults at init_main_conf. */
    ngx_str_t    dns_hook_add;      /* exec to publish the TXT, "" if unset */
    ngx_str_t    dns_hook_remove;   /* exec to remove the TXT, "" if unset */
    time_t       dns_propagation_delay;  /* seconds to wait after publish */
    time_t       dns_hook_timeout;  /* seconds to wait for a hook exec */

    ngx_array_t     *names;         /* ngx_str_t, collected at postconfig */

    /*
     * autolabel C: count of vhosts with `autocert on;`, regardless of whether
     * any of them contributed an issuable server_name. This — NOT names->nelts
     * — is the "autocert is in use" signal that provisions the runtime
     * registry, the challenge surfaces and the ACME account.
     *
     * A label-driven gateway matches its hosts with a regex/catch-all
     * server_name and learns every real hostname at runtime, so it legitimately
     * has zero config names. Gating on names->nelts left such a deployment with
     * no requests_zone to attach and no challenge surface to answer on, so
     * runtime issuance could never activate (it failed silently: the consumer's
     * init marked the current API layout inactive and every helper fail-safed
     * to inert).
     */
    ngx_uint_t       enabled_servers;

    /* M2: enabled names grouped by CA. ngx_autocert_ca_entry_t array; one entry
     * until M4 introduces per-vhost CAs. The flat `names` above stays the serve
     * gate; ca_list is what the driver (M5) iterates to order per CA. */
    ngx_array_t     *ca_list;       /* ngx_autocert_ca_entry_t */

    /* M5 HTTP-01 challenge token store (token -> keyauth), written by the
     * helper, read by the :80 worker handler. */
    ngx_shm_zone_t  *challenge_zone;

    /* M5 test-only seed: autocert_test_challenge <token> <keyauth>; the helper
     * inserts it at startup so the serve path can be exercised without a full
     * order flow. token.len == 0 when unset. */
    ngx_str_t        test_token;
    ngx_str_t        test_keyauth;

    /* M10b tls-alpn-01 challenge cert store (domain -> {cert,key} PEM), written
     * by the helper, read by the worker handshake (cert_cb). */
    ngx_shm_zone_t  *alpn_zone;

    /* autolabel A1: runtime cert-request registry shared with a consumer module
     * (nginx-label-autoconf) by NAME. autocert owns it (stamps api_version);
     * the consumer attaches the same-named zone and walks it. NULL until
     * postconfig adds it (only when autocert is enabled). Layout:
     * ngx_autocert_requests.h. */
    ngx_shm_zone_t  *requests_zone;

    /* M10b test-only seed: autocert_test_alpn <domain> <keyauth>; the helper
     * builds the challenge cert at startup and inserts it into alpn_zone so the
     * ALPN serve path can be exercised without a full order flow. domain.len ==
     * 0 when unset. */
    ngx_str_t        test_alpn_domain;
    ngx_str_t        test_alpn_keyauth;

    /* autolabel C test-only seed: autocert_test_runtime_request <host>; the
     * driver's kick handler inserts it into requests_zone as REQUESTED once,
     * so the Pebble e2e can exercise the full runtime-issuance lifecycle
     * (A3 drain/order -> A4 serve -> A6 persist) without a real consumer
     * module. host.len == 0 when unset. */
    ngx_str_t        test_runtime_host;

    /* autolabel GC: idle TTL for runtime registry nodes. The registry is a
     * bounded table (NGX_AUTOCERT_REQUESTS_MAX); without eviction a gateway
     * churning distinct runtime hosts wedges at the cap. A node's last_seen is
     * refreshed on every consumer ensure() and driver set_state(); the sched
     * tick evicts nodes idle past this TTL (+ removes their A6 marker).
     * 0 = GC off (pre-TTL behavior: learned hosts persist forever). */
    time_t           runtime_ttl;
} ngx_http_autocert_main_conf_t;


/* The HTTP module instance, referenced by the accessor for its ctx_index. */
extern ngx_module_t  ngx_http_autocert_module;


#endif /* _NGX_HTTP_AUTOCERT_CONF_H_INCLUDED_ */
