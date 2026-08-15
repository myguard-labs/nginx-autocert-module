# Runtime cert shm API — consumer guide

Audience: authors of a **separate** nginx dynamic module that wants autocert
to obtain and serve a TLS certificate for a host discovered at runtime (e.g.
a Docker label), without linking against autocert's `.so`.

For the full ABI contract (struct layout, exact function signatures, locking
rule) read [`src/ngx_autocert_requests.h`](../src/ngx_autocert_requests.h) —
it is the single source of truth; this doc is a task-oriented walkthrough on
top of it. If the two disagree, the header wins.

## Why a shm zone and not a function call

The state both modules must agree on lives in shared memory anyway (it is read
and written from every worker), so the integration surface is a **named nginx
shared-memory zone** plus a versioned on-shm layout, not an exported function
API. Both modules attach the same zone by name and compile the same accessor
code against the same struct layout.

Crucially, this is **not** because the symbols are invisible to each other:
nginx `dlopen()`s modules with `RTLD_NOW | RTLD_GLOBAL`
(`src/os/unix/ngx_dlopen.h`), so every module's globals land in the process's
global symbol scope. That is precisely why the accessors must be **hidden**
(see below) — otherwise two `.so`s carrying a copy of the same helper would
interpose on each other and whichever loaded first would serve both, so an
N/N+1 version skew would parse one layout with the other's code.

## 1. Compile the header AND the .c into your module

Vendor **both** `src/ngx_autocert_requests.h` and `src/ngx_autocert_requests.c`
into your module's source tree and add the `.c` to your `config`'s
`ngx_addon_srcs`. They have no dependencies beyond `ngx_core.h`.

Every definition is declared `NGX_AUTOCERT_REQUESTS_API`
(`__attribute__((visibility("hidden")))`), so your `.so` binds its **own private
copy**:

- load order between the two modules does not matter;
- autocert being absent is not a link error (there are no unresolved symbols to
  satisfy);
- no ELF interposition, so a version skew degrades through the `api_version`
  check instead of silently running the wrong layout's code.

Bump-tracking: if autocert changes `NGX_AUTOCERT_API_VERSION`, re-vendor both
files. A stale consumer sees the zone's stamped version compare unequal and
labels the integration "off" — it never mis-parses a foreign layout. The new
owner also rejects a graceful reload over a foreign layout. Perform a true
stop/start for an ABI-changing upgrade so nginx allocates a fresh arena; retiring
workers still share the old arena during an ordinary reload.

## 2. Attach the zone in your module's postconfig

```c
static ngx_int_t
my_module_postconfig(ngx_conf_t *cf)
{
    ngx_shm_zone_t *zone;

    zone = ngx_shared_memory_add(cf, &(ngx_str_t) ngx_string(NGX_AUTOCERT_REQUESTS_ZONE),
                                  NGX_AUTOCERT_REQUESTS_ZONE_SIZE, NULL /* tag MUST be NULL */);
    if (zone == NULL) {
        return NGX_ERROR;
    }

    /* Install the consumer callback ONLY if nobody has claimed the zone yet.
     * A non-NULL init means autocert's postconfig already ran and installed its
     * OWNER callback; overwriting it would mark the API inactive and disable
     * runtime certs even though autocert is present.
     *
     * Do NOT test zone->data — nginx leaves it NULL at config time. The requests
     * header lives inside the slab arena at shpool->data; the init callback's
     * data argument is unused. zone->data is not an ownership marker. */
    if (zone->init == NULL) {
        zone->init = ngx_autocert_requests_init_zone_consumer;
    }

    my_conf->requests_zone = zone;  /* stash on your own conf struct */
    return NGX_OK;
}
```

Whichever module's postconfig runs first actually creates the zone; the other
attaches the same name (nginx dedups by name+tag — hence the tag MUST be
`NULL` on both sides, or `ngx_shared_memory_add()` will see two different
"uses" of the same name and error out). Load order between the two modules is
NOT guaranteed by config file order alone, so both sides must be order-safe:

| postconfig order | what happens |
|---|---|
| autocert first | autocert installs the owner init; your `zone->init == NULL` test fails, you leave it alone; zone stamps `NGX_AUTOCERT_API_VERSION`. |
| consumer first | you install the consumer init; autocert then **overrides** it with the owner init (it deliberately claims the zone) and stamps `NGX_AUTOCERT_API_VERSION`. |
| autocert absent (or disabled) | only your consumer init runs, stamps `NGX_AUTOCERT_API_INACTIVE_VERSION`; every helper fails safe and the runtime-cert feature is inert, while the current layout identity is retained. |

On a reload, active version `N` and inactive version `N` can switch safely in
either direction without touching the tree. A legacy zero stamp is accepted
only when the tree is empty. A non-empty zero stamp or any foreign-version arena
is never relabelled: the consumer remains inert, while the owner rejects the
reload and asks for a full stop/start.

## 3. Check the zone is actually live before using it

```c
ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) zone->shm.addr;
ngx_autocert_requests_sh_t *sh = shpool->data;

if (sh == NULL || sh->api_version != NGX_AUTOCERT_API_VERSION) {
    /* autocert absent, or a version you don't understand: disable the
     * runtime-cert feature and fall back to whatever your module does
     * without it (e.g. serve HTTP-only, or via a pre-provisioned cert). */
}
```

Every helper in `ngx_autocert_requests.h` (`ensure`/`state`/`set_state`) does
this check internally and returns `REQ_UNKNOWN` on a bad/absent zone, so a
consumer that only calls the helpers (never walks the tree itself) gets this
fail-safe for free — the explicit check above is for a consumer that wants to
disable a whole feature path up front rather than handling `REQ_UNKNOWN` at
every call site.

## 4. Request a certificate

```c
ngx_str_t host = ngx_string("app.example.com");   /* from your label/discovery source */

ngx_int_t state = ngx_autocert_requests_ensure(my_conf->requests_zone, &host);

switch (state) {
case NGX_AUTOCERT_REQ_DENIED:
    /* over the 64-name cap, or host failed charset/wildcard validation —
     * terminal, do not retry this exact host without operator action. */
    break;
case NGX_AUTOCERT_REQ_UNKNOWN:
    /* zone missing/version-mismatched; autocert integration is off. */
    break;
default:
    /* REQUESTED/PENDING/ISSUED/FAILED — a node now exists; poll it later. */
    break;
}
```

`ensure` is idempotent — calling it again for a host already in the registry
just returns its current state without re-enqueueing or resetting backoff.
Safe to call on every reconcile pass of your own module's discovery loop.

## 5. Poll until issued, then let autocert serve it

```c
ngx_int_t state = ngx_autocert_requests_state(my_conf->requests_zone, &host);

if (state == NGX_AUTOCERT_REQ_ISSUED) {
    /* Cert is on disk AND already being served: autocert's TLS cert
     * callback falls back to this zone on any SNI that misses its
     * config-driven name index. Your module does not load, path-resolve,
     * or touch the certificate/key at all — it is 100% autocert's. */
}
```

There is no "please serve this now" call — `ISSUED` in the zone is itself the
signal that the cert is servable. If your module needs to know *when* a name
transitions to `ISSUED` (e.g. to flip a health check), poll on your own
module's timer; there is no shm-side notification/callback mechanism.

## 6. If your module ALSO serves certificates: delegate, never install

**If your module has no certificates of its own to serve, skip this section — but
then you must not call `SSL_CTX_set_cert_cb()` anywhere. Read the first bullet of
"What you must NOT do".**

OpenSSL keeps exactly **one** `cert_cb` per `SSL_CTX`, and
`SSL_CTX_set_cert_cb()` **replaces** it. There is no `SSL_CTX_get_cert_cb()` to
chain through. So a consumer that installs its own callback on an
autocert-managed server silently **destroys autocert's serving**: certs still
order, issue and land in the store, but every autocert name — runtime *and*
ordinary config-time `server_name`s — is served the self-signed `CN=localhost`
bootstrap cert instead. Nothing logs an error. (This is exactly what happened to
the reference consumer; it is why this section exists.)

autocert therefore **owns the OpenSSL slot** and calls you:

```c
#include <dlfcn.h>

/* Your per-SNI cert logic. Return NGX_OK if you installed a cert on this SSL,
 * NGX_DECLINED to let autocert serve it from its store, NGX_ERROR to fail the
 * handshake. NOT OpenSSL's 1/0: "1" cannot distinguish "I installed a cert"
 * from "I did nothing", and autocert must know which. */
static ngx_int_t
my_cert_serve(SSL *ssl_conn, void *arg)
{
    ...
    if (nothing_for_this_sni) {
        return NGX_DECLINED;      /* autocert's store lookup runs next */
    }
    /* SSL_use_certificate() / SSL_use_PrivateKey() / SSL_set1_chain() ... */
    return NGX_OK;
}

/* In your postconfiguration, INSTEAD of SSL_CTX_set_cert_cb(): */
ngx_int_t (*reg)(ngx_int_t (*)(SSL *, void *), void *);

*(void **) &reg = dlsym(RTLD_DEFAULT, "ngx_autocert_cert_cb_register");

if (reg != NULL) {
    if (reg(my_cert_serve, my_conf) != NGX_OK) {
        return NGX_ERROR;
    }
    /* Registered. Do NOT also call SSL_CTX_set_cert_cb(). */
} else {
    /* autocert is not loaded: you are the only cert_cb, install it yourself. */
    SSL_CTX_set_cert_cb(sscf->ssl.ctx, my_cert_cb, my_conf);
}
```

Your callback is invoked **first** on every handshake, and autocert falls back to
its store whenever you return `NGX_DECLINED` — so an explicit per-container cert
wins over an ACME-issued one, and everything else is autocert's.

**Resolve it with `dlsym`, not a direct call.** nginx `dlopen()`s modules with
`RTLD_NOW | RTLD_GLOBAL`. `RTLD_NOW` is *eager*: a direct reference to
`ngx_autocert_cert_cb_register` makes nginx **refuse to start** whenever autocert
is absent, turning an optional integration into a hard dependency.
`RTLD_GLOBAL` puts the symbol in the global namespace, so `RTLD_DEFAULT` finds it
whichever order the two `.so` files loaded in. A `NULL` result simply means
"autocert is not there".

Registration is per-cycle (autocert stamps it with the registering cycle and
ignores anything older), so re-register from your config phase on every reload —
the snippet above already does, being in `postconfiguration`.

Note this is a **real exported symbol**, unlike the `ngx_autocert_requests_*`
helpers you vendored in step 1: those are hidden-visibility code copies that share
state through *shm*, whereas the cert callback's state is autocert's private
per-worker cache and per-server config. A vendored copy of it would hold its own
zeroed static variables and could never serve autocert's certs.

## What you must NOT do

- **Do not** call `SSL_CTX_set_cert_cb()` on a server that autocert manages. You
  will replace autocert's callback and silently break TLS for every name it
  serves (see section 6). If your module needs to serve certs, register via
  `ngx_autocert_cert_cb_register()`; if it does not, install nothing.
- **Do not** call `ngx_autocert_requests_set_state`, `_drain`, or
  `_list_issued` from a consumer module — those are the autocert worker-0
  driver's exclusive write path (state transitions, claiming, renewal
  scanning). A consumer only ever calls `ensure` (write, enqueue-only) and
  `state` (read-only).
- **Do not** walk the rbtree yourself without holding
  `((ngx_slab_pool_t *) zone->shm.addr)->mutex` for the entire traversal —
  nodes are inserted/relinked under that mutex by autocert's driver, so an
  unlocked walk can dereference a node mid-rotation.
- **Do not** request a wildcard or an IP literal through this path — the
  registry only accepts LDH hostnames (see the header's charset validation);
  wildcard/IP issuance is config-only in the current arc.
- **Do not** assume DNS-01 is used for a runtime name — autocert hard-pins
  runtime orders to HTTP-01/TLS-ALPN-01 regardless of the configured
  `autocert_ca` challenge mode (ACME validation IS the runtime allowlist; a
  dangling/misdirected `CNAME` under dns-01 would let anyone claim a cert for
  an arbitrary name). Your module does not need to configure or care about
  this — it is automatic and not overridable per-request.

## Reference implementation

[`nginx-label-autoconf-module`](https://github.com/myguard-labs/nginx-label-autoconf-module)
is the first real consumer of this API — it discovers Docker containers
labeled `nda.tls.auto=true` and enqueues their `server_name` via `ensure()`.
Read its integration code for a worked example alongside this doc.
