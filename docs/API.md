# Runtime cert shm API — consumer guide

Audience: authors of a **separate** nginx dynamic module that wants autocert
to obtain and serve a TLS certificate for a host discovered at runtime (e.g.
a Docker label), without linking against autocert's `.so`.

For the full ABI contract (struct layout, exact function signatures, locking
rule) read [`src/ngx_autocert_requests.h`](../src/ngx_autocert_requests.h) —
it is the single source of truth; this doc is a task-oriented walkthrough on
top of it. If the two disagree, the header wins.

## Why a shm zone and not a function call

nginx loads each dynamic module's `.so` with `dlopen(..., RTLD_LOCAL)` (no
`RTLD_GLOBAL`), so C symbols in autocert's `.so` are invisible to any other
module's `.so` and vice versa — there is no cross-module `dlsym` to lean on
(this is the same wall `ngx_http_autocert_conf.h` documents for autocert's own
internal accessor). The only thing both modules can agree on without linking
is a **named nginx shared-memory zone**, attached by both under the same
name, with a versioned struct layout compiled into both `.so`s from the same
header file (vendor/copy `ngx_autocert_requests.h` into the consumer module's
tree — it has no other dependencies, just `ngx_core.h`).

## 1. Compile the header into your module

Copy `src/ngx_autocert_requests.h` into your module's source tree (no `.c` to
copy — the functions are provided by whichever module's `.so` actually
creates/owns the zone; declaring the prototypes is enough for the linker,
since both `.so`s attach the same zone by name and only autocert's `.so`
needs the implementation loaded into the process for the driver side to run).
Bump-tracking: if autocert ever changes `NGX_AUTOCERT_API_VERSION`, re-vendor
the header — a stale copy with an old version number will simply see the
zone's stamped version compare unequal and label the integration "off",
never mis-parse a foreign layout.

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

    /* Only set init if nobody has claimed it yet — if autocert's postconfig
     * ran first, zone->data already points at ITS init callback and you must
     * not overwrite it. */
    if (zone->data == NULL) {
        zone->init = ngx_autocert_requests_init_zone_consumer;
    }

    my_conf->requests_zone = zone;  /* stash on your own conf struct */
    return NGX_OK;
}
```

Whichever module's postconfig runs first actually creates the zone; the other
attaches the same name (nginx dedups by name+tag — hence the tag MUST be
`NULL` on both sides, or `ngx_shared_memory_add()` will see two different
"uses" of the same name and error out). Load-order between the two modules is
NOT guaranteed by config file order alone in every nginx version, so always
install a consumer-side init callback defensively as above rather than
assuming autocert loads first.

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

## What you must NOT do

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
