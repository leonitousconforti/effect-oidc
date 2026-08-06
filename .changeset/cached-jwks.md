---
"effect-oidc": patch
---

`Oidc.cachedJwks` builds a cached view of an issuer's JWKS document: fetched lazily, reused for a ttl (10 minutes by default), a failed refresh serves the last good document, and a failure with nothing to fall back on is evicted immediately instead of being cached for the rest of the ttl. `ResourceServer.layer` now uses it, fixing a cold-cache outage where a single failed first fetch was cached and answered 500 to every request until the ttl lapsed, and gains a `jwks` option for providing the issuer's keys statically, which skips fetching entirely for resource servers that already hold them (such as one living in the same process as its provider).
