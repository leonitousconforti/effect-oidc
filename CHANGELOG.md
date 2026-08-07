# effect-oidc

## 0.0.8

### Patch Changes

- aada1db: `Oidc.cachedJwks` builds a cached view of an issuer's JWKS document: fetched lazily, reused for a ttl (10 minutes by default), a failed refresh serves the last good document, and a failure with nothing to fall back on is evicted immediately instead of being cached for the rest of the ttl. `ResourceServer.layer` now uses it, fixing a cold-cache outage where a single failed first fetch was cached and answered 500 to every request until the ttl lapsed, and gains a `jwks` option for providing the issuer's keys statically, which skips fetching entirely for resource servers that already hold them (such as one living in the same process as its provider).
- e8e6a99: Update Effect-TS packages to v4.0.0-beta.104
- d415fda: Add the RelyingParty module: the server side of "Sign in with ..." for web apps. `RelyingParty.make` realizes a provider registration into `beginAuthorization` (the authorization redirect plus short-lived state, PKCE verifier, and opaque payload transaction cookies) and `completeAuthorization` (state validation, code exchange, and id token verification, failing with a coarse `CallbackError` reason that is safe to surface in a redirect). The provider's keys are read through `Oidc.cachedJwks`, so a transient JWKS fetch failure serves the last good key set instead of failing sign-ins.

## 0.0.7

### Patch Changes

- d3e64fb: Update Effect-TS packages to v4.0.0-beta.103

## 0.0.6

### Patch Changes

- 079d941: `Oidc.verifyIdToken` now accepts RS256 signatures alongside ES256 by default, and takes an `algorithms` option to override the accepted set. The previous hardcoded ES256-only list rejected every id token from providers that sign with RSA keys (Google, Discord) with a `BadAlgorithm` error.

## 0.0.5

### Patch Changes

- 06f0cad: Remove type assertions and add helpers

## 0.0.4

### Patch Changes

- 8515ae0: Small improvements to OIDC

## 0.0.3

### Patch Changes

- bf804a6: Improve middleware

## 0.0.2

### Patch Changes

- a73ad5c: Initial release: JWA/JWK/JWS/JWT/JWE schemas with WebCrypto signing and verification, OIDC discovery/token/PKCE protocol surface, and HttpApi resource-server middleware
