# effect-oidc

## 0.1.0

### Minor Changes

- bc4fb75: `ResourceServer.OIDCScopes` now accepts a scope carrying its description, and `ResourceServer.scopeCatalog` reads those back off an api.

    An annotation entry may be a bare name as before, or a `ScopeDescription` - `{ name, description }` - where the name is what a token's `scope` claim carries and enforcement reads, and the description is the sentence a consent screen or a self-service dashboard shows for it. Both forms may sit in the same list, and existing bare-string annotations are untouched.

    `scopeCatalog(api)` returns every described scope an api declares, deduped by name, in declaration order: groups as they were added, and within each group its own annotation before its endpoints'. That is the list a consent screen renders, read off the endpoints that actually enforce the scopes rather than kept as a second copy beside them - a copy that can name a scope no endpoint accepts, or miss one every endpoint does.

    `requireScopes` accepts either form too, so the same constant guards a handler and describes the scope.

    A description is one string in one language, and only described scopes are in the catalog: a bare name says nothing about what it lets someone do, and a catalog that guessed a sentence for it would be putting words in front of the person deciding what to grant. A service that shows its scopes in several languages should annotate a message key and resolve it per request.

- 1a80733: Add a `DynamicClientRegistration` module: RFC 7591, both ends.

    For a provider, `ClientMetadataRequestSchema` decodes a registration body and `validateClientMetadata` applies a `RegistrationPolicy` to it - filling in the defaults the RFC leaves to the server and refusing anything the provider could not honour later, so a client never registers with a redirect uri, grant, response type or scope that every subsequent request would then be refused for. `clientInformationResponse` builds the answer, including the `client_secret_expires_at` that RFC 7591 Section 3.2.1 makes required alongside an issued secret.

    Two refusals are worth naming. A public client asking for `client_credentials` is turned away at registration rather than earning an `invalid_client` at the token endpoint, where the answer would not say which field was wrong. And the `authorization_code` grant and the `code` response type each require the other, per RFC 7591 Section 2.1.

    For a client, `register` finds the endpoint through the issuer's discovery document - which is what makes `NotOffered` a real answer rather than a guessed path - presents an initial access token when the provider gates registration, and comes back with a `client_id` and, for a confidential client, a `Redacted` secret. `registerAt` skips discovery when the endpoint is already known. Neither retries: whether a provider that is still coming up is worth waiting for is the caller's judgement, and `Effect.retry` composes.

## 0.0.14

### Patch Changes

- 8b9fa51: Add the optional `registration_endpoint` (RFC 7591) to `DiscoveryDocumentSchema`.

    A provider that offers dynamic client registration advertises it there, and a client can now learn it from `Oidc.fetchDiscovery` instead of assuming a path. It is validated like every other endpoint in the document: same-origin with the issuer, and https away from loopback, because although a registration request carries no credentials its answer issues them.

- 8b9fa51: Accept plain http on the loopback interface in `Oidc.fetchDiscovery`.

    Every endpoint in a discovery document still has to be same-origin with the issuer, and https everywhere except `localhost`, `127.0.0.1` and `[::1]`, where nothing is on the wire. A relying party can now read discovery from a provider running on `http://localhost` in development instead of building the endpoint urls by hand; away from loopback the https requirement of RFC 8414 Section 2 is enforced exactly as before.

## 0.0.13

### Patch Changes

- 9eba3db: Infer the error type of `ResourceServer.layer`'s `revoked` predicate instead of fixing it to `unknown`.

    A denylist backed by a database keeps its own error type through the option now, rather than having it widened away at the boundary, and the internal `any-unknown-in-error-context` suppression that went with the old signature is gone. Behaviour is unchanged: a predicate failure is still answered as `500 Internal Server Error`, because a revocation check that cannot answer is a server problem rather than a client one.

    `layer` gains a leading type parameter, so an explicit `layer<MyContext>(...)` now reads as the error type rather than the context. Inferred calls are unaffected.

## 0.0.12

### Patch Changes

- e0ba955: Security audit fixes and hardening.

    - `Jwk.JwkSet` now skips keys it does not understand (JWE `alg` values such as `RSA-OAEP`, `kty: "OKP"`, malformed entries) instead of failing the whole set, per RFC 7517 Section 5. Previously one such key in a provider's JWKS (Keycloak publishes an encryption key by default) failed every verification.
    - `Oidc.fetchDiscovery` now validates `revocation_endpoint` and `userinfo_endpoint` (https, same origin as the issuer) alongside the authorization, token, and JWKS endpoints, so a hostile discovery document cannot redirect client secrets or access tokens.
    - Well-known URLs are resolved relative to the issuer (`Oidc.issuerUrl`) rather than its origin, so issuers with a path (`https://idp.example/realms/tenant`) work. `ResourceServer.layer` additionally accepts an explicit `jwksUri`.
    - `Oidc.issueAccessToken` mints `typ: "at+jwt"` (RFC 9068) and `ResourceServer.layer` pins `types: ["at+jwt"]` by default, so the issuer's other JWTs (id tokens) cannot be presented as access tokens. `Jwt.sign` accepts a `typ` option. Pass `types` to the layer if your issuer mints another value.
    - `RelyingParty` sends a `nonce` on the authorization request, keeps it in a transaction cookie, and checks it against the id token.
    - `Oidc.jwksCache` exposes a rate-limited `refresh`; `ResourceServer` and `RelyingParty` refetch the JWKS once when a token names an unknown `kid` (key rotation). `Oidc.cachedJwks` is unchanged.
    - `Jwk.isCompatibleWith` honours a key's own `alg` and `key_ops`.
    - `Oidc.clientAuthentication` rejects requests that use both a Basic header and a body `client_secret` (RFC 6749 Section 2.3).
    - `Oidc.TokenResponseSchema.scope` is optional, as RFC 6749 Section 5.1 allows.
    - `Jwe.decrypt` continues with a random CEK when RSA-OAEP key decryption fails (RFC 7516 Section 11.5), enforces the 8 octet PBES2 salt minimum, and decodes base64url strictly. `Jwe.encrypt` fails with typed `KeyManagementFailed`/`EncryptionFailed` errors instead of defects when handed the wrong kind of key.

## 0.0.11

### Patch Changes

- e4b135c: Update Effect-TS packages to v4.0.0-rc.111

## 0.0.10

### Patch Changes

- 9c19f0c: Update Effect-TS packages to v4.0.0-rc.108

## 0.0.9

### Patch Changes

- 0a4750b: Update Effect-TS packages to v4.0.0-beta.105

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
