---
"effect-oidc": patch
---

Security audit fixes and hardening.

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
