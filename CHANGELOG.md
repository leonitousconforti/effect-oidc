# effect-oidc

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
