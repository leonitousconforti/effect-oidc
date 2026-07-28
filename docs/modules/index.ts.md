---
title: index.ts
nav_order: 1
parent: Modules
---

## index.ts overview

JSON Web Algorithms (JWA) schemas based on RFC 7518.

This module defines the cryptographic algorithm identifiers used for JWS
digital signatures and MACs (RFC 7518 Section 3), along with the WebCrypto
parameter sets needed to import keys and to sign/verify with each
algorithm. Those two parameter sets differ (e.g. ECDSA import needs
`namedCurve` while signing needs `hash`), so they are exposed separately.

It also defines the JWE algorithm identifiers: the "alg" key management
algorithms (RFC 7518 Section 4) used to encrypt or derive the Content
Encryption Key, the "enc" content encryption algorithms (RFC 7518
Section 5) that perform authenticated encryption on the plaintext, and the
structural parameters (key/IV/tag sizes) each content encryption algorithm
requires.

**See**

- https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)

Since v1.0.0

---

## Exports Grouped by Category

- [Jwt](#jwt)
  - [Jwt (namespace export)](#jwt-namespace-export)
- [Oidc](#oidc)
  - [Oidc (namespace export)](#oidc-namespace-export)
- [ResourceServer](#resourceserver)
  - [ResourceServer (namespace export)](#resourceserver-namespace-export)
- [utils](#utils)
  - [Jwa (namespace export)](#jwa-namespace-export)
  - [Jwe (namespace export)](#jwe-namespace-export)
  - [Jwk (namespace export)](#jwk-namespace-export)
  - [Jws (namespace export)](#jws-namespace-export)

---

# Jwt

## Jwt (namespace export)

Re-exports all named exports from the "./Jwt.ts" module as `Jwt`.

**See**

- https://www.rfc-editor.org/rfc/rfc7519 - JSON Web Token (JWT)

**Signature**

```ts
export * as Jwt from "./Jwt.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L105)

Since v1.0.0

# Oidc

## Oidc (namespace export)

Re-exports all named exports from the "./Oidc.ts" module as `Oidc`.

**Signature**

```ts
export * as Oidc from "./Oidc.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L122)

Since v1.0.0

# ResourceServer

## ResourceServer (namespace export)

Re-exports all named exports from the "./ResourceServer.ts" module as `ResourceServer`.

**Signature**

```ts
export * as ResourceServer from "./ResourceServer.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L155)

Since v1.0.0

# utils

## Jwa (namespace export)

Re-exports all named exports from the "./Jwa.ts" module as `Jwa`.

**See**

- https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)

**Signature**

```ts
export * as Jwa from "./Jwa.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L24)

Since v1.0.0

## Jwe (namespace export)

Re-exports all named exports from the "./Jwe.ts" module as `Jwe`.

**See**

- https://www.rfc-editor.org/rfc/rfc7516 - JSON Web Encryption (JWE)
- https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)

**Signature**

```ts
export * as Jwe from "./Jwe.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L50)

Since v1.0.0

## Jwk (namespace export)

Re-exports all named exports from the "./Jwk.ts" module as `Jwk`.

**See**

- https://www.rfc-editor.org/rfc/rfc7517 - JSON Web Key (JWK)
- https://www.rfc-editor.org/rfc/rfc7518#section-6 - Cryptographic Algorithms for Keys

**Signature**

```ts
export * as Jwk from "./Jwk.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L68)

Since v1.0.0

## Jws (namespace export)

Re-exports all named exports from the "./Jws.ts" module as `Jws`.

**See**

- https://www.rfc-editor.org/rfc/rfc7515 - JSON Web Signature (JWS)
- https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)

**Signature**

```ts
export * as Jws from "./Jws.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L90)

Since v1.0.0
