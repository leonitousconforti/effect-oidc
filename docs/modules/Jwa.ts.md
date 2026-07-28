---
title: Jwa.ts
nav_order: 2
parent: Modules
---

## Jwa.ts overview

JSON Web Algorithms (JWA) schemas based on RFC 7518.

This module defines the cryptographic algorithm identifiers used for JWS
digital signatures and MACs (RFC 7518 Section 3), along with the WebCrypto
parameter sets needed to import keys and to sign/verify with each
algorithm. Those two parameter sets differ (e.g. ECDSA import needs
`namedCurve` while signing needs `hash`), so they are exposed separately.

**See**

- https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)

Since v1.0.0

---

## Exports Grouped by Category

- [JWS](#jws)
  - [JwsAlgorithm](#jwsalgorithm)
- [WebCrypto](#webcrypto)
  - [importParameters](#importparameters)
  - [signatureParameters](#signatureparameters)

---

# JWS

## JwsAlgorithm

JWS algorithm values as defined in RFC 7518 Section 3.1. These algorithms
are used for digital signatures and MACs to secure the JWS. The "none"
algorithm is intentionally unsupported.

**See**

- https://www.rfc-editor.org/rfc/rfc7518#section-3.1

**Signature**

```ts
declare const JwsAlgorithm: Schema.Literals<
  readonly ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/tree/main/src/Jwa.ts#L25)

Since v1.0.0

# WebCrypto

## importParameters

WebCrypto parameters for `crypto.subtle.importKey` for each JWS algorithm.

**Signature**

```ts
declare const importParameters: (
  u:
    | "HS256"
    | "HS384"
    | "HS512"
    | "RS256"
    | "RS384"
    | "RS512"
    | "ES256"
    | "ES384"
    | "ES512"
    | "PS256"
    | "PS384"
    | "PS512"
) => RsaHashedImportParams | EcKeyImportParams | HmacImportParams
```

[Source](https://github.com/leonitousconforti/effect-oidc/tree/main/src/Jwa.ts#L57)

Since v1.0.0

## signatureParameters

WebCrypto parameters for `crypto.subtle.sign`/`crypto.subtle.verify` for
each JWS algorithm.

**Signature**

```ts
declare const signatureParameters: (
  u:
    | "HS256"
    | "HS384"
    | "HS512"
    | "RS256"
    | "RS384"
    | "RS512"
    | "ES256"
    | "ES384"
    | "ES512"
    | "PS256"
    | "PS384"
    | "PS512"
) => AlgorithmIdentifier | RsaPssParams | EcdsaParams
```

[Source](https://github.com/leonitousconforti/effect-oidc/tree/main/src/Jwa.ts#L80)

Since v1.0.0
