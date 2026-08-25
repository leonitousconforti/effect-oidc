---
title: Jwa.ts
nav_order: 3
parent: Modules
---

## Jwa.ts overview

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

- [JWE](#jwe)
  - [JweAlgorithm](#jwealgorithm)
  - [JweEncryption](#jweencryption)
  - [encryptionParameters](#encryptionparameters)
- [JWS](#jws)
  - [JwsAlgorithm](#jwsalgorithm)
- [WebCrypto](#webcrypto)
  - [importParameters](#importparameters)
  - [signatureParameters](#signatureparameters)

---

# JWE

## JweAlgorithm

JWE "alg" (key management) algorithm values as defined in RFC 7518 Section
4.1. These determine how the Content Encryption Key (CEK) is encrypted or
derived. `RSA1_5` is intentionally omitted: the Web Crypto API does not
implement RSAES-PKCS1-v1_5 encryption, and RFC 8725 discourages its use.

**See**

- https://www.rfc-editor.org/rfc/rfc7518#section-4.1

**Signature**

```ts
declare const JweAlgorithm: Schema.Literals<
  readonly [
    "RSA-OAEP",
    "RSA-OAEP-256",
    "A128KW",
    "A192KW",
    "A256KW",
    "dir",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW"
  ]
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwa.ts#L109)

Since v1.0.0

## JweEncryption

JWE "enc" (content encryption) algorithm values as defined in RFC 7518
Section 5.1. These perform authenticated encryption on the plaintext.

**See**

- https://www.rfc-editor.org/rfc/rfc7518#section-5.1

**Signature**

```ts
declare const JweEncryption: Schema.Literals<
  readonly ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"]
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwa.ts#L151)

Since v1.0.0

## encryptionParameters

Structural parameters for a JWE content encryption algorithm: the Content
Encryption Key size, IV size, and (for the composite AES-CBC-HMAC family)
the split key sizes, authentication tag size, and HMAC hash.

**Signature**

```ts
declare const encryptionParameters: (
  u: "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512" | "A128GCM" | "A192GCM" | "A256GCM"
) =>
  | { readonly kind: "gcm"; readonly cekBytes: 16; readonly ivBytes: 12 }
  | { readonly kind: "gcm"; readonly cekBytes: 24; readonly ivBytes: 12 }
  | { readonly kind: "gcm"; readonly cekBytes: 32; readonly ivBytes: 12 }
  | {
      readonly kind: "cbc"
      readonly cekBytes: 32
      readonly ivBytes: 16
      readonly macBytes: 16
      readonly encBytes: 16
      readonly tagBytes: 16
      readonly hash: "SHA-256"
    }
  | {
      readonly kind: "cbc"
      readonly cekBytes: 48
      readonly ivBytes: 16
      readonly macBytes: 24
      readonly encBytes: 24
      readonly tagBytes: 24
      readonly hash: "SHA-384"
    }
  | {
      readonly kind: "cbc"
      readonly cekBytes: 64
      readonly ivBytes: 16
      readonly macBytes: 32
      readonly encBytes: 32
      readonly tagBytes: 32
      readonly hash: "SHA-512"
    }
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwa.ts#L175)

Since v1.0.0

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwa.ts#L32)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwa.ts#L64)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwa.ts#L87)

Since v1.0.0
