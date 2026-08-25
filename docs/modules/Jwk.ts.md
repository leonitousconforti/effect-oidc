---
title: Jwk.ts
nav_order: 5
parent: Modules
---

## Jwk.ts overview

JSON Web Key (JWK) schemas based on RFC 7517 and RFC 7518 Section 6.

This module provides Effect Schema definitions for representing
cryptographic keys as JSON objects, including key-type-specific parameters
for EC, RSA, and symmetric (oct) keys, as well as the JWK Set format.

Binary-valued members (coordinates, exponents, key values) are kept in
their base64url wire form: they encode raw bytes, not UTF-8 text, and the
base64url form is exactly what `crypto.subtle.importKey("jwk", ...)`
expects.

**See**

- https://www.rfc-editor.org/rfc/rfc7517 - JSON Web Key (JWK)
- https://www.rfc-editor.org/rfc/rfc7518#section-6 - Cryptographic Algorithms for Keys

Since v1.0.0

---

## Exports Grouped by Category

- [Compatibility](#compatibility)
  - [isCompatibleWith](#iscompatiblewith)
  - [isPrivate](#isprivate)
  - [isSymmetric](#issymmetric)
- [Elliptic Curve](#elliptic-curve)
  - [EcPrivateKey](#ecprivatekey)
  - [EcPublicKey](#ecpublickey)
  - [EllipticCurve](#ellipticcurve)
- [JWK](#jwk)
  - [Jwk](#jwk-1)
- [JWK Set](#jwk-set)
  - [JwkSet](#jwkset)
- [Key Operations](#key-operations)
  - [KeyOperation](#keyoperation)
- [Key Type](#key-type)
  - [KeyType](#keytype)
- [Key Use](#key-use)
  - [KeyUse](#keyuse)
- [RSA](#rsa)
  - [RsaPrivateKey](#rsaprivatekey)
  - [RsaPublicKey](#rsapublickey)
- [Symmetric](#symmetric)
  - [OctKey](#octkey)

---

# Compatibility

## isCompatibleWith

Returns whether a JWK may verify a signature under the given JWS algorithm:
the key type (and EC curve) must match the algorithm family, a key marked
for encryption (`use: "enc"`) is rejected, a key that names its own `alg`
(RFC 7517 Section 4.4) is only used for that algorithm, and a key that
lists `key_ops` (Section 4.3) must include `verify`. Gate key selection
with this so a token cannot steer a key of one family into an incompatible
algorithm (the classic asymmetric/symmetric confusion).

**Signature**

```ts
declare const isCompatibleWith: (alg: (typeof JwsAlgorithm)["Type"], jwk: (typeof Jwk)["Type"]) => boolean
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L385)

Since v1.0.0

## isPrivate

Returns whether a JWK carries private key material (`d` for EC/RSA).

**Signature**

```ts
declare const isPrivate: (jwk: (typeof Jwk)["Type"]) => boolean
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L428)

Since v1.0.0

## isSymmetric

Returns whether a JWK is a symmetric (secret) key. Never accept such a key
from an untrusted source (a token's `jku`/`jwk` header) for signature
verification - that enables forgery.

**Signature**

```ts
declare const isSymmetric: (jwk: (typeof Jwk)["Type"]) => boolean
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L420)

Since v1.0.0

# Elliptic Curve

## EcPrivateKey

An Elliptic Curve private key represented as a JWK. Extends the public key
with the private key parameter "d".

**See**

- https://www.rfc-editor.org/rfc/rfc7518#section-6.2.2

**Signature**

```ts
declare const EcPrivateKey: Schema.Struct<{
  readonly d: Schema.String
  readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
  readonly key_ops: Schema.optional<
    Schema.$Array<
      Schema.Literals<
        readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
      >
    >
  >
  readonly alg: Schema.optional<
    Schema.Literals<
      readonly [
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512"
      ]
    >
  >
  readonly kid: Schema.optional<Schema.String>
  readonly x5u: Schema.optional<Schema.String>
  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
  readonly x5t: Schema.optional<Schema.String>
  readonly "x5t#S256": Schema.optional<Schema.String>
  readonly kty: Schema.Literal<"EC">
  readonly crv: Schema.Literals<readonly ["P-256", "P-384", "P-521"]>
  readonly x: Schema.String
  readonly y: Schema.String
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L173)

Since v1.0.0

## EcPublicKey

An Elliptic Curve public key represented as a JWK.

Members "kty", "crv", "x", and "y" are required for EC public keys.

**See**

- https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1

**Signature**

```ts
declare const EcPublicKey: Schema.Struct<{
  readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
  readonly key_ops: Schema.optional<
    Schema.$Array<
      Schema.Literals<
        readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
      >
    >
  >
  readonly alg: Schema.optional<
    Schema.Literals<
      readonly [
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512"
      ]
    >
  >
  readonly kid: Schema.optional<Schema.String>
  readonly x5u: Schema.optional<Schema.String>
  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
  readonly x5t: Schema.optional<Schema.String>
  readonly "x5t#S256": Schema.optional<Schema.String>
  readonly kty: Schema.Literal<"EC">
  readonly crv: Schema.Literals<readonly ["P-256", "P-384", "P-521"]>
  readonly x: Schema.String
  readonly y: Schema.String
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L137)

Since v1.0.0

## EllipticCurve

JWK Curve parameter values for Elliptic Curve keys as defined in RFC 7518
Section 6.2.1.1.

**See**

- https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1

**Signature**

```ts
declare const EllipticCurve: Schema.Literals<readonly ["P-256", "P-384", "P-521"]>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L86)

Since v1.0.0

# JWK

## Jwk

A JSON Web Key (JWK) as defined in RFC 7517. This is a discriminated union
over the "kty" field, supporting EC, RSA, and symmetric (oct) key types.

The union includes both public and private key representations - consumers
can narrow using the individual schemas (e.g. `EcPublicKey`,
`RsaPrivateKey`) when a specific key form is expected. Private forms come
first so that keys carrying private members decode as private keys.

**See**

- https://www.rfc-editor.org/rfc/rfc7517#section-4

**Signature**

```ts
declare const Jwk: Schema.Union<
  readonly [
    Schema.Struct<{
      readonly d: Schema.String
      readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
      readonly key_ops: Schema.optional<
        Schema.$Array<
          Schema.Literals<
            readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
          >
        >
      >
      readonly alg: Schema.optional<
        Schema.Literals<
          readonly [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
          ]
        >
      >
      readonly kid: Schema.optional<Schema.String>
      readonly x5u: Schema.optional<Schema.String>
      readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
      readonly x5t: Schema.optional<Schema.String>
      readonly "x5t#S256": Schema.optional<Schema.String>
      readonly kty: Schema.Literal<"EC">
      readonly crv: Schema.Literals<readonly ["P-256", "P-384", "P-521"]>
      readonly x: Schema.String
      readonly y: Schema.String
    }>,
    Schema.Struct<{
      readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
      readonly key_ops: Schema.optional<
        Schema.$Array<
          Schema.Literals<
            readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
          >
        >
      >
      readonly alg: Schema.optional<
        Schema.Literals<
          readonly [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
          ]
        >
      >
      readonly kid: Schema.optional<Schema.String>
      readonly x5u: Schema.optional<Schema.String>
      readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
      readonly x5t: Schema.optional<Schema.String>
      readonly "x5t#S256": Schema.optional<Schema.String>
      readonly kty: Schema.Literal<"EC">
      readonly crv: Schema.Literals<readonly ["P-256", "P-384", "P-521"]>
      readonly x: Schema.String
      readonly y: Schema.String
    }>,
    Schema.Union<
      readonly [
        Schema.Struct<{
          readonly d: Schema.String
          readonly p: Schema.String
          readonly q: Schema.String
          readonly dp: Schema.String
          readonly dq: Schema.String
          readonly qi: Schema.String
          readonly oth: Schema.optional<
            Schema.$Array<
              Schema.Struct<{ readonly r: Schema.String; readonly d: Schema.String; readonly t: Schema.String }>
            >
          >
          readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
          readonly key_ops: Schema.optional<
            Schema.$Array<
              Schema.Literals<
                readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
              >
            >
          >
          readonly alg: Schema.optional<
            Schema.Literals<
              readonly [
                "HS256",
                "HS384",
                "HS512",
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
                "PS256",
                "PS384",
                "PS512"
              ]
            >
          >
          readonly kid: Schema.optional<Schema.String>
          readonly x5u: Schema.optional<Schema.String>
          readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
          readonly x5t: Schema.optional<Schema.String>
          readonly "x5t#S256": Schema.optional<Schema.String>
          readonly kty: Schema.Literal<"RSA">
          readonly n: Schema.String
          readonly e: Schema.String
        }>,
        Schema.Struct<{
          readonly d: Schema.String
          readonly oth: Schema.optional<
            Schema.$Array<
              Schema.Struct<{ readonly r: Schema.String; readonly d: Schema.String; readonly t: Schema.String }>
            >
          >
          readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
          readonly key_ops: Schema.optional<
            Schema.$Array<
              Schema.Literals<
                readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
              >
            >
          >
          readonly alg: Schema.optional<
            Schema.Literals<
              readonly [
                "HS256",
                "HS384",
                "HS512",
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
                "PS256",
                "PS384",
                "PS512"
              ]
            >
          >
          readonly kid: Schema.optional<Schema.String>
          readonly x5u: Schema.optional<Schema.String>
          readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
          readonly x5t: Schema.optional<Schema.String>
          readonly "x5t#S256": Schema.optional<Schema.String>
          readonly kty: Schema.Literal<"RSA">
          readonly n: Schema.String
          readonly e: Schema.String
        }>
      ]
    >,
    Schema.Struct<{
      readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
      readonly key_ops: Schema.optional<
        Schema.$Array<
          Schema.Literals<
            readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
          >
        >
      >
      readonly alg: Schema.optional<
        Schema.Literals<
          readonly [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
          ]
        >
      >
      readonly kid: Schema.optional<Schema.String>
      readonly x5u: Schema.optional<Schema.String>
      readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
      readonly x5t: Schema.optional<Schema.String>
      readonly "x5t#S256": Schema.optional<Schema.String>
      readonly kty: Schema.Literal<"RSA">
      readonly n: Schema.String
      readonly e: Schema.String
    }>,
    Schema.Struct<{
      readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
      readonly key_ops: Schema.optional<
        Schema.$Array<
          Schema.Literals<
            readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
          >
        >
      >
      readonly alg: Schema.optional<
        Schema.Literals<
          readonly [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
          ]
        >
      >
      readonly kid: Schema.optional<Schema.String>
      readonly x5u: Schema.optional<Schema.String>
      readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
      readonly x5t: Schema.optional<Schema.String>
      readonly "x5t#S256": Schema.optional<Schema.String>
      readonly kty: Schema.Literal<"oct">
      readonly k: Schema.String
    }>
  ]
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L334)

Since v1.0.0

# JWK Set

## JwkSet

A JWK Set as defined in RFC 7517 Section 5. A JSON object that represents
a set of JWKs. The "keys" member is required and must be an array of JWKs.

Keys this module does not understand (an unsupported `kty` such as "OKP",
an encryption key carrying a JWE `alg` such as "RSA-OAEP", or a malformed
entry) are skipped on decode rather than failing the whole set, as RFC
7517 Section 5 recommends - a provider publishing one exotic key next to
its signing keys must not take every verification down with it.

**See**

- https://www.rfc-editor.org/rfc/rfc7517#section-5

**Signature**

```ts
declare const JwkSet: Schema.Struct<{
  readonly keys: Schema.decodeTo<
    Schema.$Array<
      Schema.Union<
        readonly [
          Schema.Struct<{
            readonly d: Schema.String
            readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
            readonly key_ops: Schema.optional<
              Schema.$Array<
                Schema.Literals<
                  readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
                >
              >
            >
            readonly alg: Schema.optional<
              Schema.Literals<
                readonly [
                  "HS256",
                  "HS384",
                  "HS512",
                  "RS256",
                  "RS384",
                  "RS512",
                  "ES256",
                  "ES384",
                  "ES512",
                  "PS256",
                  "PS384",
                  "PS512"
                ]
              >
            >
            readonly kid: Schema.optional<Schema.String>
            readonly x5u: Schema.optional<Schema.String>
            readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
            readonly x5t: Schema.optional<Schema.String>
            readonly "x5t#S256": Schema.optional<Schema.String>
            readonly kty: Schema.Literal<"EC">
            readonly crv: Schema.Literals<readonly ["P-256", "P-384", "P-521"]>
            readonly x: Schema.String
            readonly y: Schema.String
          }>,
          Schema.Struct<{
            readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
            readonly key_ops: Schema.optional<
              Schema.$Array<
                Schema.Literals<
                  readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
                >
              >
            >
            readonly alg: Schema.optional<
              Schema.Literals<
                readonly [
                  "HS256",
                  "HS384",
                  "HS512",
                  "RS256",
                  "RS384",
                  "RS512",
                  "ES256",
                  "ES384",
                  "ES512",
                  "PS256",
                  "PS384",
                  "PS512"
                ]
              >
            >
            readonly kid: Schema.optional<Schema.String>
            readonly x5u: Schema.optional<Schema.String>
            readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
            readonly x5t: Schema.optional<Schema.String>
            readonly "x5t#S256": Schema.optional<Schema.String>
            readonly kty: Schema.Literal<"EC">
            readonly crv: Schema.Literals<readonly ["P-256", "P-384", "P-521"]>
            readonly x: Schema.String
            readonly y: Schema.String
          }>,
          Schema.Union<
            readonly [
              Schema.Struct<{
                readonly d: Schema.String
                readonly p: Schema.String
                readonly q: Schema.String
                readonly dp: Schema.String
                readonly dq: Schema.String
                readonly qi: Schema.String
                readonly oth: Schema.optional<
                  Schema.$Array<
                    Schema.Struct<{ readonly r: Schema.String; readonly d: Schema.String; readonly t: Schema.String }>
                  >
                >
                readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
                readonly key_ops: Schema.optional<
                  Schema.$Array<
                    Schema.Literals<
                      readonly [
                        "sign",
                        "verify",
                        "encrypt",
                        "decrypt",
                        "wrapKey",
                        "unwrapKey",
                        "deriveKey",
                        "deriveBits"
                      ]
                    >
                  >
                >
                readonly alg: Schema.optional<
                  Schema.Literals<
                    readonly [
                      "HS256",
                      "HS384",
                      "HS512",
                      "RS256",
                      "RS384",
                      "RS512",
                      "ES256",
                      "ES384",
                      "ES512",
                      "PS256",
                      "PS384",
                      "PS512"
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly kty: Schema.Literal<"RSA">
                readonly n: Schema.String
                readonly e: Schema.String
              }>,
              Schema.Struct<{
                readonly d: Schema.String
                readonly oth: Schema.optional<
                  Schema.$Array<
                    Schema.Struct<{ readonly r: Schema.String; readonly d: Schema.String; readonly t: Schema.String }>
                  >
                >
                readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
                readonly key_ops: Schema.optional<
                  Schema.$Array<
                    Schema.Literals<
                      readonly [
                        "sign",
                        "verify",
                        "encrypt",
                        "decrypt",
                        "wrapKey",
                        "unwrapKey",
                        "deriveKey",
                        "deriveBits"
                      ]
                    >
                  >
                >
                readonly alg: Schema.optional<
                  Schema.Literals<
                    readonly [
                      "HS256",
                      "HS384",
                      "HS512",
                      "RS256",
                      "RS384",
                      "RS512",
                      "ES256",
                      "ES384",
                      "ES512",
                      "PS256",
                      "PS384",
                      "PS512"
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly kty: Schema.Literal<"RSA">
                readonly n: Schema.String
                readonly e: Schema.String
              }>
            ]
          >,
          Schema.Struct<{
            readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
            readonly key_ops: Schema.optional<
              Schema.$Array<
                Schema.Literals<
                  readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
                >
              >
            >
            readonly alg: Schema.optional<
              Schema.Literals<
                readonly [
                  "HS256",
                  "HS384",
                  "HS512",
                  "RS256",
                  "RS384",
                  "RS512",
                  "ES256",
                  "ES384",
                  "ES512",
                  "PS256",
                  "PS384",
                  "PS512"
                ]
              >
            >
            readonly kid: Schema.optional<Schema.String>
            readonly x5u: Schema.optional<Schema.String>
            readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
            readonly x5t: Schema.optional<Schema.String>
            readonly "x5t#S256": Schema.optional<Schema.String>
            readonly kty: Schema.Literal<"RSA">
            readonly n: Schema.String
            readonly e: Schema.String
          }>,
          Schema.Struct<{
            readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
            readonly key_ops: Schema.optional<
              Schema.$Array<
                Schema.Literals<
                  readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
                >
              >
            >
            readonly alg: Schema.optional<
              Schema.Literals<
                readonly [
                  "HS256",
                  "HS384",
                  "HS512",
                  "RS256",
                  "RS384",
                  "RS512",
                  "ES256",
                  "ES384",
                  "ES512",
                  "PS256",
                  "PS384",
                  "PS512"
                ]
              >
            >
            readonly kid: Schema.optional<Schema.String>
            readonly x5u: Schema.optional<Schema.String>
            readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
            readonly x5t: Schema.optional<Schema.String>
            readonly "x5t#S256": Schema.optional<Schema.String>
            readonly kty: Schema.Literal<"oct">
            readonly k: Schema.String
          }>
        ]
      >
    >,
    Schema.$Array<Schema.Unknown>,
    never,
    never
  >
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L354)

Since v1.0.0

# Key Operations

## KeyOperation

JWK Key Operations parameter values as defined in RFC 7517 Section 4.3.
These values intentionally match the Web Cryptography API KeyUsage values.

**See**

- https://www.rfc-editor.org/rfc/rfc7517#section-4.3

**Signature**

```ts
declare const KeyOperation: Schema.Literals<
  readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L63)

Since v1.0.0

# Key Type

## KeyType

JWK "kty" (Key Type) parameter values as defined in RFC 7518 Section 6.1.

**See**

- https://www.rfc-editor.org/rfc/rfc7518#section-6.1

**Signature**

```ts
declare const KeyType: Schema.Literals<readonly ["EC", "RSA", "oct"]>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L29)

Since v1.0.0

# Key Use

## KeyUse

JWK Public Key Use parameter values as defined in RFC 7517 Section 4.2.

**See**

- https://www.rfc-editor.org/rfc/rfc7517#section-4.2

**Signature**

```ts
declare const KeyUse: Schema.Literals<readonly ["sig", "enc"]>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L46)

Since v1.0.0

# RSA

## RsaPrivateKey

An RSA private key represented as a JWK. Extends the public key with
private key parameters. The "d" parameter is required; the CRT parameters
("p", "q", "dp", "dq", "qi") should be included together - if any one of
them is present then all of them must be present, which the union encodes.

**See**

- https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2

**Signature**

```ts
declare const RsaPrivateKey: Schema.Union<
  readonly [
    Schema.Struct<{
      readonly d: Schema.String
      readonly p: Schema.String
      readonly q: Schema.String
      readonly dp: Schema.String
      readonly dq: Schema.String
      readonly qi: Schema.String
      readonly oth: Schema.optional<
        Schema.$Array<
          Schema.Struct<{ readonly r: Schema.String; readonly d: Schema.String; readonly t: Schema.String }>
        >
      >
      readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
      readonly key_ops: Schema.optional<
        Schema.$Array<
          Schema.Literals<
            readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
          >
        >
      >
      readonly alg: Schema.optional<
        Schema.Literals<
          readonly [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
          ]
        >
      >
      readonly kid: Schema.optional<Schema.String>
      readonly x5u: Schema.optional<Schema.String>
      readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
      readonly x5t: Schema.optional<Schema.String>
      readonly "x5t#S256": Schema.optional<Schema.String>
      readonly kty: Schema.Literal<"RSA">
      readonly n: Schema.String
      readonly e: Schema.String
    }>,
    Schema.Struct<{
      readonly d: Schema.String
      readonly oth: Schema.optional<
        Schema.$Array<
          Schema.Struct<{ readonly r: Schema.String; readonly d: Schema.String; readonly t: Schema.String }>
        >
      >
      readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
      readonly key_ops: Schema.optional<
        Schema.$Array<
          Schema.Literals<
            readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
          >
        >
      >
      readonly alg: Schema.optional<
        Schema.Literals<
          readonly [
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512"
          ]
        >
      >
      readonly kid: Schema.optional<Schema.String>
      readonly x5u: Schema.optional<Schema.String>
      readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
      readonly x5t: Schema.optional<Schema.String>
      readonly "x5t#S256": Schema.optional<Schema.String>
      readonly kty: Schema.Literal<"RSA">
      readonly n: Schema.String
      readonly e: Schema.String
    }>
  ]
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L250)

Since v1.0.0

## RsaPublicKey

An RSA public key represented as a JWK.

Members "kty", "n", and "e" are required for RSA public keys.

**See**

- https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1

**Signature**

```ts
declare const RsaPublicKey: Schema.Struct<{
  readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
  readonly key_ops: Schema.optional<
    Schema.$Array<
      Schema.Literals<
        readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
      >
    >
  >
  readonly alg: Schema.optional<
    Schema.Literals<
      readonly [
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512"
      ]
    >
  >
  readonly kid: Schema.optional<Schema.String>
  readonly x5u: Schema.optional<Schema.String>
  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
  readonly x5t: Schema.optional<Schema.String>
  readonly "x5t#S256": Schema.optional<Schema.String>
  readonly kty: Schema.Literal<"RSA">
  readonly n: Schema.String
  readonly e: Schema.String
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L215)

Since v1.0.0

# Symmetric

## OctKey

A symmetric key (octet sequence) represented as a JWK.

Members "kty" and "k" are required for symmetric keys.

**See**

- https://www.rfc-editor.org/rfc/rfc7518#section-6.4

**Signature**

```ts
declare const OctKey: Schema.Struct<{
  readonly use: Schema.optional<Schema.Literals<readonly ["sig", "enc"]>>
  readonly key_ops: Schema.optional<
    Schema.$Array<
      Schema.Literals<
        readonly ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]
      >
    >
  >
  readonly alg: Schema.optional<
    Schema.Literals<
      readonly [
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512"
      ]
    >
  >
  readonly kid: Schema.optional<Schema.String>
  readonly x5u: Schema.optional<Schema.String>
  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
  readonly x5t: Schema.optional<Schema.String>
  readonly "x5t#S256": Schema.optional<Schema.String>
  readonly kty: Schema.Literal<"oct">
  readonly k: Schema.String
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwk.ts#L303)

Since v1.0.0
