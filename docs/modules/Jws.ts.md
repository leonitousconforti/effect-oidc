---
title: Jws.ts
nav_order: 5
parent: Modules
---

## Jws.ts overview

JSON Web Signature (JWS) schemas based on RFC 7515.

This module provides Effect Schema definitions for JWS structures, which
represent content secured with digital signatures or Message Authentication
Codes (MACs) using JSON-based data structures. All three serializations are
supported (Compact, Flattened JSON, General JSON), along with signing and
verification built on WebCrypto, extensible critical headers with
compile-time key validation, and schema combinators (`Verified`,
`Signed`) that treat signing/verification as schema transformations.

Keys embedded in the token itself (`jwk` and `jku` header parameters) are
IGNORED during verification unless explicitly opted into - an attacker can
put any key they control in those headers, so trusting them by default
would make signature verification meaningless for authentication use.

**See**

- https://www.rfc-editor.org/rfc/rfc7515 - JSON Web Signature (JWS)
- https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)

Since v1.0.0

---

## Exports Grouped by Category

- [Errors](#errors)
  - [InvalidHeaders (class)](#invalidheaders-class)
  - [InvalidJws (class)](#invalidjws-class)
  - [InvalidSignature (class)](#invalidsignature-class)
- [JOSE Header](#jose-header)
  - [JoseHeader](#joseheader)
  - [JoseProtectedHeader](#joseprotectedheader)
  - [JoseUnprotectedHeader](#joseunprotectedheader)
  - [ProtectedHeaderExtras (type alias)](#protectedheaderextras-type-alias)
  - [ValidateCriticalHeaderKey (type alias)](#validatecriticalheaderkey-type-alias)
  - [ValidateCriticalHeaderKeys (type alias)](#validatecriticalheaderkeys-type-alias)
- [JWS](#jws)
  - [Unsecured](#unsecured)
  - [sign](#sign)
  - [verify](#verify)
- [JWS Compact Serialization](#jws-compact-serialization)
  - [Compact (class)](#compact-class)
- [JWS JSON Serialization](#jws-json-serialization)
  - [Flattened (class)](#flattened-class)
  - [General (class)](#general-class)
- [Schema Combinators](#schema-combinators)
  - [Signed](#signed)
  - [Verified](#verified)

---

# Errors

## InvalidHeaders (class)

**Signature**

```ts
declare class InvalidHeaders
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L424)

Since v1.0.0

## InvalidJws (class)

**Signature**

```ts
declare class InvalidJws
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L436)

Since v1.0.0

## InvalidSignature (class)

**Signature**

```ts
declare class InvalidSignature
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L430)

Since v1.0.0

# JOSE Header

## JoseHeader

JOSE Header for JWS as defined in RFC 7515 Section 4. The JOSE Header
describes the cryptographic operations applied to the JWS Protected Header
and the JWS Payload.

This schema is extensible - additional public and private header parameters
are permitted per RFC 7515 Sections 4.2 and 4.3.

**See**

- https://www.rfc-editor.org/rfc/rfc7515#section-4

**Signature**

```ts
declare const JoseHeader: VariantSchema.Struct<{
  readonly alg: VariantSchema.Field<{
    readonly protected: Schema.Literals<
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
    readonly unprotected: Schema.optional<
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
  }>
  readonly jku: Schema.optional<Schema.String>
  readonly jwk: Schema.optional<
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
  >
  readonly kid: Schema.optional<Schema.String>
  readonly x5u: Schema.optional<Schema.String>
  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
  readonly x5t: Schema.optional<Schema.String>
  readonly "x5t#S256": Schema.optional<Schema.String>
  readonly typ: Schema.optional<Schema.String>
  readonly cty: Schema.optional<Schema.String>
  readonly crit: VariantSchema.Field<{ readonly protected: Schema.optionalKey<Schema.Never> }>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L45)

Since v1.0.0

## JoseProtectedHeader

The integrity-protected JOSE header variant.

**See**

- https://www.rfc-editor.org/rfc/rfc7515#section-4

**Signature**

```ts
declare const JoseProtectedHeader: Schema.Struct<{
  readonly alg: Schema.Literals<
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
  readonly jku: Schema.optional<Schema.String>
  readonly jwk: Schema.optional<
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
  >
  readonly kid: Schema.optional<Schema.String>
  readonly x5u: Schema.optional<Schema.String>
  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
  readonly x5t: Schema.optional<Schema.String>
  readonly "x5t#S256": Schema.optional<Schema.String>
  readonly typ: Schema.optional<Schema.String>
  readonly cty: Schema.optional<Schema.String>
  readonly crit: Schema.optionalKey<Schema.Never>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L146)

Since v1.0.0

## JoseUnprotectedHeader

The unprotected JOSE header variant, carried alongside JSON serializations.

**See**

- https://www.rfc-editor.org/rfc/rfc7515#section-4

**Signature**

```ts
declare const JoseUnprotectedHeader: Schema.Struct<{
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
  readonly jku: Schema.optional<Schema.String>
  readonly jwk: Schema.optional<
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
  >
  readonly kid: Schema.optional<Schema.String>
  readonly x5u: Schema.optional<Schema.String>
  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
  readonly x5t: Schema.optional<Schema.String>
  readonly "x5t#S256": Schema.optional<Schema.String>
  readonly typ: Schema.optional<Schema.String>
  readonly cty: Schema.optional<Schema.String>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L155)

Since v1.0.0

## ProtectedHeaderExtras (type alias)

Additional protected header parameters that callers may set when signing
(everything except `alg`, which comes from the signing key entry, and
`crit`, which is managed by the critical-header machinery).

**Signature**

```ts
type ProtectedHeaderExtras = Omit<(typeof JoseProtectedHeader)["Type"], "alg" | "crit">
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L165)

Since v1.0.0

## ValidateCriticalHeaderKey (type alias)

Type-level validation to prevent critical header keys from colliding with
registered JOSE header parameters. Critical header keys must be distinct
from any registered JOSE header parameter keys, as they would cause
ambiguity in the JOSE header structure and violate the JWS specification.

**Signature**

```ts
type ValidateCriticalHeaderKey<K> = K extends
  keyof typeof JoseProtectedHeader.fields | keyof typeof JoseUnprotectedHeader.fields
  ? `${K} is a registered JOSE header parameter and cannot be used as a critical header key`
  : {}
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L176)

Since v1.0.0

## ValidateCriticalHeaderKeys (type alias)

Type-level validation applied to a whole record of critical headers.

**Signature**

```ts
type ValidateCriticalHeaderKeys<CriticalHeaders> = {
  [K in Extract<keyof CriticalHeaders, string>]: ValidateCriticalHeaderKey<K>
}
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L188)

Since v1.0.0

# JWS

## Unsecured

Any unverified JWS serialization.

**Signature**

```ts
declare const Unsecured: Schema.Union<readonly [typeof General, typeof Flattened, typeof Compact]>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L406)

Since v1.0.0

## sign

Builds a JWS signer. Each private key entry carries its algorithm and any
additional protected header parameters (e.g. `kid`, `typ`). Signing with a
single key produces the Flattened serialization; multiple keys produce the
General serialization.

**See**

- https://www.rfc-editor.org/rfc/rfc7515#section-5.1

**Signature**

```ts
declare const sign: <
  A = string,
  RE1 = never,
  PrivateKeys extends Array.NonEmptyReadonlyArray<{
    algorithm: (typeof JwsAlgorithm)["Type"]
    key: CryptoKey
    header?: ProtectedHeaderExtras | undefined
  }> = never,
  CriticalHeaders extends { readonly [K in string]: Schema.Codec<unknown, Schema.Json, unknown, unknown> } = {}
>(options: {
  privateKeys: PrivateKeys
  payload?: Schema.Codec<A, string, unknown, RE1> | undefined
  criticalHeaders?: (CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>) | undefined
}) => (
  payload: A,
  criticalHeaders?: Schema.Struct.Type<CriticalHeaders>
) => Effect.Effect<
  PrivateKeys extends [infer _] ? (typeof Flattened)["Encoded"] : (typeof General)["Encoded"],
  Schema.SchemaError,
  RE1 | Schema.Struct.EncodingServices<CriticalHeaders>
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L604)

Since v1.0.0

## verify

Builds a JWS verifier. Signatures are checked against the provided
`publicKeys`. Keys embedded in the token (`jwk` header) are only
considered when `trustEmbeddedJwk` is set, and `jku` URLs are only
followed when a `resolveJku` effect is supplied - both default to off
because tokens choose their own headers.

**See**

- https://www.rfc-editor.org/rfc/rfc7515#section-5.2

**Signature**

```ts
declare const verify: <
  A = string,
  RD1 = never,
  E2 = never,
  R2 = never,
  CriticalHeaders extends { readonly [K in string]: Schema.Codec<unknown, Schema.Json, unknown, unknown> } = {}
>({
  algorithms,
  criticalHeaders,
  maxSignatures,
  payload,
  publicKeys,
  resolveJku,
  trustEmbeddedJwk
}: {
  payload?: Schema.Codec<A, string, RD1, unknown> | undefined
  publicKeys?: ReadonlyArray<CryptoKey> | undefined
  trustEmbeddedJwk?: boolean | undefined
  resolveJku?: ((url: string) => Effect.Effect<(typeof JwkSet)["Type"], E2, R2>) | undefined
  criticalHeaders?: (CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>) | undefined
  algorithms?: ReadonlyArray<(typeof JwsAlgorithm)["Type"]> | undefined
  maxSignatures?: number | undefined
}) => (
  jws: (typeof Unsecured)["Type"]
) => Effect.Effect<
  {
    signature: Uint8Array<ArrayBufferLike>
    protected: Schema.Struct.View<
      {
        [
          K in keyof {
            [
              K in keyof ((
                "alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit"
              ) &
                ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
                ? {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  } & CriticalHeaders &
                    ValidateCriticalHeaderKeys<CriticalHeaders> & {
                      readonly crit:
                        | Extract<keyof CriticalHeaders, string>
                        | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                        ? Schema.optionalKey<Schema.Never>
                        : Schema.$Array<
                            Schema.Union<
                              readonly [
                                Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >,
                                ...Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >[]
                              ]
                            >
                          >
                    }
                : Omit<
                    {
                      readonly alg: Schema.Literals<
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
                      readonly jku: Schema.optional<Schema.String>
                      readonly jwk: Schema.optional<
                        Schema.Union<
                          readonly [
                            Schema.Struct<{
                              readonly d: Schema.String
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
                                      Schema.Struct<{
                                        readonly r: Schema.String
                                        readonly d: Schema.String
                                        readonly t: Schema.String
                                      }>
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
                                      Schema.Struct<{
                                        readonly r: Schema.String
                                        readonly d: Schema.String
                                        readonly t: Schema.String
                                      }>
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
                              readonly kty: Schema.Literal<"oct">
                              readonly k: Schema.String
                            }>
                          ]
                        >
                      >
                      readonly kid: Schema.optional<Schema.String>
                      readonly x5u: Schema.optional<Schema.String>
                      readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                      readonly x5t: Schema.optional<Schema.String>
                      readonly "x5t#S256": Schema.optional<Schema.String>
                      readonly typ: Schema.optional<Schema.String>
                      readonly cty: Schema.optional<Schema.String>
                      readonly crit: Schema.optionalKey<Schema.Never>
                    },
                    ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                      ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                  > &
                    CriticalHeaders &
                    ValidateCriticalHeaderKeys<CriticalHeaders> & {
                      readonly crit:
                        | Extract<keyof CriticalHeaders, string>
                        | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                        ? Schema.optionalKey<Schema.Never>
                        : Schema.$Array<
                            Schema.Union<
                              readonly [
                                Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >,
                                ...Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >[]
                              ]
                            >
                          >
                    })
            ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
              ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
              ? {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                } & CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  }
              : Omit<
                  {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  },
                  ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                    ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                > &
                  CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  })[K]
          }
        ]: {
          [
            K in keyof (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
              ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
              ? {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                } & CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  }
              : Omit<
                  {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  },
                  ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                    ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                > &
                  CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  })
          ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
            ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
            ? {
                readonly alg: Schema.Literals<
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
                readonly jku: Schema.optional<Schema.String>
                readonly jwk: Schema.optional<
                  Schema.Union<
                    readonly [
                      Schema.Struct<{
                        readonly d: Schema.String
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                        readonly kty: Schema.Literal<"oct">
                        readonly k: Schema.String
                      }>
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly typ: Schema.optional<Schema.String>
                readonly cty: Schema.optional<Schema.String>
                readonly crit: Schema.optionalKey<Schema.Never>
              } & CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                }
            : Omit<
                {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                },
                ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                  ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
              > &
                CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                })[K]
        }[K]
      },
      "Type",
      Schema.Struct.TypeOptionalKeys<{
        [
          K in keyof {
            [
              K in keyof ((
                "alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit"
              ) &
                ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
                ? {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  } & CriticalHeaders &
                    ValidateCriticalHeaderKeys<CriticalHeaders> & {
                      readonly crit:
                        | Extract<keyof CriticalHeaders, string>
                        | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                        ? Schema.optionalKey<Schema.Never>
                        : Schema.$Array<
                            Schema.Union<
                              readonly [
                                Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >,
                                ...Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >[]
                              ]
                            >
                          >
                    }
                : Omit<
                    {
                      readonly alg: Schema.Literals<
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
                      readonly jku: Schema.optional<Schema.String>
                      readonly jwk: Schema.optional<
                        Schema.Union<
                          readonly [
                            Schema.Struct<{
                              readonly d: Schema.String
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
                                      Schema.Struct<{
                                        readonly r: Schema.String
                                        readonly d: Schema.String
                                        readonly t: Schema.String
                                      }>
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
                                      Schema.Struct<{
                                        readonly r: Schema.String
                                        readonly d: Schema.String
                                        readonly t: Schema.String
                                      }>
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
                              readonly kty: Schema.Literal<"oct">
                              readonly k: Schema.String
                            }>
                          ]
                        >
                      >
                      readonly kid: Schema.optional<Schema.String>
                      readonly x5u: Schema.optional<Schema.String>
                      readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                      readonly x5t: Schema.optional<Schema.String>
                      readonly "x5t#S256": Schema.optional<Schema.String>
                      readonly typ: Schema.optional<Schema.String>
                      readonly cty: Schema.optional<Schema.String>
                      readonly crit: Schema.optionalKey<Schema.Never>
                    },
                    ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                      ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                  > &
                    CriticalHeaders &
                    ValidateCriticalHeaderKeys<CriticalHeaders> & {
                      readonly crit:
                        | Extract<keyof CriticalHeaders, string>
                        | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                        ? Schema.optionalKey<Schema.Never>
                        : Schema.$Array<
                            Schema.Union<
                              readonly [
                                Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >,
                                ...Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >[]
                              ]
                            >
                          >
                    })
            ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
              ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
              ? {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                } & CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  }
              : Omit<
                  {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  },
                  ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                    ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                > &
                  CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  })[K]
          }
        ]: {
          [
            K in keyof (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
              ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
              ? {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                } & CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  }
              : Omit<
                  {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  },
                  ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                    ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                > &
                  CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  })
          ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
            ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
            ? {
                readonly alg: Schema.Literals<
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
                readonly jku: Schema.optional<Schema.String>
                readonly jwk: Schema.optional<
                  Schema.Union<
                    readonly [
                      Schema.Struct<{
                        readonly d: Schema.String
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                        readonly kty: Schema.Literal<"oct">
                        readonly k: Schema.String
                      }>
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly typ: Schema.optional<Schema.String>
                readonly cty: Schema.optional<Schema.String>
                readonly crit: Schema.optionalKey<Schema.Never>
              } & CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                }
            : Omit<
                {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                },
                ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                  ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
              > &
                CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                })[K]
        }[K]
      }>,
      Schema.Struct.TypeMutableKeys<{
        [
          K in keyof {
            [
              K in keyof ((
                "alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit"
              ) &
                ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
                ? {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  } & CriticalHeaders &
                    ValidateCriticalHeaderKeys<CriticalHeaders> & {
                      readonly crit:
                        | Extract<keyof CriticalHeaders, string>
                        | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                        ? Schema.optionalKey<Schema.Never>
                        : Schema.$Array<
                            Schema.Union<
                              readonly [
                                Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >,
                                ...Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >[]
                              ]
                            >
                          >
                    }
                : Omit<
                    {
                      readonly alg: Schema.Literals<
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
                      readonly jku: Schema.optional<Schema.String>
                      readonly jwk: Schema.optional<
                        Schema.Union<
                          readonly [
                            Schema.Struct<{
                              readonly d: Schema.String
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
                                      Schema.Struct<{
                                        readonly r: Schema.String
                                        readonly d: Schema.String
                                        readonly t: Schema.String
                                      }>
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
                                      Schema.Struct<{
                                        readonly r: Schema.String
                                        readonly d: Schema.String
                                        readonly t: Schema.String
                                      }>
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
                              readonly kty: Schema.Literal<"oct">
                              readonly k: Schema.String
                            }>
                          ]
                        >
                      >
                      readonly kid: Schema.optional<Schema.String>
                      readonly x5u: Schema.optional<Schema.String>
                      readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                      readonly x5t: Schema.optional<Schema.String>
                      readonly "x5t#S256": Schema.optional<Schema.String>
                      readonly typ: Schema.optional<Schema.String>
                      readonly cty: Schema.optional<Schema.String>
                      readonly crit: Schema.optionalKey<Schema.Never>
                    },
                    ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                      ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                  > &
                    CriticalHeaders &
                    ValidateCriticalHeaderKeys<CriticalHeaders> & {
                      readonly crit:
                        | Extract<keyof CriticalHeaders, string>
                        | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                        ? Schema.optionalKey<Schema.Never>
                        : Schema.$Array<
                            Schema.Union<
                              readonly [
                                Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >,
                                ...Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >[]
                              ]
                            >
                          >
                    })
            ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
              ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
              ? {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                } & CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  }
              : Omit<
                  {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  },
                  ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                    ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                > &
                  CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  })[K]
          }
        ]: {
          [
            K in keyof (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
              ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
              ? {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                } & CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  }
              : Omit<
                  {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  },
                  ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                    ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                > &
                  CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  })
          ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
            ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
            ? {
                readonly alg: Schema.Literals<
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
                readonly jku: Schema.optional<Schema.String>
                readonly jwk: Schema.optional<
                  Schema.Union<
                    readonly [
                      Schema.Struct<{
                        readonly d: Schema.String
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                        readonly kty: Schema.Literal<"oct">
                        readonly k: Schema.String
                      }>
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly typ: Schema.optional<Schema.String>
                readonly cty: Schema.optional<Schema.String>
                readonly crit: Schema.optionalKey<Schema.Never>
              } & CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                }
            : Omit<
                {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                },
                ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                  ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
              > &
                CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                })[K]
        }[K]
      }>
    >
    header:
      | {
          readonly alg?:
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
            | undefined
          readonly kid?: string | undefined
          readonly x5u?: string | undefined
          readonly x5c?: ReadonlyArray<string> | undefined
          readonly x5t?: string | undefined
          readonly "x5t#S256"?: string | undefined
          readonly jwk?:
            | {
                readonly kty: "EC"
                readonly crv: "P-256" | "P-384" | "P-521"
                readonly x: string
                readonly y: string
                readonly d: string
                readonly use?: "sig" | "enc" | undefined
                readonly key_ops?:
                  | ReadonlyArray<
                      "sign" | "verify" | "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits"
                    >
                  | undefined
                readonly alg?:
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
                  | undefined
                readonly kid?: string | undefined
                readonly x5u?: string | undefined
                readonly x5c?: ReadonlyArray<string> | undefined
                readonly x5t?: string | undefined
                readonly "x5t#S256"?: string | undefined
              }
            | {
                readonly kty: "EC"
                readonly crv: "P-256" | "P-384" | "P-521"
                readonly x: string
                readonly y: string
                readonly use?: "sig" | "enc" | undefined
                readonly key_ops?:
                  | ReadonlyArray<
                      "sign" | "verify" | "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits"
                    >
                  | undefined
                readonly alg?:
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
                  | undefined
                readonly kid?: string | undefined
                readonly x5u?: string | undefined
                readonly x5c?: ReadonlyArray<string> | undefined
                readonly x5t?: string | undefined
                readonly "x5t#S256"?: string | undefined
              }
            | {
                readonly kty: "RSA"
                readonly d: string
                readonly n: string
                readonly e: string
                readonly p: string
                readonly q: string
                readonly dp: string
                readonly dq: string
                readonly qi: string
                readonly use?: "sig" | "enc" | undefined
                readonly key_ops?:
                  | ReadonlyArray<
                      "sign" | "verify" | "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits"
                    >
                  | undefined
                readonly alg?:
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
                  | undefined
                readonly kid?: string | undefined
                readonly x5u?: string | undefined
                readonly x5c?: ReadonlyArray<string> | undefined
                readonly x5t?: string | undefined
                readonly "x5t#S256"?: string | undefined
                readonly oth?: ReadonlyArray<{ readonly r: string; readonly d: string; readonly t: string }> | undefined
              }
            | {
                readonly kty: "RSA"
                readonly d: string
                readonly n: string
                readonly e: string
                readonly use?: "sig" | "enc" | undefined
                readonly key_ops?:
                  | ReadonlyArray<
                      "sign" | "verify" | "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits"
                    >
                  | undefined
                readonly alg?:
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
                  | undefined
                readonly kid?: string | undefined
                readonly x5u?: string | undefined
                readonly x5c?: ReadonlyArray<string> | undefined
                readonly x5t?: string | undefined
                readonly "x5t#S256"?: string | undefined
                readonly oth?: ReadonlyArray<{ readonly r: string; readonly d: string; readonly t: string }> | undefined
              }
            | {
                readonly kty: "RSA"
                readonly n: string
                readonly e: string
                readonly use?: "sig" | "enc" | undefined
                readonly key_ops?:
                  | ReadonlyArray<
                      "sign" | "verify" | "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits"
                    >
                  | undefined
                readonly alg?:
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
                  | undefined
                readonly kid?: string | undefined
                readonly x5u?: string | undefined
                readonly x5c?: ReadonlyArray<string> | undefined
                readonly x5t?: string | undefined
                readonly "x5t#S256"?: string | undefined
              }
            | {
                readonly kty: "oct"
                readonly k: string
                readonly use?: "sig" | "enc" | undefined
                readonly key_ops?:
                  | ReadonlyArray<
                      "sign" | "verify" | "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits"
                    >
                  | undefined
                readonly alg?:
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
                  | undefined
                readonly kid?: string | undefined
                readonly x5u?: string | undefined
                readonly x5c?: ReadonlyArray<string> | undefined
                readonly x5t?: string | undefined
                readonly "x5t#S256"?: string | undefined
              }
            | undefined
          readonly jku?: string | undefined
          readonly typ?: string | undefined
          readonly cty?: string | undefined
        }
      | undefined
    payload: A
  },
  Schema.SchemaError | InvalidJws,
  | RD1
  | R2
  | Schema.Struct.DecodingServices<{
      [
        K in keyof {
          [
            K in keyof (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
              ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
              ? {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                } & CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  }
              : Omit<
                  {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  },
                  ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                    ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                > &
                  CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  })
          ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
            ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
            ? {
                readonly alg: Schema.Literals<
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
                readonly jku: Schema.optional<Schema.String>
                readonly jwk: Schema.optional<
                  Schema.Union<
                    readonly [
                      Schema.Struct<{
                        readonly d: Schema.String
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                        readonly kty: Schema.Literal<"oct">
                        readonly k: Schema.String
                      }>
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly typ: Schema.optional<Schema.String>
                readonly cty: Schema.optional<Schema.String>
                readonly crit: Schema.optionalKey<Schema.Never>
              } & CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                }
            : Omit<
                {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                },
                ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                  ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
              > &
                CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                })[K]
        }
      ]: {
        [
          K in keyof (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
            ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
            ? {
                readonly alg: Schema.Literals<
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
                readonly jku: Schema.optional<Schema.String>
                readonly jwk: Schema.optional<
                  Schema.Union<
                    readonly [
                      Schema.Struct<{
                        readonly d: Schema.String
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                        readonly kty: Schema.Literal<"oct">
                        readonly k: Schema.String
                      }>
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly typ: Schema.optional<Schema.String>
                readonly cty: Schema.optional<Schema.String>
                readonly crit: Schema.optionalKey<Schema.Never>
              } & CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                }
            : Omit<
                {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                },
                ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                  ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
              > &
                CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                })
        ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
          ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
          ? {
              readonly alg: Schema.Literals<
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
              readonly jku: Schema.optional<Schema.String>
              readonly jwk: Schema.optional<
                Schema.Union<
                  readonly [
                    Schema.Struct<{
                      readonly d: Schema.String
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
                              Schema.Struct<{
                                readonly r: Schema.String
                                readonly d: Schema.String
                                readonly t: Schema.String
                              }>
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
                              Schema.Struct<{
                                readonly r: Schema.String
                                readonly d: Schema.String
                                readonly t: Schema.String
                              }>
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
                      readonly kty: Schema.Literal<"oct">
                      readonly k: Schema.String
                    }>
                  ]
                >
              >
              readonly kid: Schema.optional<Schema.String>
              readonly x5u: Schema.optional<Schema.String>
              readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
              readonly x5t: Schema.optional<Schema.String>
              readonly "x5t#S256": Schema.optional<Schema.String>
              readonly typ: Schema.optional<Schema.String>
              readonly cty: Schema.optional<Schema.String>
              readonly crit: Schema.optionalKey<Schema.Never>
            } & CriticalHeaders &
              ValidateCriticalHeaderKeys<CriticalHeaders> & {
                readonly crit:
                  | Extract<keyof CriticalHeaders, string>
                  | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                  ? Schema.optionalKey<Schema.Never>
                  : Schema.$Array<
                      Schema.Union<
                        readonly [
                          Schema.Literal<
                            | Extract<keyof CriticalHeaders, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                          >,
                          ...Schema.Literal<
                            | Extract<keyof CriticalHeaders, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                          >[]
                        ]
                      >
                    >
              }
          : Omit<
              {
                readonly alg: Schema.Literals<
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
                readonly jku: Schema.optional<Schema.String>
                readonly jwk: Schema.optional<
                  Schema.Union<
                    readonly [
                      Schema.Struct<{
                        readonly d: Schema.String
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                        readonly kty: Schema.Literal<"oct">
                        readonly k: Schema.String
                      }>
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly typ: Schema.optional<Schema.String>
                readonly cty: Schema.optional<Schema.String>
                readonly crit: Schema.optionalKey<Schema.Never>
              },
              ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
            > &
              CriticalHeaders &
              ValidateCriticalHeaderKeys<CriticalHeaders> & {
                readonly crit:
                  | Extract<keyof CriticalHeaders, string>
                  | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                  ? Schema.optionalKey<Schema.Never>
                  : Schema.$Array<
                      Schema.Union<
                        readonly [
                          Schema.Literal<
                            | Extract<keyof CriticalHeaders, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                          >,
                          ...Schema.Literal<
                            | Extract<keyof CriticalHeaders, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                          >[]
                        ]
                      >
                    >
              })[K]
      }[K]
    }>
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L449)

Since v1.0.0

# JWS Compact Serialization

## Compact (class)

JWS Compact Serialization as defined in RFC 7515 Section 7.1. Represents a
compact, URL-safe string of the form:

    BASE64URL(UTF8(JWS Protected Header)) || '.' ||
    BASE64URL(JWS Payload) || '.' ||
    BASE64URL(JWS Signature)

Only one signature/MAC is supported by the JWS Compact Serialization and it
provides no syntax to represent a JWS Unprotected Header value.

**See**

- https://www.rfc-editor.org/rfc/rfc7515#section-7.1

**Signature**

```ts
declare class Compact
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L367)

Since v1.0.0

# JWS JSON Serialization

## Flattened (class)

Flattened JWS JSON Serialization as defined in RFC 7515 Section 7.2.2.
Optimized for the single digital signature or MAC case - the "signatures"
member is flattened into top-level "protected", "header", and "signature"
members alongside "payload".

```json
{
  "payload": "<payload contents>",
  "protected": "<integrity-protected header contents>",
  "header": { ... },
  "signature": "<signature contents>"
}
```

**See**

- https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2

**Signature**

```ts
declare class Flattened
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L333)

Since v1.0.0

## General (class)

General JWS JSON Serialization as defined in RFC 7515 Section 7.2.1.
Supports multiple digital signatures and/or MACs for the same payload.

```json
{
  "payload": "<payload contents>",
  "signatures": [
    { "protected": "<header 1>", "header": { ... }, "signature": "<sig 1>" },
    { "protected": "<header N>", "header": { ... }, "signature": "<sig N>" }
  ]
}
```

**See**

- https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1

**Signature**

```ts
declare class General
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L291)

Since v1.0.0

# Schema Combinators

## Signed

Schema combinator that signs a payload (and critical headers) during
decode, producing an unverified JWS serialization. Encoding is forbidden.

**Signature**

```ts
declare const Signed: <
  A = string,
  RD1 = never,
  RE1 = never,
  PrivateKeys extends Array.NonEmptyReadonlyArray<{
    algorithm: (typeof JwsAlgorithm)["Type"]
    key: CryptoKey
    header?: ProtectedHeaderExtras | undefined
  }> = never,
  CriticalHeaders extends { readonly [K in string]: Schema.Codec<unknown, Schema.Json, unknown, unknown> } = {}
>(options: {
  privateKeys: PrivateKeys
  payload?: Schema.Codec<A, string, RD1, RE1> | undefined
  criticalHeaders?: (CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>) | undefined
}) => <To extends (typeof Unsecured)["members"][number] | Schema.Decoder<(typeof Unsecured)["Type"], unknown>>(
  to: To
) => Schema.decodeTo<
  To,
  Schema.Struct<
    { readonly payload: Schema.Codec<A, string, RD1, RE1> } & ([{}] extends [CriticalHeaders]
      ? {}
      : { readonly criticalHeaders: Schema.Struct<CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>> })
  >,
  never,
  never
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L771)

Since v1.0.0

## Verified

Schema combinator that decodes an unverified JWS into its verified payload
and headers, failing decode when no signature verifies. Encoding is
forbidden - use `Signed` to produce a JWS.

**Signature**

```ts
declare const Verified: <
  A = string,
  RD1 = never,
  RE1 = never,
  E2 = never,
  R2 = never,
  CriticalHeaders extends { readonly [K in string]: Schema.Codec<unknown, Schema.Json, unknown, unknown> } = {}
>(options: {
  payload?: Schema.Codec<A, string, RD1, RE1> | undefined
  publicKeys?: ReadonlyArray<CryptoKey> | undefined
  trustEmbeddedJwk?: boolean | undefined
  resolveJku?: ((url: string) => Effect.Effect<(typeof JwkSet)["Type"], E2, R2>) | undefined
  criticalHeaders?: (CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>) | undefined
}) => <From extends (typeof Unsecured)["members"][number] | Schema.Decoder<(typeof Unsecured)["Type"], unknown>>(
  from: From
) => Schema.decodeTo<
  Schema.toType<
    Schema.Struct<{
      readonly signature: Schema.Uint8ArrayFromBase64Url
      readonly payload: Schema.Codec<A, string, RD1, RE1>
      readonly header: Schema.optional<
        Schema.Struct<{
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
          readonly jku: Schema.optional<Schema.String>
          readonly jwk: Schema.optional<
            Schema.Union<
              readonly [
                Schema.Struct<{
                  readonly d: Schema.String
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
                          Schema.Struct<{
                            readonly r: Schema.String
                            readonly d: Schema.String
                            readonly t: Schema.String
                          }>
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
                          Schema.Struct<{
                            readonly r: Schema.String
                            readonly d: Schema.String
                            readonly t: Schema.String
                          }>
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
                  readonly kty: Schema.Literal<"oct">
                  readonly k: Schema.String
                }>
              ]
            >
          >
          readonly kid: Schema.optional<Schema.String>
          readonly x5u: Schema.optional<Schema.String>
          readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
          readonly x5t: Schema.optional<Schema.String>
          readonly "x5t#S256": Schema.optional<Schema.String>
          readonly typ: Schema.optional<Schema.String>
          readonly cty: Schema.optional<Schema.String>
        }>
      >
      readonly protected: Schema.Struct<{
        [
          K in keyof {
            [
              K in keyof ((
                "alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit"
              ) &
                ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
                ? {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  } & CriticalHeaders &
                    ValidateCriticalHeaderKeys<CriticalHeaders> & {
                      readonly crit:
                        | Extract<keyof CriticalHeaders, string>
                        | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                        ? Schema.optionalKey<Schema.Never>
                        : Schema.$Array<
                            Schema.Union<
                              readonly [
                                Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >,
                                ...Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >[]
                              ]
                            >
                          >
                    }
                : Omit<
                    {
                      readonly alg: Schema.Literals<
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
                      readonly jku: Schema.optional<Schema.String>
                      readonly jwk: Schema.optional<
                        Schema.Union<
                          readonly [
                            Schema.Struct<{
                              readonly d: Schema.String
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
                                      Schema.Struct<{
                                        readonly r: Schema.String
                                        readonly d: Schema.String
                                        readonly t: Schema.String
                                      }>
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
                                      Schema.Struct<{
                                        readonly r: Schema.String
                                        readonly d: Schema.String
                                        readonly t: Schema.String
                                      }>
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
                              readonly kty: Schema.Literal<"oct">
                              readonly k: Schema.String
                            }>
                          ]
                        >
                      >
                      readonly kid: Schema.optional<Schema.String>
                      readonly x5u: Schema.optional<Schema.String>
                      readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                      readonly x5t: Schema.optional<Schema.String>
                      readonly "x5t#S256": Schema.optional<Schema.String>
                      readonly typ: Schema.optional<Schema.String>
                      readonly cty: Schema.optional<Schema.String>
                      readonly crit: Schema.optionalKey<Schema.Never>
                    },
                    ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                      ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                  > &
                    CriticalHeaders &
                    ValidateCriticalHeaderKeys<CriticalHeaders> & {
                      readonly crit:
                        | Extract<keyof CriticalHeaders, string>
                        | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                        ? Schema.optionalKey<Schema.Never>
                        : Schema.$Array<
                            Schema.Union<
                              readonly [
                                Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >,
                                ...Schema.Literal<
                                  | Extract<keyof CriticalHeaders, string>
                                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                                >[]
                              ]
                            >
                          >
                    })
            ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
              ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
              ? {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                } & CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  }
              : Omit<
                  {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  },
                  ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                    ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                > &
                  CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  })[K]
          }
        ]: {
          [
            K in keyof (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
              ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
              ? {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                } & CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  }
              : Omit<
                  {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  },
                  ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                    ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
                > &
                  CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                              >[]
                            ]
                          >
                        >
                  })
          ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
            ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>) extends never
            ? {
                readonly alg: Schema.Literals<
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
                readonly jku: Schema.optional<Schema.String>
                readonly jwk: Schema.optional<
                  Schema.Union<
                    readonly [
                      Schema.Struct<{
                        readonly d: Schema.String
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                        readonly kty: Schema.Literal<"oct">
                        readonly k: Schema.String
                      }>
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly typ: Schema.optional<Schema.String>
                readonly cty: Schema.optional<Schema.String>
                readonly crit: Schema.optionalKey<Schema.Never>
              } & CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                }
            : Omit<
                {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                },
                ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                  ("crit" | keyof CriticalHeaders | Extract<keyof CriticalHeaders, string>)
              > &
                CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                            >[]
                          ]
                        >
                      >
                })[K]
        }[K]
      }>
    }>
  >,
  typeof Flattened | typeof Compact | typeof General | Schema.Decoder<Flattened | Compact | General, unknown>,
  | RD1
  | R2
  | Schema.Struct.DecodingServices<{
      [
        K in keyof {
          [
            K in keyof (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
              (
                | "crit"
                | keyof CriticalHeaders
                | Extract<keyof CriticalHeaders, string>
                | Extract<keyof CriticalHeaders, string>
                | Extract<Extract<keyof CriticalHeaders, string>, string>
              ) extends never
              ? {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                } & CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> &
                  ValidateCriticalHeaderKeys<CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string>
                      | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                                | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                                | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                              >[]
                            ]
                          >
                        >
                  }
              : Omit<
                  {
                    readonly alg: Schema.Literals<
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
                    readonly jku: Schema.optional<Schema.String>
                    readonly jwk: Schema.optional<
                      Schema.Union<
                        readonly [
                          Schema.Struct<{
                            readonly d: Schema.String
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                                    Schema.Struct<{
                                      readonly r: Schema.String
                                      readonly d: Schema.String
                                      readonly t: Schema.String
                                    }>
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
                            readonly kty: Schema.Literal<"oct">
                            readonly k: Schema.String
                          }>
                        ]
                      >
                    >
                    readonly kid: Schema.optional<Schema.String>
                    readonly x5u: Schema.optional<Schema.String>
                    readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                    readonly x5t: Schema.optional<Schema.String>
                    readonly "x5t#S256": Schema.optional<Schema.String>
                    readonly typ: Schema.optional<Schema.String>
                    readonly cty: Schema.optional<Schema.String>
                    readonly crit: Schema.optionalKey<Schema.Never>
                  },
                  ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                    (
                      | "crit"
                      | keyof CriticalHeaders
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string>
                    )
                > &
                  CriticalHeaders &
                  ValidateCriticalHeaderKeys<CriticalHeaders> &
                  ValidateCriticalHeaderKeys<CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>> & {
                    readonly crit:
                      | Extract<keyof CriticalHeaders, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string>
                      | Extract<Extract<keyof CriticalHeaders, string>, string>
                      | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string> extends never
                      ? Schema.optionalKey<Schema.Never>
                      : Schema.$Array<
                          Schema.Union<
                            readonly [
                              Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                                | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                              >,
                              ...Schema.Literal<
                                | Extract<keyof CriticalHeaders, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                                | Extract<Extract<keyof CriticalHeaders, string>, string>
                                | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                              >[]
                            ]
                          >
                        >
                  })
          ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
            (
              | "crit"
              | keyof CriticalHeaders
              | Extract<keyof CriticalHeaders, string>
              | Extract<keyof CriticalHeaders, string>
              | Extract<Extract<keyof CriticalHeaders, string>, string>
            ) extends never
            ? {
                readonly alg: Schema.Literals<
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
                readonly jku: Schema.optional<Schema.String>
                readonly jwk: Schema.optional<
                  Schema.Union<
                    readonly [
                      Schema.Struct<{
                        readonly d: Schema.String
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                        readonly kty: Schema.Literal<"oct">
                        readonly k: Schema.String
                      }>
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly typ: Schema.optional<Schema.String>
                readonly cty: Schema.optional<Schema.String>
                readonly crit: Schema.optionalKey<Schema.Never>
              } & CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> &
                ValidateCriticalHeaderKeys<CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string>
                    | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                            >[]
                          ]
                        >
                      >
                }
            : Omit<
                {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                },
                ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                  (
                    | "crit"
                    | keyof CriticalHeaders
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string>
                  )
              > &
                CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> &
                ValidateCriticalHeaderKeys<CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string>
                    | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                            >[]
                          ]
                        >
                      >
                })[K]
        }
      ]: {
        [
          K in keyof (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
            (
              | "crit"
              | keyof CriticalHeaders
              | Extract<keyof CriticalHeaders, string>
              | Extract<keyof CriticalHeaders, string>
              | Extract<Extract<keyof CriticalHeaders, string>, string>
            ) extends never
            ? {
                readonly alg: Schema.Literals<
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
                readonly jku: Schema.optional<Schema.String>
                readonly jwk: Schema.optional<
                  Schema.Union<
                    readonly [
                      Schema.Struct<{
                        readonly d: Schema.String
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                        readonly kty: Schema.Literal<"oct">
                        readonly k: Schema.String
                      }>
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly typ: Schema.optional<Schema.String>
                readonly cty: Schema.optional<Schema.String>
                readonly crit: Schema.optionalKey<Schema.Never>
              } & CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> &
                ValidateCriticalHeaderKeys<CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string>
                    | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                            >[]
                          ]
                        >
                      >
                }
            : Omit<
                {
                  readonly alg: Schema.Literals<
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
                  readonly jku: Schema.optional<Schema.String>
                  readonly jwk: Schema.optional<
                    Schema.Union<
                      readonly [
                        Schema.Struct<{
                          readonly d: Schema.String
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                                  Schema.Struct<{
                                    readonly r: Schema.String
                                    readonly d: Schema.String
                                    readonly t: Schema.String
                                  }>
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
                          readonly kty: Schema.Literal<"oct">
                          readonly k: Schema.String
                        }>
                      ]
                    >
                  >
                  readonly kid: Schema.optional<Schema.String>
                  readonly x5u: Schema.optional<Schema.String>
                  readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                  readonly x5t: Schema.optional<Schema.String>
                  readonly "x5t#S256": Schema.optional<Schema.String>
                  readonly typ: Schema.optional<Schema.String>
                  readonly cty: Schema.optional<Schema.String>
                  readonly crit: Schema.optionalKey<Schema.Never>
                },
                ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                  (
                    | "crit"
                    | keyof CriticalHeaders
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string>
                  )
              > &
                CriticalHeaders &
                ValidateCriticalHeaderKeys<CriticalHeaders> &
                ValidateCriticalHeaderKeys<CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>> & {
                  readonly crit:
                    | Extract<keyof CriticalHeaders, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string>
                    | Extract<Extract<keyof CriticalHeaders, string>, string>
                    | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string> extends never
                    ? Schema.optionalKey<Schema.Never>
                    : Schema.$Array<
                        Schema.Union<
                          readonly [
                            Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                            >,
                            ...Schema.Literal<
                              | Extract<keyof CriticalHeaders, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<keyof CriticalHeaders, string>, string>
                              | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                            >[]
                          ]
                        >
                      >
                })
        ]: (("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
          (
            | "crit"
            | keyof CriticalHeaders
            | Extract<keyof CriticalHeaders, string>
            | Extract<keyof CriticalHeaders, string>
            | Extract<Extract<keyof CriticalHeaders, string>, string>
          ) extends never
          ? {
              readonly alg: Schema.Literals<
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
              readonly jku: Schema.optional<Schema.String>
              readonly jwk: Schema.optional<
                Schema.Union<
                  readonly [
                    Schema.Struct<{
                      readonly d: Schema.String
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
                              Schema.Struct<{
                                readonly r: Schema.String
                                readonly d: Schema.String
                                readonly t: Schema.String
                              }>
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
                              Schema.Struct<{
                                readonly r: Schema.String
                                readonly d: Schema.String
                                readonly t: Schema.String
                              }>
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
                      readonly kty: Schema.Literal<"oct">
                      readonly k: Schema.String
                    }>
                  ]
                >
              >
              readonly kid: Schema.optional<Schema.String>
              readonly x5u: Schema.optional<Schema.String>
              readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
              readonly x5t: Schema.optional<Schema.String>
              readonly "x5t#S256": Schema.optional<Schema.String>
              readonly typ: Schema.optional<Schema.String>
              readonly cty: Schema.optional<Schema.String>
              readonly crit: Schema.optionalKey<Schema.Never>
            } & CriticalHeaders &
              ValidateCriticalHeaderKeys<CriticalHeaders> &
              ValidateCriticalHeaderKeys<CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>> & {
                readonly crit:
                  | Extract<keyof CriticalHeaders, string>
                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                  | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string> extends never
                  ? Schema.optionalKey<Schema.Never>
                  : Schema.$Array<
                      Schema.Union<
                        readonly [
                          Schema.Literal<
                            | Extract<keyof CriticalHeaders, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                            | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                          >,
                          ...Schema.Literal<
                            | Extract<keyof CriticalHeaders, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                            | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                          >[]
                        ]
                      >
                    >
              }
          : Omit<
              {
                readonly alg: Schema.Literals<
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
                readonly jku: Schema.optional<Schema.String>
                readonly jwk: Schema.optional<
                  Schema.Union<
                    readonly [
                      Schema.Struct<{
                        readonly d: Schema.String
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                                Schema.Struct<{
                                  readonly r: Schema.String
                                  readonly d: Schema.String
                                  readonly t: Schema.String
                                }>
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
                        readonly kty: Schema.Literal<"oct">
                        readonly k: Schema.String
                      }>
                    ]
                  >
                >
                readonly kid: Schema.optional<Schema.String>
                readonly x5u: Schema.optional<Schema.String>
                readonly x5c: Schema.optional<Schema.$Array<Schema.String>>
                readonly x5t: Schema.optional<Schema.String>
                readonly "x5t#S256": Schema.optional<Schema.String>
                readonly typ: Schema.optional<Schema.String>
                readonly cty: Schema.optional<Schema.String>
                readonly crit: Schema.optionalKey<Schema.Never>
              },
              ("alg" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "jwk" | "jku" | "typ" | "cty" | "crit") &
                (
                  | "crit"
                  | keyof CriticalHeaders
                  | Extract<keyof CriticalHeaders, string>
                  | Extract<keyof CriticalHeaders, string>
                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                )
            > &
              CriticalHeaders &
              ValidateCriticalHeaderKeys<CriticalHeaders> &
              ValidateCriticalHeaderKeys<CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>> & {
                readonly crit:
                  | Extract<keyof CriticalHeaders, string>
                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                  | Extract<Extract<keyof CriticalHeaders, string>, string>
                  | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string> extends never
                  ? Schema.optionalKey<Schema.Never>
                  : Schema.$Array<
                      Schema.Union<
                        readonly [
                          Schema.Literal<
                            | Extract<keyof CriticalHeaders, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                            | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                          >,
                          ...Schema.Literal<
                            | Extract<keyof CriticalHeaders, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                            | Extract<Extract<keyof CriticalHeaders, string>, string>
                            | Extract<Extract<Extract<keyof CriticalHeaders, string>, string>, string>
                          >[]
                        ]
                      >
                    >
              })[K]
      }[K]
    }>,
  never
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jws.ts#L713)

Since v1.0.0
