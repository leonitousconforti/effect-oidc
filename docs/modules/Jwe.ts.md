---
title: Jwe.ts
nav_order: 4
parent: Modules
---

## Jwe.ts overview

JSON Web Encryption (JWE) based on RFC 7516.

This module provides the JWE Compact Serialization together with WebCrypto
backed authenticated encryption and decryption. It supports the AES-GCM and
AES-CBC-HMAC-SHA2 content encryption families and the `dir`, RSA-OAEP,
AES key wrap, AES-GCM key wrap, ECDH-ES (direct and key-wrap), and PBES2
key management families.

`RSA1_5` key management is intentionally unsupported - the Web Crypto API
does not implement RSAES-PKCS1-v1_5 encryption and RFC 8725 discourages it.

Security note: AES-GCM (content encryption and `A*GCMKW` key wrapping) uses
a fresh random 96-bit IV per operation. Random 96-bit nonces are only safe
up to roughly 2^32 encryptions under a single fixed key before the
birthday-bound collision risk becomes non-negligible; this matters for
`dir` with a reused Content Encryption Key and for a reused `A*GCMKW`
key-encryption key. Rotate long-lived symmetric keys well before that
bound, or prefer a key-management mode that derives a fresh CEK per message.

**See**

- https://www.rfc-editor.org/rfc/rfc7516 - JSON Web Encryption (JWE)
- https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)

Since v1.0.0

---

## Exports Grouped by Category

- [Decryption](#decryption)
  - [decrypt](#decrypt)
- [Encryption](#encryption)
  - [encrypt](#encrypt)
- [Errors](#errors)
  - [JweError (class)](#jweerror-class)
  - [JweErrorReason (type alias)](#jweerrorreason-type-alias)
- [Schema](#schema)
  - [Compact](#compact)
  - [ProtectedHeader](#protectedheader)

---

# Decryption

## decrypt

Decrypts a JWE Compact Serialization string, returning the decoded
protected header and the plaintext bytes. The `key` must be the
counterpart to the one used for encryption (RSA/EC private key, or the
shared symmetric/PBKDF2 key).

**See**

- https://www.rfc-editor.org/rfc/rfc7516#section-5.2

**Signature**

```ts
declare const decrypt: (options: {
  readonly jwe: string
  readonly key: CryptoKey
  readonly keyManagementAlgorithms?: ReadonlyArray<(typeof JweAlgorithm)["Type"]> | undefined
  readonly contentEncryptionAlgorithms?: ReadonlyArray<(typeof JweEncryption)["Type"]> | undefined
  readonly maxPBES2Count?: number | undefined
}) => Effect.Effect<
  {
    protectedHeader: {
      readonly [x: string]: unknown
      readonly enc: "A128CBC-HS256" | "A192CBC-HS384" | "A256CBC-HS512" | "A128GCM" | "A192GCM" | "A256GCM"
      readonly alg:
        | "RSA-OAEP"
        | "RSA-OAEP-256"
        | "A128KW"
        | "A192KW"
        | "A256KW"
        | "dir"
        | "ECDH-ES"
        | "ECDH-ES+A128KW"
        | "ECDH-ES+A192KW"
        | "ECDH-ES+A256KW"
        | "A128GCMKW"
        | "A192GCMKW"
        | "A256GCMKW"
        | "PBES2-HS256+A128KW"
        | "PBES2-HS384+A192KW"
        | "PBES2-HS512+A256KW"
      readonly kid?: string | undefined
      readonly typ?: string | undefined
      readonly cty?: string | undefined
      readonly epk?:
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
      readonly apu?: string | undefined
      readonly apv?: string | undefined
      readonly iv?: string | undefined
      readonly tag?: string | undefined
      readonly p2s?: string | undefined
      readonly p2c?: number | undefined
    }
    plaintext: Uint8Array<ArrayBuffer>
  },
  JweError,
  never
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwe.ts#L768)

Since v1.0.0

# Encryption

## encrypt

Encrypts a plaintext into a JWE Compact Serialization string.

The `key` must be a WebCrypto `CryptoKey` appropriate for `algorithm`: an
RSA public key for RSA-OAEP, an AES key for the key-wrap families, an EC
key imported for `ECDH` for the ECDH-ES families, a PBKDF2 key for PBES2,
or the shared content key for `dir`.

**See**

- https://www.rfc-editor.org/rfc/rfc7516#section-5.1

**Signature**

```ts
declare const encrypt: (options: {
  readonly plaintext: string | Uint8Array
  readonly key: CryptoKey
  readonly algorithm: (typeof JweAlgorithm)["Type"]
  readonly encryption: (typeof JweEncryption)["Type"]
  readonly protectedHeader?: Record<string, unknown> | undefined
  readonly p2c?: number | undefined
  readonly apu?: Uint8Array | undefined
  readonly apv?: Uint8Array | undefined
}) => Effect.Effect<string, JweError, never>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwe.ts#L716)

Since v1.0.0

# Errors

## JweError (class)

**Signature**

```ts
declare class JweError
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwe.ts#L195)

Since v1.0.0

## JweErrorReason (type alias)

The reasons a JWE operation can fail.

**Signature**

```ts
type JweErrorReason =
  "Malformed" | "UnsupportedAlgorithm" | "KeyManagementFailed" | "EncryptionFailed" | "DecryptionFailed"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwe.ts#L184)

Since v1.0.0

# Schema

## Compact

The parsed parts of a JWE Compact Serialization (RFC 7516 Section 7.1):

    BASE64URL(UTF8(Protected Header)) . BASE64URL(Encrypted Key) .
    BASE64URL(IV) . BASE64URL(Ciphertext) . BASE64URL(Authentication Tag)

**See**

- https://www.rfc-editor.org/rfc/rfc7516#section-7.1

**Signature**

```ts
declare const Compact: Schema.decodeTo<
  Schema.Struct<{
    readonly protected: Schema.String
    readonly encryptedKey: Schema.String
    readonly iv: Schema.String
    readonly ciphertext: Schema.String
    readonly tag: Schema.String
  }>,
  Schema.TemplateLiteralParser<
    readonly [
      Schema.String,
      Schema.Literal<".">,
      Schema.String,
      Schema.Literal<".">,
      Schema.String,
      Schema.Literal<".">,
      Schema.String,
      Schema.Literal<".">,
      Schema.String
    ]
  >,
  never,
  never
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwe.ts#L133)

Since v1.0.0

## ProtectedHeader

The JWE Protected Header (RFC 7516 Section 4). Carries the required `alg`
and `enc` parameters plus the optional shared and algorithm-specific
parameters, and is extensible with additional public/private parameters.

**See**

- https://www.rfc-editor.org/rfc/rfc7516#section-4

**Signature**

```ts
declare const ProtectedHeader: Schema.StructWithRest<
  Schema.Struct<{
    readonly alg: Schema.Literals<
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
    readonly enc: Schema.Literals<
      readonly ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"]
    >
    readonly kid: Schema.optional<Schema.String>
    readonly typ: Schema.optional<Schema.String>
    readonly cty: Schema.optional<Schema.String>
    readonly epk: Schema.optional<
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
    >
    readonly apu: Schema.optional<Schema.String>
    readonly apv: Schema.optional<Schema.String>
    readonly iv: Schema.optional<Schema.String>
    readonly tag: Schema.optional<Schema.String>
    readonly p2s: Schema.optional<Schema.String>
    readonly p2c: Schema.optional<Schema.Number>
  }>,
  readonly [Schema.$Record<Schema.String, Schema.UndefinedOr<Schema.Unknown>>]
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwe.ts#L51)

Since v1.0.0
