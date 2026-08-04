---
title: Jwt.ts
nav_order: 6
parent: Modules
---

## Jwt.ts overview

High-level JSON Web Tokens (RFC 7519) built on the `Jws`, `Jwk`,
and `Jwa` modules: compact-serialized, signed with any supported JWS
algorithm, verified against a JWKS with registered-claim validation.

This is the opinionated layer the OIDC modules use. Reach for the `Jws`
module directly when you need multiple signatures, unprotected headers,
critical extension headers, or non-JSON payloads.

**See**

- https://www.rfc-editor.org/rfc/rfc7519 - JSON Web Token (JWT)

Since v1.0.0

---

## Exports Grouped by Category

- [Errors](#errors)
  - [JwtError (class)](#jwterror-class)
- [Keys](#keys)
  - [generateSigningKey](#generatesigningkey)
  - [toPublicKey](#topublickey)
- [Schema](#schema)
  - [JwksSchema](#jwksschema)
  - [PrivateJwkSchema](#privatejwkschema)
  - [PublicJwkSchema](#publicjwkschema)
  - [RegisteredClaimsSchema](#registeredclaimsschema)
  - [StandardClaimsSchema](#standardclaimsschema)
- [Signing](#signing)
  - [sign](#sign)
- [Verification](#verification)
  - [decodeClaims](#decodeclaims)
  - [verify](#verify)

---

# Errors

## JwtError (class)

**Signature**

```ts
declare class JwtError
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwt.ts#L78)

Since v1.0.0

# Keys

## generateSigningKey

Generates a fresh ES256 signing key pair with a random `kid`. Intended for
provider key provisioning/rotation scripts - persist the private JWK as a
secret and publish the public JWK in the JWKS document.

**Signature**

```ts
declare const generateSigningKey: () => Effect.Effect<
  {
    privateJwk: {
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
    publicJwk: {
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
  },
  Schema.SchemaError,
  never
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwt.ts#L126)

Since v1.0.0

## toPublicKey

Converts a private JWK to its public half, dropping the private scalar and
re-declaring `key_ops` for verification. The public JWK is suitable for
publishing in the JWKS document.

**Signature**

```ts
declare const toPublicKey: (privateJwk: {
  readonly kty: "EC"
  readonly crv: "P-256" | "P-384" | "P-521"
  readonly x: string
  readonly y: string
  readonly d: string
  readonly use?: "sig" | "enc" | undefined
  readonly key_ops?:
    | ReadonlyArray<"sign" | "verify" | "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits">
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
}) => Effect.Effect<
  {
    readonly kty: "EC"
    readonly crv: "P-256" | "P-384" | "P-521"
    readonly x: string
    readonly y: string
    readonly use?: "sig" | "enc" | undefined
    readonly key_ops?:
      | ReadonlyArray<"sign" | "verify" | "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits">
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
  },
  Schema.SchemaError,
  never
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwt.ts#L295)

Since v1.0.0

# Schema

## JwksSchema

The JWKS document served at `/.well-known/jwks.json`.

**Signature**

```ts
declare const JwksSchema: Schema.Struct<{
  readonly keys: Schema.$Array<
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
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwt.ts#L44)

Since v1.0.0

## PrivateJwkSchema

Private EC signing key, held only by the provider. Load it from secret
configuration - it is never serialized into any response.

**Signature**

```ts
declare const PrivateJwkSchema: Schema.Struct<{
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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwt.ts#L36)

Since v1.0.0

## PublicJwkSchema

Public EC signing key as published in the JWKS document.

**Signature**

```ts
declare const PublicJwkSchema: Schema.Struct<{
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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwt.ts#L27)

Since v1.0.0

## RegisteredClaimsSchema

The registered claims (RFC 7519 Section 4.1) every issued token carries.

**Signature**

```ts
declare const RegisteredClaimsSchema: Schema.Struct<{
  readonly iss: Schema.String
  readonly sub: Schema.String
  readonly aud: Schema.Union<readonly [Schema.String, Schema.$Array<Schema.String>]>
  readonly exp: Schema.Number
  readonly iat: Schema.Number
  readonly nbf: Schema.optional<Schema.Number>
  readonly jti: Schema.optional<Schema.String>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwt.ts#L52)

Since v1.0.0

## StandardClaimsSchema

Registered claims plus a rest record for token-specific claims, which can
be decoded with a more specific schema from the claims returned by
`verify`.

**Signature**

```ts
declare const StandardClaimsSchema: Schema.StructWithRest<
  Schema.Struct<{
    readonly iss: Schema.String
    readonly sub: Schema.String
    readonly aud: Schema.Union<readonly [Schema.String, Schema.$Array<Schema.String>]>
    readonly exp: Schema.Number
    readonly iat: Schema.Number
    readonly nbf: Schema.optional<Schema.Number>
    readonly jti: Schema.optional<Schema.String>
  }>,
  readonly [Schema.$Record<Schema.String, Schema.UndefinedOr<Schema.Unknown>>]
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwt.ts#L70)

Since v1.0.0

# Signing

## sign

Signs a payload as a compact-serialized JWT with the given private JWK,
using the key's `alg` (defaulting to ES256) and carrying its `kid` in the
protected header.

**Signature**

```ts
declare const sign: (options: {
  readonly privateJwk: Schema.Schema.Type<typeof PrivateJwkSchema>
  readonly payload: Record<string, unknown>
}) => Effect.Effect<string, Schema.SchemaError, never>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwt.ts#L168)

Since v1.0.0

# Verification

## decodeClaims

Builds a decoder that narrows the standard claims returned by
`verify` with a more precise, token-specific claims schema, turning
the `unknown` values of the rest record into fully typed claims.

**Signature**

```ts
declare const decodeClaims: <S extends Schema.Top>(
  schema: S
) => (
  input: {
    readonly [x: string]: unknown
    readonly aud: string | ReadonlyArray<string>
    readonly iss: string
    readonly sub: string
    readonly exp: number
    readonly iat: number
    readonly nbf?: number | undefined
    readonly jti?: string | undefined
  },
  options?: ParseOptions
) => Effect.Effect<S["Type"], Schema.SchemaError, S["DecodingServices"]>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwt.ts#L284)

Since v1.0.0

## verify

Verifies a compact-serialized JWT against a JWKS: signature (any supported
JWS algorithm, with `kid`-based key selection), `exp`/`nbf` (with 30s
skew), and, when provided, `iss` and `aud`. Returns the validated
standard claims plus the rest record for decoding token-specific claims
with a more precise schema.

**Signature**

```ts
declare const verify: (
  token: string,
  options: {
    readonly jwks: Schema.Schema.Type<typeof JwksSchema>
    readonly issuer?: string | undefined
    readonly audience?: string | undefined
    readonly algorithms?: ReadonlyArray<(typeof Jwa.JwsAlgorithm)["Type"]> | undefined
    readonly types?: ReadonlyArray<string> | undefined
  }
) => Effect.Effect<
  {
    readonly [x: string]: unknown
    readonly aud: string | ReadonlyArray<string>
    readonly iss: string
    readonly sub: string
    readonly exp: number
    readonly iat: number
    readonly nbf?: number | undefined
    readonly jti?: string | undefined
  },
  JwtError,
  never
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Jwt.ts#L207)

Since v1.0.0
