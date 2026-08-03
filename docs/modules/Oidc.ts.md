---
title: Oidc.ts
nav_order: 7
parent: Modules
---

## Oidc.ts overview

The OIDC protocol surface: discovery and token endpoint schemas, PKCE
utilities, token issuing helpers for the provider, and a code-flow client
for relying apps.

The provider serves, by convention relative to the issuer:

- `/.well-known/openid-configuration` - `DiscoveryDocumentSchema`
- `/.well-known/jwks.json` - `Jwt.JwksSchema`
- `/oauth/authorize` - browser page decoding `AuthorizationRequestSchema`
- `/oauth/token` - decoding `TokenRequestSchema` (authorization_code
  with PKCE, refresh_token, and client_credentials grants; confidential
  clients authenticate via `clientAuthentication`), answering
  `TokenResponseSchema`
- `/oauth/revoke` - decoding `RevocationRequestSchema` (RFC 7009),
  adding the token's `jti` to a denylist until the token's `exp`

Since v1.0.0

---

## Exports Grouped by Category

- [Client](#client)
  - [authorizationUrl](#authorizationurl)
  - [exchangeAuthorizationCode](#exchangeauthorizationcode)
  - [exchangeClientCredentials](#exchangeclientcredentials)
  - [fetchDiscovery](#fetchdiscovery)
  - [fetchJwks](#fetchjwks)
  - [generatePkce](#generatepkce)
  - [revokeToken](#revoketoken)
  - [verifyIdToken](#verifyidtoken)
- [Errors](#errors)
  - [DiscoveryError (class)](#discoveryerror-class)
- [Provider](#provider)
  - [clientAuthentication](#clientauthentication)
  - [issueAccessToken](#issueaccesstoken)
  - [issueIdToken](#issueidtoken)
  - [makeDiscoveryDocument](#makediscoverydocument)
- [Schema](#schema)
  - [AccessTokenClaimsSchema](#accesstokenclaimsschema)
  - [AuthorizationRequestSchema](#authorizationrequestschema)
  - [DiscoveryDocumentSchema](#discoverydocumentschema)
  - [IdTokenClaimsSchema](#idtokenclaimsschema)
  - [RevocationRequestSchema](#revocationrequestschema)
  - [TokenRequestSchema](#tokenrequestschema)
  - [TokenResponseSchema](#tokenresponseschema)

---

# Client

## authorizationUrl

Builds the browser redirect URL that starts the code flow.

**Signature**

```ts
declare const authorizationUrl: (options: {
  readonly authorizationEndpoint: string
  readonly clientId: string
  readonly redirectUri: string
  readonly scopes: ReadonlyArray<string>
  readonly state: string
  readonly codeChallenge: string
  readonly nonce?: string | undefined
}) => string
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L362)

Since v1.0.0

## exchangeAuthorizationCode

Exchanges an authorization code for tokens at the provider's token
endpoint.

**Signature**

```ts
declare const exchangeAuthorizationCode: (options: {
  readonly tokenEndpoint: string
  readonly clientId: string
  readonly clientSecret?: string | undefined
  readonly code: string
  readonly codeVerifier: string
  readonly redirectUri: string
}) => Effect.Effect<
  {
    readonly scope: string
    readonly token_type: "Bearer"
    readonly access_token: string
    readonly expires_in: number
    readonly refresh_token?: string | undefined
    readonly id_token?: string | undefined
  },
  Schema.SchemaError | HttpClientError,
  HttpClient.HttpClient
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L390)

Since v1.0.0

## exchangeClientCredentials

Obtains an access token with the client credentials grant - the machine
to machine flow for confidential clients, with no user involved. The
client authenticates with `client_secret_basic` (the OIDC default
method).

**Signature**

```ts
declare const exchangeClientCredentials: (options: {
  readonly tokenEndpoint: string
  readonly clientId: string
  readonly clientSecret: string
  readonly scopes?: ReadonlyArray<string> | undefined
}) => Effect.Effect<
  {
    readonly scope: string
    readonly token_type: "Bearer"
    readonly access_token: string
    readonly expires_in: number
    readonly refresh_token?: string | undefined
    readonly id_token?: string | undefined
  },
  Schema.SchemaError | HttpClientError,
  HttpClient.HttpClient
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L422)

Since v1.0.0

## fetchDiscovery

Fetches and decodes the issuer's discovery document.

**Signature**

```ts
declare const fetchDiscovery: (
  issuer: string
) => Effect.Effect<
  {
    readonly response_types_supported: ReadonlyArray<string>
    readonly grant_types_supported: ReadonlyArray<string>
    readonly scopes_supported: ReadonlyArray<string>
    readonly subject_types_supported: ReadonlyArray<string>
    readonly id_token_signing_alg_values_supported: ReadonlyArray<string>
    readonly code_challenge_methods_supported: ReadonlyArray<string>
    readonly issuer: string
    readonly authorization_endpoint: string
    readonly token_endpoint: string
    readonly jwks_uri: string
    readonly userinfo_endpoint?: string | undefined
    readonly token_endpoint_auth_methods_supported?: ReadonlyArray<string> | undefined
    readonly revocation_endpoint?: string | undefined
  },
  Schema.SchemaError | DiscoveryError | HttpClientError,
  HttpClient.HttpClient
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L318)

Since v1.0.0

## fetchJwks

Fetches and decodes the issuer's JWKS document.

**Signature**

```ts
declare const fetchJwks: (
  jwksUri: string
) => Effect.Effect<
  {
    readonly keys: ReadonlyArray<
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
    >
  },
  Schema.SchemaError | HttpClientError,
  HttpClient.HttpClient
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L350)

Since v1.0.0

## generatePkce

Generates a PKCE verifier and its S256 challenge.

**Signature**

```ts
declare const generatePkce: () => Effect.Effect<{ verifier: string; challenge: string; method: "S256" }, never, never>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L302)

Since v1.0.0

## revokeToken

Revokes a token at the provider's RFC 7009 revocation endpoint.
Confidential clients authenticate with `client_secret_basic`; public
clients send only their `client_id`.

**Signature**

```ts
declare const revokeToken: (options: {
  readonly revocationEndpoint: string
  readonly token: string
  readonly clientId?: string | undefined
  readonly clientSecret?: string | undefined
}) => Effect.Effect<void, HttpClientError, HttpClient.HttpClient>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L453)

Since v1.0.0

## verifyIdToken

Verifies an id token against the issuer's JWKS and decodes its claims,
checking the audience (the client id) and, when provided, the nonce. This
is the last step of the sign-in flow - the returned `sub` is the stable
account id at the provider to key local users on.

**Signature**

```ts
declare const verifyIdToken: (options: {
  readonly idToken: string
  readonly jwks: Schema.Schema.Type<typeof Jwt.JwksSchema>
  readonly issuer: string
  readonly clientId: string
  readonly nonce?: string | undefined
}) => Effect.Effect<
  {
    readonly aud: string | ReadonlyArray<string>
    readonly iss: string
    readonly sub: string
    readonly exp: number
    readonly iat: number
    readonly nbf?: number | undefined
    readonly jti?: string | undefined
    readonly nonce?: string | undefined
    readonly azp?: string | undefined
    readonly name?: string | undefined
    readonly picture?: string | undefined
  },
  Jwt.JwtError,
  never
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L484)

Since v1.0.0

# Errors

## DiscoveryError (class)

Raised when a fetched discovery document fails validation.

**Signature**

```ts
declare class DiscoveryError
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L159)

Since v1.0.0

# Provider

## clientAuthentication

Resolves how a token request authenticates its client: the
`Authorization: Basic` header (`client_secret_basic`, the OIDC default
method) takes precedence over the `client_id`/`client_secret` body
parameters (`client_secret_post`). Returns `Option.none` when the request
names no client at all, or when a presented Basic header is malformed.

For the provider's token endpoint: public clients resolve with an
undefined secret, confidential clients must have their secret verified
against the registration before the grant is honoured.

**See**

- https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1

**Signature**

```ts
declare const clientAuthentication: (options: {
  readonly authorization?: string | undefined
  readonly request: { readonly client_id?: string | undefined; readonly client_secret?: string | undefined }
}) => Option.Option<{ readonly clientId: string; readonly clientSecret: string | undefined }>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L202)

Since v1.0.0

## issueAccessToken

Issues an access token JWT. Used by the provider's token endpoint.

**Signature**

```ts
declare const issueAccessToken: (options: {
  readonly privateJwk: Schema.Schema.Type<typeof Jwt.PrivateJwkSchema>
  readonly issuer: string
  readonly subject: string
  readonly audience: string
  readonly clientId: string
  readonly scope: string
  readonly ttlSeconds: number
}) => Effect.Effect<string, Schema.SchemaError, never>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L239)

Since v1.0.0

## issueIdToken

Issues an id token JWT for "Sign in with Tinyburg". The audience is the
client id, per OIDC.

**Signature**

```ts
declare const issueIdToken: (options: {
  readonly privateJwk: Schema.Schema.Type<typeof Jwt.PrivateJwkSchema>
  readonly issuer: string
  readonly subject: string
  readonly clientId: string
  readonly ttlSeconds: number
  readonly nonce?: string | undefined
  readonly profile?: { readonly name?: string | undefined; readonly picture?: string | undefined } | undefined
}) => Effect.Effect<string, Schema.SchemaError, never>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L271)

Since v1.0.0

## makeDiscoveryDocument

Builds the discovery document for an issuer, using the conventional
endpoint paths.

**Signature**

```ts
declare const makeDiscoveryDocument: (issuer: string) => Schema.Schema.Type<typeof DiscoveryDocumentSchema>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L171)

Since v1.0.0

# Schema

## AccessTokenClaimsSchema

Claims carried by an access token, beyond the registered ones.

**Signature**

```ts
declare const AccessTokenClaimsSchema: Schema.Struct<{
  readonly scope: Schema.String
  readonly client_id: Schema.String
  readonly iss: Schema.String
  readonly sub: Schema.String
  readonly aud: Schema.Union<readonly [Schema.String, Schema.$Array<Schema.String>]>
  readonly exp: Schema.Number
  readonly iat: Schema.Number
  readonly nbf: Schema.optional<Schema.Number>
  readonly jti: Schema.optional<Schema.String>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L119)

Since v1.0.0

## AuthorizationRequestSchema

The query parameters of an OAuth 2.1 authorization request. PKCE is
mandatory for every client, public or confidential.

**Signature**

```ts
declare const AuthorizationRequestSchema: Schema.Struct<{
  readonly response_type: Schema.Literal<"code">
  readonly client_id: Schema.String
  readonly redirect_uri: Schema.String
  readonly scope: Schema.String
  readonly state: Schema.String
  readonly nonce: Schema.optional<Schema.String>
  readonly code_challenge: Schema.String
  readonly code_challenge_method: Schema.Literal<"S256">
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L54)

Since v1.0.0

## DiscoveryDocumentSchema

**Signature**

```ts
declare const DiscoveryDocumentSchema: Schema.Struct<{
  readonly issuer: Schema.String
  readonly authorization_endpoint: Schema.String
  readonly token_endpoint: Schema.String
  readonly jwks_uri: Schema.String
  readonly userinfo_endpoint: Schema.optional<Schema.String>
  readonly response_types_supported: Schema.$Array<Schema.String>
  readonly grant_types_supported: Schema.$Array<Schema.String>
  readonly scopes_supported: Schema.$Array<Schema.String>
  readonly subject_types_supported: Schema.$Array<Schema.String>
  readonly id_token_signing_alg_values_supported: Schema.$Array<Schema.String>
  readonly code_challenge_methods_supported: Schema.$Array<Schema.String>
  readonly token_endpoint_auth_methods_supported: Schema.optional<Schema.$Array<Schema.String>>
  readonly revocation_endpoint: Schema.optional<Schema.String>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L31)

Since v1.0.0

## IdTokenClaimsSchema

**Signature**

```ts
declare const IdTokenClaimsSchema: Schema.Struct<{
  readonly azp: Schema.optional<Schema.String>
  readonly nonce: Schema.optional<Schema.String>
  readonly name: Schema.optional<Schema.String>
  readonly picture: Schema.optional<Schema.String>
  readonly iss: Schema.String
  readonly sub: Schema.String
  readonly aud: Schema.Union<readonly [Schema.String, Schema.$Array<Schema.String>]>
  readonly exp: Schema.Number
  readonly iat: Schema.Number
  readonly nbf: Schema.optional<Schema.Number>
  readonly jti: Schema.optional<Schema.String>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L144)

Since v1.0.0

## RevocationRequestSchema

The form body of an RFC 7009 revocation request. The endpoint must answer
`200` whether or not the presented token was valid, so callers cannot use
it to probe token validity; on success the token's `jti` joins a denylist
until the token's `exp`, which keeps the denylist bounded.

**See**

- https://www.rfc-editor.org/rfc/rfc7009 - OAuth 2.0 Token Revocation

**Signature**

```ts
declare const RevocationRequestSchema: Schema.Struct<{
  readonly token: Schema.String
  readonly token_type_hint: Schema.optional<Schema.String>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L135)

Since v1.0.0

## TokenRequestSchema

The form body of a token request. Public clients (SPAs, native apps) use
the `authorization_code` and `refresh_token` grants with PKCE and no
secret; confidential clients additionally authenticate - via the
`Authorization: Basic` header or the `client_secret` body parameter, see
`clientAuthentication` - and may use the machine-to-machine
`client_credentials` grant, where the credentials commonly arrive in the
header and the body carries only the grant type and scope.

**Signature**

```ts
declare const TokenRequestSchema: Schema.Union<
  readonly [
    Schema.Struct<{
      readonly grant_type: Schema.Literal<"authorization_code">
      readonly code: Schema.String
      readonly redirect_uri: Schema.String
      readonly client_id: Schema.String
      readonly client_secret: Schema.optional<Schema.String>
      readonly code_verifier: Schema.String
    }>,
    Schema.Struct<{
      readonly grant_type: Schema.Literal<"refresh_token">
      readonly refresh_token: Schema.String
      readonly client_id: Schema.String
      readonly client_secret: Schema.optional<Schema.String>
    }>,
    Schema.Struct<{
      readonly grant_type: Schema.Literal<"client_credentials">
      readonly scope: Schema.optional<Schema.String>
      readonly client_id: Schema.optional<Schema.String>
      readonly client_secret: Schema.optional<Schema.String>
    }>
  ]
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L77)

Since v1.0.0

## TokenResponseSchema

**Signature**

```ts
declare const TokenResponseSchema: Schema.Struct<{
  readonly access_token: Schema.String
  readonly token_type: Schema.Literal<"Bearer">
  readonly expires_in: Schema.Int
  readonly scope: Schema.String
  readonly refresh_token: Schema.optional<Schema.String>
  readonly id_token: Schema.optional<Schema.String>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L104)

Since v1.0.0
