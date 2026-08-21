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
  - [JwksCache (interface)](#jwkscache-interface)
  - [authorizationRequest](#authorizationrequest)
  - [cachedJwks](#cachedjwks)
  - [exchangeAuthorizationCode](#exchangeauthorizationcode)
  - [exchangeClientCredentials](#exchangeclientcredentials)
  - [fetchDiscovery](#fetchdiscovery)
  - [fetchJwks](#fetchjwks)
  - [generatePkce](#generatepkce)
  - [jwksCache](#jwkscache)
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
- [Utilities](#utilities)
  - [issuerUrl](#issuerurl)

---

# Client

## JwksCache (interface)

A cached view of an issuer's JWKS document - see `jwksCache`.

**Signature**

```ts
export interface JwksCache<E> {
  /** The cached document, fetched on first use and refreshed after the ttl. */
  readonly get: Effect.Effect<Schema.Schema.Type<typeof Jwt.JwksSchema>, E>
  /**
   * Drops the cached document and fetches a fresh one, for when a token
   * names a `kid` the cached set lacks (the issuer rotated its keys). Rate
   * limited to one forced refresh per `minRefreshInterval` - within the
   * window it simply answers the cached document - so unknown `kid`s in
   * hostile tokens cannot be turned into a request flood at the issuer.
   */
  readonly refresh: Effect.Effect<Schema.Schema.Type<typeof Jwt.JwksSchema>, E>
}
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L402)

Since v1.0.0

## authorizationRequest

Builds the browser redirect URL that starts the code flow.

**Signature**

```ts
declare const authorizationRequest: (options: {
  readonly authorizationEndpoint: string
  readonly clientId: string
  readonly redirectUri: string
  readonly scopes: ReadonlyArray<string>
  readonly state: string
  readonly codeChallenge: string
  readonly nonce?: string | undefined
}) => HttpClientRequest.HttpClientRequest
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L480)

Since v1.0.0

## cachedJwks

Builds a cached view of an issuer's JWKS document - the `get` half of
`jwksCache`, for callers that do not need forced refreshes.

**Signature**

```ts
declare const cachedJwks: (
  jwksUri: string,
  ttl?: Duration.Input
) => Effect.Effect<
  Effect.Effect<
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
  >,
  never,
  never
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L471)

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
    readonly token_type: "Bearer"
    readonly access_token: string
    readonly expires_in: number
    readonly scope?: string | undefined
    readonly refresh_token?: string | undefined
    readonly id_token?: string | undefined
  },
  Schema.SchemaError | HttpClientError,
  HttpClient.HttpClient
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L508)

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
    readonly token_type: "Bearer"
    readonly access_token: string
    readonly expires_in: number
    readonly scope?: string | undefined
    readonly refresh_token?: string | undefined
    readonly id_token?: string | undefined
  },
  Schema.SchemaError | HttpClientError,
  HttpClient.HttpClient
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L538)

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
  Schema.SchemaError | HttpClientError | DiscoveryError,
  HttpClient.HttpClient
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L351)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L393)

Since v1.0.0

## generatePkce

Generates a PKCE verifier and its S256 challenge.

**Signature**

```ts
declare const generatePkce: () => Effect.Effect<{ verifier: string; challenge: string; method: "S256" }, never, never>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L335)

Since v1.0.0

## jwksCache

Builds a cached view of an issuer's JWKS document for verifiers that run
per request: the document is fetched lazily on first use (concurrent
callers share one fetch), reused for `ttl` (10 minutes by default), and
refreshed after that. A forced `refresh` (for an unknown `kid`) is rate
limited to one per `minRefreshInterval` (30 seconds by default).

Availability beats freshness on the failure paths. A failed refresh
serves the previously fetched document, so a blip at the issuer cannot
fail verifications the old keys could still answer. A failure with
nothing to fall back on (the very first fetch) fails its own caller but
is evicted from the cache immediately, so the next caller retries
instead of inheriting the failure for the rest of the ttl.

**Signature**

```ts
declare const jwksCache: (
  jwksUri: string,
  options?: { readonly ttl?: Duration.Input | undefined; readonly minRefreshInterval?: Duration.Input | undefined }
) => Effect.Effect<
  {
    get: Effect.Effect<
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
    refresh: Effect.Effect<
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
  },
  never,
  never
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L432)

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
}) => Effect.Effect<HttpClientResponse.HttpClientResponse, HttpClientError, HttpClient.HttpClient>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L569)

Since v1.0.0

## verifyIdToken

Verifies an id token against the issuer's JWKS and decodes its claims,
checking the audience (the client id) and, when provided, the nonce. This
is the last step of the sign-in flow - the returned `sub` is the stable
account id at the provider to key local users on.

Accepts ES256 and RS256 signatures by default: ES256 is what this
library's provider signs with, and RS256 is what the large third-party
providers (Google, Discord) sign with. Pass `algorithms` to narrow or
widen the accepted set - never include an HMAC algorithm, since the JWKS
is public and anyone holding it could mint "signed" tokens.

**Signature**

```ts
declare const verifyIdToken: (options: {
  readonly idToken: string
  readonly jwks: Schema.Schema.Type<typeof Jwt.JwksSchema>
  readonly issuer: string
  readonly clientId: string
  readonly nonce?: string | undefined
  readonly algorithms?: ReadonlyArray<(typeof Jwa.JwsAlgorithm)["Type"]> | undefined
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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L608)

Since v1.0.0

# Errors

## DiscoveryError (class)

Raised when a fetched discovery document fails validation.

**Signature**

```ts
declare class DiscoveryError
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L161)

Since v1.0.0

# Provider

## clientAuthentication

Resolves how a token request authenticates its client: the
`Authorization: Basic` header (`client_secret_basic`, the OIDC default
method) takes precedence over the `client_id`/`client_secret` body
parameters (`client_secret_post`). Returns `Option.none` when the request
names no client at all, when a presented Basic header is malformed, or
when the request uses both methods at once (a body `client_secret` next
to a Basic header), which RFC 6749 Section 2.3 forbids.

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L219)

Since v1.0.0

## issueAccessToken

Issues an access token JWT (RFC 9068, `typ: "at+jwt"`). Used by the
provider's token endpoint.

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L264)

Since v1.0.0

## issueIdToken

Issues an id token JWT. The audience is the
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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L299)

Since v1.0.0

## makeDiscoveryDocument

Builds the discovery document for an issuer, using the conventional
endpoint paths.

**Signature**

```ts
declare const makeDiscoveryDocument: (issuer: string) => Schema.Schema.Type<typeof DiscoveryDocumentSchema>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L186)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L122)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L56)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L33)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L147)

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
  readonly token_type_hint: Schema.optional<Schema.String>
  readonly token: Schema.String
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L138)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L79)

Since v1.0.0

## TokenResponseSchema

**Signature**

```ts
declare const TokenResponseSchema: Schema.Struct<{
  readonly access_token: Schema.String
  readonly token_type: Schema.Literal<"Bearer">
  readonly expires_in: Schema.Int
  readonly scope: Schema.optional<Schema.String>
  readonly refresh_token: Schema.optional<Schema.String>
  readonly id_token: Schema.optional<Schema.String>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L106)

Since v1.0.0

# Utilities

## issuerUrl

Resolves a path relative to an issuer identifier, keeping any path the
issuer itself carries (OIDC Discovery 1.0 Section 4.1: the well-known
suffix is appended to the issuer, not to its origin). `new URL(path,
issuer)` would drop `/realms/tenant` from `https://idp.example/realms/tenant`
and silently talk to a different (or nonexistent) issuer.

**Signature**

```ts
declare const issuerUrl: (issuer: string, path: string) => string
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/Oidc.ts#L176)

Since v1.0.0
