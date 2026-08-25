---
title: DynamicClientRegistration.ts
nav_order: 1
parent: Modules
---

## DynamicClientRegistration.ts overview

Dynamic client registration, RFC 7591: the endpoint where a client hands a
provider its metadata and is handed back a `client_id` - and, when it asked
to be confidential, a `client_secret`.

Both ends are here. A provider decodes `ClientMetadataRequestSchema`
and runs `validateClientMetadata` against its own
`RegistrationPolicy`, which fills in the defaults the RFC leaves to
the server and refuses anything the provider could not honour later;
`clientInformationResponse` builds the answer. A client calls
`register`, which finds the endpoint through discovery and comes back
with its credentials.

Registering is not authorizing. Nothing here decides who may register: RFC
7591 Section 3 offers an initial access token for that, and this module will
present one (`register`) and expects the provider to have checked it
before calling `validateClientMetadata`. An open registration endpoint
lets anyone mint a client and put a consent screen in front of users under
the provider's name, so a deployment that cannot gate it should not offer
it at all - and should not advertise `registration_endpoint` in discovery.

Nor does registering make a client trusted. A registered client is subject
to the same authorization code + PKCE flow as any other, and a provider
should not skip its consent screen for one just because it registered
successfully.

**See**

- https://www.rfc-editor.org/rfc/rfc7591 - OAuth 2.0 Dynamic Client Registration Protocol

Since v1.0.0

---

## Exports Grouped by Category

- [Client](#client)
  - [register](#register)
  - [registerAt](#registerat)
- [Errors](#errors)
  - [RegistrationError (class)](#registrationerror-class)
- [Models](#models)
  - [ClientRegistrationRequest (interface)](#clientregistrationrequest-interface)
  - [GrantType (type alias)](#granttype-type-alias)
  - [Registration (interface)](#registration-interface)
  - [RegistrationErrorCode (type alias)](#registrationerrorcode-type-alias)
  - [ResponseType (type alias)](#responsetype-type-alias)
  - [TokenEndpointAuthMethod (type alias)](#tokenendpointauthmethod-type-alias)
- [Provider](#provider)
  - [ClientMetadata (interface)](#clientmetadata-interface)
  - [RegistrationPolicy (interface)](#registrationpolicy-interface)
  - [clientInformationResponse](#clientinformationresponse)
  - [isRegistrableRedirectUri](#isregistrableredirecturi)
  - [validateClientMetadata](#validateclientmetadata)
- [Schema](#schema)
  - [ClientInformationResponseSchema](#clientinformationresponseschema)
  - [ClientMetadataRequestSchema](#clientmetadatarequestschema)
  - [GrantTypeSchema](#granttypeschema)
  - [RegistrationErrorCodeSchema](#registrationerrorcodeschema)
  - [RegistrationErrorResponseSchema](#registrationerrorresponseschema)
  - [ResponseTypeSchema](#responsetypeschema)
  - [TokenEndpointAuthMethodSchema](#tokenendpointauthmethodschema)
- [Utilities](#utilities)
  - [scopesOf](#scopesof)

---

# Client

## register

Registers at an issuer, finding the endpoint through discovery.

Safe to call on every boot when the provider keys registrations by
`softwareId`: the same client comes back, and there is nothing for the
service to persist between runs.

The endpoint is taken from the issuer's discovery document rather than
assumed, which is also what makes `NotOffered` a real answer: a provider
that does not advertise `registration_endpoint` does not register clients,
and no path is worth guessing at.

```ts
import { Effect, Option, Redacted } from "effect"
import { DynamicClientRegistration } from "effect-oidc"

const registration = DynamicClientRegistration.register({
  issuer: "https://id.example.com",
  initialAccessToken: Redacted.make(process.env["REGISTRATION_TOKEN"] ?? ""),
  metadata: {
    softwareId: "my-service",
    clientName: "My Service",
    redirectUris: ["https://app.example.com/auth/callback"],
    tokenEndpointAuthMethod: "none",
    scopes: ["openid", "profile"]
  }
}).pipe(
  Effect.tap(({ clientId }) => Effect.logInfo(`registered as ${clientId}`)),
  Effect.retry({ times: 5 }),
  Effect.map(({ clientId, clientSecret }) => ({
    clientId,
    clientSecret: Option.map(clientSecret, Redacted.value)
  }))
)
```

**Signature**

```ts
declare const register: (options: {
  readonly issuer: string
  readonly metadata: ClientRegistrationRequest
  readonly initialAccessToken?: Redacted.Redacted | string | undefined
}) => Effect.Effect<
  {
    clientId: string
    clientSecret: Option.Option<Redacted.Redacted<string>>
    issuedAt: Option.Option<DateTime.Utc>
    secretExpiresAt: Option.Option<DateTime.Utc>
  },
  RegistrationError,
  HttpClient.HttpClient
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L684)

Since v1.0.0

## registerAt

Registers at a known registration endpoint (RFC 7591 Section 3.1).

The initial access token, when the provider gate needs one, rides as a
bearer token on the request. Nothing is retried: whether a provider that is
still coming up is worth waiting for is the caller's judgement, and
`Effect.retry` composes.

**Signature**

```ts
declare const registerAt: (options: {
  readonly registrationEndpoint: string
  readonly metadata: ClientRegistrationRequest
  readonly initialAccessToken?: Redacted.Redacted | string | undefined
}) => Effect.Effect<
  {
    clientId: string
    clientSecret: Option.Option<Redacted.Redacted<string>>
    issuedAt: Option.Option<DateTime.Utc>
    secretExpiresAt: Option.Option<DateTime.Utc>
  },
  RegistrationError,
  HttpClient.HttpClient
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L565)

Since v1.0.0

# Errors

## RegistrationError (class)

Why registering failed:

- `NotOffered`: the provider's discovery document names no
  `registration_endpoint`, so this provider does not offer registration.
- `Rejected`: the provider answered, and what it said was not usable - it
  refused the metadata (`detail` carries the RFC 7591 Section 3.2.2 error
  code), refused the initial access token, or served a discovery document
  that failed validation.
- `Unreachable`: the provider could not be reached, or answered with
  something that was not a registration.

**Signature**

```ts
declare class RegistrationError
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L486)

Since v1.0.0

# Models

## ClientRegistrationRequest (interface)

What a client asks to be registered as.

**Signature**

```ts
export interface ClientRegistrationRequest {
  readonly redirectUris: readonly [string, ...Array<string>]
  /**
   * `none` for a public client. Never inferred: a client that leaves this
   * out is registered as confidential, which is the RFC 7591 Section 2
   * default, so it is required here rather than quietly defaulted.
   */
  readonly tokenEndpointAuthMethod: TokenEndpointAuthMethod
  readonly clientName?: string | undefined
  readonly scopes?: ReadonlyArray<string> | undefined
  /** Defaults to `["authorization_code"]`. */
  readonly grantTypes?: ReadonlyArray<GrantType> | undefined
  /** Defaults to `["code"]`. */
  readonly responseTypes?: ReadonlyArray<ResponseType> | undefined
  /**
   * Identifies the software, not the installation: the same value in every
   * copy of a service, stable across restarts and redeploys. A provider
   * that keys registrations by it recognizes the client on its next boot,
   * so changing this registers a new client rather than updating that one.
   */
  readonly softwareId?: string | undefined
  readonly softwareVersion?: string | undefined
}
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L516)

Since v1.0.0

## GrantType (type alias)

**Signature**

```ts
type GrantType = (typeof GrantTypeSchema)["Type"]
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L69)

Since v1.0.0

## Registration (interface)

The credentials a registration was issued.

**Signature**

```ts
export interface Registration {
  readonly clientId: string
  /** `Option.none` for a public client, which is issued no secret. */
  readonly clientSecret: Option.Option<Redacted.Redacted>
  readonly issuedAt: Option.Option<DateTime.Utc>
  /**
   * `Option.none` for a secret that does not expire, which RFC 7591 Section
   * 3.2.1 writes as `0`, and for a public client, which has none.
   */
  readonly secretExpiresAt: Option.Option<DateTime.Utc>
}
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L498)

Since v1.0.0

## RegistrationErrorCode (type alias)

**Signature**

```ts
type RegistrationErrorCode = (typeof RegistrationErrorCodeSchema)["Type"]
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L167)

Since v1.0.0

## ResponseType (type alias)

**Signature**

```ts
type ResponseType = (typeof ResponseTypeSchema)["Type"]
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L85)

Since v1.0.0

## TokenEndpointAuthMethod (type alias)

**Signature**

```ts
type TokenEndpointAuthMethod = (typeof TokenEndpointAuthMethodSchema)["Type"]
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L55)

Since v1.0.0

# Provider

## ClientMetadata (interface)

A validated registration: what the provider should store, with the RFC's
defaults applied and every value checked against the policy.

**Signature**

```ts
export interface ClientMetadata {
  readonly redirectUris: readonly [string, ...Array<string>]
  readonly tokenEndpointAuthMethod: TokenEndpointAuthMethod
  readonly grantTypes: ReadonlyArray<GrantType>
  readonly responseTypes: ReadonlyArray<ResponseType>
  /** Space delimited, as it travels on the wire and as `scope` claims carry it. */
  readonly scope: string
  readonly clientName: string
  readonly softwareId: Option.Option<string>
  readonly softwareVersion: Option.Option<string>
  /** Whether this registration is for a confidential client, which is to be issued a secret. */
  readonly confidential: boolean
}
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L276)

Since v1.0.0

## RegistrationPolicy (interface)

What a provider will register, and the defaults it fills in for what a
client left out.

**Signature**

```ts
export interface RegistrationPolicy {
  /**
   * The scopes this provider issues. A registration is refused unless every
   * scope it asks for is one of these, so a client never registers with a
   * scope every later authorization would then refuse.
   */
  readonly supportedScopes: ReadonlyArray<string>
  /** Defaults to every method `Oidc.clientAuthentication` can resolve. */
  readonly tokenEndpointAuthMethods?: ReadonlyArray<TokenEndpointAuthMethod> | undefined
  /** Defaults to every grant in {@link GrantTypeSchema}. */
  readonly grantTypes?: ReadonlyArray<GrantType> | undefined
  /** Defaults to `["code"]`. */
  readonly responseTypes?: ReadonlyArray<ResponseType> | undefined
  /** What a client that names no scope is registered with. Defaults to `"openid"`. */
  readonly defaultScope?: string | undefined
  /** What a client that names itself nothing is called. Defaults to `"Dynamically registered client"`. */
  readonly defaultClientName?: string | undefined
  /**
   * Whether `software_id` is required, which RFC 7591 leaves optional.
   *
   * Require it to key registrations by it: registering again under the same
   * `software_id` updates that client instead of making another, which is
   * what lets a service register on every boot and keep no record of its own
   * registration. Without one there is nothing to recognize a client by on
   * its next boot and it collects a new registration every time it starts.
   */
  readonly requireSoftwareId?: boolean | undefined
  /** Whether a loopback redirect uri may be plain http. Defaults to `true`. */
  readonly allowLoopbackHttp?: boolean | undefined
}
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L238)

Since v1.0.0

## clientInformationResponse

Builds the client information response (RFC 7591 Section 3.2.1).

Answered with `201 Created`. The `client_secret` is in it exactly once, at
registration: a provider that stores only the secret's hash cannot ever
show it again, which is also why re-registering a confidential client
should hand it a fresh one rather than expect it to have kept the last.

`client_secret_expires_at` is filled in whenever a secret is issued,
because the RFC makes it REQUIRED there, with `0` for a secret that does
not expire. Pass `secretExpiresAt` for one that does.

**Signature**

```ts
declare const clientInformationResponse: (options: {
  readonly clientId: string
  readonly metadata: ClientMetadata
  readonly clientSecret?: string | undefined
  readonly issuedAt?: DateTime.Utc | undefined
  readonly secretExpiresAt?: DateTime.Utc | undefined
}) => (typeof ClientInformationResponseSchema)["Type"]
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L433)

Since v1.0.0

## isRegistrableRedirectUri

Whether a provider will register a redirect uri: absolute, with no fragment
(RFC 6749 Section 3.1.2), and https unless it points at the loopback
interface.

The check is on the shape of the uri, not on who is asking. A provider that
wants to refuse a redirect uri for some other reason - an origin it does
not recognize, a host it has blocked - does that on top of this.

**See**

- https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2

**Signature**

```ts
declare const isRegistrableRedirectUri: (
  value: string,
  options?: { readonly allowLoopbackHttp?: boolean | undefined }
) => boolean
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L212)

Since v1.0.0

## validateClientMetadata

Applies a provider's registration policy to a request body: fills in the
defaults the RFC leaves to the server, and refuses anything the provider
could not honour, so that a client never registers with a redirect uri,
grant, response type or scope that every later request would then be
refused for.

The checks run in the order below, and the first failure is the answer:

1. `redirect_uris` - present, non-empty, and every one
   `isRegistrableRedirectUri`. Answers `invalid_redirect_uri`; every
   later refusal answers `invalid_client_metadata`.
2. `software_id`, when the policy requires it.
3. `token_endpoint_auth_method` - defaults to `client_secret_basic`, which
   is the RFC 7591 Section 2 default, and must be one the policy allows.
   Note that the default registers a _confidential_ client: a public client
   has to say `none`, it is never inferred.
4. `response_types` - defaults to `["code"]`.
5. `grant_types` - defaults to `["authorization_code"]`.
6. RFC 7591 Section 2.1 consistency: the `authorization_code` grant and the
   `code` response type each require the other.
7. `client_credentials` for a public client. Machine to machine is a
   confidential flow - a public client has no credentials to exchange - so
   registering for it would only ever earn an `invalid_client` at the token
   endpoint. Refused here, where the answer says which field was wrong.
8. `scope` - defaults to the policy's, and every scope must be supported.

What it does not do is decide _whether_ this client may register at all.
That is the initial access token (RFC 7591 Section 3), checked before this
is ever called.

**Signature**

```ts
declare const validateClientMetadata: (
  request: (typeof ClientMetadataRequestSchema)["Type"],
  policy: RegistrationPolicy
) => Result.Result<ClientMetadata, RegistrationErrorCode>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L347)

Since v1.0.0

# Schema

## ClientInformationResponseSchema

The client information response (RFC 7591 Section 3.2.1): the issued
credentials, followed by the registered metadata as the provider recorded
it, which is not always what the client asked for.

**Signature**

```ts
declare const ClientInformationResponseSchema: Schema.Struct<{
  readonly client_id: Schema.String
  readonly client_secret: Schema.optional<Schema.String>
  readonly client_id_issued_at: Schema.optional<Schema.Number>
  readonly client_secret_expires_at: Schema.optional<Schema.Number>
  readonly redirect_uris: Schema.optional<Schema.$Array<Schema.String>>
  readonly token_endpoint_auth_method: Schema.optional<Schema.String>
  readonly grant_types: Schema.optional<Schema.$Array<Schema.String>>
  readonly response_types: Schema.optional<Schema.$Array<Schema.String>>
  readonly client_name: Schema.optional<Schema.String>
  readonly scope: Schema.optional<Schema.String>
  readonly software_id: Schema.optional<Schema.String>
  readonly software_version: Schema.optional<Schema.String>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L124)

Since v1.0.0

## ClientMetadataRequestSchema

The client metadata of a registration request (RFC 7591 Section 2).

Every field is optional at the wire, as the RFC has it, and every value is
a plain string rather than one of the literal unions above. The defaults
and the refusals belong to `validateClientMetadata` instead, so that
a bad redirect uri and a bad auth method can be told apart in the response:
a schema that rejected them both would answer `invalid_client_metadata` for
a redirect uri the RFC gives its own error code to.

RFC 7591 defines further display and legal metadata - `client_uri`,
`logo_uri`, `contacts`, `tos_uri`, `policy_uri`. They are absent here
because nothing in the registration decision reads them; a provider that
stores them can decode them from the same body alongside this schema.

**Signature**

```ts
declare const ClientMetadataRequestSchema: Schema.Struct<{
  readonly redirect_uris: Schema.optional<Schema.$Array<Schema.String>>
  readonly token_endpoint_auth_method: Schema.optional<Schema.String>
  readonly grant_types: Schema.optional<Schema.$Array<Schema.String>>
  readonly response_types: Schema.optional<Schema.$Array<Schema.String>>
  readonly client_name: Schema.optional<Schema.String>
  readonly scope: Schema.optional<Schema.String>
  readonly software_id: Schema.optional<Schema.String>
  readonly software_version: Schema.optional<Schema.String>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L105)

Since v1.0.0

## GrantTypeSchema

The grants a client may register for.

**Signature**

```ts
declare const GrantTypeSchema: Schema.Literals<readonly ["authorization_code", "refresh_token", "client_credentials"]>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L63)

Since v1.0.0

## RegistrationErrorCodeSchema

The refusals RFC 7591 Section 3.2.2 defines.

`invalid_redirect_uri` is the reason a redirect uri gets its own code: it
is the one piece of metadata that decides where credentials are delivered,
so a client whose registration was refused for it should not have to guess
which of its fields was wrong.

**Signature**

```ts
declare const RegistrationErrorCodeSchema: Schema.Literals<
  readonly [
    "invalid_redirect_uri",
    "invalid_client_metadata",
    "invalid_software_statement",
    "unapproved_software_statement"
  ]
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L156)

Since v1.0.0

## RegistrationErrorResponseSchema

A registration refusal (RFC 7591 Section 3.2.2).

`error` is a plain string rather than `RegistrationErrorCodeSchema`
because this schema also decodes what a foreign provider answered, and a
provider that sends a code outside the four defined ones should surface it
rather than fail to decode and lose the only explanation on offer.

**Signature**

```ts
declare const RegistrationErrorResponseSchema: Schema.Struct<{
  readonly error: Schema.String
  readonly error_description: Schema.optional<Schema.String>
}>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L180)

Since v1.0.0

## ResponseTypeSchema

The response types a client may register for. Only `code`: the implicit
and hybrid flows return tokens through the front channel, which OAuth 2.1
removes and this library never implemented.

**Signature**

```ts
declare const ResponseTypeSchema: Schema.Literals<readonly ["code"]>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L79)

Since v1.0.0

## TokenEndpointAuthMethodSchema

How a client authenticates at the token endpoint (RFC 7591 Section 2).
`none` registers a public client, which proves itself with PKCE and is
issued no secret; the other two register a confidential client and come
back with one.

These are the methods `Oidc.clientAuthentication` can resolve. A provider
that supports fewer narrows them through `RegistrationPolicy`.

**Signature**

```ts
declare const TokenEndpointAuthMethodSchema: Schema.Literals<
  readonly ["none", "client_secret_basic", "client_secret_post"]
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L49)

Since v1.0.0

# Utilities

## scopesOf

Splits a space delimited scope string, dropping empties and duplicates.

RFC 6749 Appendix A.4 delimits with a single space, but a client that pads
or tabs is describing scopes it can be given rather than making a request
that has to be refused.

**Signature**

```ts
declare const scopesOf: (scope: string) => ReadonlyArray<string>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/DynamicClientRegistration.ts#L300)

Since v1.0.0
