---
title: index.ts
nav_order: 2
parent: Modules
---

## index.ts overview

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

- [DynamicClientRegistration](#dynamicclientregistration)
  - [DynamicClientRegistration (namespace export)](#dynamicclientregistration-namespace-export)
- [Jwt](#jwt)
  - [Jwt (namespace export)](#jwt-namespace-export)
- [Oidc](#oidc)
  - [Oidc (namespace export)](#oidc-namespace-export)
- [RelyingParty](#relyingparty)
  - [RelyingParty (namespace export)](#relyingparty-namespace-export)
- [ResourceServer](#resourceserver)
  - [ResourceServer (namespace export)](#resourceserver-namespace-export)
- [utils](#utils)
  - [Jwa (namespace export)](#jwa-namespace-export)
  - [Jwe (namespace export)](#jwe-namespace-export)
  - [Jwk (namespace export)](#jwk-namespace-export)
  - [Jws (namespace export)](#jws-namespace-export)

---

# DynamicClientRegistration

## DynamicClientRegistration (namespace export)

Re-exports all named exports from the "./DynamicClientRegistration.ts" module as `DynamicClientRegistration`.

**See**

- https://www.rfc-editor.org/rfc/rfc7591 - OAuth 2.0 Dynamic Client Registration Protocol

**Signature**

```ts
export * as DynamicClientRegistration from "./DynamicClientRegistration.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L35)

Since v1.0.0

# Jwt

## Jwt (namespace export)

Re-exports all named exports from the "./Jwt.ts" module as `Jwt`.

**See**

- https://www.rfc-editor.org/rfc/rfc7519 - JSON Web Token (JWT)

**Signature**

```ts
export * as Jwt from "./Jwt.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L137)

Since v1.0.0

# Oidc

## Oidc (namespace export)

Re-exports all named exports from the "./Oidc.ts" module as `Oidc`.

**Signature**

```ts
export * as Oidc from "./Oidc.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L159)

Since v1.0.0

# RelyingParty

## RelyingParty (namespace export)

Re-exports all named exports from the "./RelyingParty.ts" module as `RelyingParty`.

**Signature**

```ts
export * as RelyingParty from "./RelyingParty.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L232)

Since v1.0.0

# ResourceServer

## ResourceServer (namespace export)

Re-exports all named exports from the "./ResourceServer.ts" module as `ResourceServer`.

**Signature**

```ts
export * as ResourceServer from "./ResourceServer.ts"
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L291)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L56)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L82)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L100)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/index.ts#L122)

Since v1.0.0
