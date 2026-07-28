---
title: ResourceServer.ts
nav_order: 8
parent: Modules
---

## ResourceServer.ts overview

Drop-in bearer authentication for `HttpApi` services. Any service becomes
a resource server of an OIDC provider by adding the `Authorization`
middleware to its api groups and providing `layer` with the issuer
and its audience:

```ts
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import { ResourceServer } from "effect-oidc"

const MyEndpoint = HttpApiEndpoint.get("MyEndpoint", "/me", { success: Schema.String })

const MyGroup = HttpApiGroup.make("MyGroup").add(MyEndpoint).middleware(ResourceServer.Authorization)

const AuthorizationLive = ResourceServer.layer({
  issuer: "https://id.example.com",
  audience: "my-api"
})
```

Tokens are verified statelessly: the issuer's JWKS is fetched once and
cached, so no shared database or network hop is needed per request.
Handlers read the caller from `CurrentUser` and can guard individual
endpoints with `requireScopes`.

Since v1.0.0

---

## Exports Grouped by Category

- [Layers](#layers)
  - [layer](#layer)
- [Middleware](#middleware)
  - [Authorization (class)](#authorization-class)
  - [requireScopes](#requirescopes)
- [Services](#services)
  - [CurrentUser (class)](#currentuser-class)

---

# Layers

## layer

Implements `Authorization` by verifying bearer JWTs against the
issuer's JWKS (fetched lazily and cached for `jwksTtl`, default 10
minutes). Requires an `HttpClient` for the JWKS fetch.

**Signature**

```ts
declare const layer: (options: {
  readonly issuer: string
  readonly audience: string
  readonly jwksTtl?: Duration.Input | undefined
  readonly algorithms?: ReadonlyArray<(typeof Jwa.JwsAlgorithm)["Type"]> | undefined
}) => Layer.Layer<Authorization, never, HttpClient.HttpClient>
```

[Source](https://github.com/leonitousconforti/effect-oidc/tree/main/src/ResourceServer.ts#L97)

Since v1.0.0

# Middleware

## Authorization (class)

**Signature**

```ts
declare class Authorization
```

[Source](https://github.com/leonitousconforti/effect-oidc/tree/main/src/ResourceServer.ts#L64)

Since v1.0.0

## requireScopes

Fails with `Forbidden` unless the current user's token grants every one of
the given scopes.

**Signature**

```ts
declare const requireScopes: (
  ...args: Array<any>
) => Effect.Effect<
  {
    readonly sub: string
    readonly scopes: ReadonlySet<string>
    readonly clientId: string
    readonly claims: Schema.Schema.Type<typeof Oidc.AccessTokenClaimsSchema>
  },
  HttpApiError.Forbidden,
  CurrentUser
>
```

[Source](https://github.com/leonitousconforti/effect-oidc/tree/main/src/ResourceServer.ts#L83)

Since v1.0.0

# Services

## CurrentUser (class)

The authenticated caller: the account at the provider (`sub`), the granted
scopes, and the OAuth client acting on the account's behalf.

**Signature**

```ts
declare class CurrentUser
```

[Source](https://github.com/leonitousconforti/effect-oidc/tree/main/src/ResourceServer.ts#L50)

Since v1.0.0
