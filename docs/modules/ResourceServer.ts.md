---
title: ResourceServer.ts
nav_order: 9
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

Every credential arrives as `Authorization: Bearer <jwt>` - there is no
cookie transport and no opaque credential. Interactive access tokens
(from public SPAs and confidential clients alike) and long-lived api keys
are all just JWTs minted by the issuer - an api key is nothing more than
a token with a long expiry - and verified statelessly: the issuer's JWKS
is fetched once and cached, so no shared database or network hop is
needed per request.

Revocation is the one optional piece of state: give `layer` a
`revoked` predicate backed by the issuer's RFC 7009 denylist (see
`Oidc.RevocationRequestSchema`) and cache it as aggressively as your
revocation latency allows - without it, tokens are simply valid until
they expire.

Handlers read the caller from `CurrentUser` - the account (`sub`),
its scopes, the OAuth client acting on its behalf, and the verified
claims - and can guard individual endpoints with `requireScopes`.

Scopes are enforced per endpoint without inventing names: by default an
endpoint accepts its derived scope (`"MyGroup:MyEndpoint"`) or the bare
group identifier (`"MyGroup"`), which grants every endpoint in the group.
Annotating an endpoint (or group) with `OIDCScopes` replaces that
default with an explicit list of accepted scopes - empty to require none.

Since v1.0.0

---

## Exports Grouped by Category

- [Layers](#layers)
  - [layer](#layer)
- [Middleware](#middleware)
  - [Authorization (class)](#authorization-class)
  - [requireScopes](#requirescopes)
- [Scopes](#scopes)
  - [OIDCScopes (class)](#oidcscopes-class)
- [Services](#services)
  - [CurrentUser (class)](#currentuser-class)

---

# Layers

## layer

Implements `Authorization`: bearer JWTs are verified against the
issuer's JWKS (fetched lazily and cached for `jwksTtl`, default 10
minutes), the optional `revoked` predicate is consulted, and each
endpoint's accepted scopes (`OIDCScopes` annotation, or the derived
`"<group>:<endpoint>"` / `"<group>"` default) are enforced for every
caller. Requires an `HttpClient` for the JWKS fetch.

**Signature**

```ts
declare const layer: <RRevoked = never>(options: {
  readonly issuer: string
  readonly audience: string
  readonly jwksTtl?: Duration.Input | undefined
  readonly algorithms?: ReadonlyArray<(typeof Jwa.JwsAlgorithm)["Type"]> | undefined
  readonly revoked?:
    | ((claims: Schema.Schema.Type<typeof Oidc.AccessTokenClaimsSchema>) => Effect.Effect<boolean, unknown, RRevoked>)
    | undefined
}) => Layer.Layer<Authorization, never, HttpClient.HttpClient | RRevoked>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L160)

Since v1.0.0

# Middleware

## Authorization (class)

**Signature**

```ts
declare class Authorization
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L85)

Since v1.0.0

## requireScopes

Fails with `Forbidden` unless the current user's token grants every one of
the given scopes.

**Signature**

```ts
declare const requireScopes: (
  ...scopes: ReadonlyArray<string>
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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L104)

Since v1.0.0

# Scopes

## OIDCScopes (class)

Annotation naming the scopes accepted for an endpoint - a token must grant
at least one of them. Annotate an endpoint (or a whole group; the endpoint
annotation wins) to replace the derived default, or with `[]` to require
no scopes at all (a valid token is still required):

```ts
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import { ResourceServer } from "effect-oidc"

const Notes = HttpApiGroup.make("notes")
  // Accepts "notes:listNotes" or "notes" (the derived default)
  .add(HttpApiEndpoint.get("listNotes", "/notes", { success: Schema.String }))
  // Accepts only "admin"
  .add(
    HttpApiEndpoint.delete("purgeNotes", "/notes", { success: Schema.String }).annotate(ResourceServer.OIDCScopes, [
      "admin"
    ])
  )
  .middleware(ResourceServer.Authorization)
```

Without the annotation an endpoint accepts its derived name
(`"<group>:<endpoint>"`) or the bare group identifier (`"<group>"`), so a
group scope grants every endpoint in the group while endpoint scopes
grant just the one.

**Signature**

```ts
declare class OIDCScopes
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L140)

Since v1.0.0

# Services

## CurrentUser (class)

The authenticated caller: the account at the provider (`sub`), the granted
scopes, the OAuth client acting on the account's behalf, and the verified
token claims.

**Signature**

```ts
declare class CurrentUser
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L71)

Since v1.0.0
