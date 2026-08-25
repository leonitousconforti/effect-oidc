---
title: ResourceServer.ts
nav_order: 10
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
is fetched lazily and cached, or handed to `layer` as `jwks` when
the keys are already at hand, so no shared database or network hop is
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

A scope in that list may be a bare name or a `ScopeDescription`, which
carries the sentence a consent screen shows for it. `scopeCatalog`
reads those back off an api, so the screen asking for a scope and the
endpoint enforcing it are the same declaration rather than two copies that
drift apart.

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
  - [Scope (type alias)](#scope-type-alias)
  - [ScopeDescription (interface)](#scopedescription-interface)
  - [scopeCatalog](#scopecatalog)
  - [scopeName](#scopename)
- [Services](#services)
  - [CurrentUser (class)](#currentuser-class)

---

# Layers

## layer

Implements `Authorization`: bearer JWTs are verified against the
issuer's JWKS (provided statically as `jwks`, or fetched lazily and
cached for `jwksTtl`, default 10 minutes), the optional `revoked`
predicate is consulted, and each endpoint's accepted scopes
(`OIDCScopes` annotation, or the derived `"<group>:<endpoint>"` /
`"<group>"` default) are enforced for every caller. Requires an
`HttpClient` for the JWKS fetch.

**Signature**

```ts
declare const layer: <ERevoked = never, RRevoked = never>(options: {
  readonly issuer: string
  readonly audience: string
  readonly jwks?: Schema.Schema.Type<typeof Jwt.JwksSchema> | undefined
  readonly jwksUri?: string | undefined
  readonly jwksTtl?: Duration.Input | undefined
  readonly algorithms?: ReadonlyArray<(typeof Jwa.JwsAlgorithm)["Type"]> | undefined
  readonly types?: ReadonlyArray<string> | undefined
  readonly revoked?:
    | ((claims: Schema.Schema.Type<typeof Oidc.AccessTokenClaimsSchema>) => Effect.Effect<boolean, ERevoked, RRevoked>)
    | undefined
}) => Layer.Layer<Authorization, never, HttpClient.HttpClient | RRevoked>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L284)

Since v1.0.0

# Middleware

## Authorization (class)

**Signature**

```ts
declare class Authorization
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L92)

Since v1.0.0

## requireScopes

Fails with `Forbidden` unless the current user's token grants every one of
the given scopes.

**Signature**

```ts
declare const requireScopes: (
  ...scopes: ReadonlyArray<Scope>
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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L111)

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

A scope may carry the sentence a consent screen shows for it, which
`scopeCatalog` then reads back off the api. Name it once and share the
constant, so that the endpoint enforcing a scope and the screen asking for
it cannot disagree about what it means:

```ts
import { Schema } from "effect"
import { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
import { ResourceServer } from "effect-oidc"

const PullSave = { name: "sync:pull", description: "Download a tower's current save data" } as const

const Sync = HttpApiGroup.make("sync")
  .add(
    HttpApiEndpoint.get("pullSave", "/sync/pull", { success: Schema.String }).annotate(ResourceServer.OIDCScopes, [
      PullSave
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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L202)

Since v1.0.0

## Scope (type alias)

A scope as an endpoint names it: bare, or carrying its description.

Both grant the same thing - `scopeName` is what enforcement reads, and
it is the same either way. A description only adds the words for it, so
annotations written before descriptions existed keep working untouched.

**Signature**

```ts
type Scope = string | ScopeDescription
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L150)

Since v1.0.0

## ScopeDescription (interface)

A scope, and the sentence shown to whoever is deciding whether to grant it.

The description belongs here, on the endpoint the scope guards, rather than
in a catalog kept beside it: the two would drift, and the copy that drifts
is the one a person reads before consenting. See `scopeCatalog`.

One string, in one language. A service that shows its scopes in several
should put a message key here and resolve it per request, the way it
already resolves every other string it shows.

**Signature**

```ts
export interface ScopeDescription {
  /** What appears in a token's `scope` claim. */
  readonly name: string
  /** What a consent screen or a dashboard shows for it. */
  readonly description: string
}
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L133)

Since v1.0.0

## scopeCatalog

Every described scope an api declares, in declaration order: groups as
they were added, and within each group its own annotation before its
endpoints'.

This is the catalog a consent screen lists and a dashboard offers, read off
the endpoints that enforce the scopes rather than kept beside them. A copy
kept beside them is a copy that goes stale: it can name a scope no endpoint
accepts, or miss one every endpoint does.

Only described scopes are in it. A bare string names a scope without saying
what it lets someone do, and an interface that guessed a sentence for it
would be putting words in front of a person deciding what to grant. The
derived `"<group>:<endpoint>"` defaults are absent for the same reason.

A scope named on several endpoints is listed once, described the first way
it was described - so a second, differing description for the same name is
silently the loser. Name each scope once and share the constant.

Reads the same annotations enforcement reads: each group's own and each
endpoint's own. An annotation on the api itself is not one of them, because
it is not one the middleware would accept a token against either.

**Signature**

```ts
declare const scopeCatalog: <Id extends string, Groups extends HttpApiGroup.Constraint>(
  api: HttpApi.HttpApi<Id, Groups>
) => ReadonlyArray<ScopeDescription>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L240)

Since v1.0.0

## scopeName

The name a scope is granted under, whichever form it was written in. This
is what appears in a token's `scope` claim either way; a description is
for people, and never travels on the wire.

**Signature**

```ts
declare const scopeName: (scope: Scope) => string
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L212)

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

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/ResourceServer.ts#L78)

Since v1.0.0
