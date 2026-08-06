---
title: RelyingParty.ts
nav_order: 8
parent: Modules
---

## RelyingParty.ts overview

The server side of "Sign in with ..." for web apps: an OIDC relying party
that owns the browser-facing half of the authorization code + PKCE flow.
`make` realizes a provider registration into two route handlers'
worth of logic: `beginAuthorization` answers the login route with a
redirect to the provider and drops the short-lived transaction cookies
(state, PKCE verifier, and an optional opaque payload such as a return-to
path), and `completeAuthorization` answers the callback route by
validating the echoed state against those cookies, exchanging the code,
and verifying the id token - handing back the claims for the app to turn
into its own session:

```ts
import { Effect, Layer, Option } from "effect"
import { HttpRouter, HttpServerResponse } from "effect/unstable/http"
import { RelyingParty } from "effect-oidc"

const GoogleSignIn = Effect.gen(function* () {
  const google = yield* RelyingParty.make({
    issuer: "https://accounts.google.com",
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
    clientId: "my-client-id",
    clientSecret: "my-client-secret",
    redirectUri: "https://app.example.com/auth/google/callback",
    scopes: ["openid", "email", "profile"],
    cookies: { prefix: "google_oauth" }
  })

  const login = google
    .beginAuthorization({ payload: "/dashboard" })
    .pipe(Effect.catch(() => Effect.succeed(HttpServerResponse.redirect("/login?error=start_failed"))))

  const callback = google.completeAuthorization.pipe(
    Effect.map(({ claims, payload }) =>
      // Create the local session for claims.sub here, then land the
      // visitor back where they started.
      HttpServerResponse.redirect(Option.getOrElse(payload, () => `/welcome/${claims.sub}`))
    ),
    Effect.catch((error) => Effect.succeed(HttpServerResponse.redirect(`/login?error=${error.reason}`))),
    Effect.flatMap(google.expireTransactionCookies),
    Effect.orDie
  )

  return Layer.mergeAll(
    HttpRouter.add("GET", "/auth/google/login", login),
    HttpRouter.add("GET", "/auth/google/callback", callback)
  )
}).pipe(Layer.unwrap)
```

The module deliberately stops at verified claims: creating the local
account or session, deciding where errors redirect, and setting the
session cookie are the app's business. On both the success and the
failure response, pass the response through `expireTransactionCookies` so
the spent state, verifier, and payload cookies do not outlive the flow.

The endpoints can be pinned statically (as above) or resolved at startup
from `Oidc.fetchDiscovery`. The provider's JWKS is fetched lazily, cached
for `jwksTtl` (default 10 minutes), and the last good key set is served
through fetch failures so a transient blip at the provider does not read
as a failed sign in - see `Oidc.cachedJwks`.

Since v1.0.0

---

## Exports Grouped by Category

- [Constructors](#constructors)
  - [make](#make)
- [Errors](#errors)
  - [CallbackError (class)](#callbackerror-class)
- [Models](#models)
  - [RelyingParty (interface)](#relyingparty-interface)

---

# Constructors

## make

Realizes a provider registration into a `RelyingParty`. The
`HttpClient` is captured up front - both the JWKS cache and the code
exchange use it - so the realized value requires only the incoming
request.

Cookie behavior is adjustable without being escapable: `prefix`
namespaces the three transaction cookies (mandatory when one app talks to
several providers), `name` lets an app-wide cookie policy rewrite the
final names (a `__Host-` prefix, an environment suffix), and `secure`
exists solely for plain-http local development. The cookies are always
`httpOnly`, `sameSite: "lax"`, scoped to `/`, and short-lived (`maxAge`,
default 10 minutes).

**Signature**

```ts
declare const make: (options: {
  readonly issuer: string
  readonly authorizationEndpoint: string
  readonly tokenEndpoint: string
  readonly jwksUri: string
  readonly clientId: string
  readonly clientSecret?: Redacted.Redacted | string | undefined
  readonly redirectUri: string
  readonly scopes: ReadonlyArray<string>
  readonly jwksTtl?: Duration.Input | undefined
  readonly algorithms?: ReadonlyArray<(typeof Jwa.JwsAlgorithm)["Type"]> | undefined
  readonly cookies?:
    | {
        readonly prefix?: string | undefined
        readonly name?: ((name: string) => string) | undefined
        readonly secure?: boolean | undefined
        readonly maxAge?: Duration.Input | undefined
      }
    | undefined
}) => Effect.Effect<RelyingParty, never, HttpClient.HttpClient>
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/RelyingParty.ts#L180)

Since v1.0.0

# Errors

## CallbackError (class)

Raised when the callback leg of the code flow cannot be completed. The
`reason` is deliberately coarse - it names which step failed, never why,
so it is safe to surface in a redirect. `AccessDenied` is the one the
visitor caused (they cancelled at the provider); everything else is a
protocol failure.

**Signature**

```ts
declare class CallbackError
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/RelyingParty.ts#L90)

Since v1.0.0

# Models

## RelyingParty (interface)

A realized relying party - see `make`.

**Signature**

```ts
export interface RelyingParty {
  /**
   * The provider's signing keys: fetched lazily, cached, and served stale
   * through fetch failures once a good set has been seen.
   */
  readonly jwks: Effect.Effect<
    Schema.Schema.Type<typeof Jwt.JwksSchema>,
    HttpClientError.HttpClientError | Schema.SchemaError
  >

  /**
   * Answers the login route: redirects the browser to the provider's
   * authorization endpoint with a fresh state and PKCE challenge, riding
   * the transaction cookies the callback will verify. The optional
   * `payload` is an opaque string carried through the flow - a return-to
   * path, a serialized intent - and handed back by
   * `completeAuthorization`; never put anything secret or trusted in it,
   * it lives in a cookie the browser can rewrite.
   */
  readonly beginAuthorization: (options?: {
    readonly payload?: string | undefined
  }) => Effect.Effect<HttpServerResponse.HttpServerResponse, Cookies.CookiesError | Url.UrlError>

  /**
   * Answers the callback route: validates the provider's redirect against
   * the transaction cookies, exchanges the authorization code (with the
   * PKCE verifier), verifies the id token, and returns the claims - the
   * `sub` inside is the stable account id to key local users on -
   * together with the raw token response and the payload that
   * `beginAuthorization` carried. The response the app builds from this,
   * failure or success, should pass through `expireTransactionCookies`.
   */
  readonly completeAuthorization: Effect.Effect<
    {
      readonly claims: Schema.Schema.Type<typeof Oidc.IdTokenClaimsSchema>
      readonly tokens: Schema.Schema.Type<typeof Oidc.TokenResponseSchema>
      readonly payload: Option.Option<string>
    },
    CallbackError,
    HttpServerRequest.HttpServerRequest | HttpServerRequest.ParsedSearchParams
  >

  /**
   * The payload cookie riding the current request, if any - readable on
   * its own so error handling can recover the payload even when
   * `completeAuthorization` failed before returning it.
   */
  readonly payload: Effect.Effect<Option.Option<string>, never, HttpServerRequest.HttpServerRequest>

  /** Expires the spent state, verifier, and payload cookies on a response. */
  readonly expireTransactionCookies: (
    response: HttpServerResponse.HttpServerResponse
  ) => Effect.Effect<HttpServerResponse.HttpServerResponse, Cookies.CookiesError>
}
```

[Source](https://github.com/leonitousconforti/effect-oidc/blob/main/src/RelyingParty.ts#L108)

Since v1.0.0
