/**
 * Drop-in bearer authentication for `HttpApi` services. Any service becomes
 * a resource server of an OIDC provider by adding the {@link Authorization}
 * middleware to its api groups and providing {@link layer} with the issuer
 * and its audience:
 *
 * ```ts
 * import { Schema } from "effect"
 * import { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
 * import { ResourceServer } from "effect-oidc"
 *
 * const MyEndpoint = HttpApiEndpoint.get("MyEndpoint", "/me", { success: Schema.String })
 *
 * const MyGroup = HttpApiGroup.make("MyGroup")
 *     .add(MyEndpoint)
 *     .middleware(ResourceServer.Authorization)
 *
 * const AuthorizationLive = ResourceServer.layer({
 *     issuer: "https://id.example.com",
 *     audience: "my-api",
 * })
 * ```
 *
 * Every credential arrives as `Authorization: Bearer <jwt>` - there is no
 * cookie transport and no opaque credential. Interactive access tokens
 * (from public SPAs and confidential clients alike) and long-lived api keys
 * are all just JWTs minted by the issuer - an api key is nothing more than
 * a token with a long expiry - and verified statelessly: the issuer's JWKS
 * is fetched lazily and cached, or handed to {@link layer} as `jwks` when
 * the keys are already at hand, so no shared database or network hop is
 * needed per request.
 *
 * Revocation is the one optional piece of state: give {@link layer} a
 * `revoked` predicate backed by the issuer's RFC 7009 denylist (see
 * `Oidc.RevocationRequestSchema`) and cache it as aggressively as your
 * revocation latency allows - without it, tokens are simply valid until
 * they expire.
 *
 * Handlers read the caller from {@link CurrentUser} - the account (`sub`),
 * its scopes, the OAuth client acting on its behalf, and the verified
 * claims - and can guard individual endpoints with {@link requireScopes}.
 *
 * Scopes are enforced per endpoint without inventing names: by default an
 * endpoint accepts its derived scope (`"MyGroup:MyEndpoint"`) or the bare
 * group identifier (`"MyGroup"`), which grants every endpoint in the group.
 * Annotating an endpoint (or group) with {@link OIDCScopes} replaces that
 * default with an explicit list of accepted scopes - empty to require none.
 *
 * A scope in that list may be a bare name or a {@link ScopeDescription}, which
 * carries the sentence a consent screen shows for it. {@link scopeCatalog}
 * reads those back off an api, so the screen asking for a scope and the
 * endpoint enforcing it are the same declaration rather than two copies that
 * drift apart.
 *
 * @since 1.0.0
 * @category ResourceServer
 */

import type { HttpClient, HttpClientError } from "effect/unstable/http";
import type { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi";

import { Context, type Duration, Effect, Layer, Option, Redacted, type Schema } from "effect";
import { HttpApi, HttpApiError, HttpApiMiddleware, HttpApiSecurity } from "effect/unstable/httpapi";

import type * as Jwa from "./Jwa.ts";

import * as Jwt from "./Jwt.ts";
import * as Oidc from "./Oidc.ts";

/**
 * The authenticated caller: the account at the provider (`sub`), the granted
 * scopes, the OAuth client acting on the account's behalf, and the verified
 * token claims.
 *
 * @since 1.0.0
 * @category Services
 */
export class CurrentUser extends Context.Service<
    CurrentUser,
    {
        readonly sub: string;
        readonly scopes: ReadonlySet<string>;
        readonly clientId: string;
        readonly claims: Schema.Schema.Type<typeof Oidc.AccessTokenClaimsSchema>;
    }
>()("effect-oidc/CurrentUser") {}

/**
 * @since 1.0.0
 * @category Middleware
 */
export class Authorization extends HttpApiMiddleware.Service<
    Authorization,
    {
        provides: CurrentUser;
    }
>()("effect-oidc/Authorization", {
    error: [HttpApiError.Unauthorized, HttpApiError.Forbidden, HttpApiError.InternalServerError],
    security: {
        bearer: HttpApiSecurity.bearer,
    },
}) {}

/**
 * Fails with `Forbidden` unless the current user's token grants every one of
 * the given scopes.
 *
 * @since 1.0.0
 * @category Middleware
 */
export const requireScopes = (...scopes: ReadonlyArray<Scope>) =>
    Effect.flatMap(CurrentUser, (user) => {
        if (!scopes.every((scope) => user.scopes.has(scopeName(scope)))) {
            return Effect.fail(new HttpApiError.Forbidden());
        }
        return Effect.succeed(user);
    });

/**
 * A scope, and the sentence shown to whoever is deciding whether to grant it.
 *
 * The description belongs here, on the endpoint the scope guards, rather than
 * in a catalog kept beside it: the two would drift, and the copy that drifts
 * is the one a person reads before consenting. See {@link scopeCatalog}.
 *
 * One string, in one language. A service that shows its scopes in several
 * should put a message key here and resolve it per request, the way it
 * already resolves every other string it shows.
 *
 * @since 1.0.0
 * @category Scopes
 */
export interface ScopeDescription {
    /** What appears in a token's `scope` claim. */
    readonly name: string;
    /** What a consent screen or a dashboard shows for it. */
    readonly description: string;
}

/**
 * A scope as an endpoint names it: bare, or carrying its description.
 *
 * Both grant the same thing - {@link scopeName} is what enforcement reads, and
 * it is the same either way. A description only adds the words for it, so
 * annotations written before descriptions existed keep working untouched.
 *
 * @since 1.0.0
 * @category Scopes
 */
export type Scope = string | ScopeDescription;

/**
 * Annotation naming the scopes accepted for an endpoint - a token must grant
 * at least one of them. Annotate an endpoint (or a whole group; the endpoint
 * annotation wins) to replace the derived default, or with `[]` to require
 * no scopes at all (a valid token is still required):
 *
 * ```ts
 * import { Schema } from "effect"
 * import { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
 * import { ResourceServer } from "effect-oidc"
 *
 * const Notes = HttpApiGroup.make("notes")
 *     // Accepts "notes:listNotes" or "notes" (the derived default)
 *     .add(HttpApiEndpoint.get("listNotes", "/notes", { success: Schema.String }))
 *     // Accepts only "admin"
 *     .add(
 *         HttpApiEndpoint.delete("purgeNotes", "/notes", { success: Schema.String })
 *             .annotate(ResourceServer.OIDCScopes, ["admin"])
 *     )
 *     .middleware(ResourceServer.Authorization)
 * ```
 *
 * A scope may carry the sentence a consent screen shows for it, which
 * {@link scopeCatalog} then reads back off the api. Name it once and share the
 * constant, so that the endpoint enforcing a scope and the screen asking for
 * it cannot disagree about what it means:
 *
 * ```ts
 * import { Schema } from "effect"
 * import { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
 * import { ResourceServer } from "effect-oidc"
 *
 * const PullSave = { name: "sync:pull", description: "Download a tower's current save data" } as const
 *
 * const Sync = HttpApiGroup.make("sync")
 *     .add(
 *         HttpApiEndpoint.get("pullSave", "/sync/pull", { success: Schema.String })
 *             .annotate(ResourceServer.OIDCScopes, [PullSave])
 *     )
 *     .middleware(ResourceServer.Authorization)
 * ```
 *
 * Without the annotation an endpoint accepts its derived name
 * (`"<group>:<endpoint>"`) or the bare group identifier (`"<group>"`), so a
 * group scope grants every endpoint in the group while endpoint scopes
 * grant just the one.
 *
 * @since 1.0.0
 * @category Scopes
 */
export class OIDCScopes extends Context.Service<OIDCScopes, ReadonlyArray<Scope>>()("effect-oidc/Scopes") {}

/**
 * The name a scope is granted under, whichever form it was written in. This
 * is what appears in a token's `scope` claim either way; a description is
 * for people, and never travels on the wire.
 *
 * @since 1.0.0
 * @category Scopes
 */
export const scopeName = (scope: Scope): string => (typeof scope === "string" ? scope : scope.name);

/**
 * Every described scope an api declares, in declaration order: groups as
 * they were added, and within each group its own annotation before its
 * endpoints'.
 *
 * This is the catalog a consent screen lists and a dashboard offers, read off
 * the endpoints that enforce the scopes rather than kept beside them. A copy
 * kept beside them is a copy that goes stale: it can name a scope no endpoint
 * accepts, or miss one every endpoint does.
 *
 * Only described scopes are in it. A bare string names a scope without saying
 * what it lets someone do, and an interface that guessed a sentence for it
 * would be putting words in front of a person deciding what to grant. The
 * derived `"<group>:<endpoint>"` defaults are absent for the same reason.
 *
 * A scope named on several endpoints is listed once, described the first way
 * it was described - so a second, differing description for the same name is
 * silently the loser. Name each scope once and share the constant.
 *
 * Reads the same annotations enforcement reads: each group's own and each
 * endpoint's own. An annotation on the api itself is not one of them, because
 * it is not one the middleware would accept a token against either.
 *
 * @since 1.0.0
 * @category Scopes
 */
export const scopeCatalog = <Id extends string, Groups extends HttpApiGroup.Constraint>(
    api: HttpApi.HttpApi<Id, Groups>
): ReadonlyArray<ScopeDescription> => {
    const described = new Map<string, string>();

    const collect = (annotations: Context.Context<never>): void => {
        for (const scope of Option.getOrElse(Context.getOption(annotations, OIDCScopes), () => [])) {
            if (typeof scope === "string" || described.has(scope.name)) continue;
            described.set(scope.name, scope.description);
        }
    };

    // `reflect` walks groups in the order they were added and, within each,
    // the group before its endpoints - and it takes a concrete api, which
    // `HttpApi.Top` would not: the phantom request members make a concrete
    // api no subtype of it.
    HttpApi.reflect(api, {
        onGroup: ({ group }) => collect(group.annotations),
        onEndpoint: ({ endpoint }) => collect(endpoint.annotations),
    });

    return Array.from(described, ([name, description]) => ({ name, description }));
};

/** The scopes a token must grant one of to call an endpoint. */
const acceptedScopes = (group: HttpApiGroup.Top, endpoint: HttpApiEndpoint.Top): ReadonlyArray<string> =>
    Context.getOption(endpoint.annotations, OIDCScopes).pipe(
        Option.orElse(() => Context.getOption(group.annotations, OIDCScopes)),
        Option.map((scopes) => scopes.map(scopeName)),
        Option.getOrElse(() => [`${group.identifier}:${endpoint.identifier}`, group.identifier])
    );

/**
 * Implements {@link Authorization}: bearer JWTs are verified against the
 * issuer's JWKS (provided statically as `jwks`, or fetched lazily and
 * cached for `jwksTtl`, default 10 minutes), the optional `revoked`
 * predicate is consulted, and each endpoint's accepted scopes
 * ({@link OIDCScopes} annotation, or the derived `"<group>:<endpoint>"` /
 * `"<group>"` default) are enforced for every caller. Requires an
 * `HttpClient` for the JWKS fetch.
 *
 * @since 1.0.0
 * @category Layers
 */
export const layer = <ERevoked = never, RRevoked = never>(options: {
    readonly issuer: string;
    readonly audience: string;
    /**
     * The issuer's JWKS, provided statically instead of fetched. For a
     * resource server living in the same process as its provider, or keys
     * distributed out of band, this removes the network dependency on the
     * issuer entirely; `jwksUri` and `jwksTtl` are then ignored.
     */
    readonly jwks?: Schema.Schema.Type<typeof Jwt.JwksSchema> | undefined;
    /**
     * Where to fetch the JWKS. Defaults to `<issuer>/.well-known/jwks.json`,
     * the path this library's provider serves; third-party issuers publish
     * theirs as `jwks_uri` in the discovery document - pass that instead.
     */
    readonly jwksUri?: string | undefined;
    readonly jwksTtl?: Duration.Input | undefined;
    /**
     * Accepted signing algorithms (defaults to `["ES256"]`). Pinning the
     * algorithm is defense-in-depth against downgrade / key-confusion.
     */
    readonly algorithms?: ReadonlyArray<(typeof Jwa.JwsAlgorithm)["Type"]> | undefined;
    /**
     * Accepted `typ` header values (defaults to `["at+jwt"]`, RFC 9068). A
     * token must carry one of them, which keeps the issuer's other JWTs (id
     * tokens, with `typ: "JWT"`) from being presented as access tokens.
     * Pass the values your issuer actually mints if it predates RFC 9068.
     */
    readonly types?: ReadonlyArray<string> | undefined;
    /**
     * Decides whether a verified token has been revoked - the stateful
     * complement to the issuer's RFC 7009 revocation endpoint, typically a
     * denylist of revoked `jti` claims kept until each token's `exp`.
     * Checked after signature verification; `true` answers
     * `401 Unauthorized` and predicate failures answer `500 Internal Server
     * Error`. Cache the underlying denylist as aggressively as your
     * revocation latency allows. Without this option tokens stay valid
     * until they expire.
     *
     * The predicate's own error type is inferred rather than fixed, so a
     * denylist backed by a database keeps its `SqlError` instead of having it
     * widened away. Every failure is still answered as
     * `500 Internal Server Error`; the type is for the caller's benefit, not
     * this layer's.
     */
    readonly revoked?:
        | ((
              claims: Schema.Schema.Type<typeof Oidc.AccessTokenClaimsSchema>
          ) => Effect.Effect<boolean, ERevoked, RRevoked>)
        | undefined;
}): Layer.Layer<Authorization, never, HttpClient.HttpClient | RRevoked> =>
    Layer.effect(
        Authorization,
        Effect.gen(function* () {
            const services = yield* Effect.context<HttpClient.HttpClient | RRevoked>();
            const jwksUri = options.jwksUri ?? Oidc.issuerUrl(options.issuer, "/.well-known/jwks.json");
            const algorithms = options.algorithms ?? ["ES256"];
            const types = options.types ?? ["at+jwt"];

            // Static keys skip the fetch entirely. Otherwise Oidc.jwksCache
            // reuses a fetched document for the TTL, serves the previous
            // (stale) keys when a refresh fails, and evicts a failure with
            // nothing to fall back on right away - a transient blip must not
            // become a fleet-wide auth outage lasting the whole TTL. The very
            // first fetch still fails closed.
            type JwksEffect = Effect.Effect<
                Schema.Schema.Type<typeof Jwt.JwksSchema>,
                Schema.SchemaError | HttpClientError.HttpClientError
            >;
            const jwksSource: { readonly get: JwksEffect; readonly refresh: JwksEffect } =
                options.jwks !== undefined
                    ? { get: Effect.succeed(options.jwks), refresh: Effect.succeed(options.jwks) }
                    : yield* Oidc.jwksCache(jwksUri, { ttl: options.jwksTtl }).pipe(
                          Effect.map((cache) => ({
                              get: Effect.provideContext(cache.get, services),
                              refresh: Effect.provideContext(cache.refresh, services),
                          }))
                      );

            const verify = (token: string, jwks: Schema.Schema.Type<typeof Jwt.JwksSchema>) =>
                Jwt.verify(token, { jwks, issuer: options.issuer, audience: options.audience, algorithms, types });

            return {
                bearer: Effect.fnUntraced(function* (next, { credential, endpoint, group }) {
                    if (Redacted.value(credential) === "") return yield* new HttpApiError.Unauthorized();

                    const token = Redacted.value(credential);
                    const jwks = yield* jwksSource.get.pipe(Effect.catch(() => new HttpApiError.InternalServerError()));

                    // A token naming a key the cached set lacks is most likely
                    // signed by a freshly rotated key: refetch (rate limited by
                    // the cache) and try once more before refusing it.
                    const claims = yield* verify(token, jwks).pipe(
                        Effect.catch((error) =>
                            error.reason === "UnknownKey"
                                ? jwksSource.refresh.pipe(Effect.flatMap((fresh) => verify(token, fresh)))
                                : Effect.fail(error)
                        ),
                        Effect.catch(() => new HttpApiError.Unauthorized())
                    );

                    const accessClaims = yield* Jwt.decodeClaims(Oidc.AccessTokenClaimsSchema)(claims).pipe(
                        Effect.catch(() => new HttpApiError.Unauthorized())
                    );

                    if (options.revoked !== undefined) {
                        // Whatever the predicate fails with, the caller learns
                        // nothing from it: a revocation check that cannot answer
                        // is a server problem, not a client one.
                        const revoked = yield* options.revoked(accessClaims).pipe(
                            Effect.provideContext(services),
                            Effect.catch(() => new HttpApiError.InternalServerError())
                        );
                        if (revoked) return yield* new HttpApiError.Unauthorized();
                    }

                    const scopes = new Set(accessClaims.scope.split(" "));
                    const accepted = acceptedScopes(group, endpoint);
                    if (accepted.length > 0 && !accepted.some((scope) => scopes.has(scope))) {
                        return yield* new HttpApiError.Forbidden();
                    }

                    return yield* Effect.provideService(next, CurrentUser, {
                        sub: accessClaims.sub,
                        scopes,
                        clientId: accessClaims.client_id,
                        claims: accessClaims,
                    });
                }),
            };
        })
    );
