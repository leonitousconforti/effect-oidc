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
 * @since 1.0.0
 * @category ResourceServer
 */

import type { HttpClient, HttpClientError } from "effect/unstable/http";
import type { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi";

import { Context, type Duration, Effect, Layer, Option, Redacted, type Schema } from "effect";
import { HttpApiError, HttpApiMiddleware, HttpApiSecurity } from "effect/unstable/httpapi";

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
export const requireScopes = (...scopes: ReadonlyArray<string>) =>
    Effect.flatMap(CurrentUser, (user) => {
        if (!scopes.every((scope) => user.scopes.has(scope))) return Effect.fail(new HttpApiError.Forbidden());
        return Effect.succeed(user);
    });

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
 * Without the annotation an endpoint accepts its derived name
 * (`"<group>:<endpoint>"`) or the bare group identifier (`"<group>"`), so a
 * group scope grants every endpoint in the group while endpoint scopes
 * grant just the one.
 *
 * @since 1.0.0
 * @category Scopes
 */
export class OIDCScopes extends Context.Service<OIDCScopes, ReadonlyArray<string>>()("effect-oidc/Scopes") {}

/** The scopes a token must grant one of to call an endpoint. */
const acceptedScopes = (group: HttpApiGroup.Top, endpoint: HttpApiEndpoint.Top): ReadonlyArray<string> =>
    Context.getOption(endpoint.annotations, OIDCScopes).pipe(
        Option.orElse(() => Context.getOption(group.annotations, OIDCScopes)),
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
