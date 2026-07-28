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
 * Tokens are verified statelessly: the issuer's JWKS is fetched once and
 * cached, so no shared database or network hop is needed per request.
 * Handlers read the caller from {@link CurrentUser} and can guard individual
 * endpoints with {@link requireScopes}.
 *
 * @since 1.0.0
 * @category ResourceServer
 */

import type { HttpClient } from "effect/unstable/http";

import { Context, Duration, Effect, Layer, Option, Redacted, Ref, Schema } from "effect";
import { HttpApiError, HttpApiMiddleware, HttpApiSecurity } from "effect/unstable/httpapi";

import type * as Jwa from "./Jwa.ts";

import * as Jwt from "./Jwt.ts";
import * as Oidc from "./Oidc.ts";

/**
 * The authenticated caller: the account at the provider (`sub`), the granted
 * scopes, and the OAuth client acting on the account's behalf.
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
export const requireScopes = Effect.fnUntraced(function* (...scopes: ReadonlyArray<string>) {
    const user = yield* CurrentUser;
    if (!scopes.every((scope) => user.scopes.has(scope))) return yield* new HttpApiError.Forbidden();
    return user;
});

/**
 * Implements {@link Authorization} by verifying bearer JWTs against the
 * issuer's JWKS (fetched lazily and cached for `jwksTtl`, default 10
 * minutes). Requires an `HttpClient` for the JWKS fetch.
 *
 * @since 1.0.0
 * @category Layers
 */
export const layer = (options: {
    readonly issuer: string;
    readonly audience: string;
    readonly jwksTtl?: Duration.Input | undefined;
    /**
     * Accepted signing algorithms (defaults to `["ES256"]`). Pinning the
     * algorithm is defence-in-depth against downgrade / key-confusion.
     */
    readonly algorithms?: ReadonlyArray<(typeof Jwa.JwsAlgorithm)["Type"]> | undefined;
}): Layer.Layer<Authorization, never, HttpClient.HttpClient> =>
    Layer.effect(
        Authorization,
        Effect.gen(function* () {
            const httpContext = yield* Effect.context<HttpClient.HttpClient>();
            const jwksUri = new URL("/.well-known/jwks.json", options.issuer).toString();
            const algorithms = options.algorithms ?? ["ES256"];

            // Cache the last successfully fetched JWKS. On a fetch failure we
            // serve the previous (stale) keys rather than failing every request
            // for the whole TTL - a transient blip must not become a
            // fleet-wide auth outage. The very first fetch still fails closed.
            const lastGood = yield* Ref.make<Option.Option<Schema.Schema.Type<typeof Jwt.JwksSchema>>>(Option.none());
            const cachedJwks = yield* Effect.cachedWithTTL(
                Oidc.fetchJwks(jwksUri).pipe(
                    Effect.provideContext(httpContext),
                    Effect.tap((jwks) => Ref.set(lastGood, Option.some(jwks))),
                    Effect.catch((error) =>
                        Ref.get(lastGood).pipe(
                            Effect.flatMap(Option.match({ onNone: () => Effect.fail(error), onSome: Effect.succeed }))
                        )
                    )
                ),
                options.jwksTtl ?? Duration.minutes(10)
            );

            return {
                bearer: Effect.fnUntraced(function* (next, { credential }) {
                    const jwks = yield* cachedJwks.pipe(Effect.catch(() => new HttpApiError.InternalServerError()));

                    const claims = yield* Jwt.verify(Redacted.value(credential), {
                        jwks,
                        issuer: options.issuer,
                        audience: options.audience,
                        algorithms,
                    }).pipe(Effect.catch(() => new HttpApiError.Unauthorized()));

                    const accessClaims = yield* Schema.decodeUnknownEffect(Oidc.AccessTokenClaimsSchema)(claims).pipe(
                        Effect.catch(() => new HttpApiError.Unauthorized())
                    );

                    return yield* Effect.provideService(next, CurrentUser, {
                        sub: accessClaims.sub,
                        scopes: new Set(accessClaims.scope.split(" ")),
                        clientId: accessClaims.client_id,
                        claims: accessClaims,
                    });
                }),
            };
        })
    );
