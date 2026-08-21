/**
 * The server side of "Sign in with ..." for web apps: an OIDC relying party
 * that owns the browser-facing half of the authorization code + PKCE flow.
 * {@link make} realizes a provider registration into two route handlers'
 * worth of logic: `beginAuthorization` answers the login route with a
 * redirect to the provider and drops the short-lived transaction cookies
 * (state, PKCE verifier, id token nonce, and an optional opaque payload such
 * as a return-to path), and `completeAuthorization` answers the callback
 * route by validating the echoed state against those cookies, exchanging the
 * code, and verifying the id token (including its nonce) - handing back the
 * claims for the app to turn into its own session:
 *
 * ```ts
 * import { Effect, Layer, Option } from "effect"
 * import { HttpRouter, HttpServerResponse } from "effect/unstable/http"
 * import { RelyingParty } from "effect-oidc"
 *
 * const GoogleSignIn = Effect.gen(function* () {
 *     const google = yield* RelyingParty.make({
 *         issuer: "https://accounts.google.com",
 *         authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
 *         tokenEndpoint: "https://oauth2.googleapis.com/token",
 *         jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
 *         clientId: "my-client-id",
 *         clientSecret: "my-client-secret",
 *         redirectUri: "https://app.example.com/auth/google/callback",
 *         scopes: ["openid", "email", "profile"],
 *         cookies: { prefix: "google_oauth" },
 *     })
 *
 *     const login = google
 *         .beginAuthorization({ payload: "/dashboard" })
 *         .pipe(Effect.catch(() => Effect.succeed(HttpServerResponse.redirect("/login?error=start_failed"))))
 *
 *     // The payload rides a cookie the browser can rewrite: only ever follow
 *     // it to a local path, never to an absolute or protocol-relative URL.
 *     const localPath = (payload: string) => (payload.startsWith("/") && !payload.startsWith("//") ? payload : "/")
 *
 *     const callback = google.completeAuthorization.pipe(
 *         Effect.map(({ claims, payload }) =>
 *             // Create the local session for claims.sub here, then land the
 *             // visitor back where they started.
 *             HttpServerResponse.redirect(Option.match(payload, { onNone: () => `/welcome/${claims.sub}`, onSome: localPath }))
 *         ),
 *         Effect.catch((error) => Effect.succeed(HttpServerResponse.redirect(`/login?error=${error.reason}`))),
 *         Effect.flatMap(google.expireTransactionCookies),
 *         Effect.orDie
 *     )
 *
 *     return Layer.mergeAll(
 *         HttpRouter.add("GET", "/auth/google/login", login),
 *         HttpRouter.add("GET", "/auth/google/callback", callback)
 *     )
 * }).pipe(Layer.unwrap)
 * ```
 *
 * The module deliberately stops at verified claims: creating the local
 * account or session, deciding where errors redirect, and setting the
 * session cookie are the app's business. On both the success and the
 * failure response, pass the response through `expireTransactionCookies` so
 * the spent state, verifier, and payload cookies do not outlive the flow.
 *
 * The endpoints can be pinned statically (as above) or resolved at startup
 * from `Oidc.fetchDiscovery`. The provider's JWKS is fetched lazily, cached
 * for `jwksTtl` (default 10 minutes), and the last good key set is served
 * through fetch failures so a transient blip at the provider does not read
 * as a failed sign in - see `Oidc.cachedJwks`.
 *
 * @since 1.0.0
 * @category RelyingParty
 */

import type { Duration } from "effect";
import type { Cookies, HttpClientError } from "effect/unstable/http";

import { Effect, Encoding, Option, Redacted, Schema } from "effect";
import { HttpClient, HttpServerRequest, HttpServerResponse, Url } from "effect/unstable/http";

import type * as Jwa from "./Jwa.ts";
import type * as Jwt from "./Jwt.ts";

import * as Oidc from "./Oidc.ts";

/**
 * Raised when the callback leg of the code flow cannot be completed. The
 * `reason` is deliberately coarse - it names which step failed, never why,
 * so it is safe to surface in a redirect. `AccessDenied` is the one the
 * visitor caused (they cancelled at the provider); everything else is a
 * protocol failure.
 *
 * @since 1.0.0
 * @category Errors
 */
export class CallbackError extends Schema.Error<CallbackError>("effect-oidc/CallbackError")({
    _tag: Schema.tag("CallbackError"),
    reason: Schema.Literals([
        "InvalidCallback",
        "AccessDenied",
        "ProviderError",
        "StateMismatch",
        "ExchangeFailed",
        "InvalidIdToken",
    ]),
}) {}

/**
 * A realized relying party - see {@link make}.
 *
 * @since 1.0.0
 * @category Models
 */
export interface RelyingParty {
    /**
     * The provider's signing keys: fetched lazily, cached, and served stale
     * through fetch failures once a good set has been seen.
     */
    readonly jwks: Effect.Effect<
        Schema.Schema.Type<typeof Jwt.JwksSchema>,
        HttpClientError.HttpClientError | Schema.SchemaError
    >;

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
        readonly payload?: string | undefined;
    }) => Effect.Effect<HttpServerResponse.HttpServerResponse, Cookies.CookiesError | Url.UrlError>;

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
            readonly claims: Schema.Schema.Type<typeof Oidc.IdTokenClaimsSchema>;
            readonly tokens: Schema.Schema.Type<typeof Oidc.TokenResponseSchema>;
            readonly payload: Option.Option<string>;
        },
        CallbackError,
        HttpServerRequest.HttpServerRequest | HttpServerRequest.ParsedSearchParams
    >;

    /**
     * The payload cookie riding the current request, if any - readable on
     * its own so error handling can recover the payload even when
     * `completeAuthorization` failed before returning it.
     */
    readonly payload: Effect.Effect<Option.Option<string>, never, HttpServerRequest.HttpServerRequest>;

    /** Expires the spent state, verifier, nonce, and payload cookies on a response. */
    readonly expireTransactionCookies: (
        response: HttpServerResponse.HttpServerResponse
    ) => Effect.Effect<HttpServerResponse.HttpServerResponse, Cookies.CookiesError>;
}

/**
 * Realizes a provider registration into a {@link RelyingParty}. The
 * `HttpClient` is captured up front - both the JWKS cache and the code
 * exchange use it - so the realized value requires only the incoming
 * request.
 *
 * Cookie behavior is adjustable without being escapable: `prefix`
 * namespaces the four transaction cookies (mandatory when one app talks to
 * several providers), `name` lets an app-wide cookie policy rewrite the
 * final names (a `__Host-` prefix, an environment suffix), and `secure`
 * exists solely for plain-http local development. The cookies are always
 * `httpOnly`, `sameSite: "lax"`, scoped to `/`, and short-lived (`maxAge`,
 * default 10 minutes).
 *
 * @since 1.0.0
 * @category Constructors
 */
export const make = Effect.fnUntraced(function* (options: {
    /** The issuer id tokens must name - see `Oidc.verifyIdToken`. */
    readonly issuer: string;
    readonly authorizationEndpoint: string;
    readonly tokenEndpoint: string;
    readonly jwksUri: string;
    readonly clientId: string;
    /** Omit for a public client - PKCE alone carries the proof. */
    readonly clientSecret?: Redacted.Redacted | string | undefined;
    readonly redirectUri: string;
    readonly scopes: ReadonlyArray<string>;
    readonly jwksTtl?: Duration.Input | undefined;
    /** Accepted id token signing algorithms - see `Oidc.verifyIdToken`. */
    readonly algorithms?: ReadonlyArray<(typeof Jwa.JwsAlgorithm)["Type"]> | undefined;
    readonly cookies?:
        | {
              /** Namespaces the transaction cookies (default `"oidc"`). */
              readonly prefix?: string | undefined;
              /** Rewrites each final cookie name, e.g. a `__Host-` policy. */
              readonly name?: ((name: string) => string) | undefined;
              /** Default `true`; disable only for plain-http development. */
              readonly secure?: boolean | undefined;
              /** How long a flow may take to complete (default 10 minutes). */
              readonly maxAge?: Duration.Input | undefined;
          }
        | undefined;
}) {
    const httpClient = yield* HttpClient.HttpClient;
    const jwksCache = yield* Oidc.jwksCache(options.jwksUri, { ttl: options.jwksTtl });
    const jwks = Effect.provideService(jwksCache.get, HttpClient.HttpClient, httpClient);
    const refreshJwks = Effect.provideService(jwksCache.refresh, HttpClient.HttpClient, httpClient);

    const clientSecret =
        typeof options.clientSecret === "string"
            ? options.clientSecret
            : options.clientSecret === undefined
              ? undefined
              : Redacted.value(options.clientSecret);

    const prefix = options.cookies?.prefix ?? "oidc";
    const cookieName = options.cookies?.name ?? ((name: string) => name);
    const secure = options.cookies?.secure ?? true;
    const stateCookieName = cookieName(`${prefix}_state`);
    const verifierCookieName = cookieName(`${prefix}_code_verifier`);
    const nonceCookieName = cookieName(`${prefix}_nonce`);
    const payloadCookieName = cookieName(`${prefix}_payload`);

    const setOptions = {
        maxAge: options.cookies?.maxAge ?? "10 minutes",
        httpOnly: true,
        path: "/",
        secure,
        sameSite: "lax",
    } as const;

    const expireOptions = {
        httpOnly: true,
        path: "/",
        secure,
        sameSite: "lax",
    } as const;

    const beginAuthorization: RelyingParty["beginAuthorization"] = Effect.fnUntraced(function* (beginOptions) {
        const pkce = yield* Oidc.generatePkce();
        const state = Encoding.encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
        // OIDC Core Section 3.1.2.1: the nonce binds the id token to this
        // browser session, so a captured id token cannot be replayed into
        // another sign-in.
        const nonce = Encoding.encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));

        const authorizationRequest = Oidc.authorizationRequest({
            authorizationEndpoint: options.authorizationEndpoint,
            clientId: options.clientId,
            redirectUri: options.redirectUri,
            scopes: options.scopes,
            state,
            codeChallenge: pkce.challenge,
            nonce,
        });

        const authorizationUrl = yield* Effect.fromResult(
            Url.make(
                authorizationRequest.url,
                authorizationRequest.urlParams,
                authorizationRequest.hash.valueOrUndefined
            )
        );

        const transactionCookies: Array<readonly [name: string, value: string, options: typeof setOptions]> = [
            [stateCookieName, state, setOptions],
            [verifierCookieName, pkce.verifier, setOptions],
            [nonceCookieName, nonce, setOptions],
        ];
        if (beginOptions?.payload !== undefined) {
            transactionCookies.push([payloadCookieName, beginOptions.payload, setOptions]);
        }

        return yield* HttpServerResponse.redirect(authorizationUrl).pipe(
            HttpServerResponse.setCookies(transactionCookies)
        );
    });

    const payload: RelyingParty["payload"] = Effect.map(HttpServerRequest.HttpServerRequest, (request) =>
        Option.fromNullishOr(request.cookies[payloadCookieName])
    );

    const expireTransactionCookies: RelyingParty["expireTransactionCookies"] = (response) =>
        Effect.succeed(response).pipe(
            Effect.flatMap(HttpServerResponse.expireCookie(stateCookieName, expireOptions)),
            Effect.flatMap(HttpServerResponse.expireCookie(verifierCookieName, expireOptions)),
            Effect.flatMap(HttpServerResponse.expireCookie(nonceCookieName, expireOptions)),
            Effect.flatMap(HttpServerResponse.expireCookie(payloadCookieName, expireOptions))
        );

    const completeAuthorization: RelyingParty["completeAuthorization"] = Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;

        // The provider redirects back with either an error or a code
        const maybeUrlParams = yield* HttpServerRequest.schemaSearchParams(
            Schema.Union([
                Schema.Struct({
                    error: Schema.String,
                }),
                Schema.Struct({
                    code: Schema.String,
                    state: Schema.String,
                }),
            ])
        ).pipe(Effect.option);
        if (Option.isNone(maybeUrlParams)) {
            return yield* new CallbackError({ reason: "InvalidCallback" });
        }

        // The visitor cancelled at the provider, or the provider refused
        const urlParams = maybeUrlParams.value;
        if ("error" in urlParams) {
            return yield* new CallbackError({
                reason: urlParams.error === "access_denied" ? "AccessDenied" : "ProviderError",
            });
        }

        // The state cookie must match the state the provider echoed back,
        // and the verifier and nonce must have survived alongside it
        const stateCookie = request.cookies[stateCookieName];
        const verifierCookie = request.cookies[verifierCookieName];
        const nonceCookie = request.cookies[nonceCookieName];
        if (
            stateCookie === undefined ||
            verifierCookie === undefined ||
            nonceCookie === undefined ||
            stateCookie !== urlParams.state
        ) {
            return yield* new CallbackError({ reason: "StateMismatch" });
        }

        const tokens = yield* Oidc.exchangeAuthorizationCode({
            tokenEndpoint: options.tokenEndpoint,
            clientId: options.clientId,
            clientSecret,
            redirectUri: options.redirectUri,
            code: urlParams.code,
            codeVerifier: verifierCookie,
        }).pipe(
            Effect.provideService(HttpClient.HttpClient, httpClient),
            Effect.catch(() => new CallbackError({ reason: "ExchangeFailed" }))
        );

        const verify = (fetched: Schema.Schema.Type<typeof Jwt.JwksSchema>) =>
            Oidc.verifyIdToken({
                jwks: fetched,
                clientId: options.clientId,
                issuer: options.issuer,
                idToken: tokens.id_token ?? "",
                algorithms: options.algorithms,
                nonce: nonceCookie,
            });
        // An unknown `kid` most likely means the provider rotated its keys:
        // refetch (rate limited by the cache) and try once more.
        const claims = yield* jwks.pipe(
            Effect.flatMap(verify),
            Effect.catch((error) =>
                error._tag === "JwtError" && error.reason === "UnknownKey"
                    ? refreshJwks.pipe(Effect.flatMap(verify))
                    : Effect.fail(error)
            ),
            Effect.catch(() => new CallbackError({ reason: "InvalidIdToken" }))
        );

        return {
            claims,
            tokens,
            payload: Option.fromNullishOr(request.cookies[payloadCookieName]),
        };
    });

    const relyingParty: RelyingParty = {
        jwks,
        beginAuthorization,
        completeAuthorization,
        payload,
        expireTransactionCookies,
    };

    return relyingParty;
});
