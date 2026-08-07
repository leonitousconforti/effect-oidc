/**
 * A complete, minimal OIDC provider. It serves, relative to the issuer:
 *
 * - GET  /.well-known/openid-configuration - the discovery document
 * - GET  /.well-known/jwks.json            - the signing keys
 * - GET  /oauth/authorize                  - validates the authorization request,
 *                                            signs in a demo user, and redirects
 *                                            back with a single-use code
 * - POST /oauth/token                      - authorization_code (PKCE-checked),
 *                                            refresh_token, and client_credentials
 *                                            grants
 * - POST /oauth/revoke                     - RFC 7009 revocation: the token's
 *                                            jti joins a denylist until its exp
 * - GET  /oauth/revocations                - demo-only: the denylist, polled by
 *                                            the resource server
 * - POST /demo/api-key                     - demo-only: mints a long-lived
 *                                            api-key JWT (a real provider does
 *                                            this from an authenticated
 *                                            dashboard)
 *
 * Everything lives in memory: two registered OAuth clients (a public SPA and
 * a confidential service), one user, and a signing key generated at startup.
 * A real provider swaps the auto-approval in the authorize handler for a
 * login page + consent screen, persists its keys, grants, and client
 * registrations (hashing the secrets), and serves over https.
 *
 * Run with (then see 03-resource-server.ts and 04-oidc-client.ts):
 *
 *     pnpm tsx examples/02-oidc-provider.ts
 */

import { Context, DateTime, Effect, Encoding, Function, Layer, Option, type Schema } from "effect";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";

import { createServer } from "node:http";

import { NodeHttpServer, NodeRuntime } from "@effect/platform-node";
import { Jwt, Oidc } from "effect-oidc";

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

/** Demo only - a real issuer MUST be https (clients enforce this). */
const issuer = "http://localhost:3001";
const port = 3001;

/** How long issued access and id tokens live. */
const tokenTtlSeconds = 3600;

/** The audience access tokens are minted for (the resource server's name). */
const apiAudience = "demo-api";

/**
 * A public client (native app / SPA shaped): there is no client secret -
 * PKCE is what binds the code to the client that started the flow.
 */
const registeredClient = {
    clientId: "demo-app",
    redirectUris: ["http://localhost:3000/callback"],
};

/**
 * A confidential ("private") client: a backend service that can hold a
 * secret and uses the client_credentials grant for machine-to-machine
 * access, with no user involved. The demo keeps the secret in memory; a
 * real provider stores a hash of it.
 */
const registeredService = {
    clientId: "demo-service",
    clientSecret: "demo-service-secret",
    scopes: ["notes"],
};

/** The account that "logs in". A real provider authenticates a user here. */
const demoUser = {
    sub: "user-123",
    name: "Demo User",
};

// ---------------------------------------------------------------------------
// Provider state: the signing key and the in-memory grant stores
// ---------------------------------------------------------------------------

interface PendingAuthorization {
    readonly clientId: string;
    readonly redirectUri: string;
    readonly codeChallenge: string;
    readonly scope: string;
    readonly nonce: string | undefined;
    readonly sub: string;
    readonly expiresAtMillis: number;
}

interface RefreshGrant {
    readonly clientId: string;
    readonly scope: string;
    readonly sub: string;
}

class ProviderState extends Context.Service<
    ProviderState,
    {
        readonly privateJwk: Schema.Schema.Type<typeof Jwt.PrivateJwkSchema>;
        readonly jwks: Schema.Schema.Type<typeof Jwt.JwksSchema>;
        readonly codes: Map<string, PendingAuthorization>;
        readonly refreshTokens: Map<string, RefreshGrant>;
        /** Revoked token jtis, each kept only until its token's exp. */
        readonly revokedJtis: Map<string, number>;
    }
>()("examples/ProviderState") {}

const ProviderStateLive = Layer.effect(
    ProviderState,
    Effect.gen(function* () {
        const { privateJwk, publicJwk } = yield* Jwt.generateSigningKey();
        return {
            privateJwk,
            jwks: { keys: [publicJwk] },
            codes: new Map(),
            refreshTokens: new Map(),
            revokedJtis: new Map(),
        };
    })
);

const randomToken = (): string => Encoding.encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));

/**
 * RFC 6749 Section 5.2 error response. `invalid_client` answers 401, as
 * required when the client attempted `Authorization` header authentication.
 */
const oauthError = (error: "invalid_request" | "invalid_grant" | "invalid_client" | "invalid_scope") =>
    HttpServerResponse.json({ error }, { status: error === "invalid_client" ? 401 : 400 });

/** Compare digests so the time taken does not leak where the secrets differ. */
const secretsMatch = (presented: string, registered: string) =>
    Effect.promise(async () => {
        const digest = async (value: string) =>
            new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
        const a = await digest(presented);
        const b = await digest(registered);
        return a.every((byte, index) => byte === b[index]);
    });

// ---------------------------------------------------------------------------
// GET /.well-known/openid-configuration and /.well-known/jwks.json
// ---------------------------------------------------------------------------

const DiscoveryRoute = HttpRouter.add(
    "GET",
    "/.well-known/openid-configuration",
    HttpServerResponse.schemaJson(Oidc.DiscoveryDocumentSchema)(Oidc.makeDiscoveryDocument(issuer))
);

const JwksRoute = HttpRouter.add(
    "GET",
    "/.well-known/jwks.json",
    Effect.gen(function* () {
        const state = yield* ProviderState;
        return yield* HttpServerResponse.schemaJson(Jwt.JwksSchema)(state.jwks);
    })
);

// ---------------------------------------------------------------------------
// GET /oauth/authorize
// ---------------------------------------------------------------------------

const handleAuthorize = Effect.fnUntraced(function* (
    request: Schema.Schema.Type<typeof Oidc.AuthorizationRequestSchema>
) {
    const state = yield* ProviderState;

    // The client and its registered redirect uri MUST be validated before
    // redirecting anywhere - sending a code to an unregistered redirect_uri
    // would hand tokens to whoever chose the URL.
    if (
        request.client_id !== registeredClient.clientId ||
        !registeredClient.redirectUris.includes(request.redirect_uri)
    ) {
        return HttpServerResponse.text("Unknown client_id or unregistered redirect_uri", { status: 400 });
    }

    // This is where a real provider renders a login page, authenticates the
    // user, and asks for consent to the requested scopes. The demo signs in
    // `demoUser` and approves automatically.
    const code = randomToken();
    const nowMillis = DateTime.toEpochMillis(yield* DateTime.now);
    state.codes.set(code, {
        clientId: request.client_id,
        redirectUri: request.redirect_uri,
        codeChallenge: request.code_challenge,
        scope: request.scope,
        nonce: request.nonce,
        sub: demoUser.sub,
        // Authorization codes are single-use and short-lived.
        expiresAtMillis: nowMillis + 60_000,
    });

    const location = new URL(request.redirect_uri);
    location.searchParams.set("code", code);
    location.searchParams.set("state", request.state);
    return HttpServerResponse.redirect(location);
});

const AuthorizeRoute = HttpRouter.add(
    "GET",
    "/oauth/authorize",
    Effect.gen(function* () {
        const request = yield* HttpServerRequest.schemaSearchParams(Oidc.AuthorizationRequestSchema).pipe(
            Effect.catch(() => Effect.void)
        );
        // Includes the PKCE requirement: requests without an S256 code
        // challenge do not decode.
        if (request === undefined) {
            return HttpServerResponse.text("Malformed authorization request", { status: 400 });
        }
        return yield* handleAuthorize(request);
    })
);

// ---------------------------------------------------------------------------
// POST /oauth/token
// ---------------------------------------------------------------------------

const issueTokens = Effect.fnUntraced(function* (options: {
    readonly sub: string;
    readonly clientId: string;
    readonly scope: string;
    readonly nonce?: string | undefined;
}) {
    const state = yield* ProviderState;

    const accessToken = yield* Oidc.issueAccessToken({
        privateJwk: state.privateJwk,
        issuer,
        subject: options.sub,
        audience: apiAudience,
        clientId: options.clientId,
        scope: options.scope,
        ttlSeconds: tokenTtlSeconds,
    });

    // An id token is only minted for OIDC requests (scope includes "openid");
    // its audience is the client itself, not the resource server.
    let idToken: string | undefined = undefined;
    if (options.scope.split(" ").includes("openid")) {
        idToken = yield* Oidc.issueIdToken({
            privateJwk: state.privateJwk,
            issuer,
            subject: options.sub,
            clientId: options.clientId,
            ttlSeconds: tokenTtlSeconds,
            nonce: options.nonce,
            profile: { name: demoUser.name },
        });
    }

    // Refresh tokens are opaque handles into the provider's own store, and
    // they rotate: each one is invalidated when redeemed.
    const refreshToken = randomToken();
    state.refreshTokens.set(refreshToken, {
        clientId: options.clientId,
        scope: options.scope,
        sub: options.sub,
    });

    return yield* HttpServerResponse.schemaJson(Oidc.TokenResponseSchema)({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: tokenTtlSeconds,
        scope: options.scope,
        refresh_token: refreshToken,
        ...(idToken === undefined ? {} : { id_token: idToken }),
    });
});

const handleAuthorizationCodeGrant = Effect.fnUntraced(function* (request: {
    readonly code: string;
    readonly redirect_uri: string;
    readonly client_id: string;
    readonly code_verifier: string;
}) {
    const state = yield* ProviderState;

    // Codes are single-use: consume before any validation so a failed
    // attempt burns the code too.
    const grant = state.codes.get(request.code);
    state.codes.delete(request.code);

    const nowMillis = DateTime.toEpochMillis(yield* DateTime.now);
    if (
        grant === undefined ||
        grant.expiresAtMillis < nowMillis ||
        grant.clientId !== request.client_id ||
        grant.redirectUri !== request.redirect_uri
    ) {
        return yield* oauthError("invalid_grant");
    }

    // PKCE (RFC 7636): the S256 digest of the presented verifier must match
    // the challenge bound to the code at authorization time. This is what
    // stops a stolen code from being redeemed by anyone else.
    const digest = yield* Effect.promise(() =>
        crypto.subtle.digest("SHA-256", new TextEncoder().encode(request.code_verifier))
    );
    if (Encoding.encodeBase64Url(new Uint8Array(digest)) !== grant.codeChallenge) {
        return yield* oauthError("invalid_grant");
    }

    return yield* issueTokens({
        sub: grant.sub,
        clientId: grant.clientId,
        scope: grant.scope,
        nonce: grant.nonce,
    });
});

const handleRefreshTokenGrant = Effect.fnUntraced(function* (request: {
    readonly refresh_token: string;
    readonly client_id: string;
}) {
    const state = yield* ProviderState;

    const grant = state.refreshTokens.get(request.refresh_token);
    if (grant === undefined || grant.clientId !== request.client_id) {
        return yield* oauthError("invalid_grant");
    }

    // Rotation: the presented refresh token is gone; the response carries
    // its replacement.
    state.refreshTokens.delete(request.refresh_token);
    return yield* issueTokens({ sub: grant.sub, clientId: grant.clientId, scope: grant.scope });
});

const handleClientCredentialsGrant = Effect.fnUntraced(function* (
    request: { readonly client_id?: string | undefined; readonly client_secret?: string | undefined },
    scope: string,
    authorization: string | undefined
) {
    const state = yield* ProviderState;

    // The service may authenticate with client_secret_basic (the
    // Authorization header, the OIDC default) or client_secret_post (body
    // parameters) - `clientAuthentication` resolves either.
    const auth = Oidc.clientAuthentication({ authorization, request });
    if (
        Option.isNone(auth) ||
        auth.value.clientId !== registeredService.clientId ||
        auth.value.clientSecret === undefined ||
        !(yield* secretsMatch(auth.value.clientSecret, registeredService.clientSecret))
    ) {
        return yield* oauthError("invalid_client");
    }

    // Scopes are capped to the registration.
    if (!scope.split(" ").every((requested) => registeredService.scopes.includes(requested))) {
        return yield* oauthError("invalid_scope");
    }

    // Machine-to-machine: the token's subject is the client itself, and no
    // refresh or id token is issued.
    const accessToken = yield* Oidc.issueAccessToken({
        privateJwk: state.privateJwk,
        issuer,
        subject: auth.value.clientId,
        audience: apiAudience,
        clientId: auth.value.clientId,
        scope,
        ttlSeconds: tokenTtlSeconds,
    });

    return yield* HttpServerResponse.schemaJson(Oidc.TokenResponseSchema)({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: tokenTtlSeconds,
        scope,
    });
});

const TokenRoute = HttpRouter.add(
    "POST",
    "/oauth/token",
    Effect.gen(function* () {
        const httpRequest = yield* HttpServerRequest.HttpServerRequest;
        const request = yield* HttpServerRequest.schemaBodyUrlParams(Oidc.TokenRequestSchema).pipe(
            Effect.catch(() => Effect.void)
        );
        if (request === undefined) {
            return yield* oauthError("invalid_request");
        }
        switch (request.grant_type) {
            case "authorization_code":
                return yield* handleAuthorizationCodeGrant(request);
            case "refresh_token":
                return yield* handleRefreshTokenGrant(request);
            case "client_credentials":
                return yield* handleClientCredentialsGrant(
                    request,
                    request.scope ?? registeredService.scopes.join(" "),
                    httpRequest.headers.authorization
                );
            default:
                return Function.absurd<never>(request);
        }
    })
);

// ---------------------------------------------------------------------------
// POST /oauth/revoke, GET /oauth/revocations, POST /demo/api-key
// ---------------------------------------------------------------------------

const RevokeRoute = HttpRouter.add(
    "POST",
    "/oauth/revoke",
    Effect.gen(function* () {
        const state = yield* ProviderState;
        const request = yield* HttpServerRequest.schemaBodyUrlParams(Oidc.RevocationRequestSchema).pipe(
            Effect.catch(() => Effect.void)
        );
        // RFC 7009: answer 200 whether or not the token was valid, so the
        // endpoint cannot be used to probe token validity. Only tokens this
        // provider actually signed make it onto the denylist, which is what
        // stops third parties from stuffing it.
        if (request !== undefined) {
            const claims = yield* Jwt.verify(request.token, {
                jwks: state.jwks,
                issuer,
                audience: apiAudience,
            }).pipe(Effect.catch(() => Effect.void));
            if (claims !== undefined && typeof claims.jti === "string") {
                state.revokedJtis.set(claims.jti, claims.exp * 1000);
            }
        }
        return HttpServerResponse.empty({ status: 200 });
    })
);

const RevocationsRoute = HttpRouter.add(
    "GET",
    "/oauth/revocations",
    Effect.gen(function* () {
        const state = yield* ProviderState;
        // Entries expire with their tokens, keeping the denylist bounded.
        const nowMillis = DateTime.toEpochMillis(yield* DateTime.now);
        for (const [jti, expiresAtMillis] of state.revokedJtis) {
            if (expiresAtMillis < nowMillis) state.revokedJtis.delete(jti);
        }
        return yield* HttpServerResponse.json([...state.revokedJtis.keys()]);
    })
);

const ApiKeyRoute = HttpRouter.add(
    "POST",
    "/demo/api-key",
    Effect.gen(function* () {
        const state = yield* ProviderState;
        // An api key is an ordinary JWT, just with a long ttl; the exp is
        // what bounds the revocation denylist. A real provider mints these
        // from an authenticated dashboard.
        const apiKey = yield* Oidc.issueAccessToken({
            privateJwk: state.privateJwk,
            issuer,
            subject: "robot-1",
            audience: apiAudience,
            clientId: "robot-1",
            scope: "notes",
            ttlSeconds: 30 * 24 * 3600,
        });
        return yield* HttpServerResponse.json({ api_key: apiKey });
    })
);

// ---------------------------------------------------------------------------
// Serve
// ---------------------------------------------------------------------------

const ProviderRoutes = Layer.mergeAll(
    DiscoveryRoute,
    JwksRoute,
    AuthorizeRoute,
    TokenRoute,
    RevokeRoute,
    RevocationsRoute,
    ApiKeyRoute
);

const Main = HttpRouter.serve(ProviderRoutes).pipe(
    Layer.provide(ProviderStateLive),
    Layer.provide(NodeHttpServer.layer(() => createServer(), { port }))
);

NodeRuntime.runMain(Layer.launch(Main));
