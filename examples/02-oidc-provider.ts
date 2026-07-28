/**
 * A complete, minimal OIDC provider. It serves, relative to the issuer:
 *
 * - GET  /.well-known/openid-configuration — the discovery document
 * - GET  /.well-known/jwks.json            — the signing keys
 * - GET  /oauth/authorize                  — validates the authorization request,
 *                                            signs in a demo user, and redirects
 *                                            back with a single-use code
 * - POST /oauth/token                      — authorization_code (PKCE-checked)
 *                                            and refresh_token grants
 *
 * Everything lives in memory: one registered OAuth client, one user, and a
 * signing key generated at startup. A real provider swaps the auto-approval
 * in the authorize handler for a login page + consent screen, persists its
 * keys and grants, and serves over https.
 *
 * Run with (then see 03-resource-server.ts and 04-oidc-client.ts):
 *
 *     pnpm tsx examples/02-oidc-provider.ts
 */

import { Context, DateTime, Effect, Encoding, Layer, type Schema } from "effect";
import { HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";

import { createServer } from "node:http";

import { NodeHttpServer, NodeRuntime } from "@effect/platform-node";
import { Jwt, Oidc } from "effect-oidc";

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

/** Demo only — a real issuer MUST be https (clients enforce this). */
const issuer = "http://localhost:3001";
const port = 3001;

/** How long issued access and id tokens live. */
const tokenTtlSeconds = 3600;

/** The audience access tokens are minted for (the resource server's name). */
const apiAudience = "demo-api";

/**
 * The one OAuth client this provider knows about. It is a public client
 * (native app / SPA shaped), so there is no client secret — PKCE is what
 * binds the code to the client that started the flow.
 */
const registeredClient = {
    clientId: "demo-app",
    redirectUris: ["http://localhost:3000/callback"],
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
        };
    })
);

const randomToken = (): string => Encoding.encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));

/** RFC 6749 Section 5.2 error response. */
const oauthError = (error: "invalid_request" | "invalid_grant" | "unsupported_grant_type") =>
    HttpServerResponse.json({ error }, { status: 400 });

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
    // redirecting anywhere — sending a code to an unregistered redirect_uri
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

const TokenRoute = HttpRouter.add(
    "POST",
    "/oauth/token",
    Effect.gen(function* () {
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
        }
    })
);

// ---------------------------------------------------------------------------
// Serve
// ---------------------------------------------------------------------------

const ProviderRoutes = Layer.mergeAll(DiscoveryRoute, JwksRoute, AuthorizeRoute, TokenRoute);

const Main = HttpRouter.serve(ProviderRoutes).pipe(
    Layer.provide(ProviderStateLive),
    Layer.provide(NodeHttpServer.layer(() => createServer(), { port }))
);

NodeRuntime.runMain(Layer.launch(Main));
