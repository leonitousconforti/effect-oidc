import { Effect, Encoding, Layer, Schema } from "effect";
import {
    FetchHttpClient,
    HttpClient,
    HttpClientRequest,
    HttpRouter,
    HttpServer,
    HttpServerResponse,
} from "effect/unstable/http";
import {
    HttpApi,
    HttpApiBuilder,
    HttpApiEndpoint,
    HttpApiError,
    HttpApiGroup,
    HttpApiSchema,
} from "effect/unstable/httpapi";

import { createServer } from "node:http";

import { NodeHttpServer } from "@effect/platform-node";
import { expect, it } from "@effect/vitest";
import { Jwt, Oidc, ResourceServer } from "effect-oidc";

const issuer = "https://id.example.com";
const audience = "tinyburg-api";
const oauthClient = { id: "client-abc", redirectUri: "https://app.example.com/callback" };
const account = { sub: "user-123", name: "Some User" };

// The provider and the resource server it protects, together as one HttpApi.
// The provider group serves the conventional OIDC endpoints; the protected
// group is any service guarded by the Authorization middleware.

const ProviderGroup = HttpApiGroup.make("Provider")
    .add(
        HttpApiEndpoint.get("discovery", "/.well-known/openid-configuration", {
            success: Oidc.DiscoveryDocumentSchema,
        })
    )
    .add(HttpApiEndpoint.get("jwks", "/.well-known/jwks.json", { success: Jwt.JwksSchema }))
    .add(
        HttpApiEndpoint.get("authorize", "/oauth/authorize", {
            query: Oidc.AuthorizationRequestSchema,
            error: HttpApiError.BadRequest,
        })
    )
    .add(
        HttpApiEndpoint.post("token", "/oauth/token", {
            payload: Oidc.TokenRequestSchema.pipe(HttpApiSchema.asFormUrlEncoded()),
            success: Oidc.TokenResponseSchema,
            error: HttpApiError.BadRequest,
        })
    );

const MeSchema = Schema.Struct({
    sub: Schema.String,
    clientId: Schema.String,
    scopes: Schema.Array(Schema.String),
});

const ProtectedGroup = HttpApiGroup.make("Protected")
    .add(HttpApiEndpoint.get("me", "/api/me", { success: MeSchema }))
    .add(HttpApiEndpoint.get("admin", "/api/admin", { success: Schema.String }))
    .middleware(ResourceServer.Authorization);

const Api = HttpApi.make("E2eApi").add(ProviderGroup, ProtectedGroup);

interface PendingAuthorization {
    readonly clientId: string;
    readonly redirectUri: string;
    readonly codeChallenge: string;
    readonly scope: string;
    readonly nonce: string | undefined;
}

const ProviderLive = HttpApiBuilder.group(Api, "Provider", (handlers) =>
    Effect.gen(function* () {
        const { privateJwk, publicJwk } = yield* Effect.orDie(Jwt.generateSigningKey());
        const codes = new Map<string, PendingAuthorization>();
        return handlers
            .handle("discovery", () => Effect.succeed(Oidc.makeDiscoveryDocument(issuer)))
            .handle("jwks", () => Effect.succeed({ keys: [publicJwk] }))
            .handle("authorize", ({ query }) =>
                Effect.gen(function* () {
                    // Only the pre-registered client with an exact redirect uri
                    // match may start the flow.
                    if (query.client_id !== oauthClient.id || query.redirect_uri !== oauthClient.redirectUri) {
                        return yield* new HttpApiError.BadRequest();
                    }
                    // The signed-in account consents; the code is bound to
                    // everything the token request must repeat.
                    const code = crypto.randomUUID();
                    codes.set(code, {
                        clientId: query.client_id,
                        redirectUri: query.redirect_uri,
                        codeChallenge: query.code_challenge,
                        scope: query.scope,
                        nonce: query.nonce,
                    });
                    const location = new URL(query.redirect_uri);
                    location.searchParams.set("code", code);
                    location.searchParams.set("state", query.state);
                    return HttpServerResponse.redirect(location);
                })
            )
            .handle("token", ({ payload }) =>
                Effect.gen(function* () {
                    if (payload.grant_type !== "authorization_code") return yield* new HttpApiError.BadRequest();
                    const pending = codes.get(payload.code);
                    // Single use: consumed even when the exchange fails.
                    codes.delete(payload.code);
                    if (
                        pending === undefined ||
                        pending.clientId !== payload.client_id ||
                        pending.redirectUri !== payload.redirect_uri
                    ) {
                        return yield* new HttpApiError.BadRequest();
                    }
                    const digest = yield* Effect.promise(() =>
                        crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload.code_verifier))
                    );
                    if (Encoding.encodeBase64Url(new Uint8Array(digest)) !== pending.codeChallenge) {
                        return yield* new HttpApiError.BadRequest();
                    }
                    const accessToken = yield* Effect.orDie(
                        Oidc.issueAccessToken({
                            privateJwk,
                            issuer,
                            subject: account.sub,
                            audience,
                            clientId: pending.clientId,
                            scope: pending.scope,
                            ttlSeconds: 300,
                        })
                    );
                    const idToken = yield* Effect.orDie(
                        Oidc.issueIdToken({
                            privateJwk,
                            issuer,
                            subject: account.sub,
                            clientId: pending.clientId,
                            ttlSeconds: 300,
                            nonce: pending.nonce,
                            profile: { name: account.name },
                        })
                    );
                    return {
                        access_token: accessToken,
                        token_type: "Bearer" as const,
                        expires_in: 300,
                        scope: pending.scope,
                        id_token: idToken,
                    };
                })
            );
    })
);

const ProtectedLive = HttpApiBuilder.group(Api, "Protected", (handlers) =>
    handlers
        .handle("me", () =>
            Effect.gen(function* () {
                const user = yield* ResourceServer.requireScopes("openid", "profile");
                return { sub: user.sub, clientId: user.clientId, scopes: [...user.scopes] };
            })
        )
        .handle("admin", () => Effect.as(ResourceServer.requireScopes("admin"), "admin ok"))
);

// Requests to the https issuer are routed to the local ephemeral server, like
// a test DNS + TLS terminator. Everything else (the discovery document's
// https/same-origin validation, the JWKS fetch, bearer verification) runs
// exactly as it would in production. Redirects are not followed so the test
// can play the browser and inspect the authorization callback.
const ClientLive = Layer.effect(HttpClient.HttpClient)(
    Effect.gen(function* () {
        const address = (yield* HttpServer.HttpServer).address;
        if (address._tag !== "TcpAddress") return yield* Effect.die(new Error("expected a tcp address"));
        const origin = `http://127.0.0.1:${address.port}`;
        const fetchClient = yield* HttpClient.HttpClient;
        return HttpClient.mapRequest(
            fetchClient,
            HttpClientRequest.updateUrl((url) => (url.startsWith(issuer) ? origin + url.slice(issuer.length) : url))
        );
    })
).pipe(
    Layer.provide(
        FetchHttpClient.layer.pipe(
            Layer.provide(Layer.succeed(FetchHttpClient.RequestInit)({ redirect: "manual", keepalive: false }))
        )
    )
);

const TestLive = HttpRouter.serve(HttpApiBuilder.layer(Api), { disableListenLog: true, disableLogger: true }).pipe(
    Layer.provide(Layer.mergeAll(ProviderLive, ProtectedLive)),
    Layer.provide(ResourceServer.layer({ issuer, audience })),
    Layer.provideMerge(ClientLive),
    Layer.provideMerge(NodeHttpServer.layer(createServer, { host: "127.0.0.1", port: 0 }))
);

it.live("runs the authorization code + PKCE flow end to end over http", () =>
    Effect.gen(function* () {
        const browser = yield* HttpClient.HttpClient;

        // The relying app discovers the provider and prepares PKCE.
        const discovery = yield* Oidc.fetchDiscovery(issuer);
        expect(discovery.authorization_endpoint).toBe(`${issuer}/oauth/authorize`);

        const pkce = yield* Oidc.generatePkce();
        const state = crypto.randomUUID();
        const nonce = crypto.randomUUID();

        // The browser visits the authorization endpoint; the provider
        // redirects back to the app with a fresh code and the echoed state.
        const authorizeResponse = yield* browser.get(
            Oidc.authorizationUrl({
                authorizationEndpoint: discovery.authorization_endpoint,
                clientId: oauthClient.id,
                redirectUri: oauthClient.redirectUri,
                scopes: ["openid", "profile"],
                state,
                codeChallenge: pkce.challenge,
                nonce,
            })
        );
        expect(authorizeResponse.status).toBe(302);
        const callback = new URL(authorizeResponse.headers["location"] ?? "");
        expect(`${callback.origin}${callback.pathname}`).toBe(oauthClient.redirectUri);
        expect(callback.searchParams.get("state")).toBe(state);
        const code = callback.searchParams.get("code") ?? "";
        expect(code).not.toBe("");

        // The app exchanges the code, proving possession of the verifier.
        const tokens = yield* Oidc.exchangeAuthorizationCode({
            tokenEndpoint: discovery.token_endpoint,
            clientId: oauthClient.id,
            code,
            codeVerifier: pkce.verifier,
            redirectUri: oauthClient.redirectUri,
        });
        expect(tokens.token_type).toBe("Bearer");
        expect(tokens.scope).toBe("openid profile");

        // The app verifies the id token against the provider's JWKS and signs
        // the account in.
        const jwks = yield* Oidc.fetchJwks(discovery.jwks_uri);
        const idClaims = yield* Oidc.verifyIdToken({
            idToken: tokens.id_token ?? "",
            jwks,
            issuer,
            clientId: oauthClient.id,
            nonce,
        });
        expect(idClaims.sub).toBe(account.sub);
        expect(idClaims.name).toBe(account.name);

        // The access token authenticates the app at the resource server, which
        // verifies it statelessly against the same JWKS.
        const me = yield* browser.get(`${issuer}/api/me`, {
            headers: { authorization: `Bearer ${tokens.access_token}` },
        });
        expect(me.status).toBe(200);
        expect(yield* me.json).toStrictEqual({
            sub: account.sub,
            clientId: oauthClient.id,
            scopes: ["openid", "profile"],
        });

        // No bearer token, a tampered signature, and a token minted for a
        // different audience (the id token) are all rejected.
        expect((yield* browser.get(`${issuer}/api/me`)).status).toBe(401);
        const tampered = tokens.access_token.slice(0, -1) + (tokens.access_token.endsWith("A") ? "B" : "A");
        const tamperedResponse = yield* browser.get(`${issuer}/api/me`, {
            headers: { authorization: `Bearer ${tampered}` },
        });
        expect(tamperedResponse.status).toBe(401);
        const wrongAudience = yield* browser.get(`${issuer}/api/me`, {
            headers: { authorization: `Bearer ${tokens.id_token}` },
        });
        expect(wrongAudience.status).toBe(401);

        // Scopes gate individual endpoints: the token grants openid+profile
        // but not admin.
        const admin = yield* browser.get(`${issuer}/api/admin`, {
            headers: { authorization: `Bearer ${tokens.access_token}` },
        });
        expect(admin.status).toBe(403);

        // A code exchanged with the wrong PKCE verifier is rejected, and the
        // failed attempt consumes it: retrying with the right verifier fails
        // too.
        const secondPkce = yield* Oidc.generatePkce();
        const secondVisit = yield* browser.get(
            Oidc.authorizationUrl({
                authorizationEndpoint: discovery.authorization_endpoint,
                clientId: oauthClient.id,
                redirectUri: oauthClient.redirectUri,
                scopes: ["openid", "profile"],
                state: crypto.randomUUID(),
                codeChallenge: secondPkce.challenge,
            })
        );
        const secondCode = new URL(secondVisit.headers["location"] ?? "").searchParams.get("code") ?? "";
        const exchangeRequest = (codeVerifier: string) =>
            HttpClientRequest.post(discovery.token_endpoint).pipe(
                HttpClientRequest.bodyUrlParams({
                    grant_type: "authorization_code",
                    code: secondCode,
                    redirect_uri: oauthClient.redirectUri,
                    client_id: oauthClient.id,
                    code_verifier: codeVerifier,
                })
            );
        expect((yield* browser.execute(exchangeRequest("not-the-right-verifier"))).status).toBe(400);
        expect((yield* browser.execute(exchangeRequest(secondPkce.verifier))).status).toBe(400);
    }).pipe(Effect.provide(TestLive))
);
