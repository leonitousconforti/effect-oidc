import { Effect, Encoding, Option } from "effect";
import { Cookies, HttpClient, HttpClientResponse, HttpServerRequest, HttpServerResponse } from "effect/unstable/http";

import { expect, it } from "@effect/vitest";
import { Jwt, Oidc, RelyingParty } from "effect-oidc";

const issuer = "https://id.example.com";
const clientId = "demo-app";
const redirectUri = "https://app.example.com/auth/callback";

/**
 * A stub provider: answers the JWKS fetch with a fresh signing key and the
 * token endpoint with a real signed id token, recording every token request
 * body it sees.
 */
const makeProvider = (options?: { readonly cookies?: Parameters<typeof RelyingParty.make>[0]["cookies"] }) =>
    Effect.gen(function* () {
        const { privateJwk, publicJwk } = yield* Jwt.generateSigningKey();
        const tokenRequests: Array<string> = [];

        const stub = HttpClient.make((request) =>
            Effect.gen(function* () {
                if (request.url === "https://id.example.com/.well-known/jwks.json") {
                    return HttpClientResponse.fromWeb(request, Response.json({ keys: [publicJwk] }));
                }
                if (request.url === "https://id.example.com/oauth/token") {
                    const body = request.body._tag === "Uint8Array" ? new TextDecoder().decode(request.body.body) : "";
                    tokenRequests.push(body);
                    const idToken = yield* Oidc.issueIdToken({
                        privateJwk,
                        issuer,
                        subject: "user-123",
                        clientId,
                        ttlSeconds: 300,
                        profile: { name: "Some User" },
                    }).pipe(Effect.orDie);
                    return HttpClientResponse.fromWeb(
                        request,
                        Response.json({
                            access_token: "token-123",
                            token_type: "Bearer",
                            expires_in: 3600,
                            scope: "openid profile",
                            id_token: idToken,
                        })
                    );
                }
                return HttpClientResponse.fromWeb(request, new Response("not found", { status: 404 }));
            })
        );

        const relyingParty = yield* RelyingParty.make({
            issuer,
            authorizationEndpoint: "https://id.example.com/oauth/authorize",
            tokenEndpoint: "https://id.example.com/oauth/token",
            jwksUri: "https://id.example.com/.well-known/jwks.json",
            clientId,
            redirectUri,
            scopes: ["openid", "profile"],
            ...(options?.cookies === undefined ? {} : { cookies: options.cookies }),
        }).pipe(Effect.provideService(HttpClient.HttpClient, stub));

        return { relyingParty, stub, tokenRequests };
    });

/** Serves the callback route with the given url and request cookies. */
const serveCallback = (relyingParty: RelyingParty.RelyingParty, url: string, cookies: Record<string, string>) => {
    const cookieHeader = Object.entries(cookies)
        .map(([name, value]) => `${name}=${value}`)
        .join("; ");
    const request = HttpServerRequest.fromWeb(new Request(url, { headers: { cookie: cookieHeader } }));
    return relyingParty.completeAuthorization.pipe(
        Effect.provideService(HttpServerRequest.HttpServerRequest, request),
        Effect.provideService(HttpServerRequest.ParsedSearchParams, HttpServerRequest.searchParamsFromURL(new URL(url)))
    );
};

it.live("drives the authorization code + PKCE flow end to end", () =>
    Effect.gen(function* () {
        const { relyingParty, tokenRequests } = yield* makeProvider();

        const begin = yield* relyingParty.beginAuthorization({ payload: "/dashboard" });
        expect(begin.status).toBe(302);
        const location = new URL(begin.headers.location ?? "");
        expect(`${location.origin}${location.pathname}`).toBe("https://id.example.com/oauth/authorize");
        expect(location.searchParams.get("response_type")).toBe("code");
        expect(location.searchParams.get("client_id")).toBe(clientId);
        expect(location.searchParams.get("redirect_uri")).toBe(redirectUri);
        expect(location.searchParams.get("code_challenge_method")).toBe("S256");

        // The transaction cookies carry the state, the verifier, and the payload
        const transaction = Cookies.toRecord(begin.cookies);
        const state = location.searchParams.get("state");
        expect(state).not.toBeNull();
        expect(transaction["oidc_state"]).toBe(state);
        expect(transaction["oidc_payload"]).toBe("/dashboard");

        // The challenge in the URL is the S256 digest of the verifier cookie
        const digest = yield* Effect.promise(() =>
            crypto.subtle.digest("SHA-256", new TextEncoder().encode(transaction["oidc_code_verifier"]))
        );
        expect(location.searchParams.get("code_challenge")).toBe(Encoding.encodeBase64Url(new Uint8Array(digest)));

        const result = yield* serveCallback(relyingParty, `${redirectUri}?code=code-123&state=${state}`, transaction);
        expect(result.claims.sub).toBe("user-123");
        expect(result.claims.name).toBe("Some User");
        expect(result.tokens.access_token).toBe("token-123");
        expect(result.payload).toStrictEqual(Option.some("/dashboard"));

        // The exchange sent the code and the verifier from the cookie
        expect(tokenRequests).toHaveLength(1);
        expect(tokenRequests[0]).toContain("grant_type=authorization_code");
        expect(tokenRequests[0]).toContain("code=code-123");
        expect(tokenRequests[0]).toContain(`code_verifier=${transaction["oidc_code_verifier"]}`);
    })
);

it.live("rejects a callback whose state does not match the cookie", () =>
    Effect.gen(function* () {
        const { relyingParty } = yield* makeProvider();
        const begin = yield* relyingParty.beginAuthorization();
        const transaction = Cookies.toRecord(begin.cookies);

        const mismatched = yield* Effect.flip(
            serveCallback(relyingParty, `${redirectUri}?code=code-123&state=not-the-state`, transaction)
        );
        expect(mismatched.reason).toBe("StateMismatch");

        const state = new URL(begin.headers.location ?? "").searchParams.get("state");
        const missingCookies = yield* Effect.flip(
            serveCallback(relyingParty, `${redirectUri}?code=code-123&state=${state}`, {})
        );
        expect(missingCookies.reason).toBe("StateMismatch");
    })
);

it.live("maps provider refusals and malformed callbacks to coarse reasons", () =>
    Effect.gen(function* () {
        const { relyingParty } = yield* makeProvider();

        const denied = yield* Effect.flip(serveCallback(relyingParty, `${redirectUri}?error=access_denied`, {}));
        expect(denied.reason).toBe("AccessDenied");

        const refused = yield* Effect.flip(serveCallback(relyingParty, `${redirectUri}?error=server_error`, {}));
        expect(refused.reason).toBe("ProviderError");

        const malformed = yield* Effect.flip(serveCallback(relyingParty, redirectUri, {}));
        expect(malformed.reason).toBe("InvalidCallback");
    })
);

it.live("fails the exchange step when the token endpoint refuses", () =>
    Effect.gen(function* () {
        const { relyingParty, stub } = yield* makeProvider();
        const broken = yield* RelyingParty.make({
            issuer,
            authorizationEndpoint: "https://id.example.com/oauth/authorize",
            tokenEndpoint: "https://id.example.com/oauth/broken",
            jwksUri: "https://id.example.com/.well-known/jwks.json",
            clientId,
            redirectUri,
            scopes: ["openid"],
        }).pipe(Effect.provideService(HttpClient.HttpClient, stub));

        const begin = yield* relyingParty.beginAuthorization();
        const transaction = Cookies.toRecord(begin.cookies);
        const state = new URL(begin.headers.location ?? "").searchParams.get("state");

        const failure = yield* Effect.flip(
            serveCallback(broken, `${redirectUri}?code=code-123&state=${state}`, transaction)
        );
        expect(failure.reason).toBe("ExchangeFailed");
    })
);

it.live("applies the cookie prefix and naming policy to every transaction cookie", () =>
    Effect.gen(function* () {
        const { relyingParty } = yield* makeProvider({
            cookies: { prefix: "google_oauth", name: (name) => `__Host-${name}` },
        });

        const begin = yield* relyingParty.beginAuthorization({ payload: "/account" });
        const transaction = Cookies.toRecord(begin.cookies);
        expect(Object.keys(transaction).toSorted()).toStrictEqual([
            "__Host-google_oauth_code_verifier",
            "__Host-google_oauth_payload",
            "__Host-google_oauth_state",
        ]);
    })
);

it.live("recovers the payload on its own and expires the spent cookies", () =>
    Effect.gen(function* () {
        const { relyingParty } = yield* makeProvider();

        const request = HttpServerRequest.fromWeb(
            new Request("https://app.example.com/auth/callback?error=access_denied", {
                headers: { cookie: "oidc_payload=/account" },
            })
        );
        const payload = yield* relyingParty.payload.pipe(
            Effect.provideService(HttpServerRequest.HttpServerRequest, request)
        );
        expect(payload).toStrictEqual(Option.some("/account"));

        const response = yield* relyingParty.expireTransactionCookies(HttpServerResponse.redirect("/done"));
        const setCookieHeaders = Cookies.toSetCookieHeaders(response.cookies);
        for (const name of ["oidc_state", "oidc_code_verifier", "oidc_payload"]) {
            expect(
                setCookieHeaders.some((header) => header.startsWith(`${name}=`) && header.includes("Max-Age=0"))
            ).toBe(true);
        }
    })
);
