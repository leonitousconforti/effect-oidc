import { Effect, Encoding } from "effect";

import { expect, it } from "@effect/vitest";
import { Jwt, Oidc } from "effect-oidc";

const issuer = "https://id.example.com";

it("builds a discovery document rooted at the issuer", () => {
    const document = Oidc.makeDiscoveryDocument(issuer);
    expect(document.issuer).toBe(issuer);
    expect(document.authorization_endpoint).toBe("https://id.example.com/oauth/authorize");
    expect(document.token_endpoint).toBe("https://id.example.com/oauth/token");
    expect(document.jwks_uri).toBe("https://id.example.com/.well-known/jwks.json");
    expect(document.code_challenge_methods_supported).toStrictEqual(["S256"]);
});

it("builds an authorization url that decodes back to the request", () => {
    const url = new URL(
        Oidc.authorizationUrl({
            authorizationEndpoint: "https://id.example.com/oauth/authorize",
            clientId: "client-abc",
            redirectUri: "https://app.example.com/callback",
            scopes: ["openid", "profile"],
            state: "state-1",
            codeChallenge: "challenge-1",
            nonce: "nonce-1",
        })
    );
    expect(url.origin).toBe("https://id.example.com");
    expect(url.pathname).toBe("/oauth/authorize");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("client-abc");
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.example.com/callback");
    expect(url.searchParams.get("scope")).toBe("openid profile");
    expect(url.searchParams.get("state")).toBe("state-1");
    expect(url.searchParams.get("code_challenge")).toBe("challenge-1");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("nonce")).toBe("nonce-1");
});

it.live("generates a PKCE pair whose challenge is the S256 digest of the verifier", () =>
    Effect.gen(function* () {
        const pkce = yield* Oidc.generatePkce();
        const digest = yield* Effect.promise(() =>
            crypto.subtle.digest("SHA-256", new TextEncoder().encode(pkce.verifier))
        );
        expect(pkce.method).toBe("S256");
        expect(pkce.challenge).toBe(Encoding.encodeBase64Url(new Uint8Array(digest)));
    })
);

it.live("issues and verifies an id token, including the nonce", () =>
    Effect.gen(function* () {
        const { privateJwk, publicJwk } = yield* Jwt.generateSigningKey();
        const jwks = { keys: [publicJwk] };
        const idToken = yield* Oidc.issueIdToken({
            privateJwk,
            issuer,
            subject: "user-123",
            clientId: "client-abc",
            ttlSeconds: 300,
            nonce: "nonce-1",
            profile: { name: "Some User", picture: "https://app.example.com/avatar.png" },
        });

        const claims = yield* Oidc.verifyIdToken({
            idToken,
            jwks,
            issuer,
            clientId: "client-abc",
            nonce: "nonce-1",
        });
        expect(claims.iss).toBe(issuer);
        expect(claims.sub).toBe("user-123");
        expect(claims.aud).toBe("client-abc");
        expect(claims.name).toBe("Some User");
        expect(claims.picture).toBe("https://app.example.com/avatar.png");

        const wrongNonce = yield* Effect.flip(
            Oidc.verifyIdToken({ idToken, jwks, issuer, clientId: "client-abc", nonce: "nonce-2" })
        );
        expect(wrongNonce._tag).toBe("JwtError");

        const wrongClient = yield* Effect.flip(Oidc.verifyIdToken({ idToken, jwks, issuer, clientId: "client-other" }));
        expect(wrongClient._tag).toBe("JwtError");
    })
);
