import { Effect, Encoding, Option, Schema } from "effect";
import { HttpClient, HttpClientResponse } from "effect/unstable/http";

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
    expect(document.grant_types_supported).toStrictEqual(["authorization_code", "refresh_token", "client_credentials"]);
    expect(document.token_endpoint_auth_methods_supported).toStrictEqual([
        "none",
        "client_secret_basic",
        "client_secret_post",
    ]);
    expect(document.revocation_endpoint).toBe("https://id.example.com/oauth/revoke");
});

it("resolves client authentication from the Basic header or the body", () => {
    // client_secret_basic: form-urlencoded parts, joined and base64 encoded.
    // The header wins over any body parameters.
    const header = `Basic ${Encoding.encodeBase64(`${encodeURIComponent("demo service")}:${encodeURIComponent("s3:cret")}`)}`;
    expect(
        Oidc.clientAuthentication({
            authorization: header,
            request: { client_id: "body-client", client_secret: "body-secret" },
        })
    ).toStrictEqual(Option.some({ clientId: "demo service", clientSecret: "s3:cret" }));

    // client_secret_post: body parameters, secret optional (public clients).
    expect(Oidc.clientAuthentication({ request: { client_id: "demo-app", client_secret: undefined } })).toStrictEqual(
        Option.some({ clientId: "demo-app", clientSecret: undefined })
    );

    // Nothing identifying a client, or a malformed Basic header.
    expect(Oidc.clientAuthentication({ request: {} })).toStrictEqual(Option.none());
    expect(Oidc.clientAuthentication({ authorization: "Basic !!!", request: {} })).toStrictEqual(Option.none());
    expect(
        Oidc.clientAuthentication({ authorization: `Basic ${Encoding.encodeBase64("no-separator")}`, request: {} })
    ).toStrictEqual(Option.none());
});

it.live("exchanges client credentials with a Basic-authenticated token request", () =>
    Effect.gen(function* () {
        let authorization: string | undefined = undefined;
        const stub = HttpClient.make((request) => {
            authorization = request.headers.authorization;
            return Effect.succeed(
                HttpClientResponse.fromWeb(
                    request,
                    Response.json({ access_token: "token-123", token_type: "Bearer", expires_in: 3600, scope: "notes" })
                )
            );
        });

        const tokens = yield* Oidc.exchangeClientCredentials({
            tokenEndpoint: "https://id.example.com/oauth/token",
            clientId: "demo-service",
            clientSecret: "demo-service-secret",
            scopes: ["notes"],
        }).pipe(Effect.provideService(HttpClient.HttpClient, stub));

        expect(tokens.access_token).toBe("token-123");
        expect(authorization).toBe(`Basic ${Encoding.encodeBase64("demo-service:demo-service-secret")}`);
    })
);

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

it.live("verifies an RS256 id token, as third-party providers sign them", () =>
    Effect.gen(function* () {
        // Signed with WebCrypto directly rather than Jwt.sign - the signing
        // surface is EC-only, and a hand-rolled token is exactly what an
        // external provider's id token is to this library anyway.
        const pair = yield* Effect.promise(() =>
            crypto.subtle.generateKey(
                {
                    name: "RSASSA-PKCS1-v1_5",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256",
                },
                true,
                ["sign", "verify"]
            )
        );
        const { e, n } = yield* Effect.promise(() => crypto.subtle.exportKey("jwk", pair.publicKey));
        if (n === undefined || e === undefined) {
            return yield* Effect.die(new Error("WebCrypto exported an RSA public JWK without n/e"));
        }
        const jwks = yield* Schema.decodeEffect(Jwt.JwksSchema)({
            keys: [{ kty: "RSA", n, e, alg: "RS256", use: "sig", kid: "rsa-1" }],
        });

        const nowSeconds = Math.floor(Date.now() / 1000);
        const encodePart = (part: Record<string, unknown>) => Encoding.encodeBase64Url(JSON.stringify(part));
        const signingInput = `${encodePart({ alg: "RS256", typ: "JWT", kid: "rsa-1" })}.${encodePart({
            iss: issuer,
            sub: "user-123",
            aud: "client-abc",
            exp: nowSeconds + 300,
            iat: nowSeconds,
        })}`;
        const signature = yield* Effect.promise(() =>
            crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, pair.privateKey, new TextEncoder().encode(signingInput))
        );
        const idToken = `${signingInput}.${Encoding.encodeBase64Url(new Uint8Array(signature))}`;

        const claims = yield* Oidc.verifyIdToken({ idToken, jwks, issuer, clientId: "client-abc" });
        expect(claims.iss).toBe(issuer);
        expect(claims.sub).toBe("user-123");

        // Narrowing the accepted set back down still rejects it
        const narrowed = yield* Effect.flip(
            Oidc.verifyIdToken({ idToken, jwks, issuer, clientId: "client-abc", algorithms: ["ES256"] })
        );
        expect(narrowed._tag).toBe("JwtError");
        expect(narrowed.reason).toBe("BadAlgorithm");
    })
);

it.live("cachedJwks fetches once and reuses the document within the ttl", () =>
    Effect.gen(function* () {
        const { publicJwk } = yield* Jwt.generateSigningKey();
        let fetches = 0;
        const stub = HttpClient.make((request) => {
            fetches += 1;
            return Effect.succeed(HttpClientResponse.fromWeb(request, Response.json({ keys: [publicJwk] })));
        });

        const jwks = yield* Oidc.cachedJwks("https://id.example.com/.well-known/jwks.json");
        const first = yield* jwks.pipe(Effect.provideService(HttpClient.HttpClient, stub));
        const second = yield* jwks.pipe(Effect.provideService(HttpClient.HttpClient, stub));
        expect(fetches).toBe(1);
        expect(second).toStrictEqual(first);
    })
);

it.live("cachedJwks serves the last good document when a refresh fails", () =>
    Effect.gen(function* () {
        const { publicJwk } = yield* Jwt.generateSigningKey();
        let healthy = true;
        let fetches = 0;
        const stub = HttpClient.make((request) => {
            fetches += 1;
            return Effect.succeed(
                HttpClientResponse.fromWeb(request, healthy ? Response.json({ keys: [publicJwk] }) : Response.json({}))
            );
        });

        const jwks = yield* Oidc.cachedJwks("https://id.example.com/.well-known/jwks.json", "10 millis");
        const first = yield* jwks.pipe(Effect.provideService(HttpClient.HttpClient, stub));

        // Past the ttl the refresh runs and fails; the stale document answers.
        healthy = false;
        yield* Effect.sleep("50 millis");
        const stale = yield* jwks.pipe(Effect.provideService(HttpClient.HttpClient, stub));
        expect(fetches).toBe(2);
        expect(stale).toStrictEqual(first);
    })
);

it.live("cachedJwks does not cache a failure for the ttl, the next caller retries", () =>
    Effect.gen(function* () {
        const { publicJwk } = yield* Jwt.generateSigningKey();
        let healthy = false;
        let fetches = 0;
        const stub = HttpClient.make((request) => {
            fetches += 1;
            return Effect.succeed(
                HttpClientResponse.fromWeb(request, healthy ? Response.json({ keys: [publicJwk] }) : Response.json({}))
            );
        });

        // The very first fetch fails closed, for its caller only.
        const jwks = yield* Oidc.cachedJwks("https://id.example.com/.well-known/jwks.json");
        yield* Effect.flip(jwks.pipe(Effect.provideService(HttpClient.HttpClient, stub)));
        expect(fetches).toBe(1);

        // The endpoint recovers: the next caller succeeds immediately, with
        // no ttl to wait out.
        healthy = true;
        const document = yield* jwks.pipe(Effect.provideService(HttpClient.HttpClient, stub));
        expect(fetches).toBe(2);
        expect(document).toStrictEqual({ keys: [publicJwk] });
    })
);
