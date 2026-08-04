import { DateTime, Effect } from "effect";

import { expect, it } from "@effect/vitest";
import { Jwt, Oidc } from "effect-oidc";

const issuer = "https://id.example.com";

it.live("signs and verifies a JWT against the JWKS", () =>
    Effect.gen(function* () {
        const { privateJwk, publicJwk } = yield* Jwt.generateSigningKey();
        const token = yield* Oidc.issueAccessToken({
            privateJwk,
            issuer,
            subject: "user-123",
            audience: "my-api",
            clientId: "client-abc",
            scope: "openid profile",
            ttlSeconds: 3600,
        });

        const claims = yield* Jwt.verify(token, {
            jwks: { keys: [publicJwk] },
            issuer,
            audience: "my-api",
            algorithms: ["ES256"],
            types: ["JWT"],
        });

        const accessClaims = yield* Jwt.decodeClaims(Oidc.AccessTokenClaimsSchema)(claims);
        expect(accessClaims.iss).toBe(issuer);
        expect(accessClaims.sub).toBe("user-123");
        expect(accessClaims.aud).toBe("my-api");
        expect(accessClaims.scope).toBe("openid profile");
        expect(accessClaims.client_id).toBe("client-abc");
    })
);

it.live("rejects the wrong issuer, audience, algorithm, and type", () =>
    Effect.gen(function* () {
        const { privateJwk, publicJwk } = yield* Jwt.generateSigningKey();
        const jwks = { keys: [publicJwk] };
        const token = yield* Oidc.issueAccessToken({
            privateJwk,
            issuer,
            subject: "user-123",
            audience: "my-api",
            clientId: "client-abc",
            scope: "openid",
            ttlSeconds: 3600,
        });

        const badIssuer = yield* Effect.flip(Jwt.verify(token, { jwks, issuer: "https://evil.example.com" }));
        expect(badIssuer.reason).toBe("BadIssuer");

        const badAudience = yield* Effect.flip(Jwt.verify(token, { jwks, audience: "other-api" }));
        expect(badAudience.reason).toBe("BadAudience");

        const badAlgorithm = yield* Effect.flip(Jwt.verify(token, { jwks, algorithms: ["RS256"] }));
        expect(badAlgorithm.reason).toBe("BadAlgorithm");

        const badType = yield* Effect.flip(Jwt.verify(token, { jwks, types: ["at+jwt"] }));
        expect(badType.reason).toBe("BadType");
    })
);

it.live("rejects an expired token", () =>
    Effect.gen(function* () {
        const { privateJwk, publicJwk } = yield* Jwt.generateSigningKey();
        const nowSeconds = Math.floor(DateTime.toEpochMillis(yield* DateTime.now) / 1000);
        const token = yield* Jwt.sign({
            privateJwk,
            payload: {
                iss: issuer,
                sub: "user-123",
                aud: "my-api",
                exp: nowSeconds - 3600,
                iat: nowSeconds - 7200,
            },
        });

        const expired = yield* Effect.flip(Jwt.verify(token, { jwks: { keys: [publicJwk] } }));
        expect(expired.reason).toBe("Expired");
    })
);

it.live("rejects a token signed by a different key", () =>
    Effect.gen(function* () {
        const signingKey = yield* Jwt.generateSigningKey();
        const otherKey = yield* Jwt.generateSigningKey();
        const token = yield* Oidc.issueAccessToken({
            privateJwk: signingKey.privateJwk,
            issuer,
            subject: "user-123",
            audience: "my-api",
            clientId: "client-abc",
            scope: "openid",
            ttlSeconds: 3600,
        });

        // A key with a different kid is never even tried
        const unknownKey = yield* Effect.flip(Jwt.verify(token, { jwks: { keys: [otherKey.publicJwk] } }));
        expect(unknownKey.reason).toBe("UnknownKey");

        // A kid-less key is tried, but the signature does not verify
        const { kid: _kid, ...kidlessOtherKey } = otherKey.publicJwk;
        const badSignature = yield* Effect.flip(Jwt.verify(token, { jwks: { keys: [kidlessOtherKey] } }));
        expect(badSignature.reason).toBe("BadSignature");
    })
);

it.live("rejects garbage tokens as malformed", () =>
    Effect.gen(function* () {
        const { publicJwk } = yield* Jwt.generateSigningKey();
        const malformed = yield* Effect.flip(Jwt.verify("not-a-jwt", { jwks: { keys: [publicJwk] } }));
        expect(malformed.reason).toBe("Malformed");
    })
);
