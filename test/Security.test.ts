import { Effect, Schema } from "effect";

import { expect, it } from "@effect/vitest";
import { Jwk, Jws, Jwt } from "effect-oidc";

const claims = { iss: "iss", sub: "sub", aud: "aud", exp: 9999999999, iat: 1 };

it.live("binds algorithm family to key type and rejects use:enc keys", () =>
    Effect.gen(function* () {
        const { publicJwk } = yield* Jwt.generateSigningKey();
        expect(Jwk.isCompatibleWith("ES256", publicJwk)).toBe(true);
        expect(Jwk.isCompatibleWith("ES384", publicJwk)).toBe(false);
        expect(Jwk.isCompatibleWith("RS256", publicJwk)).toBe(false);
        expect(Jwk.isCompatibleWith("HS256", publicJwk)).toBe(false);
        expect(Jwk.isCompatibleWith("ES256", { ...publicJwk, use: "enc" as const })).toBe(false);

        const oct = { kty: "oct" as const, k: "AAAA" };
        expect(Jwk.isSymmetric(oct)).toBe(true);
        expect(Jwk.isSymmetric(publicJwk)).toBe(false);
    })
);

it.live("verifies against a JWKS containing a malformed key alongside the good one", () =>
    Effect.gen(function* () {
        const { privateJwk, publicJwk } = yield* Jwt.generateSigningKey();
        const token = yield* Jwt.sign({ privateJwk, payload: claims });

        // A compatible (ES256) but structurally broken key must be skipped,
        // not fail the whole verification — one bad key in an otherwise-valid
        // JWKS must not deny service to tokens signed by the good keys.
        const { kid: _kid, ...kidless } = publicJwk;
        const brokenKey = { ...kidless, x: "!!!not-base64!!!" };
        const verified = yield* Jwt.verify(token, {
            jwks: { keys: [brokenKey, publicJwk] },
            algorithms: ["ES256"],
        });
        expect(verified.sub).toBe("sub");
    })
);

it.live("does not crash on a key whose algorithm mismatches (fail-closed, not defect)", () =>
    Effect.gen(function* () {
        // An RSA-PSS verify key handed to a verifier for an ES256 token:
        // crypto.subtle.verify would reject; it must be skipped so the
        // correct key still verifies.
        const es = yield* Effect.promise(() =>
            crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
        );
        const rsa = yield* Effect.promise(() =>
            crypto.subtle.generateKey(
                { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
                true,
                ["sign", "verify"]
            )
        );
        const encoded = yield* Jws.sign({ privateKeys: [{ algorithm: "ES256", key: es.privateKey }] })("hi", {});
        const jws = yield* Schema.decodeUnknownEffect(Jws.Flattened)(encoded);

        // The rsa key comes first (would throw inside crypto.subtle.verify),
        // then the correct es key.
        const result = yield* Jws.verify({ publicKeys: [rsa.publicKey, es.publicKey] })(jws);
        expect(result.payload).toBe("hi");
    })
);

it.live("rejects a General JWS exceeding maxSignatures", () =>
    Effect.gen(function* () {
        const pair = yield* Effect.promise(() =>
            crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
        );
        const encoded = yield* Jws.sign({
            privateKeys: [
                { algorithm: "ES256", key: pair.privateKey },
                { algorithm: "ES256", key: pair.privateKey },
            ],
        })("x", {});
        const jws = yield* Schema.decodeUnknownEffect(Jws.General)(encoded);

        const error = yield* Effect.flip(Jws.verify({ publicKeys: [pair.publicKey], maxSignatures: 1 })(jws));
        expect(error._tag).toBe("InvalidJws");
    })
);

it.live("preserves the CRT parameters of a full RSA private key", () =>
    Effect.gen(function* () {
        const full = { kty: "RSA", n: "nnn", e: "AQAB", d: "ddd", p: "ppp", q: "qqq", dp: "dpv", dq: "dqv", qi: "qiv" };
        const decoded = yield* Schema.decodeUnknownEffect(Jwk.RsaPrivateKey)(full);
        expect(decoded).toStrictEqual(full);
    })
);

it.live("still decodes a d-only RSA private key", () =>
    Effect.gen(function* () {
        const dOnly = { kty: "RSA", n: "nnn", e: "AQAB", d: "ddd" };
        const decoded = yield* Schema.decodeUnknownEffect(Jwk.RsaPrivateKey)(dOnly);
        expect(decoded).toStrictEqual(dOnly);
    })
);
