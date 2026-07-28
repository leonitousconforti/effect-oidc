import { Effect, Schema } from "effect";

import { expect, it } from "@effect/vitest";
import { Jwe, Jwk, Jws, Jwt } from "effect-oidc";

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

const importAesKw = (bytes: Uint8Array<ArrayBuffer>) =>
    Effect.promise(() => crypto.subtle.importKey("raw", bytes, "AES-KW", false, ["wrapKey", "unwrapKey"]));
const importPbkdf2 = (bytes: Uint8Array<ArrayBuffer>) =>
    Effect.promise(() => crypto.subtle.importKey("raw", bytes, "PBKDF2", false, ["deriveBits"]));
const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const b64 = (bytes: Uint8Array) =>
    btoa(String.fromCharCode(...bytes))
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");

it.live("bounds the PBES2 iteration count on JWE decrypt (DoS guard)", () =>
    Effect.gen(function* () {
        const key = yield* importPbkdf2(new TextEncoder().encode("pw"));
        // craft a token with an enormous p2c by editing the header of a real one
        const jwe = yield* Jwe.encrypt({
            plaintext: "secret",
            key,
            algorithm: "PBES2-HS256+A128KW",
            encryption: "A128GCM",
            p2c: 1000,
        });
        const parts = jwe.split(".");
        const header = JSON.parse(
            new TextDecoder().decode(
                Uint8Array.from(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))
            )
        );
        header.p2c = 100_000_000;
        parts[0] = b64(new TextEncoder().encode(JSON.stringify(header)));
        const error = yield* Effect.flip(Jwe.decrypt({ jwe: parts.join("."), key }));
        expect(error.reason).toBe("Malformed");
    })
);

it.live("enforces JWE key-management and content-encryption allowlists", () =>
    Effect.gen(function* () {
        const key = yield* importAesKw(rnd(16));
        const jwe = yield* Jwe.encrypt({ plaintext: "hi", key, algorithm: "A128KW", encryption: "A128GCM" });

        const badAlg = yield* Effect.flip(Jwe.decrypt({ jwe, key, keyManagementAlgorithms: ["RSA-OAEP"] }));
        expect(badAlg.reason).toBe("UnsupportedAlgorithm");

        const badEnc = yield* Effect.flip(Jwe.decrypt({ jwe, key, contentEncryptionAlgorithms: ["A256GCM"] }));
        expect(badEnc.reason).toBe("UnsupportedAlgorithm");

        // allowlist that matches still works
        const ok = yield* Jwe.decrypt({
            jwe,
            key,
            keyManagementAlgorithms: ["A128KW"],
            contentEncryptionAlgorithms: ["A128GCM"],
        });
        expect(new TextDecoder().decode(ok.plaintext)).toBe("hi");
    })
);

it.live("rejects a JWE with an unrecognized crit header (RFC 7516 4.1.13)", () =>
    Effect.gen(function* () {
        const key = yield* importAesKw(rnd(16));
        const jwe = yield* Jwe.encrypt({
            plaintext: "hi",
            key,
            algorithm: "A128KW",
            encryption: "A128GCM",
            protectedHeader: { crit: ["exp"], exp: 1 },
        });
        const error = yield* Effect.flip(Jwe.decrypt({ jwe, key }));
        expect(error.reason).toBe("UnsupportedAlgorithm");
    })
);

it.live("returns a typed Malformed error (not a defect) on malformed JWE base64url", () =>
    Effect.gen(function* () {
        const key = yield* importAesKw(rnd(16));
        const jwe = yield* Jwe.encrypt({ plaintext: "hi", key, algorithm: "A128KW", encryption: "A128GCM" });
        const parts = jwe.split(".");
        parts[3] = "@@@not-base64@@@";
        const error = yield* Effect.flip(Jwe.decrypt({ jwe: parts.join("."), key }));
        expect(error.reason).toBe("Malformed");
    })
);

it.live("round-trips ECDH-ES with apu/apv bound into the KDF", () =>
    Effect.gen(function* () {
        const pair = yield* Effect.promise(() =>
            crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
        );
        const jwe = yield* Jwe.encrypt({
            plaintext: "agree",
            key: pair.publicKey,
            algorithm: "ECDH-ES",
            encryption: "A128GCM",
            apu: new TextEncoder().encode("Alice"),
            apv: new TextEncoder().encode("Bob"),
        });
        const result = yield* Jwe.decrypt({ jwe, key: pair.privateKey });
        expect(new TextDecoder().decode(result.plaintext)).toBe("agree");
        // apu/apv are carried in the protected header and bound into the KDF
        expect(result.protectedHeader.apu).toBeDefined();
        expect(result.protectedHeader.apv).toBeDefined();
    })
);

it.live("rejects a dir key whose length does not match the enc CEK size", () =>
    Effect.gen(function* () {
        // A128GCM needs a 16-byte CEK; give dir a 32-byte key
        const key = yield* Effect.promise(() =>
            crypto.subtle.importKey("raw", rnd(32), { name: "HMAC", hash: "SHA-256" }, true, ["sign"])
        );
        const error = yield* Effect.flip(
            Jwe.encrypt({ plaintext: "hi", key, algorithm: "dir", encryption: "A128GCM" })
        );
        expect(error.reason).toBe("KeyManagementFailed");
    })
);

it.live("rejects a wrong-length CEK (typed error, not a defect)", () =>
    Effect.gen(function* () {
        // An attacker with the recipient's RSA public key can RSA-OAEP-encrypt
        // a CEK of the wrong length. It must fail closed as DecryptionFailed,
        // never reach AES importKey and crash as an unhandled defect.
        const pair = yield* Effect.promise(() =>
            crypto.subtle.generateKey(
                { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
                true,
                ["encrypt", "decrypt"]
            )
        );
        // A128GCM needs a 16-byte CEK; wrap a 20-byte one instead
        const badCek = rnd(20);
        const wrapped = new Uint8Array(
            yield* Effect.promise(() => crypto.subtle.encrypt({ name: "RSA-OAEP" }, pair.publicKey, badCek))
        );
        const header = b64(new TextEncoder().encode(JSON.stringify({ alg: "RSA-OAEP", enc: "A128GCM" })));
        const jwe = [header, b64(wrapped), b64(rnd(12)), b64(rnd(8)), b64(rnd(16))].join(".");
        const error = yield* Effect.flip(Jwe.decrypt({ jwe, key: pair.privateKey }));
        expect(error.reason).toBe("DecryptionFailed");
    })
);

it.live("returns a typed error (not a defect) when a dir key cannot be exported", () =>
    Effect.gen(function* () {
        // An attacker picks alg:"dir" but the recipient key is an RSA private
        // key, which crypto.subtle.exportKey("raw", ...) rejects. That must fail
        // closed as a typed KeyManagementFailed, never surface as a defect.
        // Effect.flip only completes for a typed failure, so its success here
        // proves the branch does not die.
        const pair = yield* Effect.promise(() =>
            crypto.subtle.generateKey(
                { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
                true,
                ["encrypt", "decrypt"]
            )
        );
        const header = b64(new TextEncoder().encode(JSON.stringify({ alg: "dir", enc: "A128GCM" })));
        const jwe = [header, "", b64(rnd(12)), b64(rnd(8)), b64(rnd(16))].join(".");
        const error = yield* Effect.flip(Jwe.decrypt({ jwe, key: pair.privateKey }));
        expect(error.reason).toBe("KeyManagementFailed");
    })
);
