import { Effect } from "effect";

import { expect, it } from "@effect/vitest";
import { type Jwa, Jwe } from "effect-oidc";

const encryptions: ReadonlyArray<(typeof Jwa.JweEncryption)["Type"]> = [
    "A128CBC-HS256",
    "A192CBC-HS384",
    "A256CBC-HS512",
    "A128GCM",
    "A192GCM",
    "A256GCM",
];

const cekBytesFor = (enc: (typeof Jwa.JweEncryption)["Type"]): number => {
    switch (enc) {
        case "A128GCM":
            return 16;
        case "A192GCM":
            return 24;
        case "A256GCM":
            return 32;
        case "A128CBC-HS256":
            return 32;
        case "A192CBC-HS384":
            return 48;
        case "A256CBC-HS512":
            return 64;
    }
};

const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const decode = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

const importAesKw = (bytes: Uint8Array<ArrayBuffer>) =>
    Effect.promise(() => crypto.subtle.importKey("raw", bytes, "AES-KW", false, ["wrapKey", "unwrapKey"]));
const importAesGcm = (bytes: Uint8Array<ArrayBuffer>) =>
    Effect.promise(() => crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]));
const importHmac = (bytes: Uint8Array<ArrayBuffer>) =>
    Effect.promise(() => crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, true, ["sign"]));
const importPbkdf2 = (bytes: Uint8Array<ArrayBuffer>) =>
    Effect.promise(() => crypto.subtle.importKey("raw", bytes, "PBKDF2", false, ["deriveBits"]));

/** Builds an encrypt/decrypt key pair appropriate for a key management algorithm. */
const keysFor = (alg: (typeof Jwa.JweAlgorithm)["Type"], enc: (typeof Jwa.JweEncryption)["Type"]) =>
    Effect.gen(function* () {
        switch (alg) {
            case "dir": {
                // The shared key IS the CEK, so it must match the content algorithm's size.
                const key = yield* importHmac(randomBytes(cekBytesFor(enc)));
                return { encryptKey: key, decryptKey: key };
            }
            case "RSA-OAEP":
            case "RSA-OAEP-256": {
                const pair = yield* Effect.promise(() =>
                    crypto.subtle.generateKey(
                        {
                            name: "RSA-OAEP",
                            modulusLength: 2048,
                            publicExponent: new Uint8Array([1, 0, 1]),
                            hash: alg === "RSA-OAEP" ? "SHA-1" : "SHA-256",
                        },
                        true,
                        ["encrypt", "decrypt"]
                    )
                );
                return { encryptKey: pair.publicKey, decryptKey: pair.privateKey };
            }
            case "A128KW":
            case "A192KW":
            case "A256KW": {
                const bytes = alg === "A128KW" ? 16 : alg === "A192KW" ? 24 : 32;
                const key = yield* importAesKw(randomBytes(bytes));
                return { encryptKey: key, decryptKey: key };
            }
            case "A128GCMKW":
            case "A192GCMKW":
            case "A256GCMKW": {
                const bytes = alg === "A128GCMKW" ? 16 : alg === "A192GCMKW" ? 24 : 32;
                const key = yield* importAesGcm(randomBytes(bytes));
                return { encryptKey: key, decryptKey: key };
            }
            case "ECDH-ES":
            case "ECDH-ES+A128KW":
            case "ECDH-ES+A192KW":
            case "ECDH-ES+A256KW": {
                const pair = yield* Effect.promise(() =>
                    crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
                );
                return { encryptKey: pair.publicKey, decryptKey: pair.privateKey };
            }
            case "PBES2-HS256+A128KW":
            case "PBES2-HS384+A192KW":
            case "PBES2-HS512+A256KW": {
                const key = yield* importPbkdf2(new TextEncoder().encode("correct horse battery staple"));
                return { encryptKey: key, decryptKey: key };
            }
        }
    });

const algorithms: ReadonlyArray<(typeof Jwa.JweAlgorithm)["Type"]> = [
    "dir",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "A128KW",
    "A192KW",
    "A256KW",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
];

const plaintext = "The true sign of intelligence is not knowledge but imagination.";

for (const alg of algorithms) {
    it.live(`round-trips ${alg} with every content encryption algorithm`, () =>
        Effect.gen(function* () {
            for (const enc of encryptions) {
                const { decryptKey, encryptKey } = yield* keysFor(alg, enc);
                const jwe = yield* Jwe.encrypt({
                    plaintext,
                    key: encryptKey,
                    algorithm: alg,
                    encryption: enc,
                    // keep PBES2 fast in tests
                    p2c: 1000,
                });
                const parts = jwe.split(".");
                expect(parts.length, `${alg}/${enc} is not a 5-part compact JWE`).toBe(5);

                const result = yield* Jwe.decrypt({ jwe, key: decryptKey });
                expect(decode(result.plaintext), `${alg}/${enc} did not round-trip`).toBe(plaintext);
                expect(result.protectedHeader.alg).toBe(alg);
                expect(result.protectedHeader.enc).toBe(enc);
            }
        })
    );
}

it.live("carries extra protected header parameters", () =>
    Effect.gen(function* () {
        const key = yield* importAesGcm(randomBytes(16));
        const jwe = yield* Jwe.encrypt({
            plaintext,
            key,
            algorithm: "A128GCMKW",
            encryption: "A128GCM",
            protectedHeader: { kid: "key-1", cty: "text/plain" },
        });
        const result = yield* Jwe.decrypt({ jwe, key });
        expect(result.protectedHeader.kid).toBe("key-1");
        expect(result.protectedHeader.cty).toBe("text/plain");
    })
);

it.live("rejects a tampered ciphertext", () =>
    Effect.gen(function* () {
        const key = yield* importAesGcm(randomBytes(32));
        const jwe = yield* Jwe.encrypt({ plaintext, key, algorithm: "A256GCMKW", encryption: "A256GCM" });
        const parts = jwe.split(".");
        // flip a character in the ciphertext segment
        const ct = parts[3];
        parts[3] = ct.slice(0, -2) + (ct.at(-2) === "A" ? "B" : "A") + ct.slice(-1);
        const error = yield* Effect.flip(Jwe.decrypt({ jwe: parts.join("."), key }));
        expect(error.reason).toBe("DecryptionFailed");
    })
);

it.live("rejects a tampered CBC-HMAC tag", () =>
    Effect.gen(function* () {
        const key = yield* importAesKw(randomBytes(16));
        const jwe = yield* Jwe.encrypt({ plaintext, key, algorithm: "A128KW", encryption: "A128CBC-HS256" });
        const parts = jwe.split(".");
        const tag = parts[4];
        parts[4] = tag.slice(0, -2) + (tag.at(-2) === "A" ? "B" : "A") + tag.slice(-1);
        const error = yield* Effect.flip(Jwe.decrypt({ jwe: parts.join("."), key }));
        expect(error.reason).toBe("DecryptionFailed");
    })
);

it.live("fails to decrypt with the wrong key", () =>
    Effect.gen(function* () {
        const good = yield* keysFor("RSA-OAEP", "A256GCM");
        const other = yield* keysFor("RSA-OAEP", "A256GCM");
        const jwe = yield* Jwe.encrypt({
            plaintext,
            key: good.encryptKey,
            algorithm: "RSA-OAEP",
            encryption: "A256GCM",
        });
        const error = yield* Effect.flip(Jwe.decrypt({ jwe, key: other.decryptKey }));
        expect(["DecryptionFailed", "KeyManagementFailed"]).toContain(error.reason);
    })
);

// RFC 7516 Appendix A.3: A128KW + A128CBC-HS256. This is external ground
// truth for the composite AES-CBC-HMAC content decryption and AES key
// unwrap against the exact bytes produced by the spec authors.
it.live("decrypts the RFC 7516 A.3 vector", () =>
    Effect.gen(function* () {
        // JWK { kty: "oct", k: "GawgguFyGrWKav7AX4VKUg" }
        const rawKey = Uint8Array.from(
            atob("GawgguFyGrWKav7AX4VKUg".replace(/-/g, "+").replace(/_/g, "/") + "=="),
            (c) => c.charCodeAt(0)
        );
        const key = yield* importAesKw(rawKey);
        const jwe =
            "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
            "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
            "AxY8DCtDaGlsbGljb3RoZQ." +
            "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
            "U0m_YmjN04DJvceFICbCVQ";
        const result = yield* Jwe.decrypt({ jwe, key });
        expect(decode(result.plaintext)).toBe("Live long and prosper.");
        expect(result.protectedHeader.alg).toBe("A128KW");
        expect(result.protectedHeader.enc).toBe("A128CBC-HS256");
    })
);
