/**
 * Below the JWT layer sits the full JWS toolkit (RFC 7515). Two things it
 * offers that compact JWTs cannot:
 *
 * - The General JSON serialization: one payload carrying multiple
 *   signatures, so verifiers holding different keys can each check their own.
 * - Critical extension headers (`crit`): custom protected header parameters,
 *   schema-validated, that verifiers MUST understand — verification is
 *   fail-closed for anyone who does not declare them.
 *
 * Run with:
 *
 *     pnpm tsx examples/05-jws-advanced.ts
 */

import { Console, Effect, Schema } from "effect";

import { NodeRuntime } from "@effect/platform-node";
import { Jws } from "effect-oidc";

const program = Effect.gen(function* () {
    // Two services with different key types co-sign the same payload.
    const ecPair = yield* Effect.promise(() =>
        crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])
    );
    const rsaPair = yield* Effect.promise(() =>
        crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            false,
            ["sign", "verify"]
        )
    );

    // -----------------------------------------------------------------------
    // Multiple signatures — signing with one key produces the Flattened
    // serialization, with several the General serialization.
    // -----------------------------------------------------------------------

    const coSign = Jws.sign({
        privateKeys: [
            { algorithm: "ES256", key: ecPair.privateKey, header: { kid: "release-key" } },
            { algorithm: "RS256", key: rsaPair.privateKey, header: { kid: "audit-key" } },
        ],
    });
    const general = yield* coSign("attest: artifact sha256:3f785...", {});
    yield* Console.log("general serialization:", general);

    // A verifier holding only ONE of the public keys still accepts it — any
    // valid signature over the payload is enough.
    const decoded = yield* Schema.decodeUnknownEffect(Jws.General)(general);
    const viaRsa = yield* Jws.verify({ publicKeys: [rsaPair.publicKey] })(decoded);
    yield* Console.log("verified by", viaRsa.protected.kid, "->", viaRsa.payload);

    // -----------------------------------------------------------------------
    // Critical extension headers — declared with a schema at sign time, and
    // required knowledge at verify time.
    // -----------------------------------------------------------------------

    const signWithExpiry = Jws.sign({
        privateKeys: [{ algorithm: "ES256", key: ecPair.privateKey }],
        criticalHeaders: { expiresAt: Schema.Number },
    });
    const flattened = yield* signWithExpiry("payload guarded by a critical header", { expiresAt: 1_767_225_600 });
    yield* Console.log("crit header on the wire:", flattened.protected);

    const unverified = yield* Schema.decodeUnknownEffect(Jws.Flattened)(flattened);

    // A verifier that does NOT declare the extension must reject the token
    // (RFC 7515 Section 4.1.11) — unknown critical headers are not skippable.
    const unaware = yield* Effect.flip(Jws.verify({ publicKeys: [ecPair.publicKey] })(unverified));
    yield* Console.log("unaware verifier rejects:", unaware._tag);

    // One that declares it verifies the signature AND gets the decoded,
    // typed header value back.
    const aware = yield* Jws.verify({
        publicKeys: [ecPair.publicKey],
        criticalHeaders: { expiresAt: Schema.Number },
    })(unverified);
    yield* Console.log("aware verifier reads expiresAt:", aware.protected.expiresAt);
});

NodeRuntime.runMain(program);
