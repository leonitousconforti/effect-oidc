/**
 * High-level JSON Web Tokens (RFC 7519) built on the {@link Jws}, {@link Jwk},
 * and {@link Jwa} modules: compact-serialized, signed with any supported JWS
 * algorithm, verified against a JWKS with registered-claim validation.
 *
 * This is the opinionated layer the OIDC modules use. Reach for the `Jws`
 * module directly when you need multiple signatures, unprotected headers,
 * critical extension headers, or non-JSON payloads.
 *
 * @since 1.0.0
 * @category Jwt
 * @see https://www.rfc-editor.org/rfc/rfc7519 - JSON Web Token (JWT)
 */

import { DateTime, Effect, Schema } from "effect";

import * as Jwa from "./Jwa.ts";
import * as Jwk from "./Jwk.ts";
import * as Jws from "./Jws.ts";

/**
 * Public EC signing key as published in the JWKS document.
 *
 * @since 1.0.0
 * @category Schema
 */
export const PublicJwkSchema = Jwk.EcPublicKey;

/**
 * Private EC signing key, held only by the provider. Load it from secret
 * configuration - it is never serialized into any response.
 *
 * @since 1.0.0
 * @category Schema
 */
export const PrivateJwkSchema = Jwk.EcPrivateKey;

/**
 * The JWKS document served at `/.well-known/jwks.json`.
 *
 * @since 1.0.0
 * @category Schema
 */
export const JwksSchema = Jwk.JwkSet;

/**
 * The registered claims (RFC 7519 Section 4.1) every issued token carries.
 *
 * @since 1.0.0
 * @category Schema
 */
export const RegisteredClaimsSchema = Schema.Struct({
    iss: Schema.String,
    sub: Schema.String,
    aud: Schema.Union([Schema.String, Schema.Array(Schema.String)]),
    exp: Schema.Number,
    iat: Schema.Number,
    nbf: Schema.Number.pipe(Schema.optional),
    jti: Schema.String.pipe(Schema.optional),
});

/**
 * Registered claims plus a rest record for token-specific claims, which can
 * be decoded with a more specific schema from the claims returned by
 * {@link verify}.
 *
 * @since 1.0.0
 * @category Schema
 */
export const StandardClaimsSchema = Schema.StructWithRest(RegisteredClaimsSchema, [
    Schema.Record(Schema.String, Schema.UndefinedOr(Schema.Unknown)),
]);

/**
 * @since 1.0.0
 * @category Errors
 */
export class JwtError extends Schema.Error<JwtError>("effect-oidc/JwtError")({
    _tag: Schema.tag("JwtError"),
    reason: Schema.Literals([
        "Malformed",
        "UnknownKey",
        "BadAlgorithm",
        "BadType",
        "BadSignature",
        "Expired",
        "NotYetValid",
        "BadIssuer",
        "BadAudience",
    ]),
}) {}

/** Seconds of clock skew tolerated when validating time claims. */
const CLOCK_SKEW_SECONDS = 30;

/** @internal */
const PayloadFromJson = Schema.fromJsonString(Schema.Record(Schema.String, Schema.UndefinedOr(Schema.Unknown)));

/** @internal */
const ClaimsFromJson = Schema.fromJsonString(StandardClaimsSchema);

/** @internal */
const CompactFromString = Schema.String.pipe(Schema.decodeTo(Jws.Compact));

/** @internal */
const HeaderHintSchema = Schema.StringFromBase64Url.pipe(
    Schema.decodeTo(
        Schema.fromJsonString(
            Schema.Struct({
                alg: Jwa.JwsAlgorithm,
                kid: Schema.String.pipe(Schema.optional),
                typ: Schema.String.pipe(Schema.optional),
            })
        )
    )
);

/**
 * Generates a fresh ES256 signing key pair with a random `kid`. Intended for
 * provider key provisioning/rotation scripts - persist the private JWK as a
 * secret and publish the public JWK in the JWKS document.
 *
 * @since 1.0.0
 * @category Keys
 */
export const generateSigningKey = Effect.fnUntraced(function* () {
    const pair = yield* Effect.promise(() =>
        crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
    );
    const kid = crypto.randomUUID();
    const { d, x, y } = yield* Effect.promise(() => crypto.subtle.exportKey("jwk", pair.privateKey));
    if (d === undefined || x === undefined || y === undefined) {
        return yield* Effect.die(new Error("WebCrypto exported an EC private JWK without d/x/y"));
    }
    return {
        privateJwk: yield* Schema.decodeEffect(PrivateJwkSchema)({
            kty: "EC",
            crv: "P-256",
            d,
            x,
            y,
            kid,
            alg: "ES256",
            use: "sig",
            key_ops: ["sign"],
        }),
        publicJwk: yield* Schema.decodeEffect(PublicJwkSchema)({
            kty: "EC",
            crv: "P-256",
            x,
            y,
            kid,
            alg: "ES256",
            use: "sig",
            key_ops: ["verify"],
        }),
    };
});

/**
 * Signs a payload as a compact-serialized JWT with the given private JWK,
 * using the key's `alg` (defaulting to ES256) and carrying its `kid` in the
 * protected header.
 *
 * @since 1.0.0
 * @category Signing
 */
export const sign = Effect.fnUntraced(function* (options: {
    readonly privateJwk: Schema.Schema.Type<typeof PrivateJwkSchema>;
    readonly payload: Record<string, unknown>;
}) {
    const algorithm = options.privateJwk.alg ?? "ES256";
    const key = yield* Effect.promise(() =>
        crypto.subtle.importKey("jwk", Jwk.toJsonWebKey(options.privateJwk), Jwa.importParameters(algorithm), false, [
            "sign",
        ])
    );

    const signer = Jws.sign({
        payload: PayloadFromJson,
        privateKeys: [
            {
                algorithm,
                key,
                header: {
                    typ: "JWT",
                    ...(options.privateJwk.kid === undefined ? {} : { kid: options.privateJwk.kid }),
                },
            },
        ],
    });

    const flattened = yield* signer(options.payload, {});
    return `${flattened.protected}.${flattened.payload}.${flattened.signature}`;
});

/**
 * Verifies a compact-serialized JWT against a JWKS: signature (any supported
 * JWS algorithm, with `kid`-based key selection), `exp`/`nbf` (with 30s
 * skew), and, when provided, `iss` and `aud`. Returns the validated
 * standard claims plus the rest record for decoding token-specific claims
 * with a more precise schema.
 *
 * @since 1.0.0
 * @category Verification
 */
export const verify = Effect.fnUntraced(function* (
    token: string,
    options: {
        readonly jwks: Schema.Schema.Type<typeof JwksSchema>;
        readonly issuer?: string | undefined;
        readonly audience?: string | undefined;
        /** When set, only these `alg` values are accepted (e.g. `["ES256"]`). */
        readonly algorithms?: ReadonlyArray<(typeof Jwa.JwsAlgorithm)["Type"]> | undefined;
        /** When set, the `typ` header must be present and one of these. */
        readonly types?: ReadonlyArray<string> | undefined;
    }
) {
    const flattened = yield* Schema.decodeEffect(CompactFromString)(token).pipe(
        Effect.mapError(() => new JwtError({ reason: "Malformed" }))
    );

    const hint = yield* Schema.decodeEffect(HeaderHintSchema)(flattened.protected).pipe(
        Effect.mapError(() => new JwtError({ reason: "Malformed" }))
    );

    if (options.algorithms !== undefined && !options.algorithms.includes(hint.alg)) {
        return yield* new JwtError({ reason: "BadAlgorithm" });
    }
    if (options.types !== undefined && (hint.typ === undefined || !options.types.includes(hint.typ))) {
        return yield* new JwtError({ reason: "BadType" });
    }

    const candidates = options.jwks.keys
        .filter((jwk) => Jwk.isCompatibleWith(hint.alg, jwk))
        .filter((jwk) => hint.kid === undefined || jwk.kid === undefined || jwk.kid === hint.kid);
    if (candidates.length === 0) return yield* new JwtError({ reason: "UnknownKey" });

    // Import each candidate independently, skipping malformed keys rather than
    // failing the whole verification - one bad key in an otherwise-valid JWK
    // Set must not deny service to tokens signed by the good keys.
    const imported = yield* Effect.forEach(candidates, (jwk) =>
        Effect.tryPromise(() =>
            crypto.subtle.importKey("jwk", Jwk.toJsonWebKey(jwk), Jwa.importParameters(hint.alg), false, ["verify"])
        ).pipe(Effect.catch(() => Effect.succeed<CryptoKey | null>(null)))
    );
    const publicKeys = imported.filter((key): key is CryptoKey => key !== null);
    if (publicKeys.length === 0) return yield* new JwtError({ reason: "UnknownKey" });

    const result = yield* Jws.verify({ publicKeys, payload: ClaimsFromJson })(flattened).pipe(
        Effect.mapError((error) =>
            error instanceof Jws.InvalidJws
                ? new JwtError({ reason: error.reason._tag === "InvalidSignature" ? "BadSignature" : "Malformed" })
                : new JwtError({ reason: "Malformed" })
        )
    );

    const claims = result.payload;
    const nowSeconds = DateTime.toEpochMillis(yield* DateTime.now) / 1000;

    if (claims.exp + CLOCK_SKEW_SECONDS < nowSeconds) return yield* new JwtError({ reason: "Expired" });
    if (claims.nbf !== undefined && claims.nbf - CLOCK_SKEW_SECONDS > nowSeconds) {
        return yield* new JwtError({ reason: "NotYetValid" });
    }
    if (options.issuer !== undefined && claims.iss !== options.issuer) {
        return yield* new JwtError({ reason: "BadIssuer" });
    }
    if (options.audience !== undefined) {
        const audiences = typeof claims.aud === "string" ? [claims.aud] : claims.aud;
        if (!audiences.includes(options.audience)) return yield* new JwtError({ reason: "BadAudience" });
    }

    return claims;
});

/**
 * Builds a decoder that narrows the standard claims returned by
 * {@link verify} with a more precise, token-specific claims schema, turning
 * the `unknown` values of the rest record into fully typed claims.
 *
 * @since 1.0.0
 * @category Verification
 */
export const decodeClaims = <S extends Schema.Top>(schema: S) =>
    Schema.decodeEffect(Schema.toType(StandardClaimsSchema).pipe(Schema.decodeTo(schema)));

/**
 * Converts a private JWK to its public half, dropping the private scalar and
 * re-declaring `key_ops` for verification. The public JWK is suitable for
 * publishing in the JWKS document.
 *
 * @since 1.0.0
 * @category Keys
 */
export const toPublicKey = Effect.fnUntraced(function* (
    privateJwk: Schema.Schema.Type<typeof PrivateJwkSchema>
): Effect.fn.Return<Schema.Schema.Type<typeof PublicJwkSchema>, Schema.SchemaError, never> {
    const { d: _d, key_ops: _keyOps, ...rest } = privateJwk;
    return yield* Schema.decodeEffect(PublicJwkSchema)({
        key_ops: ["verify"] as const,
        ...rest,
    });
});
