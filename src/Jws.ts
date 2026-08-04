/**
 * JSON Web Signature (JWS) schemas based on RFC 7515.
 *
 * This module provides Effect Schema definitions for JWS structures, which
 * represent content secured with digital signatures or Message Authentication
 * Codes (MACs) using JSON-based data structures. All three serializations are
 * supported (Compact, Flattened JSON, General JSON), along with signing and
 * verification built on WebCrypto, extensible critical headers with
 * compile-time key validation, and schema combinators ({@link Verified},
 * {@link Signed}) that treat signing/verification as schema transformations.
 *
 * Keys embedded in the token itself (`jwk` and `jku` header parameters) are
 * IGNORED during verification unless explicitly opted into - an attacker can
 * put any key they control in those headers, so trusting them by default
 * would make signature verification meaningless for authentication use.
 *
 * @since 1.0.0
 * @see https://www.rfc-editor.org/rfc/rfc7515 - JSON Web Signature (JWS)
 * @see https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)
 */

import {
    Array,
    type Brand,
    Data,
    Effect,
    Function,
    Option,
    Schema,
    SchemaGetter,
    SchemaIssue,
    type Struct,
} from "effect";
import { VariantSchema } from "effect/unstable/schema";

import { importParameters, JwsAlgorithm, signatureParameters } from "./Jwa.ts";
import { isCompatibleWith, isPrivate, isSymmetric, Jwk, type JwkSet, toJsonWebKey } from "./Jwk.ts";

const joseVariantSchema = VariantSchema.make({
    variants: ["protected", "unprotected"],
    defaultVariant: "protected",
});

/**
 * JOSE Header for JWS as defined in RFC 7515 Section 4. The JOSE Header
 * describes the cryptographic operations applied to the JWS Protected Header
 * and the JWS Payload.
 *
 * This schema is extensible - additional public and private header parameters
 * are permitted per RFC 7515 Sections 4.2 and 4.3.
 *
 * @since 1.0.0
 * @category JOSE Header
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4
 */
export const JoseHeader = joseVariantSchema.Struct({
    /**
     * "alg" (Algorithm) Header Parameter - REQUIRED Identifies the
     * cryptographic algorithm used to secure the JWS.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1
     */
    alg: JwsAlgorithm.pipe(
        joseVariantSchema.fieldEvolve({
            unprotected: (algSchema) => Schema.optional(algSchema),
        })
    ),

    /**
     * "jku" (JWK Set URL) Header Parameter - OPTIONAL A URI that refers to a
     * resource for a set of JSON-encoded public keys.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.2
     */
    jku: Schema.String.pipe(Schema.optional),

    /**
     * "jwk" (JSON Web Key) Header Parameter - OPTIONAL The public key that
     * corresponds to the key used to digitally sign the JWS.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.3
     */
    jwk: Jwk.pipe(Schema.optional),

    /**
     * "kid" (Key ID) Header Parameter - OPTIONAL A hint indicating which key
     * was used to secure the JWS.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4
     */
    kid: Schema.String.pipe(Schema.optional),

    /**
     * "x5u" (X.509 URL) Header Parameter - OPTIONAL
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.5
     */
    x5u: Schema.String.pipe(Schema.optional),

    /**
     * "x5c" (X.509 Certificate Chain) Header Parameter - OPTIONAL
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6
     */
    x5c: Schema.Array(Schema.String).pipe(Schema.optional),

    /**
     * "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter - OPTIONAL
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.7
     */
    x5t: Schema.String.pipe(Schema.optional),

    /**
     * "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter -
     * OPTIONAL
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.8
     */
    "x5t#S256": Schema.String.pipe(Schema.optional),

    /**
     * "typ" (Type) Header Parameter - OPTIONAL (RECOMMENDED to be "JWT" for
     * JWTs) Used to declare the media type of this complete JWS.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9
     * @see https://www.rfc-editor.org/rfc/rfc7519#section-5.1
     */
    typ: Schema.String.pipe(Schema.optional),

    /**
     * "cty" (Content Type) Header Parameter - OPTIONAL Used to declare the
     * media type of the secured content (the payload). For nested JWTs, this
     * MUST be "JWT".
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.10
     * @see https://www.rfc-editor.org/rfc/rfc7519#section-5.2
     */
    cty: Schema.String.pipe(Schema.optional),

    /**
     * "crit" (Critical) Header Parameter - OPTIONAL Indicates that extensions
     * are being used that MUST be understood and processed.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11
     */
    crit: Schema.Never.pipe(Schema.optionalKey, joseVariantSchema.FieldOnly(["protected"])),
});

/**
 * The integrity-protected JOSE header variant.
 *
 * @since 1.0.0
 * @category JOSE Header
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4
 */
export const JoseProtectedHeader = joseVariantSchema.extract(JoseHeader, "protected");

/**
 * The unprotected JOSE header variant, carried alongside JSON serializations.
 *
 * @since 1.0.0
 * @category JOSE Header
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4
 */
export const JoseUnprotectedHeader = joseVariantSchema.extract(JoseHeader, "unprotected");

/**
 * Additional protected header parameters that callers may set when signing
 * (everything except `alg`, which comes from the signing key entry, and
 * `crit`, which is managed by the critical-header machinery).
 *
 * @since 1.0.0
 * @category JOSE Header
 */
export type ProtectedHeaderExtras = Omit<(typeof JoseProtectedHeader)["Type"], "alg" | "crit">;

/**
 * Type-level validation to prevent critical header keys from colliding with
 * registered JOSE header parameters. Critical header keys must be distinct
 * from any registered JOSE header parameter keys, as they would cause
 * ambiguity in the JOSE header structure and violate the JWS specification.
 *
 * @since 1.0.0
 * @category JOSE Header
 */
export type ValidateCriticalHeaderKey<K extends string> = K extends
    | keyof typeof JoseProtectedHeader.fields
    | keyof typeof JoseUnprotectedHeader.fields
    ? `${K} is a registered JOSE header parameter and cannot be used as a critical header key`
    : {};

/**
 * Type-level validation applied to a whole record of critical headers.
 *
 * @since 1.0.0
 * @category JOSE Header
 */
export type ValidateCriticalHeaderKeys<
    CriticalHeaders extends {
        readonly [K in string]: Schema.Codec<unknown, Schema.Json, unknown, unknown>;
    },
> = {
    [K in Extract<keyof CriticalHeaders, string>]: ValidateCriticalHeaderKey<K>;
};

/**
 * Adds a collection of critical extension headers to a JoseHeader-like struct
 * schema. The fields are added, and the `crit` field becomes an exact tuple
 * of all registered critical header key literals.
 *
 * @internal
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-4
 */
const joseHeaderWithCriticals = <
    CriticalHeaders extends {
        readonly [K in string]: Schema.Codec<unknown, Schema.Json, unknown, unknown>;
    },
>(
    criticalHeaders: (CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>) | undefined
) => {
    type KeyLiterals = Extract<keyof CriticalHeaders, string>;

    type InputConstraint =
        | typeof JoseProtectedHeader.fields
        | { readonly crit: Schema.$Array<Schema.Union<Array.NonEmptyReadonlyArray<Schema.Literal<string>>>> };

    type ValidateJoseHeaderAndKey<OldFields extends InputConstraint> =
        OldFields["crit"] extends Schema.$Array<
            Schema.Union<Array.NonEmptyReadonlyArray<Schema.Literal<infer OldCritKeys>>>
        >
            ? Extract<KeyLiterals, OldCritKeys> extends never
                ? {}
                : `Critical header key '${Extract<KeyLiterals, OldCritKeys>}' already exists`
            : {};

    return <
        OldFields extends InputConstraint,
        NewCritical extends (KeyLiterals extends never
            ? OldFields["crit"]
            : OldFields["crit"] extends Schema.$Array<Schema.Union<infer Elements>>
              ? Schema.$Array<Schema.Union<[...Elements, Schema.Literal<KeyLiterals>]>>
              : Schema.$Array<Schema.Union<Array.NonEmptyReadonlyArray<Schema.Literal<KeyLiterals>>>>),
        NewFields extends CriticalHeaders & { readonly crit: NewCritical },
    >(
        self: Schema.Struct<OldFields> & ValidateJoseHeaderAndKey<OldFields>
    ): Schema.Struct<Struct.Simplify<Struct.Assign<OldFields, NewFields>>> => {
        // The return type is computed at the type level from `OldFields` and
        // `CriticalHeaders`; the compiler cannot verify a runtime-built schema
        // against it, so both returns coerce. The construction mirrors the
        // type-level formula exactly: every critical header key becomes a
        // field, and `crit` becomes the array of all registered key literals.
        const entries = Object.entries(criticalHeaders ?? {});
        if (entries.length === 0) return self as never;

        const crit: InputConstraint["crit"] = self.fields.crit;
        const existingMembers = "value" in crit ? crit.value.members : [];
        const existingKeys = new Set(existingMembers.map((member) => member.literal));
        const critMembers = [
            ...existingMembers,
            ...entries.filter(([key]) => !existingKeys.has(key)).map(([key]) => Schema.Literal(key)),
        ];

        const newFields = {
            ...Object.fromEntries(entries),
            crit: Schema.Array(Schema.Union(critMembers)).check(
                Schema.isUnique({
                    message: "Duplicate critical header keys are not allowed",
                }),
                Schema.isMinLength(critMembers.length, {
                    message: "All critical header keys should be present",
                })
            ),
        };

        return self.pipe(Schema.fieldsAssign(newFields)) as never;
    };
};

/**
 * General JWS JSON Serialization as defined in RFC 7515 Section 7.2.1.
 * Supports multiple digital signatures and/or MACs for the same payload.
 *
 * ```json
 * {
 *   "payload": "<payload contents>",
 *   "signatures": [
 *     { "protected": "<header 1>", "header": { ... }, "signature": "<sig 1>" },
 *     { "protected": "<header N>", "header": { ... }, "signature": "<sig N>" }
 *   ]
 * }
 * ```
 *
 * @since 1.0.0
 * @category JWS JSON Serialization
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
 */
export class General extends Schema.Opaque<General, Brand.Brand<"General">>()(
    Schema.Struct({
        unverifiedPayload: Schema.String,
        signatures: Schema.NonEmptyArray(
            Schema.Struct({
                protected: Schema.String,
                signature: Schema.String,
                header: JoseUnprotectedHeader.pipe(Schema.optional),
            })
        ),
    })
        .pipe(
            Schema.encodeKeys({
                unverifiedPayload: "payload",
            })
        )
        .annotate({
            title: "JWS General JSON Serialization (Unverified)",
            expected: "a JWS General JSON Serialization object with unverified payload and signatures",
            description: "A JWS in General JSON Serialization format with unverified payload and signatures.",
        })
) {}

/**
 * Flattened JWS JSON Serialization as defined in RFC 7515 Section 7.2.2.
 * Optimized for the single digital signature or MAC case - the "signatures"
 * member is flattened into top-level "protected", "header", and "signature"
 * members alongside "payload".
 *
 * ```json
 * {
 *   "payload": "<payload contents>",
 *   "protected": "<integrity-protected header contents>",
 *   "header": { ... },
 *   "signature": "<signature contents>"
 * }
 * ```
 *
 * @since 1.0.0
 * @category JWS JSON Serialization
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2
 */
export class Flattened extends Schema.Opaque<Flattened, Brand.Brand<"Flattened">>()(
    Schema.Struct({
        signature: Schema.String,
        protected: Schema.String,
        unverifiedPayload: Schema.String,
        header: JoseUnprotectedHeader.pipe(Schema.optional),
    })
        .pipe(
            Schema.encodeKeys({
                unverifiedPayload: "payload",
            })
        )
        .annotate({
            title: "JWS Flattened JSON Serialization (Unverified)",
            expected: "a JWS Flattened JSON Serialization object with unverified payload and signature",
            description: "A JWS in Flattened JSON Serialization format with unverified payload and signature.",
        })
) {}

/**
 * JWS Compact Serialization as defined in RFC 7515 Section 7.1. Represents a
 * compact, URL-safe string of the form:
 *
 *     BASE64URL(UTF8(JWS Protected Header)) || '.' ||
 *     BASE64URL(JWS Payload) || '.' ||
 *     BASE64URL(JWS Signature)
 *
 * Only one signature/MAC is supported by the JWS Compact Serialization and it
 * provides no syntax to represent a JWS Unprotected Header value.
 *
 * @since 1.0.0
 * @category JWS Compact Serialization
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-7.1
 */
export class Compact extends Schema.Opaque<Compact, Brand.Brand<"Compact">>()(
    Schema.TemplateLiteralParser([
        Schema.String,
        Schema.Literal("."),
        Schema.String,
        Schema.Literal("."),
        Schema.String,
    ])
        .pipe(
            Schema.decodeTo(Flattened, {
                decode: SchemaGetter.transform(([protectedHeader, _dot1, payload, _dot2, signature]) => ({
                    protected: protectedHeader,
                    payload,
                    signature,
                })),
                encode: SchemaGetter.transformOrFail(({ header, protected: protectedHeader, payload, signature }) =>
                    header === undefined
                        ? Effect.succeed([protectedHeader, ".", payload, ".", signature] as const)
                        : Effect.fail(
                              new SchemaIssue.InvalidValue(Option.none(), {
                                  message: "Compact serialization does not support unprotected headers",
                              })
                          )
                ),
            })
        )
        .annotate({
            title: "JWS Compact Serialization (Unverified)",
            expected: "a JWS Compact Serialization string with unverified payload and signature",
            description: "A JWS in Compact Serialization format with unverified payload and signature.",
        })
) {}

/**
 * Any unverified JWS serialization.
 *
 * @since 1.0.0
 * @category JWS
 */
export const Unsecured = Schema.Union([General, Flattened, Compact]);

/**
 * The payload codec used when a caller does not supply one. Every signature
 * that leaves `payload` out also leaves `A` (and the payload service
 * parameters) at their `string`/`never` defaults, so `Schema.String` is the
 * correct codec; the compiler cannot connect a type parameter to its
 * default, hence the coercion.
 *
 * @internal
 */
const defaultPayloadCodec = <A, RD, RE>(): Schema.Codec<A, string, RD, RE> => Schema.String as never;

/**
 * @since 1.0.0
 * @category Errors
 */
export class InvalidHeaders extends Data.TaggedError("InvalidHeaders")<{}> {}

/**
 * @since 1.0.0
 * @category Errors
 */
export class InvalidSignature extends Data.TaggedError("InvalidSignature")<{}> {}

/**
 * @since 1.0.0
 * @category Errors
 */
export class InvalidJws extends Data.TaggedError("InvalidJws")<{ reason: InvalidHeaders | InvalidSignature }> {}

/**
 * Builds a JWS verifier. Signatures are checked against the provided
 * `publicKeys`. Keys embedded in the token (`jwk` header) are only
 * considered when `trustEmbeddedJwk` is set, and `jku` URLs are only
 * followed when a `resolveJku` effect is supplied - both default to off
 * because tokens choose their own headers.
 *
 * @since 1.0.0
 * @category JWS
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-5.2
 */
export function verify<
    A = string,
    RD1 = never,
    E2 = never,
    R2 = never,
    CriticalHeaders extends {
        readonly [K in string]: Schema.Codec<unknown, Schema.Json, unknown, unknown>;
    } = {},
>({
    algorithms,
    criticalHeaders,
    maxSignatures = 4,
    payload,
    publicKeys,
    resolveJku,
    trustEmbeddedJwk,
}: {
    payload?: Schema.Codec<A, string, RD1, unknown> | undefined;
    publicKeys?: ReadonlyArray<CryptoKey> | undefined;
    trustEmbeddedJwk?: boolean | undefined;
    resolveJku?: ((url: string) => Effect.Effect<(typeof JwkSet)["Type"], E2, R2>) | undefined;
    criticalHeaders?: (CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>) | undefined;
    /** When set, only these `alg` values are accepted; other tokens are rejected. */
    algorithms?: ReadonlyArray<(typeof JwsAlgorithm)["Type"]> | undefined;
    /** Maximum signatures accepted in a General serialization (default 4). */
    maxSignatures?: number | undefined;
}) {
    const keys = globalThis.Array.from(publicKeys ?? []);
    const textEncoder = new TextEncoder();

    const payloadSchema = Schema.StringFromBase64Url.pipe(
        Schema.decodeTo(payload ?? defaultPayloadCodec<A, RD1, unknown>())
    );
    const joseProtectedSchema = JoseProtectedHeader.pipe(joseHeaderWithCriticals(criticalHeaders));
    const protectedHeaderSchema = Schema.StringFromBase64Url.pipe(
        Schema.decodeTo(Schema.fromJsonString(joseProtectedSchema))
    );

    const decodePayload = Schema.decodeEffect(payloadSchema);
    const decodeProtectedHeader = Schema.decodeEffect(protectedHeaderSchema);
    const decodeSignature = Schema.decodeEffect(Schema.Uint8ArrayFromBase64Url);

    // Import may reject on malformed key material or an alg/key-type mismatch;
    // treat that as an unusable key (null) rather than an unrecoverable defect.
    const importJwk = (jwk: (typeof Jwk)["Type"], alg: (typeof JwsAlgorithm)["Type"]) =>
        Effect.tryPromise(() =>
            crypto.subtle.importKey("jwk", toJsonWebKey(jwk), importParameters(alg), false, ["verify"])
        ).pipe(Effect.catch(() => Effect.succeed<CryptoKey | null>(null)));

    const verifier = Effect.fnUntraced(function* (jws: General) {
        if (jws.signatures.length > maxSignatures) {
            return yield* new InvalidJws({ reason: new InvalidHeaders() });
        }
        for (const signatureEntry of jws.signatures) {
            const signatureBytes = yield* decodeSignature(signatureEntry.signature);
            const protectedHeader = yield* decodeProtectedHeader(signatureEntry.protected);

            const header = { ...signatureEntry.header, ...protectedHeader };
            const protectedKeys = Object.keys(protectedHeader ?? {});
            const unprotectedKeys = new Set(Object.keys(signatureEntry.header ?? {}));
            if (protectedKeys.some((key) => unprotectedKeys.has(key))) {
                return yield* new InvalidJws({ reason: new InvalidHeaders() });
            }

            if (header.alg === undefined) {
                return yield* new InvalidJws({ reason: new InvalidHeaders() });
            }

            if (algorithms !== undefined && !algorithms.includes(header.alg)) {
                return yield* new InvalidJws({ reason: new InvalidHeaders() });
            }

            const localKeys: globalThis.Array<CryptoKey> = [];

            // Keys pulled from the token itself (jku / embedded jwk) are used
            // only if they are asymmetric public keys compatible with the
            // header algorithm - never symmetric or private keys.
            const trustable = (jwk: (typeof Jwk)["Type"]) =>
                !isSymmetric(jwk) && !isPrivate(jwk) && isCompatibleWith(header.alg!, jwk);

            if (header.jku !== undefined && resolveJku !== undefined) {
                const jwkSet = yield* resolveJku(header.jku).pipe(
                    Effect.mapError(() => new InvalidJws({ reason: new InvalidHeaders() }))
                );
                for (const jwk of jwkSet.keys) {
                    if (!trustable(jwk)) continue;
                    const imported = yield* importJwk(jwk, header.alg);
                    if (imported !== null) localKeys.push(imported);
                }
            }

            if (header.jwk !== undefined && trustEmbeddedJwk === true && trustable(header.jwk)) {
                const imported = yield* importJwk(header.jwk, header.alg);
                if (imported !== null) localKeys.push(imported);
            }

            const verifyParameters = signatureParameters(header.alg);
            for (const key of [...keys, ...localKeys]) {
                // A key whose bound algorithm mismatches makes verify reject;
                // treat that as "did not verify" so the next candidate is tried.
                const verified = yield* Effect.tryPromise(() =>
                    crypto.subtle.verify(
                        verifyParameters,
                        key,
                        Uint8Array.from(signatureBytes),
                        textEncoder.encode(`${signatureEntry.protected}.${jws.unverifiedPayload}`)
                    )
                ).pipe(Effect.catch(() => Effect.succeed(false)));

                if (verified) {
                    return {
                        signature: signatureBytes,
                        protected: protectedHeader,
                        header: signatureEntry.header,
                        payload: yield* decodePayload(jws.unverifiedPayload),
                    };
                }
            }
        }

        return yield* new InvalidJws({
            reason: new InvalidSignature(),
        });
    });

    return (jws: (typeof Unsecured)["Type"]) => {
        if ("signatures" in jws) {
            return verifier(jws);
        }

        const intoGeneral = General.make({
            unverifiedPayload: jws.unverifiedPayload,
            signatures: [
                {
                    header: jws.header,
                    protected: jws.protected,
                    signature: jws.signature,
                },
            ],
        });

        return verifier(intoGeneral);
    };
}

/**
 * Builds a JWS signer. Each private key entry carries its algorithm and any
 * additional protected header parameters (e.g. `kid`, `typ`). Signing with a
 * single key produces the Flattened serialization; multiple keys produce the
 * General serialization.
 *
 * @since 1.0.0
 * @category JWS
 * @see https://www.rfc-editor.org/rfc/rfc7515#section-5.1
 */
export function sign<
    A = string,
    RE1 = never,
    PrivateKeys extends Array.NonEmptyReadonlyArray<{
        algorithm: (typeof JwsAlgorithm)["Type"];
        key: CryptoKey;
        header?: ProtectedHeaderExtras | undefined;
    }> = never,
    CriticalHeaders extends {
        readonly [K in string]: Schema.Codec<unknown, Schema.Json, unknown, unknown>;
    } = {},
>(options: {
    privateKeys: PrivateKeys;
    payload?: Schema.Codec<A, string, unknown, RE1> | undefined;
    criticalHeaders?: (CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>) | undefined;
}): (
    payload: A,
    criticalHeaders?: Schema.Struct.Type<CriticalHeaders> | undefined
) => Effect.Effect<
    PrivateKeys extends [infer _] ? (typeof Flattened)["Encoded"] : (typeof General)["Encoded"],
    Schema.SchemaError,
    RE1 | Schema.Struct.EncodingServices<CriticalHeaders>
> {
    const textEncoder = new TextEncoder();

    const payloadSchema = Schema.StringFromBase64Url.pipe(Schema.decodeTo(options.payload ?? Schema.String));
    const joseSchema = JoseProtectedHeader.pipe(joseHeaderWithCriticals(options.criticalHeaders));
    const protectedHeaderSchema = Schema.StringFromBase64Url.pipe(Schema.decodeTo(Schema.fromJsonString(joseSchema)));

    const encodePayload = Schema.encodeEffect(payloadSchema);
    const encodeProtected = Schema.encodeEffect(protectedHeaderSchema);
    const encodeSignature = Schema.encodeEffect(Schema.Uint8ArrayFromBase64Url);

    // The `crit` member must list every registered critical header key
    // (RFC 7515 Section 4.1.11) and the extended header schema requires
    // exactly that, so it is populated here rather than by callers;
    // `ProtectedHeaderExtras` deliberately excludes `crit`.
    const criticalKeys = Object.keys(options.criticalHeaders ?? {});

    const signMany = (
        encodedPayload: string,
        criticalHeaders: Schema.Struct.Type<CriticalHeaders> | undefined,
        privateKeys: Array.NonEmptyReadonlyArray<{
            algorithm: (typeof JwsAlgorithm)["Type"];
            key: CryptoKey;
            header?: ProtectedHeaderExtras | undefined;
        }>
    ) =>
        Effect.forEach(
            privateKeys,
            Effect.fnUntraced(function* ({ algorithm, header, key }) {
                // The header schema's input type is computed at the type level
                // from `CriticalHeaders`; this object matches it by the same
                // construction, which the compiler cannot verify - coerce.
                const protectedHeader = yield* encodeProtected({
                    alg: algorithm,
                    ...header,
                    ...criticalHeaders,
                    ...(criticalKeys.length === 0 ? {} : { crit: criticalKeys }),
                } as never);
                const signature = yield* Effect.promise(() =>
                    crypto.subtle.sign(
                        signatureParameters(algorithm),
                        key,
                        textEncoder.encode(`${protectedHeader}.${encodedPayload}`)
                    )
                );
                return {
                    protected: protectedHeader,
                    signature: yield* encodeSignature(new Uint8Array(signature)),
                };
            })
        );

    return Effect.fnUntraced(function* (payload: A, criticalHeaders?: Schema.Struct.Type<CriticalHeaders> | undefined) {
        const encodedPayload = yield* encodePayload(payload);
        const signatures = yield* signMany(encodedPayload, criticalHeaders, options.privateKeys);
        const result: (typeof Flattened)["Encoded"] | (typeof General)["Encoded"] =
            options.privateKeys.length === 1
                ? yield* Schema.encodeEffect(Flattened)(
                      Flattened.make({
                          unverifiedPayload: encodedPayload,
                          protected: Array.headNonEmpty(signatures).protected,
                          signature: Array.headNonEmpty(signatures).signature,
                      })
                  )
                : yield* Schema.encodeEffect(General)(
                      General.make({
                          unverifiedPayload: encodedPayload,
                          signatures,
                      })
                  );
        // Which serialization is produced is decided by `PrivateKeys` at the
        // type level and by `length` at runtime; the compiler cannot connect
        // the two, so the union coerces to the computed return type.
        return result as PrivateKeys extends [infer _] ? (typeof Flattened)["Encoded"] : (typeof General)["Encoded"];
    });
}

/**
 * Schema combinator that decodes an unverified JWS into its verified payload
 * and headers, failing decode when no signature verifies. Encoding is
 * forbidden - use {@link Signed} to produce a JWS.
 *
 * @since 1.0.0
 * @category Schema Combinators
 */
export function Verified<
    A = string,
    RD1 = never,
    RE1 = never,
    E2 = never,
    R2 = never,
    CriticalHeaders extends {
        readonly [K in string]: Schema.Codec<unknown, Schema.Json, unknown, unknown>;
    } = {},
>(options: {
    payload?: Schema.Codec<A, string, RD1, RE1> | undefined;
    publicKeys?: ReadonlyArray<CryptoKey> | undefined;
    trustEmbeddedJwk?: boolean | undefined;
    resolveJku?: ((url: string) => Effect.Effect<(typeof JwkSet)["Type"], E2, R2>) | undefined;
    criticalHeaders?: (CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>) | undefined;
}) {
    const verifier = verify(options);

    const to = Schema.Struct({
        signature: Schema.Uint8ArrayFromBase64Url,
        payload: options.payload ?? defaultPayloadCodec<A, RD1, RE1>(),
        header: JoseUnprotectedHeader.pipe(Schema.optional),
        protected: JoseProtectedHeader.pipe(joseHeaderWithCriticals(options.criticalHeaders)),
    }).pipe(Schema.toType);

    const decode = Function.flow(
        verifier,
        Effect.mapError((error) => (Schema.isSchemaError(error) ? error.issue : error)),
        Effect.catchTag("InvalidJws", (_error) =>
            Effect.fail(
                new SchemaIssue.Forbidden(Option.none(), {
                    message: "Invalid JWS",
                })
            )
        )
    );

    return <From extends (typeof Unsecured)["members"][number] | Schema.Decoder<(typeof Unsecured)["Type"], unknown>>(
        from: From
    ) => {
        return from.pipe(
            Schema.decodeTo(to, {
                decode: SchemaGetter.transformOrFail(decode),
                encode: SchemaGetter.forbidden(() => "Will not encode"),
            })
        );
    };
}

/**
 * Schema combinator that signs a payload (and critical headers) during
 * decode, producing an unverified JWS serialization. Encoding is forbidden.
 *
 * @since 1.0.0
 * @category Schema Combinators
 */
export function Signed<
    A = string,
    RD1 = never,
    RE1 = never,
    PrivateKeys extends Array.NonEmptyReadonlyArray<{
        algorithm: (typeof JwsAlgorithm)["Type"];
        key: CryptoKey;
        header?: ProtectedHeaderExtras | undefined;
    }> = never,
    CriticalHeaders extends {
        readonly [K in string]: Schema.Codec<unknown, Schema.Json, unknown, unknown>;
    } = {},
>(options: {
    privateKeys: PrivateKeys;
    payload?: Schema.Codec<A, string, RD1, RE1> | undefined;
    criticalHeaders?: (CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>) | undefined;
}) {
    const signer = sign<A, RE1, PrivateKeys, CriticalHeaders>(options);

    // The runtime struct matches the computed conditional type by
    // construction (the `criticalHeaders` field exists exactly when critical
    // headers were supplied), which the compiler cannot verify - coerce.
    const from = Schema.Struct({
        payload: options.payload ?? defaultPayloadCodec<A, RD1, RE1>(),
        ...(options.criticalHeaders ? { criticalHeaders: Schema.Struct(options.criticalHeaders) } : {}),
    }) as Schema.Struct<
        {
            readonly payload: Schema.Codec<A, string, RD1, RE1>;
        } & ([{}] extends [CriticalHeaders]
            ? {}
            : {
                  readonly criticalHeaders: Schema.Struct<
                      CriticalHeaders & ValidateCriticalHeaderKeys<CriticalHeaders>
                  >;
              })
    >;

    return <To extends (typeof Unsecured)["members"][number] | Schema.Decoder<(typeof Unsecured)["Type"], unknown>>(
        to: To
    ) => {
        return from.pipe(
            Schema.decodeTo(to, {
                encode: SchemaGetter.forbidden(() => "Will not encode"),
                // The getter's input is the conditional `from` type above and
                // its output is `sign`'s conditional serialization; both are
                // computed types the compiler cannot relate to this concrete
                // getter, so it coerces - the body stays fully typed.
                decode: SchemaGetter.transformOrFail(
                    (input: {
                        readonly payload: A;
                        readonly criticalHeaders?: Schema.Struct.Type<CriticalHeaders> | undefined;
                    }) =>
                        Effect.mapError(signer(input.payload, input.criticalHeaders), (error) =>
                            Schema.isSchemaError(error) ? error.issue : error
                        )
                ) as never,
            })
        );
    };
}
