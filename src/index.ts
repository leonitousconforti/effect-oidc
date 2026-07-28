/**
 * @since 1.0.0
 */

/**
 * JSON Web Algorithms (JWA) schemas based on RFC 7518.
 *
 * This module defines the cryptographic algorithm identifiers used for JWS
 * digital signatures and MACs (RFC 7518 Section 3), along with the WebCrypto
 * parameter sets needed to import keys and to sign/verify with each
 * algorithm. Those two parameter sets differ (e.g. ECDSA import needs
 * `namedCurve` while signing needs `hash`), so they are exposed separately.
 *
 * @since 1.0.0
 * @see https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)
 */
export * as Jwa from "./Jwa.ts"

/**
 * JSON Web Key (JWK) schemas based on RFC 7517 and RFC 7518 Section 6.
 *
 * This module provides Effect Schema definitions for representing
 * cryptographic keys as JSON objects, including key-type-specific parameters
 * for EC, RSA, and symmetric (oct) keys, as well as the JWK Set format.
 *
 * Binary-valued members (coordinates, exponents, key values) are kept in
 * their base64url wire form: they encode raw bytes, not UTF-8 text, and the
 * base64url form is exactly what `crypto.subtle.importKey("jwk", ...)`
 * expects.
 *
 * @since 1.0.0
 * @see https://www.rfc-editor.org/rfc/rfc7517 - JSON Web Key (JWK)
 * @see https://www.rfc-editor.org/rfc/rfc7518#section-6 - Cryptographic Algorithms for Keys
 */
export * as Jwk from "./Jwk.ts"

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
 * IGNORED during verification unless explicitly opted into — an attacker can
 * put any key they control in those headers, so trusting them by default
 * would make signature verification meaningless for authentication use.
 *
 * @since 1.0.0
 * @see https://www.rfc-editor.org/rfc/rfc7515 - JSON Web Signature (JWS)
 * @see https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)
 */
export * as Jws from "./Jws.ts"

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
export * as Jwt from "./Jwt.ts"

/**
 * The OIDC protocol surface: discovery and token endpoint schemas, PKCE
 * utilities, token issuing helpers for the provider, and a code-flow client
 * for relying apps.
 *
 * The provider serves, by convention relative to the issuer:
 *
 * - `/.well-known/openid-configuration` — {@link DiscoveryDocumentSchema}
 * - `/.well-known/jwks.json` — `Jwt.JwksSchema`
 * - `/oauth/authorize` — browser page decoding {@link AuthorizationRequestSchema}
 * - `/oauth/token` — decoding {@link TokenRequestSchema}, answering {@link TokenResponseSchema}
 *
 * @since 1.0.0
 * @category Oidc
 */
export * as Oidc from "./Oidc.ts"

/**
 * Drop-in bearer authentication for `HttpApi` services. Any service becomes
 * a resource server of an OIDC provider by adding the {@link Authorization}
 * middleware to its api groups and providing {@link layer} with the issuer
 * and its audience:
 *
 * ```ts
 * import { Schema } from "effect"
 * import { HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi"
 * import { ResourceServer } from "effect-oidc"
 *
 * const MyEndpoint = HttpApiEndpoint.get("MyEndpoint", "/me", { success: Schema.String })
 *
 * const MyGroup = HttpApiGroup.make("MyGroup")
 *     .add(MyEndpoint)
 *     .middleware(ResourceServer.Authorization)
 *
 * const AuthorizationLive = ResourceServer.layer({
 *     issuer: "https://id.example.com",
 *     audience: "my-api",
 * })
 * ```
 *
 * Tokens are verified statelessly: the issuer's JWKS is fetched once and
 * cached, so no shared database or network hop is needed per request.
 * Handlers read the caller from {@link CurrentUser} and can guard individual
 * endpoints with {@link requireScopes}.
 *
 * @since 1.0.0
 * @category ResourceServer
 */
export * as ResourceServer from "./ResourceServer.ts"
