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
 * It also defines the JWE algorithm identifiers: the "alg" key management
 * algorithms (RFC 7518 Section 4) used to encrypt or derive the Content
 * Encryption Key, the "enc" content encryption algorithms (RFC 7518
 * Section 5) that perform authenticated encryption on the plaintext, and the
 * structural parameters (key/IV/tag sizes) each content encryption algorithm
 * requires.
 *
 * @since 1.0.0
 * @see https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)
 */
export * as Jwa from "./Jwa.ts"

/**
 * JSON Web Encryption (JWE) based on RFC 7516.
 *
 * This module provides the JWE Compact Serialization together with WebCrypto
 * backed authenticated encryption and decryption. It supports the AES-GCM and
 * AES-CBC-HMAC-SHA2 content encryption families and the `dir`, RSA-OAEP,
 * AES key wrap, AES-GCM key wrap, ECDH-ES (direct and key-wrap), and PBES2
 * key management families.
 *
 * `RSA1_5` key management is intentionally unsupported - the Web Crypto API
 * does not implement RSAES-PKCS1-v1_5 encryption and RFC 8725 discourages it.
 *
 * Security note: AES-GCM (content encryption and `A*GCMKW` key wrapping) uses
 * a fresh random 96-bit IV per operation. Random 96-bit nonces are only safe
 * up to roughly 2^32 encryptions under a single fixed key before the
 * birthday-bound collision risk becomes non-negligible; this matters for
 * `dir` with a reused Content Encryption Key and for a reused `A*GCMKW`
 * key-encryption key. Rotate long-lived symmetric keys well before that
 * bound, or prefer a key-management mode that derives a fresh CEK per message.
 *
 * @since 1.0.0
 * @see https://www.rfc-editor.org/rfc/rfc7516 - JSON Web Encryption (JWE)
 * @see https://www.rfc-editor.org/rfc/rfc7518 - JSON Web Algorithms (JWA)
 */
export * as Jwe from "./Jwe.ts"

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
 * IGNORED during verification unless explicitly opted into - an attacker can
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
 * - `/.well-known/openid-configuration` - {@link DiscoveryDocumentSchema}
 * - `/.well-known/jwks.json` - `Jwt.JwksSchema`
 * - `/oauth/authorize` - browser page decoding {@link AuthorizationRequestSchema}
 * - `/oauth/token` - decoding {@link TokenRequestSchema} (authorization_code
 *   with PKCE, refresh_token, and client_credentials grants; confidential
 *   clients authenticate via {@link clientAuthentication}), answering
 *   {@link TokenResponseSchema}
 * - `/oauth/revoke` - decoding {@link RevocationRequestSchema} (RFC 7009),
 *   adding the token's `jti` to a denylist until the token's `exp`
 *
 * @since 1.0.0
 * @category Oidc
 */
export * as Oidc from "./Oidc.ts"

/**
 * The server side of "Sign in with ..." for web apps: an OIDC relying party
 * that owns the browser-facing half of the authorization code + PKCE flow.
 * {@link make} realizes a provider registration into two route handlers'
 * worth of logic: `beginAuthorization` answers the login route with a
 * redirect to the provider and drops the short-lived transaction cookies
 * (state, PKCE verifier, and an optional opaque payload such as a return-to
 * path), and `completeAuthorization` answers the callback route by
 * validating the echoed state against those cookies, exchanging the code,
 * and verifying the id token - handing back the claims for the app to turn
 * into its own session:
 *
 * ```ts
 * import { Effect, Layer, Option } from "effect"
 * import { HttpRouter, HttpServerResponse } from "effect/unstable/http"
 * import { RelyingParty } from "effect-oidc"
 *
 * const GoogleSignIn = Effect.gen(function* () {
 *     const google = yield* RelyingParty.make({
 *         issuer: "https://accounts.google.com",
 *         authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
 *         tokenEndpoint: "https://oauth2.googleapis.com/token",
 *         jwksUri: "https://www.googleapis.com/oauth2/v3/certs",
 *         clientId: "my-client-id",
 *         clientSecret: "my-client-secret",
 *         redirectUri: "https://app.example.com/auth/google/callback",
 *         scopes: ["openid", "email", "profile"],
 *         cookies: { prefix: "google_oauth" },
 *     })
 *
 *     const login = google
 *         .beginAuthorization({ payload: "/dashboard" })
 *         .pipe(Effect.catch(() => Effect.succeed(HttpServerResponse.redirect("/login?error=start_failed"))))
 *
 *     const callback = google.completeAuthorization.pipe(
 *         Effect.map(({ claims, payload }) =>
 *             // Create the local session for claims.sub here, then land the
 *             // visitor back where they started.
 *             HttpServerResponse.redirect(Option.getOrElse(payload, () => `/welcome/${claims.sub}`))
 *         ),
 *         Effect.catch((error) => Effect.succeed(HttpServerResponse.redirect(`/login?error=${error.reason}`))),
 *         Effect.flatMap(google.expireTransactionCookies),
 *         Effect.orDie
 *     )
 *
 *     return Layer.mergeAll(
 *         HttpRouter.add("GET", "/auth/google/login", login),
 *         HttpRouter.add("GET", "/auth/google/callback", callback)
 *     )
 * }).pipe(Layer.unwrap)
 * ```
 *
 * The module deliberately stops at verified claims: creating the local
 * account or session, deciding where errors redirect, and setting the
 * session cookie are the app's business. On both the success and the
 * failure response, pass the response through `expireTransactionCookies` so
 * the spent state, verifier, and payload cookies do not outlive the flow.
 *
 * The endpoints can be pinned statically (as above) or resolved at startup
 * from `Oidc.fetchDiscovery`. The provider's JWKS is fetched lazily, cached
 * for `jwksTtl` (default 10 minutes), and the last good key set is served
 * through fetch failures so a transient blip at the provider does not read
 * as a failed sign in - see `Oidc.cachedJwks`.
 *
 * @since 1.0.0
 * @category RelyingParty
 */
export * as RelyingParty from "./RelyingParty.ts"

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
 * Every credential arrives as `Authorization: Bearer <jwt>` - there is no
 * cookie transport and no opaque credential. Interactive access tokens
 * (from public SPAs and confidential clients alike) and long-lived api keys
 * are all just JWTs minted by the issuer - an api key is nothing more than
 * a token with a long expiry - and verified statelessly: the issuer's JWKS
 * is fetched lazily and cached, or handed to {@link layer} as `jwks` when
 * the keys are already at hand, so no shared database or network hop is
 * needed per request.
 *
 * Revocation is the one optional piece of state: give {@link layer} a
 * `revoked` predicate backed by the issuer's RFC 7009 denylist (see
 * `Oidc.RevocationRequestSchema`) and cache it as aggressively as your
 * revocation latency allows - without it, tokens are simply valid until
 * they expire.
 *
 * Handlers read the caller from {@link CurrentUser} - the account (`sub`),
 * its scopes, the OAuth client acting on its behalf, and the verified
 * claims - and can guard individual endpoints with {@link requireScopes}.
 *
 * Scopes are enforced per endpoint without inventing names: by default an
 * endpoint accepts its derived scope (`"MyGroup:MyEndpoint"`) or the bare
 * group identifier (`"MyGroup"`), which grants every endpoint in the group.
 * Annotating an endpoint (or group) with {@link OIDCScopes} replaces that
 * default with an explicit list of accepted scopes - empty to require none.
 *
 * @since 1.0.0
 * @category ResourceServer
 */
export * as ResourceServer from "./ResourceServer.ts"
