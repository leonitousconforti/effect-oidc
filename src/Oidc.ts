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

import { DateTime, Effect, Encoding, Schema } from "effect";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http";

import * as Jwt from "./Jwt.ts";

/**
 * @since 1.0.0
 * @category Schema
 */
export const DiscoveryDocumentSchema = Schema.Struct({
    issuer: Schema.String,
    authorization_endpoint: Schema.String,
    token_endpoint: Schema.String,
    jwks_uri: Schema.String,
    userinfo_endpoint: Schema.String.pipe(Schema.optional),
    response_types_supported: Schema.Array(Schema.String),
    grant_types_supported: Schema.Array(Schema.String),
    scopes_supported: Schema.Array(Schema.String),
    subject_types_supported: Schema.Array(Schema.String),
    id_token_signing_alg_values_supported: Schema.Array(Schema.String),
    code_challenge_methods_supported: Schema.Array(Schema.String),
});

/**
 * The query parameters of an OAuth 2.1 authorization request. PKCE is
 * mandatory for every client, public or confidential.
 *
 * @since 1.0.0
 * @category Schema
 */
export const AuthorizationRequestSchema = Schema.Struct({
    response_type: Schema.Literal("code"),
    client_id: Schema.String,
    redirect_uri: Schema.String,
    scope: Schema.String,
    state: Schema.String,
    nonce: Schema.String.pipe(Schema.optional),
    code_challenge: Schema.String,
    code_challenge_method: Schema.Literal("S256"),
});

/**
 * @since 1.0.0
 * @category Schema
 */
export const TokenRequestSchema = Schema.Union([
    Schema.Struct({
        grant_type: Schema.Literal("authorization_code"),
        code: Schema.String,
        redirect_uri: Schema.String,
        client_id: Schema.String,
        client_secret: Schema.String.pipe(Schema.optional),
        code_verifier: Schema.String,
    }),
    Schema.Struct({
        grant_type: Schema.Literal("refresh_token"),
        refresh_token: Schema.String,
        client_id: Schema.String,
        client_secret: Schema.String.pipe(Schema.optional),
    }),
]);

/**
 * @since 1.0.0
 * @category Schema
 */
export const TokenResponseSchema = Schema.Struct({
    access_token: Schema.String,
    token_type: Schema.Literal("Bearer"),
    expires_in: Schema.Int,
    scope: Schema.String,
    refresh_token: Schema.String.pipe(Schema.optional),
    id_token: Schema.String.pipe(Schema.optional),
});

/**
 * Claims carried by an access token, beyond the registered ones.
 *
 * @since 1.0.0
 * @category Schema
 */
export const AccessTokenClaimsSchema = Schema.Struct({
    ...Jwt.RegisteredClaimsSchema.fields,
    scope: Schema.String,
    client_id: Schema.String,
});

/**
 * @since 1.0.0
 * @category Schema
 */
export const IdTokenClaimsSchema = Schema.Struct({
    ...Jwt.RegisteredClaimsSchema.fields,
    /** Authorized party — the client the id token was issued to. */
    azp: Schema.String.pipe(Schema.optional),
    nonce: Schema.String.pipe(Schema.optional),
    name: Schema.String.pipe(Schema.optional),
    picture: Schema.String.pipe(Schema.optional),
});

/**
 * Raised when a fetched discovery document fails validation.
 *
 * @since 1.0.0
 * @category Errors
 */
export class DiscoveryError extends Schema.ErrorClass<DiscoveryError>("effect-oidc/DiscoveryError")({
    _tag: Schema.tag("DiscoveryError"),
    reason: Schema.Literals(["IssuerMismatch", "InvalidEndpoint"]),
}) {}

/**
 * Builds the discovery document for an issuer, using the conventional
 * endpoint paths.
 *
 * @since 1.0.0
 * @category Provider
 */
export const makeDiscoveryDocument = (issuer: string): Schema.Schema.Type<typeof DiscoveryDocumentSchema> => ({
    issuer,
    authorization_endpoint: new URL("/oauth/authorize", issuer).toString(),
    token_endpoint: new URL("/oauth/token", issuer).toString(),
    jwks_uri: new URL("/.well-known/jwks.json", issuer).toString(),
    userinfo_endpoint: new URL("/oauth/userinfo", issuer).toString(),
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    scopes_supported: ["openid", "profile"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    code_challenge_methods_supported: ["S256"],
});

/**
 * Issues an access token JWT. Used by the provider's token endpoint.
 *
 * @since 1.0.0
 * @category Provider
 */
export const issueAccessToken = Effect.fnUntraced(function* (options: {
    readonly privateJwk: Schema.Schema.Type<typeof Jwt.PrivateJwkSchema>;
    readonly issuer: string;
    readonly subject: string;
    readonly audience: string;
    readonly clientId: string;
    readonly scope: string;
    readonly ttlSeconds: number;
}) {
    const nowSeconds = Math.floor(DateTime.toEpochMillis(yield* DateTime.now) / 1000);
    return yield* Jwt.sign({
        privateJwk: options.privateJwk,
        payload: {
            iss: options.issuer,
            sub: options.subject,
            aud: options.audience,
            exp: nowSeconds + options.ttlSeconds,
            iat: nowSeconds,
            jti: crypto.randomUUID(),
            scope: options.scope,
            client_id: options.clientId,
        },
    });
});

/**
 * Issues an id token JWT for "Sign in with Tinyburg". The audience is the
 * client id, per OIDC.
 *
 * @since 1.0.0
 * @category Provider
 */
export const issueIdToken = Effect.fnUntraced(function* (options: {
    readonly privateJwk: Schema.Schema.Type<typeof Jwt.PrivateJwkSchema>;
    readonly issuer: string;
    readonly subject: string;
    readonly clientId: string;
    readonly ttlSeconds: number;
    readonly nonce?: string | undefined;
    readonly profile?: { readonly name?: string | undefined; readonly picture?: string | undefined } | undefined;
}) {
    const nowSeconds = Math.floor(DateTime.toEpochMillis(yield* DateTime.now) / 1000);
    return yield* Jwt.sign({
        privateJwk: options.privateJwk,
        payload: {
            iss: options.issuer,
            sub: options.subject,
            aud: options.clientId,
            exp: nowSeconds + options.ttlSeconds,
            iat: nowSeconds,
            ...(options.nonce === undefined ? {} : { nonce: options.nonce }),
            ...(options.profile?.name === undefined ? {} : { name: options.profile.name }),
            ...(options.profile?.picture === undefined ? {} : { picture: options.profile.picture }),
        },
    });
});

/**
 * Generates a PKCE verifier and its S256 challenge.
 *
 * @since 1.0.0
 * @category Client
 */
export const generatePkce = Effect.fnUntraced(function* () {
    const verifier = Encoding.encodeBase64Url(crypto.getRandomValues(new Uint8Array(48)));
    const digest = yield* Effect.promise(() => crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
    return {
        verifier,
        challenge: Encoding.encodeBase64Url(new Uint8Array(digest)),
        method: "S256" as const,
    };
});

/**
 * Fetches and decodes the issuer's discovery document.
 *
 * @since 1.0.0
 * @category Client
 */
export const fetchDiscovery = Effect.fnUntraced(function* (issuer: string) {
    const response = yield* HttpClient.get(new URL("/.well-known/openid-configuration", issuer));
    const decoded = yield* HttpClientResponse.schemaJson(Schema.Struct({ body: DiscoveryDocumentSchema }))(response);
    const document = decoded.body;

    // OIDC Discovery 1.0 §4.3 / RFC 8414 §3.3: the returned issuer MUST equal
    // the one used to build the request, and every endpoint the client will
    // send credentials to MUST be https and same-origin with that issuer.
    // Without this check a hostile discovery document could point the token
    // endpoint at an attacker and harvest the code + PKCE verifier.
    if (document.issuer !== issuer) {
        return yield* new DiscoveryError({ reason: "IssuerMismatch" });
    }
    const issuerOrigin = new URL(issuer).origin;
    for (const endpoint of [document.authorization_endpoint, document.token_endpoint, document.jwks_uri]) {
        const url = yield* Effect.try({
            try: () => new URL(endpoint),
            catch: () => new DiscoveryError({ reason: "InvalidEndpoint" }),
        });
        if (url.protocol !== "https:" || url.origin !== issuerOrigin) {
            return yield* new DiscoveryError({ reason: "InvalidEndpoint" });
        }
    }
    return document;
});

/**
 * Fetches and decodes the issuer's JWKS document.
 *
 * @since 1.0.0
 * @category Client
 */
export const fetchJwks = Effect.fnUntraced(function* (jwksUri: string) {
    const response = yield* HttpClient.get(jwksUri);
    const decoded = yield* HttpClientResponse.schemaJson(Schema.Struct({ body: Jwt.JwksSchema }))(response);
    return decoded.body;
});

/**
 * Builds the browser redirect URL that starts the code flow.
 *
 * @since 1.0.0
 * @category Client
 */
export const authorizationUrl = (options: {
    readonly authorizationEndpoint: string;
    readonly clientId: string;
    readonly redirectUri: string;
    readonly scopes: ReadonlyArray<string>;
    readonly state: string;
    readonly codeChallenge: string;
    readonly nonce?: string | undefined;
}): string => {
    const url = new URL(options.authorizationEndpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", options.clientId);
    url.searchParams.set("redirect_uri", options.redirectUri);
    url.searchParams.set("scope", options.scopes.join(" "));
    url.searchParams.set("state", options.state);
    url.searchParams.set("code_challenge", options.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    if (options.nonce !== undefined) url.searchParams.set("nonce", options.nonce);
    return url.toString();
};

/**
 * Exchanges an authorization code for tokens at the provider's token
 * endpoint.
 *
 * @since 1.0.0
 * @category Client
 */
export const exchangeAuthorizationCode = Effect.fnUntraced(function* (options: {
    readonly tokenEndpoint: string;
    readonly clientId: string;
    readonly clientSecret?: string | undefined;
    readonly code: string;
    readonly codeVerifier: string;
    readonly redirectUri: string;
}) {
    const request = HttpClientRequest.post(options.tokenEndpoint).pipe(
        HttpClientRequest.bodyUrlParams({
            grant_type: "authorization_code",
            code: options.code,
            redirect_uri: options.redirectUri,
            client_id: options.clientId,
            code_verifier: options.codeVerifier,
            ...(options.clientSecret === undefined ? {} : { client_secret: options.clientSecret }),
        })
    );
    const response = yield* HttpClient.execute(request);
    const decoded = yield* HttpClientResponse.schemaJson(Schema.Struct({ body: TokenResponseSchema }))(response);
    return decoded.body;
});

/**
 * Verifies an id token against the issuer's JWKS and decodes its claims,
 * checking the audience (the client id) and, when provided, the nonce. This
 * is the last step of the sign-in flow — the returned `sub` is the stable
 * account id at the provider to key local users on.
 *
 * @since 1.0.0
 * @category Client
 */
export const verifyIdToken = Effect.fnUntraced(function* (options: {
    readonly idToken: string;
    readonly jwks: Schema.Schema.Type<typeof Jwt.JwksSchema>;
    readonly issuer: string;
    readonly clientId: string;
    readonly nonce?: string | undefined;
}) {
    const claims = yield* Jwt.verify(options.idToken, {
        jwks: options.jwks,
        issuer: options.issuer,
        audience: options.clientId,
        algorithms: ["ES256"],
    });
    const idClaims = yield* Schema.decodeUnknownEffect(IdTokenClaimsSchema)(claims).pipe(
        Effect.mapError(() => new Jwt.JwtError({ reason: "Malformed" }))
    );
    // OIDC §3.1.3.7: when the token is issued to multiple audiences, or an azp
    // claim is present, azp MUST be present and equal to this client id.
    const audiences = typeof idClaims.aud === "string" ? [idClaims.aud] : idClaims.aud;
    if ((audiences.length > 1 || idClaims.azp !== undefined) && idClaims.azp !== options.clientId) {
        return yield* new Jwt.JwtError({ reason: "BadAudience" });
    }
    if (options.nonce !== undefined && idClaims.nonce !== options.nonce) {
        return yield* new Jwt.JwtError({ reason: "BadSignature" });
    }
    return idClaims;
});
