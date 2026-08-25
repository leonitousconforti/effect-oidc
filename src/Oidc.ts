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

import { DateTime, Duration, Effect, Encoding, Option, Ref, Result, Schema } from "effect";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http";

import type * as Jwa from "./Jwa.ts";

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
    token_endpoint_auth_methods_supported: Schema.Array(Schema.String).pipe(Schema.optional),
    revocation_endpoint: Schema.String.pipe(Schema.optional),
    /** RFC 7591 Section 3: where a client may register itself, when the provider offers that. */
    registration_endpoint: Schema.String.pipe(Schema.optional),
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
 * The form body of a token request. Public clients (SPAs, native apps) use
 * the `authorization_code` and `refresh_token` grants with PKCE and no
 * secret; confidential clients additionally authenticate - via the
 * `Authorization: Basic` header or the `client_secret` body parameter, see
 * {@link clientAuthentication} - and may use the machine-to-machine
 * `client_credentials` grant, where the credentials commonly arrive in the
 * header and the body carries only the grant type and scope.
 *
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
    Schema.Struct({
        grant_type: Schema.Literal("client_credentials"),
        scope: Schema.String.pipe(Schema.optional),
        client_id: Schema.String.pipe(Schema.optional),
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
    /** RFC 6749 Section 5.1: optional when identical to the scope requested. */
    scope: Schema.String.pipe(Schema.optional),
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
 * The form body of an RFC 7009 revocation request. The endpoint must answer
 * `200` whether or not the presented token was valid, so callers cannot use
 * it to probe token validity; on success the token's `jti` joins a denylist
 * until the token's `exp`, which keeps the denylist bounded.
 *
 * @since 1.0.0
 * @category Schema
 * @see https://www.rfc-editor.org/rfc/rfc7009 - OAuth 2.0 Token Revocation
 */
export const RevocationRequestSchema = Schema.Struct({
    token_type_hint: Schema.String.pipe(Schema.optional),
    token: Schema.String,
});

/**
 * @since 1.0.0
 * @category Schema
 */
export const IdTokenClaimsSchema = Schema.Struct({
    ...Jwt.RegisteredClaimsSchema.fields,
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
export class DiscoveryError extends Schema.Error<DiscoveryError>("effect-oidc/DiscoveryError")({
    _tag: Schema.tag("DiscoveryError"),
    reason: Schema.Literals(["IssuerMismatch", "InvalidEndpoint"]),
}) {}

/**
 * Resolves a path relative to an issuer identifier, keeping any path the
 * issuer itself carries (OIDC Discovery 1.0 Section 4.1: the well-known
 * suffix is appended to the issuer, not to its origin). `new URL(path,
 * issuer)` would drop `/realms/tenant` from `https://idp.example/realms/tenant`
 * and silently talk to a different (or nonexistent) issuer.
 *
 * @since 1.0.0
 * @category Utilities
 */
export const issuerUrl = (issuer: string, path: string): string =>
    `${issuer.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;

/**
 * Builds the discovery document for an issuer, using the conventional
 * endpoint paths.
 *
 * @since 1.0.0
 * @category Provider
 */
export const makeDiscoveryDocument = (issuer: string): Schema.Schema.Type<typeof DiscoveryDocumentSchema> => ({
    issuer,
    authorization_endpoint: issuerUrl(issuer, "/oauth/authorize"),
    token_endpoint: issuerUrl(issuer, "/oauth/token"),
    jwks_uri: issuerUrl(issuer, "/.well-known/jwks.json"),
    userinfo_endpoint: issuerUrl(issuer, "/oauth/userinfo"),
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
    scopes_supported: ["openid", "profile"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
    revocation_endpoint: issuerUrl(issuer, "/oauth/revoke"),
});

/**
 * Resolves how a token request authenticates its client: the
 * `Authorization: Basic` header (`client_secret_basic`, the OIDC default
 * method) takes precedence over the `client_id`/`client_secret` body
 * parameters (`client_secret_post`). Returns `Option.none` when the request
 * names no client at all, when a presented Basic header is malformed, or
 * when the request uses both methods at once (a body `client_secret` next
 * to a Basic header), which RFC 6749 Section 2.3 forbids.
 *
 * For the provider's token endpoint: public clients resolve with an
 * undefined secret, confidential clients must have their secret verified
 * against the registration before the grant is honoured.
 *
 * @since 1.0.0
 * @category Provider
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1
 */
export const clientAuthentication = (options: {
    /** The raw `Authorization` request header, if one was sent. */
    readonly authorization?: string | undefined;
    /** The decoded token request body. */
    readonly request: {
        readonly client_id?: string | undefined;
        readonly client_secret?: string | undefined;
    };
}): Option.Option<{ readonly clientId: string; readonly clientSecret: string | undefined }> => {
    const header = options.authorization;

    if (typeof header === "string" && header.slice(0, 6).toLowerCase() === "basic ") {
        if (options.request.client_secret !== undefined) return Option.none();
        const decoded = Result.getOrUndefined(Encoding.decodeBase64String(header.slice(6).trim()));
        const separator = decoded === undefined ? -1 : decoded.indexOf(":");
        if (decoded === undefined || separator === -1) return Option.none();
        // RFC 6749 Section 2.3.1: both values are form-urlencoded before
        // being joined and base64 encoded.
        try {
            return Option.some({
                clientId: decodeURIComponent(decoded.slice(0, separator)),
                clientSecret: decodeURIComponent(decoded.slice(separator + 1)),
            });
        } catch {
            return Option.none();
        }
    }

    if (options.request.client_id !== undefined) {
        return Option.some({
            clientId: options.request.client_id,
            clientSecret: options.request.client_secret,
        });
    }

    return Option.none();
};

/**
 * Issues an access token JWT (RFC 9068, `typ: "at+jwt"`). Used by the
 * provider's token endpoint.
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
    const nowSeconds = yield* DateTime.now.pipe(Effect.map((now) => Math.floor(DateTime.toEpochMillis(now) / 1000)));
    // RFC 9068 Section 2.1: access tokens carry `typ: "at+jwt"` so a resource
    // server can refuse any other JWT the issuer signs (an id token, say).
    return yield* Jwt.sign({
        privateJwk: options.privateJwk,
        typ: "at+jwt",
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
 * Issues an id token JWT. The audience is the
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
    readonly profile?:
        | {
              readonly name?: string | undefined;
              readonly picture?: string | undefined;
          }
        | undefined;
}) {
    const nowSeconds = yield* DateTime.now.pipe(Effect.map((now) => Math.floor(DateTime.toEpochMillis(now) / 1000)));
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

const LOOPBACK_HOSTS: ReadonlyArray<string> = ["localhost", "127.0.0.1", "[::1]"];

/**
 * Whether credentials may travel to a url: https, or plain http to the
 * loopback interface, where nothing is on the wire. The loopback exception is
 * what lets a relying party run against a provider on `localhost` in
 * development; away from loopback, RFC 8414 Section 2 makes https mandatory
 * and so does this.
 */
const isSecureEndpoint = (url: URL): boolean =>
    url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.includes(url.hostname));

/**
 * Fetches and decodes the issuer's discovery document.
 *
 * Every endpoint in the document must be same-origin with the issuer and
 * https, except that plain http is accepted on the loopback interface
 * (`localhost`, `127.0.0.1`, `[::1]`) so a development provider can be
 * reached without a certificate.
 *
 * @since 1.0.0
 * @category Client
 */
export const fetchDiscovery = Effect.fnUntraced(function* (issuer: string) {
    const document = yield* Effect.flatMap(
        HttpClient.get(issuerUrl(issuer, "/.well-known/openid-configuration")),
        HttpClientResponse.schemaBodyJson(DiscoveryDocumentSchema)
    );

    // OIDC Discovery 1.0 §4.3 / RFC 8414 §3.3: the returned issuer MUST equal
    // the one used to build the request, and every endpoint the client will
    // send credentials to MUST be https (loopback excepted) and same-origin
    // with that issuer. Without this check a hostile discovery document could
    // point the token endpoint at an attacker and harvest the code + PKCE
    // verifier.
    if (document.issuer !== issuer) {
        return yield* new DiscoveryError({ reason: "IssuerMismatch" });
    }

    const issuerOrigin = new URL(issuer).origin;
    const endpoints = [
        document.authorization_endpoint,
        document.token_endpoint,
        document.jwks_uri,
        document.userinfo_endpoint,
        document.revocation_endpoint,
        document.registration_endpoint,
    ].filter((endpoint) => endpoint !== undefined);
    for (const endpoint of endpoints) {
        const url = yield* Effect.try({
            try: () => new URL(endpoint),
            catch: () => new DiscoveryError({ reason: "InvalidEndpoint" }),
        });
        if (!isSecureEndpoint(url) || url.origin !== issuerOrigin) {
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
export const fetchJwks = (jwksUri: string) =>
    Effect.flatMap(HttpClient.get(jwksUri), HttpClientResponse.schemaBodyJson(Jwt.JwksSchema));

/**
 * A cached view of an issuer's JWKS document - see {@link jwksCache}.
 *
 * @since 1.0.0
 * @category Client
 */
export interface JwksCache<E> {
    /** The cached document, fetched on first use and refreshed after the ttl. */
    readonly get: Effect.Effect<Schema.Schema.Type<typeof Jwt.JwksSchema>, E>;
    /**
     * Drops the cached document and fetches a fresh one, for when a token
     * names a `kid` the cached set lacks (the issuer rotated its keys). Rate
     * limited to one forced refresh per `minRefreshInterval` - within the
     * window it simply answers the cached document - so unknown `kid`s in
     * hostile tokens cannot be turned into a request flood at the issuer.
     */
    readonly refresh: Effect.Effect<Schema.Schema.Type<typeof Jwt.JwksSchema>, E>;
}

/**
 * Builds a cached view of an issuer's JWKS document for verifiers that run
 * per request: the document is fetched lazily on first use (concurrent
 * callers share one fetch), reused for `ttl` (10 minutes by default), and
 * refreshed after that. A forced `refresh` (for an unknown `kid`) is rate
 * limited to one per `minRefreshInterval` (30 seconds by default).
 *
 * Availability beats freshness on the failure paths. A failed refresh
 * serves the previously fetched document, so a blip at the issuer cannot
 * fail verifications the old keys could still answer. A failure with
 * nothing to fall back on (the very first fetch) fails its own caller but
 * is evicted from the cache immediately, so the next caller retries
 * instead of inheriting the failure for the rest of the ttl.
 *
 * @since 1.0.0
 * @category Client
 */
export const jwksCache = (
    jwksUri: string,
    options?: { readonly ttl?: Duration.Input | undefined; readonly minRefreshInterval?: Duration.Input | undefined }
) =>
    Effect.gen(function* () {
        const lastGood = yield* Ref.make(Option.none<Schema.Schema.Type<typeof Jwt.JwksSchema>>());
        const lastRefreshMillis = yield* Ref.make(0);
        const minRefreshMillis = Duration.toMillis(options?.minRefreshInterval ?? "30 seconds");

        const [cached, invalidate] = yield* fetchJwks(jwksUri).pipe(
            Effect.tap((jwks) => Ref.set(lastGood, Option.some(jwks))),
            Effect.catch((error) =>
                Ref.get(lastGood).pipe(
                    Effect.flatMap(Option.match({ onNone: () => Effect.fail(error), onSome: Effect.succeed }))
                )
            ),
            Effect.cachedInvalidateWithTTL(options?.ttl ?? "10 minutes")
        );
        const get = Effect.tapError(cached, () => invalidate);

        const refresh = Effect.gen(function* () {
            const nowMillis = DateTime.toEpochMillis(yield* DateTime.now);
            const last = yield* Ref.get(lastRefreshMillis);
            if (nowMillis - last < minRefreshMillis) return yield* get;
            yield* Ref.set(lastRefreshMillis, nowMillis);
            yield* invalidate;
            return yield* get;
        });

        return { get, refresh };
    });

/**
 * Builds a cached view of an issuer's JWKS document - the `get` half of
 * {@link jwksCache}, for callers that do not need forced refreshes.
 *
 * @since 1.0.0
 * @category Client
 */
export const cachedJwks = (jwksUri: string, ttl: Duration.Input = "10 minutes") =>
    Effect.map(jwksCache(jwksUri, { ttl }), (cache) => cache.get);

/**
 * Builds the browser redirect URL that starts the code flow.
 *
 * @since 1.0.0
 * @category Client
 */
export const authorizationRequest = (options: {
    readonly authorizationEndpoint: string;
    readonly clientId: string;
    readonly redirectUri: string;
    readonly scopes: ReadonlyArray<string>;
    readonly state: string;
    readonly codeChallenge: string;
    readonly nonce?: string | undefined;
}) =>
    HttpClientRequest.empty.pipe(
        HttpClientRequest.setUrl(options.authorizationEndpoint),
        HttpClientRequest.setUrlParam("response_type", "code"),
        HttpClientRequest.setUrlParam("client_id", options.clientId),
        HttpClientRequest.setUrlParam("redirect_uri", options.redirectUri),
        HttpClientRequest.setUrlParam("scope", options.scopes.join(" ")),
        HttpClientRequest.setUrlParam("state", options.state),
        HttpClientRequest.setUrlParam("code_challenge", options.codeChallenge),
        HttpClientRequest.setUrlParam("code_challenge_method", "S256"),
        options.nonce === undefined ? (self) => self : HttpClientRequest.setUrlParam("nonce", options.nonce)
    );

/**
 * Exchanges an authorization code for tokens at the provider's token
 * endpoint.
 *
 * @since 1.0.0
 * @category Client
 */
export const exchangeAuthorizationCode = (options: {
    readonly tokenEndpoint: string;
    readonly clientId: string;
    readonly clientSecret?: string | undefined;
    readonly code: string;
    readonly codeVerifier: string;
    readonly redirectUri: string;
}) =>
    HttpClientRequest.post(options.tokenEndpoint).pipe(
        HttpClientRequest.bodyUrlParams({
            grant_type: "authorization_code",
            code: options.code,
            redirect_uri: options.redirectUri,
            client_id: options.clientId,
            code_verifier: options.codeVerifier,
            ...(options.clientSecret === undefined ? {} : { client_secret: options.clientSecret }),
        }),
        HttpClient.execute,
        Effect.flatMap(HttpClientResponse.schemaBodyJson(TokenResponseSchema))
    );

/**
 * Obtains an access token with the client credentials grant - the machine
 * to machine flow for confidential clients, with no user involved. The
 * client authenticates with `client_secret_basic` (the OIDC default
 * method).
 *
 * @since 1.0.0
 * @category Client
 */
export const exchangeClientCredentials = (options: {
    readonly tokenEndpoint: string;
    readonly clientId: string;
    readonly clientSecret: string;
    readonly scopes?: ReadonlyArray<string> | undefined;
}) => {
    // RFC 6749 Section 2.3.1: form-urlencode the id and secret before
    // joining them for the Basic header.
    const basic = Encoding.encodeBase64(
        `${encodeURIComponent(options.clientId)}:${encodeURIComponent(options.clientSecret)}`
    );

    return HttpClientRequest.post(options.tokenEndpoint).pipe(
        HttpClientRequest.setHeader("authorization", `Basic ${basic}`),
        HttpClientRequest.bodyUrlParams({
            grant_type: "client_credentials",
            ...(options.scopes === undefined ? {} : { scope: options.scopes.join(" ") }),
        }),
        HttpClient.execute,
        Effect.flatMap(HttpClientResponse.schemaBodyJson(TokenResponseSchema))
    );
};

/**
 * Revokes a token at the provider's RFC 7009 revocation endpoint.
 * Confidential clients authenticate with `client_secret_basic`; public
 * clients send only their `client_id`.
 *
 * @since 1.0.0
 * @category Client
 */
export const revokeToken = (options: {
    readonly revocationEndpoint: string;
    readonly token: string;
    readonly clientId?: string | undefined;
    readonly clientSecret?: string | undefined;
}) => {
    const basic =
        options.clientId === undefined || options.clientSecret === undefined
            ? undefined
            : Encoding.encodeBase64(
                  `${encodeURIComponent(options.clientId)}:${encodeURIComponent(options.clientSecret)}`
              );

    const request = HttpClientRequest.post(options.revocationEndpoint).pipe(
        basic === undefined ? (self) => self : HttpClientRequest.setHeader("authorization", `Basic ${basic}`),
        HttpClientRequest.bodyUrlParams({
            token: options.token,
            ...(basic === undefined && options.clientId !== undefined ? { client_id: options.clientId } : {}),
        })
    );

    return HttpClient.execute(request);
};

/**
 * Verifies an id token against the issuer's JWKS and decodes its claims,
 * checking the audience (the client id) and, when provided, the nonce. This
 * is the last step of the sign-in flow - the returned `sub` is the stable
 * account id at the provider to key local users on.
 *
 * Accepts ES256 and RS256 signatures by default: ES256 is what this
 * library's provider signs with, and RS256 is what the large third-party
 * providers (Google, Discord) sign with. Pass `algorithms` to narrow or
 * widen the accepted set - never include an HMAC algorithm, since the JWKS
 * is public and anyone holding it could mint "signed" tokens.
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
    readonly algorithms?: ReadonlyArray<(typeof Jwa.JwsAlgorithm)["Type"]> | undefined;
}) {
    const claims = yield* Jwt.verify(options.idToken, {
        jwks: options.jwks,
        issuer: options.issuer,
        audience: options.clientId,
        algorithms: options.algorithms ?? ["ES256", "RS256"],
    });

    const idClaims = yield* Schema.decodeEffect(IdTokenClaimsSchema)(claims).pipe(
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
