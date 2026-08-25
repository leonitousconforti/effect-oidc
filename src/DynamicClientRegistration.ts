/**
 * Dynamic client registration, RFC 7591: the endpoint where a client hands a
 * provider its metadata and is handed back a `client_id` - and, when it asked
 * to be confidential, a `client_secret`.
 *
 * Both ends are here. A provider decodes {@link ClientMetadataRequestSchema}
 * and runs {@link validateClientMetadata} against its own
 * {@link RegistrationPolicy}, which fills in the defaults the RFC leaves to
 * the server and refuses anything the provider could not honour later;
 * {@link clientInformationResponse} builds the answer. A client calls
 * {@link register}, which finds the endpoint through discovery and comes back
 * with its credentials.
 *
 * Registering is not authorizing. Nothing here decides who may register: RFC
 * 7591 Section 3 offers an initial access token for that, and this module will
 * present one ({@link register}) and expects the provider to have checked it
 * before calling {@link validateClientMetadata}. An open registration endpoint
 * lets anyone mint a client and put a consent screen in front of users under
 * the provider's name, so a deployment that cannot gate it should not offer
 * it at all - and should not advertise `registration_endpoint` in discovery.
 *
 * Nor does registering make a client trusted. A registered client is subject
 * to the same authorization code + PKCE flow as any other, and a provider
 * should not skip its consent screen for one just because it registered
 * successfully.
 *
 * @since 1.0.0
 * @category DynamicClientRegistration
 * @see https://www.rfc-editor.org/rfc/rfc7591 - OAuth 2.0 Dynamic Client Registration Protocol
 */

import { DateTime, Effect, Option, Redacted, Result, Schema } from "effect";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http";

import * as Oidc from "./Oidc.ts";

/**
 * How a client authenticates at the token endpoint (RFC 7591 Section 2).
 * `none` registers a public client, which proves itself with PKCE and is
 * issued no secret; the other two register a confidential client and come
 * back with one.
 *
 * These are the methods `Oidc.clientAuthentication` can resolve. A provider
 * that supports fewer narrows them through {@link RegistrationPolicy}.
 *
 * @since 1.0.0
 * @category Schema
 */
export const TokenEndpointAuthMethodSchema = Schema.Literals(["none", "client_secret_basic", "client_secret_post"]);

/**
 * @since 1.0.0
 * @category Models
 */
export type TokenEndpointAuthMethod = (typeof TokenEndpointAuthMethodSchema)["Type"];

/**
 * The grants a client may register for.
 *
 * @since 1.0.0
 * @category Schema
 */
export const GrantTypeSchema = Schema.Literals(["authorization_code", "refresh_token", "client_credentials"]);

/**
 * @since 1.0.0
 * @category Models
 */
export type GrantType = (typeof GrantTypeSchema)["Type"];

/**
 * The response types a client may register for. Only `code`: the implicit
 * and hybrid flows return tokens through the front channel, which OAuth 2.1
 * removes and this library never implemented.
 *
 * @since 1.0.0
 * @category Schema
 */
export const ResponseTypeSchema = Schema.Literals(["code"]);

/**
 * @since 1.0.0
 * @category Models
 */
export type ResponseType = (typeof ResponseTypeSchema)["Type"];

/**
 * The client metadata of a registration request (RFC 7591 Section 2).
 *
 * Every field is optional at the wire, as the RFC has it, and every value is
 * a plain string rather than one of the literal unions above. The defaults
 * and the refusals belong to {@link validateClientMetadata} instead, so that
 * a bad redirect uri and a bad auth method can be told apart in the response:
 * a schema that rejected them both would answer `invalid_client_metadata` for
 * a redirect uri the RFC gives its own error code to.
 *
 * RFC 7591 defines further display and legal metadata - `client_uri`,
 * `logo_uri`, `contacts`, `tos_uri`, `policy_uri`. They are absent here
 * because nothing in the registration decision reads them; a provider that
 * stores them can decode them from the same body alongside this schema.
 *
 * @since 1.0.0
 * @category Schema
 */
export const ClientMetadataRequestSchema = Schema.Struct({
    redirect_uris: Schema.Array(Schema.String).pipe(Schema.optional),
    token_endpoint_auth_method: Schema.String.pipe(Schema.optional),
    grant_types: Schema.Array(Schema.String).pipe(Schema.optional),
    response_types: Schema.Array(Schema.String).pipe(Schema.optional),
    client_name: Schema.String.pipe(Schema.optional),
    scope: Schema.String.pipe(Schema.optional),
    software_id: Schema.String.pipe(Schema.optional),
    software_version: Schema.String.pipe(Schema.optional),
});

/**
 * The client information response (RFC 7591 Section 3.2.1): the issued
 * credentials, followed by the registered metadata as the provider recorded
 * it, which is not always what the client asked for.
 *
 * @since 1.0.0
 * @category Schema
 */
export const ClientInformationResponseSchema = Schema.Struct({
    client_id: Schema.String,
    client_secret: Schema.String.pipe(Schema.optional),
    /** Seconds since the epoch. */
    client_id_issued_at: Schema.Number.pipe(Schema.optional),
    /**
     * Seconds since the epoch, or `0` for a secret that does not expire. RFC
     * 7591 Section 3.2.1 makes this REQUIRED whenever a `client_secret` is
     * issued - see {@link clientInformationResponse}.
     */
    client_secret_expires_at: Schema.Number.pipe(Schema.optional),
    redirect_uris: Schema.Array(Schema.String).pipe(Schema.optional),
    token_endpoint_auth_method: Schema.String.pipe(Schema.optional),
    grant_types: Schema.Array(Schema.String).pipe(Schema.optional),
    response_types: Schema.Array(Schema.String).pipe(Schema.optional),
    client_name: Schema.String.pipe(Schema.optional),
    scope: Schema.String.pipe(Schema.optional),
    software_id: Schema.String.pipe(Schema.optional),
    software_version: Schema.String.pipe(Schema.optional),
});

/**
 * The refusals RFC 7591 Section 3.2.2 defines.
 *
 * `invalid_redirect_uri` is the reason a redirect uri gets its own code: it
 * is the one piece of metadata that decides where credentials are delivered,
 * so a client whose registration was refused for it should not have to guess
 * which of its fields was wrong.
 *
 * @since 1.0.0
 * @category Schema
 */
export const RegistrationErrorCodeSchema = Schema.Literals([
    "invalid_redirect_uri",
    "invalid_client_metadata",
    "invalid_software_statement",
    "unapproved_software_statement",
]);

/**
 * @since 1.0.0
 * @category Models
 */
export type RegistrationErrorCode = (typeof RegistrationErrorCodeSchema)["Type"];

/**
 * A registration refusal (RFC 7591 Section 3.2.2).
 *
 * `error` is a plain string rather than {@link RegistrationErrorCodeSchema}
 * because this schema also decodes what a foreign provider answered, and a
 * provider that sends a code outside the four defined ones should surface it
 * rather than fail to decode and lose the only explanation on offer.
 *
 * @since 1.0.0
 * @category Schema
 */
export const RegistrationErrorResponseSchema = Schema.Struct({
    error: Schema.String,
    error_description: Schema.String.pipe(Schema.optional),
});

/**
 * Loopback hosts, where a redirect uri may be plain http.
 *
 * RFC 8252 Section 7.3 has a native app receive its redirect on a loopback
 * listener, which cannot hold a certificate for a name it does not own. It
 * is also what lets a development deployment register `http://localhost:3000`
 * against a provider next door. Nothing is on the wire either way.
 *
 * Distinct from the same-looking list behind `Oidc.fetchDiscovery`, which
 * asks whether *credentials* may travel to a url. This asks whether a browser
 * may be redirected to one.
 */
const LOOPBACK_HOSTS: ReadonlyArray<string> = ["localhost", "127.0.0.1", "[::1]"];

/**
 * Whether a provider will register a redirect uri: absolute, with no fragment
 * (RFC 6749 Section 3.1.2), and https unless it points at the loopback
 * interface.
 *
 * The check is on the shape of the uri, not on who is asking. A provider that
 * wants to refuse a redirect uri for some other reason - an origin it does
 * not recognize, a host it has blocked - does that on top of this.
 *
 * @since 1.0.0
 * @category Provider
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2
 */
export const isRegistrableRedirectUri = (
    value: string,
    options?: { readonly allowLoopbackHttp?: boolean | undefined }
): boolean => {
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        return false;
    }
    // RFC 6749 Section 3.1.2: the endpoint uri MUST NOT include a fragment.
    // The browser never sends one to the server, so a registration carrying
    // one has recorded something that cannot be matched at authorize time.
    if (url.hash !== "") return false;
    if (url.protocol === "https:") return true;
    if (options?.allowLoopbackHttp === false) return false;
    return url.protocol === "http:" && LOOPBACK_HOSTS.includes(url.hostname);
};

/**
 * What a provider will register, and the defaults it fills in for what a
 * client left out.
 *
 * @since 1.0.0
 * @category Provider
 */
export interface RegistrationPolicy {
    /**
     * The scopes this provider issues. A registration is refused unless every
     * scope it asks for is one of these, so a client never registers with a
     * scope every later authorization would then refuse.
     */
    readonly supportedScopes: ReadonlyArray<string>;
    /** Defaults to every method `Oidc.clientAuthentication` can resolve. */
    readonly tokenEndpointAuthMethods?: ReadonlyArray<TokenEndpointAuthMethod> | undefined;
    /** Defaults to every grant in {@link GrantTypeSchema}. */
    readonly grantTypes?: ReadonlyArray<GrantType> | undefined;
    /** Defaults to `["code"]`. */
    readonly responseTypes?: ReadonlyArray<ResponseType> | undefined;
    /** What a client that names no scope is registered with. Defaults to `"openid"`. */
    readonly defaultScope?: string | undefined;
    /** What a client that names itself nothing is called. Defaults to `"Dynamically registered client"`. */
    readonly defaultClientName?: string | undefined;
    /**
     * Whether `software_id` is required, which RFC 7591 leaves optional.
     *
     * Require it to key registrations by it: registering again under the same
     * `software_id` updates that client instead of making another, which is
     * what lets a service register on every boot and keep no record of its own
     * registration. Without one there is nothing to recognize a client by on
     * its next boot and it collects a new registration every time it starts.
     */
    readonly requireSoftwareId?: boolean | undefined;
    /** Whether a loopback redirect uri may be plain http. Defaults to `true`. */
    readonly allowLoopbackHttp?: boolean | undefined;
}

/**
 * A validated registration: what the provider should store, with the RFC's
 * defaults applied and every value checked against the policy.
 *
 * @since 1.0.0
 * @category Provider
 */
export interface ClientMetadata {
    readonly redirectUris: readonly [string, ...Array<string>];
    readonly tokenEndpointAuthMethod: TokenEndpointAuthMethod;
    readonly grantTypes: ReadonlyArray<GrantType>;
    readonly responseTypes: ReadonlyArray<ResponseType>;
    /** Space delimited, as it travels on the wire and as `scope` claims carry it. */
    readonly scope: string;
    readonly clientName: string;
    readonly softwareId: Option.Option<string>;
    readonly softwareVersion: Option.Option<string>;
    /** Whether this registration is for a confidential client, which is to be issued a secret. */
    readonly confidential: boolean;
}

/**
 * Splits a space delimited scope string, dropping empties and duplicates.
 *
 * RFC 6749 Appendix A.4 delimits with a single space, but a client that pads
 * or tabs is describing scopes it can be given rather than making a request
 * that has to be refused.
 *
 * @since 1.0.0
 * @category Utilities
 */
export const scopesOf = (scope: string): ReadonlyArray<string> => [...new Set(scope.split(/\s+/).filter(Boolean))];

const isOneOf = <const T extends ReadonlyArray<string>>(values: T, value: string): value is T[number] =>
    values.includes(value);

const DEFAULT_AUTH_METHODS: ReadonlyArray<TokenEndpointAuthMethod> = [
    "none",
    "client_secret_basic",
    "client_secret_post",
];
const DEFAULT_GRANT_TYPES: ReadonlyArray<GrantType> = ["authorization_code", "refresh_token", "client_credentials"];
const DEFAULT_RESPONSE_TYPES: ReadonlyArray<ResponseType> = ["code"];

/**
 * Applies a provider's registration policy to a request body: fills in the
 * defaults the RFC leaves to the server, and refuses anything the provider
 * could not honour, so that a client never registers with a redirect uri,
 * grant, response type or scope that every later request would then be
 * refused for.
 *
 * The checks run in the order below, and the first failure is the answer:
 *
 * 1. `redirect_uris` - present, non-empty, and every one
 *    {@link isRegistrableRedirectUri}. Answers `invalid_redirect_uri`; every
 *    later refusal answers `invalid_client_metadata`.
 * 2. `software_id`, when the policy requires it.
 * 3. `token_endpoint_auth_method` - defaults to `client_secret_basic`, which
 *    is the RFC 7591 Section 2 default, and must be one the policy allows.
 *    Note that the default registers a *confidential* client: a public client
 *    has to say `none`, it is never inferred.
 * 4. `response_types` - defaults to `["code"]`.
 * 5. `grant_types` - defaults to `["authorization_code"]`.
 * 6. RFC 7591 Section 2.1 consistency: the `authorization_code` grant and the
 *    `code` response type each require the other.
 * 7. `client_credentials` for a public client. Machine to machine is a
 *    confidential flow - a public client has no credentials to exchange - so
 *    registering for it would only ever earn an `invalid_client` at the token
 *    endpoint. Refused here, where the answer says which field was wrong.
 * 8. `scope` - defaults to the policy's, and every scope must be supported.
 *
 * What it does not do is decide *whether* this client may register at all.
 * That is the initial access token (RFC 7591 Section 3), checked before this
 * is ever called.
 *
 * @since 1.0.0
 * @category Provider
 */
export const validateClientMetadata = (
    request: (typeof ClientMetadataRequestSchema)["Type"],
    policy: RegistrationPolicy
): Result.Result<ClientMetadata, RegistrationErrorCode> => {
    const authMethods = policy.tokenEndpointAuthMethods ?? DEFAULT_AUTH_METHODS;
    const grantTypes = policy.grantTypes ?? DEFAULT_GRANT_TYPES;
    const responseTypes = policy.responseTypes ?? DEFAULT_RESPONSE_TYPES;

    const redirectUris = request.redirect_uris ?? [];
    const allowLoopbackHttp = policy.allowLoopbackHttp ?? true;
    // Destructured rather than length-checked, so that the head the result
    // carries is the one the type promises without an assertion.
    const [firstRedirectUri, ...otherRedirectUris] = redirectUris;
    if (
        firstRedirectUri === undefined ||
        !redirectUris.every((uri) => isRegistrableRedirectUri(uri, { allowLoopbackHttp }))
    ) {
        return Result.fail("invalid_redirect_uri");
    }

    const softwareId = request.software_id?.trim() ?? "";
    if (policy.requireSoftwareId === true && softwareId.length === 0) {
        return Result.fail("invalid_client_metadata");
    }

    // RFC 7591 Section 2: a client that names no method is registered with
    // `client_secret_basic`, the OAuth 2.0 default.
    const tokenEndpointAuthMethod = request.token_endpoint_auth_method ?? "client_secret_basic";
    if (!isOneOf(authMethods, tokenEndpointAuthMethod)) return Result.fail("invalid_client_metadata");

    const requestedResponseTypes = request.response_types ?? ["code"];
    if (!requestedResponseTypes.every((type) => isOneOf(responseTypes, type))) {
        return Result.fail("invalid_client_metadata");
    }

    const requestedGrantTypes = request.grant_types ?? ["authorization_code"];
    if (!requestedGrantTypes.every((type) => isOneOf(grantTypes, type))) {
        return Result.fail("invalid_client_metadata");
    }

    // RFC 7591 Section 2.1: `authorization_code` and `code` are two halves of
    // one flow. Either alone describes a client that could start something it
    // could not finish, or finish something it could not start.
    const wantsCodeGrant = requestedGrantTypes.includes("authorization_code");
    const wantsCodeResponse = requestedResponseTypes.includes("code");
    if (wantsCodeGrant !== wantsCodeResponse) return Result.fail("invalid_client_metadata");

    const confidential = tokenEndpointAuthMethod !== "none";
    if (!confidential && requestedGrantTypes.includes("client_credentials")) {
        return Result.fail("invalid_client_metadata");
    }

    const scopes = scopesOf(request.scope ?? policy.defaultScope ?? "openid");
    if (scopes.length === 0 || !scopes.every((scope) => policy.supportedScopes.includes(scope))) {
        return Result.fail("invalid_client_metadata");
    }

    const clientName = request.client_name?.trim() ?? "";
    return Result.succeed({
        redirectUris: [firstRedirectUri, ...otherRedirectUris],
        tokenEndpointAuthMethod,
        grantTypes: requestedGrantTypes,
        responseTypes: requestedResponseTypes,
        scope: scopes.join(" "),
        clientName: clientName.length > 0 ? clientName : (policy.defaultClientName ?? "Dynamically registered client"),
        softwareId: softwareId.length > 0 ? Option.some(softwareId) : Option.none(),
        softwareVersion: Option.fromNullishOr(request.software_version),
        confidential,
    });
};

/**
 * Builds the client information response (RFC 7591 Section 3.2.1).
 *
 * Answered with `201 Created`. The `client_secret` is in it exactly once, at
 * registration: a provider that stores only the secret's hash cannot ever
 * show it again, which is also why re-registering a confidential client
 * should hand it a fresh one rather than expect it to have kept the last.
 *
 * `client_secret_expires_at` is filled in whenever a secret is issued,
 * because the RFC makes it REQUIRED there, with `0` for a secret that does
 * not expire. Pass `secretExpiresAt` for one that does.
 *
 * @since 1.0.0
 * @category Provider
 */
export const clientInformationResponse = (options: {
    readonly clientId: string;
    readonly metadata: ClientMetadata;
    /** Present only in the response to the registration that issued it. */
    readonly clientSecret?: string | undefined;
    readonly issuedAt?: DateTime.Utc | undefined;
    /** Omitted for a secret that does not expire, which the RFC writes as `0`. */
    readonly secretExpiresAt?: DateTime.Utc | undefined;
}): (typeof ClientInformationResponseSchema)["Type"] => ({
    client_id: options.clientId,
    ...(options.clientSecret === undefined
        ? {}
        : {
              client_secret: options.clientSecret,
              client_secret_expires_at:
                  options.secretExpiresAt === undefined
                      ? 0
                      : Math.floor(DateTime.toEpochMillis(options.secretExpiresAt) / 1000),
          }),
    ...(options.issuedAt === undefined
        ? {}
        : { client_id_issued_at: Math.floor(DateTime.toEpochMillis(options.issuedAt) / 1000) }),
    redirect_uris: options.metadata.redirectUris,
    token_endpoint_auth_method: options.metadata.tokenEndpointAuthMethod,
    grant_types: options.metadata.grantTypes,
    response_types: options.metadata.responseTypes,
    client_name: options.metadata.clientName,
    scope: options.metadata.scope,
    ...Option.match(options.metadata.softwareId, {
        onNone: () => ({}),
        onSome: (software_id) => ({ software_id }),
    }),
    ...Option.match(options.metadata.softwareVersion, {
        onNone: () => ({}),
        onSome: (software_version) => ({ software_version }),
    }),
});

/**
 * Why registering failed:
 *
 * - `NotOffered`: the provider's discovery document names no
 *   `registration_endpoint`, so this provider does not offer registration.
 * - `Rejected`: the provider answered, and what it said was not usable - it
 *   refused the metadata (`detail` carries the RFC 7591 Section 3.2.2 error
 *   code), refused the initial access token, or served a discovery document
 *   that failed validation.
 * - `Unreachable`: the provider could not be reached, or answered with
 *   something that was not a registration.
 *
 * @since 1.0.0
 * @category Errors
 */
export class RegistrationError extends Schema.Error<RegistrationError>("effect-oidc/RegistrationError")({
    _tag: Schema.tag("RegistrationError"),
    reason: Schema.Literals(["NotOffered", "Rejected", "Unreachable"]),
    detail: Schema.String.pipe(Schema.optional),
}) {}

/**
 * The credentials a registration was issued.
 *
 * @since 1.0.0
 * @category Models
 */
export interface Registration {
    readonly clientId: string;
    /** `Option.none` for a public client, which is issued no secret. */
    readonly clientSecret: Option.Option<Redacted.Redacted>;
    readonly issuedAt: Option.Option<DateTime.Utc>;
    /**
     * `Option.none` for a secret that does not expire, which RFC 7591 Section
     * 3.2.1 writes as `0`, and for a public client, which has none.
     */
    readonly secretExpiresAt: Option.Option<DateTime.Utc>;
}

/**
 * What a client asks to be registered as.
 *
 * @since 1.0.0
 * @category Models
 */
export interface ClientRegistrationRequest {
    readonly redirectUris: readonly [string, ...Array<string>];
    /**
     * `none` for a public client. Never inferred: a client that leaves this
     * out is registered as confidential, which is the RFC 7591 Section 2
     * default, so it is required here rather than quietly defaulted.
     */
    readonly tokenEndpointAuthMethod: TokenEndpointAuthMethod;
    readonly clientName?: string | undefined;
    readonly scopes?: ReadonlyArray<string> | undefined;
    /** Defaults to `["authorization_code"]`. */
    readonly grantTypes?: ReadonlyArray<GrantType> | undefined;
    /** Defaults to `["code"]`. */
    readonly responseTypes?: ReadonlyArray<ResponseType> | undefined;
    /**
     * Identifies the software, not the installation: the same value in every
     * copy of a service, stable across restarts and redeploys. A provider
     * that keys registrations by it recognizes the client on its next boot,
     * so changing this registers a new client rather than updating that one.
     */
    readonly softwareId?: string | undefined;
    readonly softwareVersion?: string | undefined;
}

const bodyOf = (metadata: ClientRegistrationRequest) => ({
    redirect_uris: metadata.redirectUris,
    token_endpoint_auth_method: metadata.tokenEndpointAuthMethod,
    grant_types: metadata.grantTypes ?? ["authorization_code"],
    response_types: metadata.responseTypes ?? ["code"],
    ...(metadata.clientName === undefined ? {} : { client_name: metadata.clientName }),
    ...(metadata.scopes === undefined ? {} : { scope: metadata.scopes.join(" ") }),
    ...(metadata.softwareId === undefined ? {} : { software_id: metadata.softwareId }),
    ...(metadata.softwareVersion === undefined ? {} : { software_version: metadata.softwareVersion }),
});

const secondsToDateTime = (seconds: number | undefined): Option.Option<DateTime.Utc> =>
    seconds === undefined || seconds === 0 ? Option.none() : Option.some(DateTime.makeUnsafe(seconds * 1000));

/**
 * Registers at a known registration endpoint (RFC 7591 Section 3.1).
 *
 * The initial access token, when the provider gate needs one, rides as a
 * bearer token on the request. Nothing is retried: whether a provider that is
 * still coming up is worth waiting for is the caller's judgement, and
 * `Effect.retry` composes.
 *
 * @since 1.0.0
 * @category Client
 */
export const registerAt = Effect.fnUntraced(
    function* (options: {
        readonly registrationEndpoint: string;
        readonly metadata: ClientRegistrationRequest;
        readonly initialAccessToken?: Redacted.Redacted | string | undefined;
    }) {
        const httpClient = yield* HttpClient.HttpClient;
        const initialAccessToken =
            options.initialAccessToken === undefined
                ? undefined
                : typeof options.initialAccessToken === "string"
                  ? options.initialAccessToken
                  : Redacted.value(options.initialAccessToken);

        const request = HttpClientRequest.post(options.registrationEndpoint).pipe(
            HttpClientRequest.bodyJsonUnsafe(bodyOf(options.metadata))
        );
        const response = yield* httpClient.execute(
            initialAccessToken === undefined ? request : HttpClientRequest.bearerToken(request, initialAccessToken)
        );

        // RFC 7591 Section 3.2.2: the gate answers 401 with a `WWW-Authenticate`
        // challenge, and says nothing else - it does not reveal whether a token
        // was required, only that this one did not open it.
        if (response.status === 401 || response.status === 403) {
            return yield* new RegistrationError({
                reason: "Rejected",
                detail:
                    initialAccessToken === undefined
                        ? "the provider requires an initial access token"
                        : "the provider refused the initial access token",
            });
        }

        if (response.status === 400) {
            const refusal = yield* HttpClientResponse.schemaBodyJson(RegistrationErrorResponseSchema)(response).pipe(
                Effect.option
            );
            return yield* new RegistrationError({
                reason: "Rejected",
                ...Option.match(refusal, {
                    onNone: () => ({}),
                    onSome: (body) => ({
                        detail:
                            body.error_description === undefined
                                ? body.error
                                : `${body.error}: ${body.error_description}`,
                    }),
                }),
            });
        }

        // RFC 7591 Section 3.2.1 answers 201; a provider that answers 200 has
        // still registered the client, and refusing its body over the status
        // line would lose credentials that now exist.
        if (response.status !== 201 && response.status !== 200) {
            return yield* new RegistrationError({
                reason: "Unreachable",
                detail: `registration answered ${response.status}`,
            });
        }

        const issued = yield* HttpClientResponse.schemaBodyJson(ClientInformationResponseSchema)(response);
        return {
            clientId: issued.client_id,
            clientSecret: Option.map(Option.fromNullishOr(issued.client_secret), Redacted.make),
            issuedAt: secondsToDateTime(issued.client_id_issued_at),
            secretExpiresAt:
                issued.client_secret === undefined ? Option.none() : secondsToDateTime(issued.client_secret_expires_at),
        } satisfies Registration;
    },
    // Reaching the provider and failing to understand it are the same outcome
    // for a caller: there is no client id, and trying again is the only move.
    Effect.catchTags({
        HttpClientError: (error) =>
            Effect.fail(new RegistrationError({ reason: "Unreachable", detail: error.message })),
        SchemaError: (error) => Effect.fail(new RegistrationError({ reason: "Unreachable", detail: error.message })),
    })
);

/**
 * Registers at an issuer, finding the endpoint through discovery.
 *
 * Safe to call on every boot when the provider keys registrations by
 * `softwareId`: the same client comes back, and there is nothing for the
 * service to persist between runs.
 *
 * The endpoint is taken from the issuer's discovery document rather than
 * assumed, which is also what makes `NotOffered` a real answer: a provider
 * that does not advertise `registration_endpoint` does not register clients,
 * and no path is worth guessing at.
 *
 * ```ts
 * import { Effect, Option, Redacted } from "effect"
 * import { DynamicClientRegistration } from "effect-oidc"
 *
 * const registration = DynamicClientRegistration.register({
 *     issuer: "https://id.example.com",
 *     initialAccessToken: Redacted.make(process.env["REGISTRATION_TOKEN"] ?? ""),
 *     metadata: {
 *         softwareId: "my-service",
 *         clientName: "My Service",
 *         redirectUris: ["https://app.example.com/auth/callback"],
 *         tokenEndpointAuthMethod: "none",
 *         scopes: ["openid", "profile"],
 *     },
 * }).pipe(
 *     Effect.tap(({ clientId }) => Effect.logInfo(`registered as ${clientId}`)),
 *     Effect.retry({ times: 5 }),
 *     Effect.map(({ clientId, clientSecret }) => ({
 *         clientId,
 *         clientSecret: Option.map(clientSecret, Redacted.value),
 *     }))
 * )
 * ```
 *
 * @since 1.0.0
 * @category Client
 */
export const register = Effect.fnUntraced(
    function* (options: {
        readonly issuer: string;
        readonly metadata: ClientRegistrationRequest;
        readonly initialAccessToken?: Redacted.Redacted | string | undefined;
    }) {
        const discovery = yield* Oidc.fetchDiscovery(options.issuer);
        const endpoint = Option.fromNullishOr(discovery.registration_endpoint);
        if (Option.isNone(endpoint)) return yield* new RegistrationError({ reason: "NotOffered" });

        return yield* registerAt({
            registrationEndpoint: endpoint.value,
            metadata: options.metadata,
            ...(options.initialAccessToken === undefined ? {} : { initialAccessToken: options.initialAccessToken }),
        });
    },
    Effect.catchTags({
        // A discovery document that failed validation is a `Rejected` rather
        // than an `Unreachable`: the provider answered, and what it said was
        // not something a client may send credentials to.
        DiscoveryError: (error) =>
            Effect.fail(new RegistrationError({ reason: "Rejected", detail: `discovery: ${error.reason}` })),
        HttpClientError: (error) =>
            Effect.fail(new RegistrationError({ reason: "Unreachable", detail: error.message })),
        SchemaError: (error) => Effect.fail(new RegistrationError({ reason: "Unreachable", detail: error.message })),
    })
);
