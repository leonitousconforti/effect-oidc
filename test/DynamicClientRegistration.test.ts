import { Effect, Option, Redacted, Result } from "effect";
import { HttpClient, HttpClientResponse } from "effect/unstable/http";

import { expect, it } from "@effect/vitest";
import { DynamicClientRegistration, Oidc } from "effect-oidc";

const issuer = "https://id.example.com";
const registrationEndpoint = "https://id.example.com/oauth/register";
const redirectUri = "https://app.example.com/auth/callback";

const policy: DynamicClientRegistration.RegistrationPolicy = {
    supportedScopes: ["openid", "profile", "towers:read"],
};

/** The metadata of a registration that should be accepted, for tweaking. */
const wellFormed = {
    redirect_uris: [redirectUri],
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    client_name: "Demo Service",
    scope: "openid profile",
    software_id: "demo-service",
} as const;

const validate = (request: Partial<(typeof DynamicClientRegistration.ClientMetadataRequestSchema)["Type"]>) =>
    DynamicClientRegistration.validateClientMetadata(request, policy);

it("accepts a well formed registration and echoes what it recorded", () => {
    const result = validate(wellFormed);
    expect(Result.isSuccess(result)).toBe(true);
    if (!Result.isSuccess(result)) return;

    expect(result.success.redirectUris).toStrictEqual([redirectUri]);
    expect(result.success.tokenEndpointAuthMethod).toBe("none");
    expect(result.success.grantTypes).toStrictEqual(["authorization_code", "refresh_token"]);
    expect(result.success.responseTypes).toStrictEqual(["code"]);
    expect(result.success.scope).toBe("openid profile");
    expect(result.success.clientName).toBe("Demo Service");
    expect(result.success.softwareId).toStrictEqual(Option.some("demo-service"));
    expect(result.success.confidential).toBe(false);
});

it("fills in the defaults RFC 7591 leaves to the server", () => {
    const result = validate({ redirect_uris: [redirectUri] });
    expect(Result.isSuccess(result)).toBe(true);
    if (!Result.isSuccess(result)) return;

    // RFC 7591 Section 2: a client that names no method is confidential. A
    // public client has to say `none` - it is never inferred from silence.
    expect(result.success.tokenEndpointAuthMethod).toBe("client_secret_basic");
    expect(result.success.confidential).toBe(true);
    expect(result.success.grantTypes).toStrictEqual(["authorization_code"]);
    expect(result.success.responseTypes).toStrictEqual(["code"]);
    expect(result.success.scope).toBe("openid");
    expect(result.success.clientName).toBe("Dynamically registered client");
    expect(result.success.softwareId).toStrictEqual(Option.none());
});

it("takes the policy's own defaults over its built in ones", () => {
    const result = DynamicClientRegistration.validateClientMetadata(
        { redirect_uris: [redirectUri] },
        { ...policy, defaultScope: "openid profile", defaultClientName: "Unnamed" }
    );
    expect(Result.isSuccess(result)).toBe(true);
    if (!Result.isSuccess(result)) return;
    expect(result.success.scope).toBe("openid profile");
    expect(result.success.clientName).toBe("Unnamed");
});

it("refuses a redirect uri with its own error code", () => {
    // The absent, the empty, the relative, the fragment-bearing, and plain
    // http anywhere but loopback.
    expect(validate({})).toStrictEqual(Result.fail("invalid_redirect_uri"));
    expect(validate({ redirect_uris: [] })).toStrictEqual(Result.fail("invalid_redirect_uri"));
    expect(validate({ redirect_uris: ["/auth/callback"] })).toStrictEqual(Result.fail("invalid_redirect_uri"));
    expect(validate({ redirect_uris: [`${redirectUri}#fragment`] })).toStrictEqual(Result.fail("invalid_redirect_uri"));
    expect(validate({ redirect_uris: ["http://app.example.com/auth/callback"] })).toStrictEqual(
        Result.fail("invalid_redirect_uri")
    );
    // One bad uri among good ones is still a refusal.
    expect(validate({ redirect_uris: [redirectUri, "not a url"] })).toStrictEqual(Result.fail("invalid_redirect_uri"));
});

it("allows plain http on the loopback interface, unless the policy says otherwise", () => {
    for (const uri of ["http://localhost:3000/callback", "http://127.0.0.1:3000/callback", "http://[::1]/callback"]) {
        expect(DynamicClientRegistration.isRegistrableRedirectUri(uri)).toBe(true);
        expect(DynamicClientRegistration.isRegistrableRedirectUri(uri, { allowLoopbackHttp: false })).toBe(false);
    }

    // A hostname that merely starts with a loopback name is not loopback.
    expect(DynamicClientRegistration.isRegistrableRedirectUri("http://localhost.evil.example/callback")).toBe(false);

    const result = DynamicClientRegistration.validateClientMetadata(
        { redirect_uris: ["http://localhost:3000/callback"] },
        { ...policy, allowLoopbackHttp: false }
    );
    expect(result).toStrictEqual(Result.fail("invalid_redirect_uri"));
});

it("refuses metadata the provider could not honour later", () => {
    const refused = Result.fail("invalid_client_metadata");

    // An auth method, response type, or grant outside what the policy offers.
    expect(validate({ ...wellFormed, token_endpoint_auth_method: "private_key_jwt" })).toStrictEqual(refused);
    expect(validate({ ...wellFormed, response_types: ["token"] })).toStrictEqual(refused);
    expect(validate({ ...wellFormed, grant_types: ["password"] })).toStrictEqual(refused);
    expect(
        DynamicClientRegistration.validateClientMetadata(wellFormed, {
            ...policy,
            tokenEndpointAuthMethods: ["client_secret_basic"],
        })
    ).toStrictEqual(refused);

    // A scope the provider does not issue, and a scope string that names none.
    expect(validate({ ...wellFormed, scope: "openid admin:everything" })).toStrictEqual(refused);
    expect(validate({ ...wellFormed, scope: "   " })).toStrictEqual(refused);

    // RFC 7591 Section 2.1: the code grant and the code response type each
    // require the other.
    expect(validate({ ...wellFormed, grant_types: ["refresh_token"] })).toStrictEqual(refused);
    expect(validate({ ...wellFormed, grant_types: ["authorization_code"], response_types: [] })).toStrictEqual(refused);
});

it("refuses client_credentials for a public client", () => {
    // A public client has no credentials to exchange, so this would only ever
    // earn an invalid_client at the token endpoint. Refused where the answer
    // still names the field.
    expect(
        validate({
            ...wellFormed,
            token_endpoint_auth_method: "none",
            grant_types: ["client_credentials"],
            response_types: [],
        })
    ).toStrictEqual(Result.fail("invalid_client_metadata"));

    // The same registration as a confidential client is fine.
    const confidential = validate({
        ...wellFormed,
        token_endpoint_auth_method: "client_secret_basic",
        grant_types: ["client_credentials"],
        response_types: [],
    });
    expect(Result.isSuccess(confidential)).toBe(true);
});

it("requires software_id only when the policy keys registrations by it", () => {
    const { software_id: _omitted, ...anonymous } = wellFormed;
    expect(Result.isSuccess(validate(anonymous))).toBe(true);
    expect(
        DynamicClientRegistration.validateClientMetadata(anonymous, { ...policy, requireSoftwareId: true })
    ).toStrictEqual(Result.fail("invalid_client_metadata"));
    // Whitespace is not an identifier.
    expect(
        DynamicClientRegistration.validateClientMetadata(
            { ...wellFormed, software_id: "  " },
            { ...policy, requireSoftwareId: true }
        )
    ).toStrictEqual(Result.fail("invalid_client_metadata"));
});

it("splits scopes on any whitespace, dropping empties and duplicates", () => {
    expect(DynamicClientRegistration.scopesOf(" openid  profile\topenid ")).toStrictEqual(["openid", "profile"]);
    expect(DynamicClientRegistration.scopesOf("")).toStrictEqual([]);
});

it("states client_secret_expires_at whenever it issues a secret", () => {
    const metadata = Result.getOrThrow(validate(wellFormed));

    // RFC 7591 Section 3.2.1 makes the expiry REQUIRED alongside a secret,
    // with 0 for one that does not expire.
    const confidential = DynamicClientRegistration.clientInformationResponse({
        clientId: "client-123",
        clientSecret: "s3cret",
        metadata,
    });
    expect(confidential.client_secret).toBe("s3cret");
    expect(confidential.client_secret_expires_at).toBe(0);

    // A public client is issued neither.
    const publicClient = DynamicClientRegistration.clientInformationResponse({ clientId: "client-123", metadata });
    expect(publicClient.client_secret).toBeUndefined();
    expect(publicClient.client_secret_expires_at).toBeUndefined();
    expect(publicClient.client_id).toBe("client-123");
    expect(publicClient.redirect_uris).toStrictEqual([redirectUri]);
    expect(publicClient.token_endpoint_auth_method).toBe("none");
    expect(publicClient.scope).toBe("openid profile");
    expect(publicClient.software_id).toBe("demo-service");
});

/**
 * A stub provider that answers the registration endpoint with `answer`, and
 * discovery with its own document, recording every request it saw.
 */
const makeProvider = (options: { readonly answer: Response; readonly registration?: string | undefined }) => {
    const requests: Array<{ readonly body: string; readonly authorization: string | undefined }> = [];
    const discovery = {
        ...Oidc.makeDiscoveryDocument(issuer),
        ...(options.registration === undefined ? {} : { registration_endpoint: options.registration }),
    };

    const client = HttpClient.make((request) =>
        Effect.gen(function* () {
            if (request.url === `${issuer}/.well-known/openid-configuration`) {
                return HttpClientResponse.fromWeb(request, Response.json(discovery));
            }
            if (request.url === registrationEndpoint) {
                requests.push({
                    body: request.body._tag === "Uint8Array" ? new TextDecoder().decode(request.body.body) : "",
                    authorization: request.headers["authorization"],
                });
                return HttpClientResponse.fromWeb(request, options.answer.clone());
            }
            return HttpClientResponse.fromWeb(request, new Response("not found", { status: 404 }));
        })
    );

    return { client, requests };
};

const metadata = {
    redirectUris: [redirectUri],
    tokenEndpointAuthMethod: "none",
    clientName: "Demo Service",
    scopes: ["openid", "profile"],
    softwareId: "demo-service",
} as const satisfies DynamicClientRegistration.ClientRegistrationRequest;

it.effect("registers at a known endpoint and carries the initial access token", () =>
    Effect.gen(function* () {
        const { client, requests } = makeProvider({
            answer: Response.json({ client_id: "client-123", client_id_issued_at: 1_700_000_000 }, { status: 201 }),
        });

        const registration = yield* DynamicClientRegistration.registerAt({
            registrationEndpoint,
            metadata,
            initialAccessToken: Redacted.make("let-me-in"),
        }).pipe(Effect.provideService(HttpClient.HttpClient, client));

        expect(registration.clientId).toBe("client-123");
        // A public client is issued no secret, and so has no secret expiry.
        expect(registration.clientSecret).toStrictEqual(Option.none());
        expect(registration.secretExpiresAt).toStrictEqual(Option.none());
        expect(Option.isSome(registration.issuedAt)).toBe(true);

        expect(requests).toHaveLength(1);
        expect(requests[0]?.authorization).toBe("Bearer let-me-in");
        const body: unknown = JSON.parse(requests[0]?.body ?? "");
        expect(body).toStrictEqual({
            redirect_uris: [redirectUri],
            token_endpoint_auth_method: "none",
            grant_types: ["authorization_code"],
            response_types: ["code"],
            client_name: "Demo Service",
            scope: "openid profile",
            software_id: "demo-service",
        });
    })
);

it.effect("redacts an issued client secret and reads 0 as never expiring", () =>
    Effect.gen(function* () {
        const { client } = makeProvider({
            answer: Response.json(
                { client_id: "client-123", client_secret: "s3cret", client_secret_expires_at: 0 },
                { status: 201 }
            ),
        });

        const registration = yield* DynamicClientRegistration.registerAt({
            registrationEndpoint,
            metadata: { ...metadata, tokenEndpointAuthMethod: "client_secret_basic" },
        }).pipe(Effect.provideService(HttpClient.HttpClient, client));

        expect(Option.map(registration.clientSecret, Redacted.value)).toStrictEqual(Option.some("s3cret"));
        // Wrapped rather than bare, so a log line or an error report that
        // happens to carry the registration does not carry the secret.
        expect(Redacted.isRedacted(Option.getOrThrow(registration.clientSecret))).toBe(true);
        expect(registration.secretExpiresAt).toStrictEqual(Option.none());
    })
);

it.effect("carries the provider's refusal through as the failure detail", () =>
    Effect.gen(function* () {
        const { client } = makeProvider({
            answer: Response.json({ error: "invalid_redirect_uri", error_description: "not https" }, { status: 400 }),
        });

        const error = yield* DynamicClientRegistration.registerAt({ registrationEndpoint, metadata }).pipe(
            Effect.provideService(HttpClient.HttpClient, client),
            Effect.flip
        );

        expect(error.reason).toBe("Rejected");
        expect(error.detail).toBe("invalid_redirect_uri: not https");
    })
);

it.effect("tells a refused gate apart from a provider that cannot be understood", () =>
    Effect.gen(function* () {
        const gated = makeProvider({ answer: new Response("", { status: 401 }) });
        const refusedWithoutToken = yield* DynamicClientRegistration.registerAt({
            registrationEndpoint,
            metadata,
        }).pipe(Effect.provideService(HttpClient.HttpClient, gated.client), Effect.flip);
        expect(refusedWithoutToken.reason).toBe("Rejected");
        expect(refusedWithoutToken.detail).toBe("the provider requires an initial access token");

        const refusedWithToken = yield* DynamicClientRegistration.registerAt({
            registrationEndpoint,
            metadata,
            initialAccessToken: "wrong",
        }).pipe(Effect.provideService(HttpClient.HttpClient, gated.client), Effect.flip);
        expect(refusedWithToken.detail).toBe("the provider refused the initial access token");

        // A status that is not a registration and not a refusal.
        const broken = makeProvider({ answer: new Response("nope", { status: 502 }) });
        const unreachable = yield* DynamicClientRegistration.registerAt({ registrationEndpoint, metadata }).pipe(
            Effect.provideService(HttpClient.HttpClient, broken.client),
            Effect.flip
        );
        expect(unreachable.reason).toBe("Unreachable");
        expect(unreachable.detail).toBe("registration answered 502");

        // A 201 whose body is not a client information response.
        const garbled = makeProvider({ answer: Response.json({ not: "a registration" }, { status: 201 }) });
        const undecodable = yield* DynamicClientRegistration.registerAt({ registrationEndpoint, metadata }).pipe(
            Effect.provideService(HttpClient.HttpClient, garbled.client),
            Effect.flip
        );
        expect(undecodable.reason).toBe("Unreachable");
    })
);

it.effect("finds the endpoint through discovery, and says so when there is none", () =>
    Effect.gen(function* () {
        const offering = makeProvider({
            answer: Response.json({ client_id: "client-123" }, { status: 201 }),
            registration: registrationEndpoint,
        });
        const registration = yield* DynamicClientRegistration.register({ issuer, metadata }).pipe(
            Effect.provideService(HttpClient.HttpClient, offering.client)
        );
        expect(registration.clientId).toBe("client-123");
        expect(offering.requests).toHaveLength(1);

        // A provider that advertises no registration_endpoint does not register
        // clients, and no path is worth guessing at.
        const silent = makeProvider({ answer: Response.json({ client_id: "client-123" }, { status: 201 }) });
        const error = yield* DynamicClientRegistration.register({ issuer, metadata }).pipe(
            Effect.provideService(HttpClient.HttpClient, silent.client),
            Effect.flip
        );
        expect(error.reason).toBe("NotOffered");
        expect(silent.requests).toHaveLength(0);
    })
);

it.effect("refuses a registration endpoint that discovery could not vouch for", () =>
    Effect.gen(function* () {
        // Same-origin and https are checked for every endpoint in the document,
        // registration included: a hostile one would collect the metadata and
        // hand back a client id pointing at an attacker's provider.
        const hostile = makeProvider({
            answer: Response.json({ client_id: "client-123" }, { status: 201 }),
            registration: "https://evil.example/oauth/register",
        });

        const error = yield* DynamicClientRegistration.register({ issuer, metadata }).pipe(
            Effect.provideService(HttpClient.HttpClient, hostile.client),
            Effect.flip
        );
        expect(error.reason).toBe("Rejected");
        expect(error.detail).toBe("discovery: InvalidEndpoint");
    })
);
