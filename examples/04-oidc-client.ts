/**
 * A relying party ("Sign in with ...") driving the complete authorization
 * code + PKCE flow against the demo provider, then calling the protected
 * resource server:
 *
 * 1. Fetch the discovery document and JWKS
 * 2. Generate PKCE + state + nonce and build the authorization URL
 * 3. "Send the browser" there and receive the code on the redirect back
 * 4. Exchange the code (with the PKCE verifier) for tokens
 * 5. Verify the id token - the `sub` inside is the signed-in account
 * 6. Call the resource server with the access token
 * 7. Rotate the refresh token for a fresh access token
 *
 * Start 02-oidc-provider.ts and 03-resource-server.ts first, then:
 *
 *     pnpm tsx examples/04-oidc-client.ts
 */

import { Console, Data, Effect, Schema } from "effect";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/unstable/http";

import { NodeHttpClient, NodeRuntime } from "@effect/platform-node";
import { Oidc } from "effect-oidc";

const issuer = "http://localhost:3001";
const resourceServer = "http://localhost:3002";

/** This client's registration at the provider (see 02-oidc-provider.ts). */
const clientId = "demo-app";
const redirectUri = "http://localhost:3000/callback";

class FlowError extends Data.TaggedError("FlowError")<{ readonly message: string }> {}

// The `FlowError` guards below exit via a never-typed effect; the generator's normal path
// runs to the end and returns nothing.
// oxlint-disable-next-line typescript/consistent-return
const program = Effect.gen(function* () {
    // 1. Discovery. `Oidc.fetchDiscovery` is this fetch plus the mandatory
    //    https/same-origin endpoint validation - use it against any real
    //    issuer. The demo provider is plain http on localhost, so the
    //    document is fetched and decoded manually here.
    const discoveryResponse = yield* HttpClient.get(new URL("/.well-known/openid-configuration", issuer));
    const discovery = (yield* HttpClientResponse.schemaJson(Schema.Struct({ body: Oidc.DiscoveryDocumentSchema }))(
        discoveryResponse
    )).body;
    const jwks = yield* Oidc.fetchJwks(discovery.jwks_uri);
    yield* Console.log("1. discovered", {
        authorization_endpoint: discovery.authorization_endpoint,
        token_endpoint: discovery.token_endpoint,
        jwks_uri: discovery.jwks_uri,
    });

    // 2. Begin the code flow. The PKCE verifier stays here; only its S256
    //    challenge goes into the URL. `state` ties the callback to this
    //    session, `nonce` ties the id token to this sign-in.
    const pkce = yield* Oidc.generatePkce();
    const state = crypto.randomUUID();
    const nonce = crypto.randomUUID();

    const authorizationRequest = Oidc.authorizationRequest({
        authorizationEndpoint: discovery.authorization_endpoint,
        clientId,
        redirectUri,
        // The resource server derives its scopes from its api definition
        // (see 03-resource-server.ts): the group scope "notes" grants every
        // endpoint in the group; request "<group>:<endpoint>" names instead
        // (e.g. "notes:listNotes") for access to specific endpoints only.
        scopes: ["openid", "profile", "notes"],
        state,
        codeChallenge: pkce.challenge,
        nonce,
    });

    // 3. A real app opens that URL in the browser; the user logs in and
    //    consents, and the provider redirects back to `redirectUri` with
    //    `code` and `state`. The demo provider auto-approves, so one request
    //    yields that redirect immediately.
    const authorizeResponse = yield* HttpClient.execute(authorizationRequest);
    const location = authorizeResponse.headers.location;
    if (authorizeResponse.status !== 302 || location === undefined) {
        return yield* new FlowError({ message: `expected a redirect, got ${authorizeResponse.status}` });
    }
    const callback = new URL(location);
    const code = callback.searchParams.get("code");
    if (code === null || callback.searchParams.get("state") !== state) {
        // A state mismatch means the callback was not the answer to OUR
        // request - abort, this is the CSRF check.
        return yield* new FlowError({ message: "callback missing code or state mismatch" });
    }
    yield* Console.log("3. authorization code:", code);

    // 4. Exchange the code for tokens. The provider recomputes S256(verifier)
    //    and compares it to the challenge bound to the code.
    const tokens = yield* Oidc.exchangeAuthorizationCode({
        tokenEndpoint: discovery.token_endpoint,
        clientId,
        code,
        codeVerifier: pkce.verifier,
        redirectUri,
    });
    yield* Console.log("4. tokens:", { ...tokens, access_token: "<jwt>", id_token: "<jwt>" });

    // 5. Verify the id token against the issuer's JWKS: signature, issuer,
    //    audience (this client), and our nonce. The returned `sub` is the
    //    stable account id to key local users on.
    if (tokens.id_token === undefined) {
        return yield* new FlowError({ message: "expected an id token (scope included openid)" });
    }
    const identity = yield* Oidc.verifyIdToken({
        idToken: tokens.id_token,
        jwks,
        issuer,
        clientId,
        nonce,
    });
    yield* Console.log("5. signed in as:", { sub: identity.sub, name: identity.name });

    // 6. Use the access token against the resource server. Without a token
    //    the middleware answers 401; with one, handlers see CurrentUser.
    const unauthorized = yield* HttpClient.get(new URL("/whoami", resourceServer));
    yield* Console.log("6. GET /whoami without a token ->", unauthorized.status);

    const whoami = yield* HttpClientRequest.get(new URL("/whoami", resourceServer)).pipe(
        HttpClientRequest.bearerToken(tokens.access_token),
        HttpClient.execute
    );
    yield* Console.log("   GET /whoami with the token ->", yield* whoami.json);

    const created = yield* HttpClientRequest.post(new URL("/notes", resourceServer)).pipe(
        HttpClientRequest.bodyJsonUnsafe({ text: "hello from the demo client" }),
        HttpClientRequest.bearerToken(tokens.access_token),
        HttpClient.execute
    );
    yield* Console.log("   POST /notes ->", yield* created.json);

    // 7. Refresh: trade the (single-use) refresh token for fresh tokens.
    //    The provider rotates it, so the response carries a replacement.
    if (tokens.refresh_token === undefined) {
        return yield* new FlowError({ message: "expected a refresh token" });
    }
    const refreshResponse = yield* HttpClient.execute(
        HttpClientRequest.post(discovery.token_endpoint).pipe(
            HttpClientRequest.bodyUrlParams({
                grant_type: "refresh_token",
                refresh_token: tokens.refresh_token,
                client_id: clientId,
            })
        )
    );
    const refreshed = (yield* HttpClientResponse.schemaJson(Schema.Struct({ body: Oidc.TokenResponseSchema }))(
        refreshResponse
    )).body;
    yield* Console.log("7. refreshed:", { ...refreshed, access_token: "<jwt>", id_token: "<jwt>" });

    // 8. Machine-to-machine: a confidential ("private") client skips the
    //    browser entirely - it authenticates to the token endpoint with its
    //    secret and receives an access token whose subject is the client
    //    itself (see the registration in 02-oidc-provider.ts).
    const m2m = yield* Oidc.exchangeClientCredentials({
        tokenEndpoint: discovery.token_endpoint,
        clientId: "demo-service",
        clientSecret: "demo-service-secret",
        scopes: ["notes"],
    });
    const asService = yield* HttpClientRequest.get(new URL("/whoami", resourceServer)).pipe(
        HttpClientRequest.bearerToken(m2m.access_token),
        HttpClient.execute
    );
    yield* Console.log("8. GET /whoami as the confidential service ->", yield* asService.json);

    // 9. Api keys are ordinary JWTs, just with a long ttl, verified exactly
    //    like access tokens. The demo provider mints one here; a real
    //    provider does this from an authenticated dashboard.
    const minted = yield* HttpClient.post(new URL("/demo/api-key", issuer));
    const { api_key } = (yield* HttpClientResponse.schemaJson(
        Schema.Struct({ body: Schema.Struct({ api_key: Schema.String }) })
    )(minted)).body;

    const viaApiKey = yield* HttpClientRequest.get(new URL("/whoami", resourceServer)).pipe(
        HttpClientRequest.bearerToken(api_key),
        HttpClient.execute
    );
    yield* Console.log("9. GET /whoami with the api key ->", yield* viaApiKey.json);

    // 10. Revocation (RFC 7009): the key's jti joins the provider's
    //     denylist. The resource server polls that denylist on a short
    //     cache, so the key dies within seconds - the price of stateless
    //     verification is that revocation is eventual, not instant.
    yield* Oidc.revokeToken({
        revocationEndpoint: discovery.revocation_endpoint ?? new URL("/oauth/revoke", issuer).toString(),
        token: api_key,
    });
    yield* Effect.sleep("4 seconds");

    const afterRevoke = yield* HttpClientRequest.get(new URL("/whoami", resourceServer)).pipe(
        HttpClientRequest.bearerToken(api_key),
        HttpClient.execute
    );
    yield* Console.log("10. GET /whoami after revoking the api key ->", afterRevoke.status);
});

NodeRuntime.runMain(program.pipe(Effect.provide(NodeHttpClient.layerUndici)));
