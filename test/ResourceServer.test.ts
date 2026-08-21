import { Context, Effect, Layer, Redacted, Schema } from "effect";
import {
    HttpClient,
    HttpClientResponse,
    HttpRouter,
    HttpServerRequest,
    HttpServerResponse,
} from "effect/unstable/http";
import { HttpApiEndpoint, HttpApiError, HttpApiGroup } from "effect/unstable/httpapi";

import { expect, it } from "@effect/vitest";
import { Jwt, Oidc, ResourceServer } from "effect-oidc";

const issuer = "https://id.example.com";
const audience = "demo-api";

const listNotes = HttpApiEndpoint.get("listNotes", "/notes", { success: Schema.String });
const createNote = HttpApiEndpoint.post("createNote", "/notes", { success: Schema.String });
const notes = HttpApiGroup.make("notes").add(listNotes, createNote);

/**
 * Builds the `Authorization` implementation with a stub `HttpClient` serving
 * the JWKS, plus helpers to mint tokens for it and to invoke the bearer
 * security scheme exactly as the `HttpApi` builder would.
 */
const makeHarness = Effect.fnUntraced(function* (harnessOptions?: {
    readonly revoked?: (
        claims: Schema.Schema.Type<typeof Oidc.AccessTokenClaimsSchema>
    ) => Effect.Effect<boolean, unknown>;
    /** Hand the harness JWKS to the layer statically instead of serving it over the stub client. */
    readonly staticJwks?: boolean;
    /** Start the stub JWKS endpoint unhealthy, answering malformed documents until `setHealthy(true)`. */
    readonly startUnhealthy?: boolean;
}) {
    const { privateJwk, publicJwk } = yield* Jwt.generateSigningKey();
    let published = publicJwk;

    let healthy = harnessOptions?.startUnhealthy !== true;
    let jwksFetches = 0;
    const StubJwksClient = Layer.succeed(
        HttpClient.HttpClient,
        HttpClient.make((request) => {
            jwksFetches += 1;
            return Effect.succeed(
                HttpClientResponse.fromWeb(request, healthy ? Response.json({ keys: [published] }) : Response.json({}))
            );
        })
    );

    const context = yield* Layer.build(
        ResourceServer.layer({
            issuer,
            audience,
            ...(harnessOptions?.staticJwks === true ? { jwks: { keys: [publicJwk] } } : {}),
            ...(harnessOptions?.revoked === undefined ? {} : { revoked: harnessOptions.revoked }),
        }).pipe(Layer.provide(StubJwksClient))
    );
    const authorization = Context.get(context, ResourceServer.Authorization);

    const issueToken = (scope: string, signingKey = privateJwk) =>
        Oidc.issueAccessToken({
            privateJwk: signingKey,
            issuer,
            subject: "user-123",
            audience,
            clientId: "client-abc",
            scope,
            ttlSeconds: 300,
        });

    // Invokes the bearer security-scheme handler exactly as the `HttpApi`
    // builder would, with the decoded credential (empty when absent). The
    // middleware never reads the router-provided services, so stub values
    // satisfy that requirement; `next` never fails, so any error outside the
    // middleware's declared ones is a defect.
    const routerProvided = Context.make(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromWeb(new Request("http://localhost/notes"))
    ).pipe(
        Context.add(HttpServerRequest.ParsedSearchParams, {}),
        Context.add(HttpRouter.RouteContext, {
            params: {},
            route: HttpRouter.route("*", "/notes", HttpServerResponse.empty()),
        })
    );
    // `HttpApiEndpoint.Top`/`HttpApiGroup.Top` are not supertypes of concrete
    // endpoints and groups (the `~Request` phantom lacks the request-part
    // members Top carries), so the erasure the `HttpApi` builder performs is
    // reproduced with conversions through the widened `Constraint` types.
    const call = (
        token: string,
        endpoint: HttpApiEndpoint.Constraint,
        callOptions?: { readonly group?: HttpApiGroup.Constraint }
    ) => {
        let seen: (typeof ResourceServer.CurrentUser)["Service"] | undefined;
        const next = Effect.gen(function* () {
            seen = yield* ResourceServer.CurrentUser;
            return HttpServerResponse.empty();
        });
        return authorization
            .bearer(next, {
                credential: Redacted.make(token),
                // oxlint-disable-next-line typescript/no-unsafe-type-assertion
                endpoint: endpoint as HttpApiEndpoint.Top,
                // oxlint-disable-next-line typescript/no-unsafe-type-assertion
                group: (callOptions?.group ?? notes) as HttpApiGroup.Top,
            })
            .pipe(
                Effect.provideContext(routerProvided),
                Effect.catch((error) =>
                    error instanceof HttpApiError.Unauthorized ||
                    error instanceof HttpApiError.Forbidden ||
                    error instanceof HttpApiError.InternalServerError
                        ? Effect.fail(error)
                        : Effect.die(error)
                ),
                Effect.flatMap(() =>
                    seen === undefined ? Effect.die(new Error("CurrentUser was not provided")) : Effect.succeed(seen)
                )
            );
    };

    return {
        privateJwk,
        issueToken,
        call,
        jwksFetches: () => jwksFetches,
        /** Rotates the key the stub JWKS endpoint publishes. */
        publish: (jwk: typeof publicJwk) => {
            published = jwk;
        },
        setHealthy: (value: boolean) => {
            healthy = value;
        },
    };
});

it.live("accepts the endpoint's derived scope by default", () =>
    Effect.gen(function* () {
        const harness = yield* makeHarness();

        const readOnly = yield* harness.issueToken("notes:listNotes");
        const user = yield* harness.call(readOnly, listNotes);
        expect(user.sub).toBe("user-123");
        expect(user.scopes).toStrictEqual(new Set(["notes:listNotes"]));

        const forbidden = yield* Effect.flip(harness.call(readOnly, createNote));
        expect(forbidden._tag).toBe("Forbidden");

        const readWrite = yield* harness.issueToken("notes:listNotes notes:createNote");
        const writer = yield* harness.call(readWrite, createNote);
        expect(writer.scopes.has("notes:createNote")).toBe(true);
    }).pipe(Effect.scoped)
);

it.live("accepts the group scope for every endpoint in the group", () =>
    Effect.gen(function* () {
        const harness = yield* makeHarness();

        const groupToken = yield* harness.issueToken("notes");
        const reader = yield* harness.call(groupToken, listNotes);
        const writer = yield* harness.call(groupToken, createNote);
        expect(reader.sub).toBe("user-123");
        expect(writer.scopes).toStrictEqual(new Set(["notes"]));

        // A scope for another group grants nothing here.
        const other = yield* harness.issueToken("payments");
        const forbidden = yield* Effect.flip(harness.call(other, listNotes));
        expect(forbidden._tag).toBe("Forbidden");
    }).pipe(Effect.scoped)
);

it.live("the Scopes annotation on an endpoint replaces the derived default", () =>
    Effect.gen(function* () {
        const purgeNotes = HttpApiEndpoint.delete("purgeNotes", "/notes").annotate(ResourceServer.OIDCScopes, [
            "admin",
        ]);
        const group = HttpApiGroup.make("notes").add(purgeNotes);
        const harness = yield* makeHarness();

        const admin = yield* harness.issueToken("admin");
        const user = yield* harness.call(admin, purgeNotes, { group });
        expect(user.scopes).toStrictEqual(new Set(["admin"]));

        // The derived endpoint and group scopes are no longer accepted.
        const derived = yield* harness.issueToken("notes:purgeNotes notes");
        const forbidden = yield* Effect.flip(harness.call(derived, purgeNotes, { group }));
        expect(forbidden._tag).toBe("Forbidden");
    }).pipe(Effect.scoped)
);

it.live("an empty Scopes annotation requires no scopes, only a valid token", () =>
    Effect.gen(function* () {
        const whoami = HttpApiEndpoint.get("whoami", "/whoami").annotate(ResourceServer.OIDCScopes, []);
        const group = HttpApiGroup.make("notes").add(whoami);
        const harness = yield* makeHarness();

        const bare = yield* harness.issueToken("openid");
        const user = yield* harness.call(bare, whoami, { group });
        expect(user.sub).toBe("user-123");
    }).pipe(Effect.scoped)
);

it.live("a Scopes annotation on the group applies to endpoints without their own", () =>
    Effect.gen(function* () {
        const purgeNotes = HttpApiEndpoint.delete("purgeNotes", "/notes").annotate(ResourceServer.OIDCScopes, [
            "admin",
        ]);
        const group = HttpApiGroup.make("notes")
            .add(listNotes, purgeNotes)
            .annotate(ResourceServer.OIDCScopes, ["notes:all"]);
        const harness = yield* makeHarness();

        // listNotes has no annotation of its own: the group annotation wins
        // over the derived default...
        const all = yield* harness.issueToken("notes:all");
        const user = yield* harness.call(all, listNotes, { group });
        expect(user.scopes).toStrictEqual(new Set(["notes:all"]));

        const derived = yield* harness.issueToken("notes:listNotes notes");
        const forbidden = yield* Effect.flip(harness.call(derived, listNotes, { group }));
        expect(forbidden._tag).toBe("Forbidden");

        // ...while purgeNotes' own annotation wins over the group's.
        const admin = yield* harness.issueToken("admin");
        const purger = yield* harness.call(admin, purgeNotes, { group });
        expect(purger.scopes).toStrictEqual(new Set(["admin"]));

        const groupOnly = yield* Effect.flip(harness.call(all, purgeNotes, { group }));
        expect(groupOnly._tag).toBe("Forbidden");
    }).pipe(Effect.scoped)
);

it.live("still rejects invalid tokens before any scope check", () =>
    Effect.gen(function* () {
        const harness = yield* makeHarness();

        const unauthorized = yield* Effect.flip(harness.call("not-a-jwt", listNotes));
        expect(unauthorized._tag).toBe("Unauthorized");
    }).pipe(Effect.scoped)
);

it.live("rejects requests without any bearer credential", () =>
    Effect.gen(function* () {
        const harness = yield* makeHarness();

        const unauthorized = yield* Effect.flip(harness.call("", listNotes));
        expect(unauthorized._tag).toBe("Unauthorized");
    }).pipe(Effect.scoped)
);

it.live("consults the revoked predicate after verification", () =>
    Effect.gen(function* () {
        let revoked = false;
        let consulted = 0;
        const harness = yield* makeHarness({
            revoked: (claims) => {
                consulted += 1;
                expect(typeof claims.jti).toBe("string");
                return Effect.succeed(revoked);
            },
        });

        const token = yield* harness.issueToken("notes");
        const user = yield* harness.call(token, listNotes);
        expect(user.sub).toBe("user-123");
        expect(consulted).toBe(1);

        revoked = true;
        const unauthorized = yield* Effect.flip(harness.call(token, listNotes));
        expect(unauthorized._tag).toBe("Unauthorized");

        // Invalid tokens never reach the predicate.
        yield* Effect.flip(harness.call("not-a-jwt", listNotes));
        expect(consulted).toBe(2);
    }).pipe(Effect.scoped)
);

it.live("answers 500 when the revocation check itself fails", () =>
    Effect.gen(function* () {
        const harness = yield* makeHarness({ revoked: () => Effect.fail("denylist unreachable") });

        const token = yield* harness.issueToken("notes");
        const failure = yield* Effect.flip(harness.call(token, listNotes));
        expect(failure._tag).toBe("InternalServerError");
    }).pipe(Effect.scoped)
);

it.live("requireScopes guards individual handlers against the granted scopes", () =>
    Effect.gen(function* () {
        const claims = yield* Schema.decodeEffect(Oidc.AccessTokenClaimsSchema)({
            iss: issuer,
            sub: "user-123",
            aud: audience,
            exp: 4102444800,
            iat: 0,
            scope: "notes:listNotes",
            client_id: "client-abc",
        });
        const user = {
            sub: claims.sub,
            scopes: new Set(claims.scope.split(" ")),
            clientId: claims.client_id,
            claims,
        };

        const granted = yield* ResourceServer.requireScopes("notes:listNotes").pipe(
            Effect.provideService(ResourceServer.CurrentUser, user)
        );
        expect(granted.sub).toBe("user-123");

        const forbidden = yield* Effect.flip(
            ResourceServer.requireScopes("notes:listNotes", "notes:createNote").pipe(
                Effect.provideService(ResourceServer.CurrentUser, user)
            )
        );
        expect(forbidden._tag).toBe("Forbidden");
    })
);

it.live("refuses the issuer's non-access-token JWTs (typ pinned to at+jwt)", () =>
    Effect.gen(function* () {
        const harness = yield* makeHarness();

        // Same issuer, same key, same audience and claims - but minted as a
        // plain `typ: "JWT"`, as an id token or any other JWT would be.
        const nowSeconds = 1_700_000_000;
        const lookalike = yield* Jwt.sign({
            privateJwk: harness.privateJwk,
            payload: {
                iss: issuer,
                sub: "user-123",
                aud: audience,
                exp: nowSeconds + 10 * 365 * 24 * 3600,
                iat: nowSeconds,
                scope: "notes",
                client_id: "client-abc",
            },
        });
        const refused = yield* Effect.flip(harness.call(lookalike, listNotes));
        expect(refused._tag).toBe("Unauthorized");

        const accessToken = yield* harness.issueToken("notes");
        const user = yield* harness.call(accessToken, listNotes);
        expect(user.sub).toBe("user-123");
    }).pipe(Effect.scoped)
);

it.live("refetches the jwks once for a token signed by a freshly rotated key", () =>
    Effect.gen(function* () {
        const harness = yield* makeHarness();

        // Warm the cache with the original key.
        const user = yield* harness.call(yield* harness.issueToken("notes"), listNotes);
        expect(user.sub).toBe("user-123");
        expect(harness.jwksFetches()).toBe(1);

        // The issuer rotates and signs with a key the cache has never seen.
        const rotated = yield* Jwt.generateSigningKey();
        harness.publish(rotated.publicJwk);
        const fresh = yield* harness.call(yield* harness.issueToken("notes", rotated.privateJwk), listNotes);
        expect(fresh.sub).toBe("user-123");
        expect(harness.jwksFetches()).toBe(2);

        // A second unknown kid inside the refresh window does not fetch again.
        const stranger = yield* Jwt.generateSigningKey();
        const refused = yield* Effect.flip(
            harness.call(yield* harness.issueToken("notes", stranger.privateJwk), listNotes)
        );
        expect(refused._tag).toBe("Unauthorized");
        expect(harness.jwksFetches()).toBe(2);
    }).pipe(Effect.scoped)
);

it.live("verifies against statically provided jwks without ever fetching", () =>
    Effect.gen(function* () {
        // The stub endpoint only answers malformed documents, so any fetch
        // attempt would fail: static keys must make it unreachable.
        const harness = yield* makeHarness({ staticJwks: true, startUnhealthy: true });

        const token = yield* harness.issueToken("notes");
        const user = yield* harness.call(token, listNotes);
        expect(user.sub).toBe("user-123");
        expect(harness.jwksFetches()).toBe(0);
    }).pipe(Effect.scoped)
);

it.live("retries the jwks fetch after a failed first fetch instead of caching the failure", () =>
    Effect.gen(function* () {
        const harness = yield* makeHarness({ startUnhealthy: true });

        const token = yield* harness.issueToken("notes");
        const failure = yield* Effect.flip(harness.call(token, listNotes));
        expect(failure._tag).toBe("InternalServerError");

        // The endpoint recovers and the very next request succeeds, with no
        // ttl to wait out before the failure leaves the cache.
        harness.setHealthy(true);
        const user = yield* harness.call(token, listNotes);
        expect(user.sub).toBe("user-123");
        expect(harness.jwksFetches()).toBe(2);
    }).pipe(Effect.scoped)
);
