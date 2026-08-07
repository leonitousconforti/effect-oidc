/**
 * A resource server: an ordinary `HttpApi` service protected by the
 * `ResourceServer.Authorization` middleware. Every credential is a bearer
 * JWT minted by the demo provider and verified statelessly against its
 * cached JWKS - interactive access tokens (even a first-party frontend
 * authenticates with one, via the code flow) and long-lived api keys alike.
 *
 * Revocation is the one piece of shared state: the `revoked` predicate
 * checks each verified token's `jti` against the provider's RFC 7009
 * denylist, fetched over http and cached for a few seconds - so revocation
 * propagates within seconds without a lookup on every request.
 *
 * Scopes are enforced from the api definition itself: each endpoint accepts
 * its own scope (`"<group>:<endpoint>"`) or the bare group scope
 * (`"<group>"`), which grants every endpoint in the group - so no scope
 * strings are ever written by hand. The `ResourceServer.OIDCScopes`
 * annotation replaces that default where a different (or no) scope is
 * wanted.
 *
 * Start the provider first, then this, then run the client:
 *
 *     pnpm tsx examples/02-oidc-provider.ts
 *     pnpm tsx examples/03-resource-server.ts
 *     pnpm tsx examples/04-oidc-client.ts
 */

import { Effect, Layer, Schema } from "effect";
import { HttpClient, HttpClientResponse, HttpRouter } from "effect/unstable/http";
import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi";

import { createServer } from "node:http";

import { NodeHttpClient, NodeHttpServer, NodeRuntime } from "@effect/platform-node";
import { ResourceServer } from "effect-oidc";

/** The provider whose tokens this API trusts. */
const issuer = "http://localhost:3001";

/** Only tokens minted for this audience are accepted. */
const audience = "demo-api";

const port = 3002;

// ---------------------------------------------------------------------------
// Api definition - attaching the middleware to the group protects every
// endpoint in it.
// ---------------------------------------------------------------------------

const Profile = Schema.Struct({
    sub: Schema.String,
    clientId: Schema.String,
    scopes: Schema.Array(Schema.String),
});

const Note = Schema.Struct({
    id: Schema.String,
    text: Schema.String,
});

const Notes = HttpApiGroup.make("notes")
    // Annotated with no accepted scopes: any valid token may call whoami.
    .add(HttpApiEndpoint.get("whoami", "/whoami", { success: Profile }).annotate(ResourceServer.OIDCScopes, []))
    // Unannotated: accepts the derived "notes:listNotes" / "notes:createNote"
    // endpoint scopes, or the group scope "notes" which grants them all.
    .add(HttpApiEndpoint.get("listNotes", "/notes", { success: Schema.Array(Note) }))
    .add(
        HttpApiEndpoint.post("createNote", "/notes", {
            payload: Schema.Struct({ text: Schema.String }),
            success: Note,
        })
    )
    .middleware(ResourceServer.Authorization);

const Api = HttpApi.make("demo-api").add(Notes);

// ---------------------------------------------------------------------------
// Handlers - `CurrentUser` is the verified caller: the account (`sub`), the
// granted scopes, and the credential it authenticated with. By the time a
// handler runs, the middleware has already rejected (403 Forbidden) callers
// granting none of the endpoint's accepted scopes.
// `ResourceServer.requireScopes` remains available for checks beyond that.
// ---------------------------------------------------------------------------

const NotesLive = HttpApiBuilder.group(Api, "notes", (handlers) =>
    Effect.gen(function* () {
        // Per-user notes, keyed by the token's `sub`.
        const notes = new Map<string, Array<typeof Note.Type>>();

        return handlers
            .handle("whoami", () =>
                Effect.gen(function* () {
                    const user = yield* ResourceServer.CurrentUser;
                    return { sub: user.sub, clientId: user.clientId, scopes: [...user.scopes] };
                })
            )
            .handle("listNotes", () =>
                Effect.gen(function* () {
                    const user = yield* ResourceServer.CurrentUser;
                    return notes.get(user.sub) ?? [];
                })
            )
            .handle("createNote", ({ payload }) =>
                Effect.gen(function* () {
                    const user = yield* ResourceServer.CurrentUser;
                    const note = { id: crypto.randomUUID(), text: payload.text };
                    notes.set(user.sub, [...(notes.get(user.sub) ?? []), note]);
                    return note;
                })
            );
    })
);

// ---------------------------------------------------------------------------
// Wire and serve - the middleware implementation needs an HttpClient for the
// (cached) JWKS fetch. The revocation denylist is fetched from the demo
// provider and cached briefly; a real deployment would usually share the
// denylist store directly instead of serving it over http.
// ---------------------------------------------------------------------------

const AuthorizationLive = Layer.unwrap(
    Effect.gen(function* () {
        const services = yield* Effect.context<HttpClient.HttpClient>();
        const revokedJtis = yield* Effect.cachedWithTTL(
            HttpClient.get(new URL("/oauth/revocations", issuer)).pipe(
                Effect.flatMap(HttpClientResponse.schemaJson(Schema.Struct({ body: Schema.Array(Schema.String) }))),
                Effect.map((decoded) => new Set(decoded.body)),
                Effect.provideContext(services)
            ),
            "3 seconds"
        );
        return ResourceServer.layer({
            issuer,
            audience,
            revoked: ({ jti }) =>
                jti === undefined ? Effect.succeed(false) : Effect.map(revokedJtis, (jtis) => jtis.has(jti)),
        });
    })
).pipe(Layer.provide(NodeHttpClient.layerUndici));

const ApiLive = HttpApiBuilder.layer(Api).pipe(Layer.provide(NotesLive), Layer.provide(AuthorizationLive));

const Main = HttpRouter.serve(ApiLive).pipe(Layer.provide(NodeHttpServer.layer(() => createServer(), { port })));

NodeRuntime.runMain(Layer.launch(Main));
