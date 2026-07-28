/**
 * A resource server: an ordinary `HttpApi` service that accepts the demo
 * provider's access tokens. The `ResourceServer.Authorization` middleware
 * does all the OIDC work - it fetches and caches the issuer's JWKS, verifies
 * bearer JWTs statelessly (no shared database, no per-request network hop),
 * and provides `CurrentUser` to the handlers. Individual endpoints gate
 * themselves with `requireScopes`.
 *
 * Start the provider first, then this, then run the client:
 *
 *     pnpm tsx examples/02-oidc-provider.ts
 *     pnpm tsx examples/03-resource-server.ts
 *     pnpm tsx examples/04-oidc-client.ts
 */

import { Effect, Layer, Schema } from "effect";
import { HttpRouter } from "effect/unstable/http";
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

const Api = HttpApi.make("demo-api").add(
    HttpApiGroup.make("notes")
        .add(HttpApiEndpoint.get("whoami", "/whoami", { success: Profile }))
        .add(HttpApiEndpoint.get("listNotes", "/notes", { success: Schema.Array(Note) }))
        .add(
            HttpApiEndpoint.post("createNote", "/notes", {
                payload: Schema.Struct({ text: Schema.String }),
                success: Note,
            })
        )
        .middleware(ResourceServer.Authorization)
);

// ---------------------------------------------------------------------------
// Handlers - `CurrentUser` is the verified caller: the account (`sub`), the
// granted scopes, and the OAuth client acting on the account's behalf.
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
                    // Fails with 403 Forbidden unless the token grants the scope.
                    const user = yield* ResourceServer.requireScopes("notes:read");
                    return notes.get(user.sub) ?? [];
                })
            )
            .handle("createNote", ({ payload }) =>
                Effect.gen(function* () {
                    const user = yield* ResourceServer.requireScopes("notes:write");
                    const note = { id: crypto.randomUUID(), text: payload.text };
                    notes.set(user.sub, [...(notes.get(user.sub) ?? []), note]);
                    return note;
                })
            );
    })
);

// ---------------------------------------------------------------------------
// Wire and serve - the middleware implementation needs an HttpClient for the
// (cached) JWKS fetch.
// ---------------------------------------------------------------------------

const AuthorizationLive = ResourceServer.layer({ issuer, audience }).pipe(Layer.provide(NodeHttpClient.layerUndici));

const ApiLive = HttpApiBuilder.layer(Api).pipe(Layer.provide(NotesLive), Layer.provide(AuthorizationLive));

const Main = HttpRouter.serve(ApiLive).pipe(Layer.provide(NodeHttpServer.layer(() => createServer(), { port })));

NodeRuntime.runMain(Layer.launch(Main));
