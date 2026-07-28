/**
 * The core loop every other example builds on: provision a signing key,
 * publish the public half as a JWKS, sign a JWT, and verify it — including
 * what verification failures look like.
 *
 * Run with:
 *
 *     pnpm tsx examples/01-jwt-sign-and-verify.ts
 */

import { Console, DateTime, Effect } from "effect";

import { NodeRuntime } from "@effect/platform-node";
import { Jwt } from "effect-oidc";

const issuer = "https://id.example.com";

const program = Effect.gen(function* () {
    // 1. Provision an ES256 signing key pair with a random `kid`. In a real
    //    provider this runs once in a key rotation script: the private JWK is
    //    persisted as a secret, the public JWK is published in the JWKS
    //    document at /.well-known/jwks.json.
    const { privateJwk, publicJwk } = yield* Jwt.generateSigningKey();
    const jwks = { keys: [publicJwk] };
    yield* Console.log("signing key kid:", publicJwk.kid);

    // 2. Sign a payload as a compact JWT. The registered claims (RFC 7519)
    //    are plain payload fields; extra claims ride along untouched.
    const nowSeconds = Math.floor(DateTime.toEpochMillis(yield* DateTime.now) / 1000);
    const token = yield* Jwt.sign({
        privateJwk,
        payload: {
            iss: issuer,
            sub: "user-123",
            aud: "my-api",
            exp: nowSeconds + 3600,
            iat: nowSeconds,
            scope: "openid profile",
        },
    });
    yield* Console.log("token:", token);

    // 3. Verify against the JWKS: signature (selected by `kid`), `exp`/`nbf`
    //    with 30s clock skew, and — because they are provided — `iss`, `aud`,
    //    the allowed algorithms, and the `typ` header.
    const claims = yield* Jwt.verify(token, {
        jwks,
        issuer,
        audience: "my-api",
        algorithms: ["ES256"],
        types: ["JWT"],
    });
    yield* Console.log("verified claims:", claims);

    // 4. Anything that does not check out fails with a typed `JwtError`
    //    describing exactly what went wrong.
    const wrongAudience = yield* Effect.flip(Jwt.verify(token, { jwks, audience: "other-api" }));
    yield* Console.log("wrong audience rejected:", wrongAudience.reason);

    const otherKey = yield* Jwt.generateSigningKey();
    const wrongKey = yield* Effect.flip(Jwt.verify(token, { jwks: { keys: [otherKey.publicJwk] } }));
    yield* Console.log("wrong key rejected:", wrongKey.reason);

    const garbage = yield* Effect.flip(Jwt.verify("not-a-jwt", { jwks }));
    yield* Console.log("garbage rejected:", garbage.reason);
});

NodeRuntime.runMain(program);
