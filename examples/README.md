# Examples

Full, runnable programs covering the library end to end. Each file is standalone and heavily commented — reading them in order tells the whole story:

| Example                                                  | What it shows                                                                                                                                 |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| [01-jwt-sign-and-verify.ts](./01-jwt-sign-and-verify.ts) | Key provisioning, signing a JWT, verifying it against a JWKS, and the typed `JwtError`s for everything that can go wrong                      |
| [02-oidc-provider.ts](./02-oidc-provider.ts)             | A complete in-memory OIDC provider: discovery, JWKS, authorization endpoint, and token endpoint with PKCE, refresh rotation, and id tokens    |
| [03-resource-server.ts](./03-resource-server.ts)         | An `HttpApi` service protected by the `ResourceServer.Authorization` middleware, with per-endpoint scope checks and `CurrentUser`             |
| [04-oidc-client.ts](./04-oidc-client.ts)                 | A relying party driving the full authorization code + PKCE flow: discovery, sign-in, code exchange, id token verification, API calls, refresh |
| [05-jws-advanced.ts](./05-jws-advanced.ts)               | The lower-level JWS toolkit: multi-signature General serialization and schema-validated critical extension headers                            |

## Running

From the repository root (after `pnpm install`):

```sh
# Self-contained examples
pnpm tsx examples/01-jwt-sign-and-verify.ts
pnpm tsx examples/05-jws-advanced.ts

# The full three-party OIDC flow — three terminals:
pnpm tsx examples/02-oidc-provider.ts    # terminal 1: the provider  (http://localhost:3001)
pnpm tsx examples/03-resource-server.ts  # terminal 2: the protected API (http://localhost:3002)
pnpm tsx examples/04-oidc-client.ts      # terminal 3: the client, driving the whole flow
```

The client walks through discovery → PKCE → authorization redirect → code exchange → id token verification → authenticated API calls → refresh token rotation, logging each step.

## Caveats

These examples optimize for being readable and runnable on localhost:

- The provider issues over plain `http` and the client therefore fetches discovery manually — real clients should use `Oidc.fetchDiscovery`, which enforces the https/same-origin endpoint validation the spec requires.
- The provider auto-approves a hard-coded user where a real one renders login and consent pages, and it keeps keys, codes, and refresh tokens in memory.
