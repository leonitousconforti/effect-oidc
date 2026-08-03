---
"effect-oidc": minor
---

Every credential is a bearer JWT minted by the issuer - no cookie transport, no opaque credentials. An api key is nothing more than an access token with a long expiry, verified identically against the issuer's JWKS. Revocation is the one optional piece of state: `Oidc.RevocationRequestSchema` models the RFC 7009 revocation endpoint (advertised as `revocation_endpoint` in the discovery document), `Oidc.revokeToken` calls it from the client side, and the new `revoked` predicate on `ResourceServer.layer` checks each verified token against the issuer's denylist - typically revoked `jti`s kept until each token's `exp`, cached as aggressively as the wanted revocation latency allows.
