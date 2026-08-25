---
"effect-oidc": patch
---

Accept plain http on the loopback interface in `Oidc.fetchDiscovery`.

Every endpoint in a discovery document still has to be same-origin with the issuer, and https everywhere except `localhost`, `127.0.0.1` and `[::1]`, where nothing is on the wire. A relying party can now read discovery from a provider running on `http://localhost` in development instead of building the endpoint urls by hand; away from loopback the https requirement of RFC 8414 Section 2 is enforced exactly as before.
