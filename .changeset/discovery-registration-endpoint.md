---
"effect-oidc": patch
---

Add the optional `registration_endpoint` (RFC 7591) to `DiscoveryDocumentSchema`.

A provider that offers dynamic client registration advertises it there, and a client can now learn it from `Oidc.fetchDiscovery` instead of assuming a path. It is validated like every other endpoint in the document: same-origin with the issuer, and https away from loopback, because although a registration request carries no credentials its answer issues them.
