---
"effect-oidc": minor
---

Confidential ("private") OAuth client support. `TokenRequestSchema` gains the machine-to-machine `client_credentials` grant, `Oidc.clientAuthentication` resolves a token request's client from the `Authorization: Basic` header (client_secret_basic, the OIDC default method) or the body parameters (client_secret_post), `Oidc.exchangeClientCredentials` performs the client credentials flow from the client side, and the discovery document schema and `makeDiscoveryDocument` advertise the supported grant types and token endpoint auth methods.
