---
"effect-oidc": minor
---

Add a `DynamicClientRegistration` module: RFC 7591, both ends.

For a provider, `ClientMetadataRequestSchema` decodes a registration body and `validateClientMetadata` applies a `RegistrationPolicy` to it - filling in the defaults the RFC leaves to the server and refusing anything the provider could not honour later, so a client never registers with a redirect uri, grant, response type or scope that every subsequent request would then be refused for. `clientInformationResponse` builds the answer, including the `client_secret_expires_at` that RFC 7591 Section 3.2.1 makes required alongside an issued secret.

Two refusals are worth naming. A public client asking for `client_credentials` is turned away at registration rather than earning an `invalid_client` at the token endpoint, where the answer would not say which field was wrong. And the `authorization_code` grant and the `code` response type each require the other, per RFC 7591 Section 2.1.

For a client, `register` finds the endpoint through the issuer's discovery document - which is what makes `NotOffered` a real answer rather than a guessed path - presents an initial access token when the provider gates registration, and comes back with a `client_id` and, for a confidential client, a `Redacted` secret. `registerAt` skips discovery when the endpoint is already known. Neither retries: whether a provider that is still coming up is worth waiting for is the caller's judgement, and `Effect.retry` composes.
