# effect-oidc

OIDC provider primitives, JWT+JWKS signing and verification, and HttpApi resource-server middleware for [Effect](https://effect.website)

## Motivation/ideation :bulb:

I wanted "Sign in with Tinyburg" and OAuth apps that could gain user consent for certain scopes (for tinyburg), without handing the identity provider role to a third party service

## Goals :white_check_mark:

- [x] - JWA, JWK, and JWS schemas (RFC 7518, RFC 7517, RFC 7515) with signing and verification built on WebCrypto
- [x] - JWT signing and verification against a JWKS with registered-claim validation (RFC 7519)
- [x] - OIDC protocol surface: discovery and token endpoint schemas, PKCE utilities, token issuing helpers for the provider, and a code-flow client for relying apps
- [x] - Drop-in bearer authentication middleware for `HttpApi` services

## WIP/Todo :construction:

- more tests
- dynamic client registration

## Blocked :ambulance:

- nothing atm

## Non-Goals :wastebasket:

- the "none" JWS algorithm
- implicit and hybrid flows, this library is OAuth 2.1 shaped (authorization code + PKCE only)

## Library docs :card_file_box:

[https://leoconforti.pages.ltgk.net/effect-oidc/](https://leoconforti.pages.ltgk.net/effect-oidc/)

## Contributing and getting help :speech_balloon: :beers:

Contributions, suggestions, and questions are welcome! I'll review prs and respond to issues/discussion here on GitHub but if you want more synchronous communication you can find me in the [effect discord](https://discord.gg/effect-ts) as @leonitous

## License :page_facing_up:

If the GNU General Public License v3.0 does not work for you, please reach out and let me know, I can be accommodating
