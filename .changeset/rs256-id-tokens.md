---
"effect-oidc": patch
---

`Oidc.verifyIdToken` now accepts RS256 signatures alongside ES256 by default, and takes an `algorithms` option to override the accepted set. The previous hardcoded ES256-only list rejected every id token from providers that sign with RSA keys (Google, Discord) with a `BadAlgorithm` error.
