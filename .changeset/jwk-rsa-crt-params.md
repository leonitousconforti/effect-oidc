---
"effect-oidc": patch
---

Fix `Jwk.RsaPrivateKey` silently dropping the CRT parameters (`p`, `q`, `dp`, `dq`, `qi`) of a complete RSA private key: the d-only union member was tried first and Struct decoding drops unlisted fields. The full CRT form now comes first. Ports the remaining fix from Effect-TS/effect#6566 along with its applicable security regression tests.
