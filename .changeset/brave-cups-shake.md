---
"effect-oidc": patch
---

Strip `@internal` declarations from the published type definitions

`tsconfig.build.json` now sets `stripInternal`, so `Jwk.toJsonWebKey` no longer appears in `dist/*.d.ts`. It was never part of the documented API and remains available at runtime.
