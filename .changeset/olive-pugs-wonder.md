---
"effect-oidc": patch
---

Update Effect-TS packages to v4.0.1

`effect/unstable/*` was flattened in v4.0.1, so `effect/unstable/http` moved to `effect/http`, `effect/unstable/httpapi` to `effect/http-api` and `effect/unstable/schema` to `effect/schema`. The root `Encoding` module was split into `effect/encoding`, so `Encoding.encodeBase64Url` is now `Base64Url.encode` and `Encoding.decodeBase64String` is now `Base64.decodeString`. `SchemaGetter.transformOrFail` was renamed to `SchemaGetter.transformEffect`.

These are internal to the library; the public API is unchanged.
