---
"effect-oidc": patch
---

Update Effect-TS packages to v4.0.5

The `effect` peer dependency is now `4.0.5`.

`JwtError`, `DiscoveryError`, `RegistrationError` and `CallbackError` now carry a brand type argument, so a plain object with the same shape is no longer accepted where one of these error classes is expected. Constructing them with `new` is unchanged.
