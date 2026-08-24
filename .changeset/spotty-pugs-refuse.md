---
"effect-oidc": patch
---

Infer the error type of `ResourceServer.layer`'s `revoked` predicate instead of fixing it to `unknown`.

A denylist backed by a database keeps its own error type through the option now, rather than having it widened away at the boundary, and the internal `any-unknown-in-error-context` suppression that went with the old signature is gone. Behaviour is unchanged: a predicate failure is still answered as `500 Internal Server Error`, because a revocation check that cannot answer is a server problem rather than a client one.

`layer` gains a leading type parameter, so an explicit `layer<MyContext>(...)` now reads as the error type rather than the context. Inferred calls are unaffected.
