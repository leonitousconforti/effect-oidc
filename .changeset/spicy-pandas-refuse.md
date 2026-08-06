---
"effect-oidc": patch
---

Add the RelyingParty module: the server side of "Sign in with ..." for web apps. `RelyingParty.make` realizes a provider registration into `beginAuthorization` (the authorization redirect plus short-lived state, PKCE verifier, and opaque payload transaction cookies) and `completeAuthorization` (state validation, code exchange, and id token verification, failing with a coarse `CallbackError` reason that is safe to surface in a redirect). The provider's keys are read through `Oidc.cachedJwks`, so a transient JWKS fetch failure serves the last good key set instead of failing sign-ins.
