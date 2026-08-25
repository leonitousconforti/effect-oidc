---
"effect-oidc": minor
---

`ResourceServer.OIDCScopes` now accepts a scope carrying its description, and `ResourceServer.scopeCatalog` reads those back off an api.

An annotation entry may be a bare name as before, or a `ScopeDescription` - `{ name, description }` - where the name is what a token's `scope` claim carries and enforcement reads, and the description is the sentence a consent screen or a self-service dashboard shows for it. Both forms may sit in the same list, and existing bare-string annotations are untouched.

`scopeCatalog(api)` returns every described scope an api declares, deduped by name, in declaration order: groups as they were added, and within each group its own annotation before its endpoints'. That is the list a consent screen renders, read off the endpoints that actually enforce the scopes rather than kept as a second copy beside them - a copy that can name a scope no endpoint accepts, or miss one every endpoint does.

`requireScopes` accepts either form too, so the same constant guards a handler and describes the scope.

A description is one string in one language, and only described scopes are in the catalog: a bare name says nothing about what it lets someone do, and a catalog that guessed a sentence for it would be putting words in front of the person deciding what to grant. A service that shows its scopes in several languages should annotate a message key and resolve it per request.
