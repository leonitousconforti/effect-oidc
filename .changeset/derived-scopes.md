---
"effect-oidc": minor
---

Per-endpoint scope enforcement with derived names. The Authorization middleware now enforces scopes on every endpoint it protects: by default an endpoint accepts its derived scope, named from the group and endpoint identifiers (`"<group>:<endpoint>"`), or the bare group identifier, so a group scope grants every endpoint in the group while endpoint scopes grant just the one. The new `ResourceServer.Scopes` annotation on an endpoint or group replaces the default with an explicit list of accepted scopes (empty to require none).
