---
"effect-oidc": minor
---

Add a `Jwe` module implementing JSON Web Encryption (RFC 7516) in Compact Serialization, ported from Effect-TS/effect#6566: WebCrypto-backed authenticated encryption with the AES-GCM and AES-CBC-HMAC-SHA2 content encryption families and the `dir`, RSA-OAEP, AES key wrap, AES-GCM key wrap, ECDH-ES (direct and key-wrap), and PBES2 key management families. The `Jwa` module gains the corresponding `JweAlgorithm`, `JweEncryption`, and `encryptionParameters` definitions. Decryption fails closed with typed `JweError`s, rejects unrecognized `crit` extensions, bounds the attacker-controlled PBES2 iteration count, validates the unwrapped CEK length, and supports `alg`/`enc` allowlists. `RSA1_5` is intentionally unsupported per RFC 8725.
