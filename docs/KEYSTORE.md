# MC04 key store

Each SSD owns eight persistent key slots (0–7). The key store is separate from the
assembly key/value map. No API returns private key material. An assembly accesses it
through `AssemblyContext.Current.Keys`; native dispatch supplies the owning
incarnation from trusted context.

`Generate(slot, KeyAlgorithm.HmacSha256)` creates a 256-bit HMAC key.
`Generate(slot, KeyAlgorithm.Aes128)` creates a 128-bit AES key, and
`Generate(slot, KeyAlgorithm.P256)` creates a P-256 private key. Generation fails if
the slot already exists, the algorithm is unsupported, entropy fails, or the quota is
exceeded. `Open(slot)` returns an opaque `KeyHandle`. `Delete(slot)` revokes it. A
handle can perform only operations allowed by its key algorithm.

Handles encode the domain incarnation and a fresh 128-bit token. Every operation checks both the current domain and the still-live token. Deleting and regenerating a slot does not restore its old handles. Deleting an SSD removes its keys. A recreated SSD has a new incarnation. Same-domain assemblies deliberately share keys and store values, as required by the profile.

The handle supports `HmacSha256`, `AesCmac`, `EncryptCbc`, `DecryptCbc`, `EncryptCcm` and `DecryptCcm`. CBC uses ISO-style 80/00 padding. CCM uses a 13-byte nonce and 16-byte tag. Callers must provide a fresh nonce for every CCM encryption under the same key. The original sample uses hardware-backed randomness for IVs/nonces and never exports a secret key.

Generation, deletion, and application-value changes use the ordinary command path
unless the application opened a `TransactionScope`. Ordinary changes commit at the
safe command boundary. An explicit transaction provides rollback and synchronous
commit. Plaintext key arrays are zeroized when their Rust entries are dropped. Opaque
handles and cryptographic result buffers reserve their exact bounded size fallibly
before native execution. Scratch storage zeroizes on provider failure. Application
records and authenticated journal plaintext use zeroizing buffers.

**Development security boundary:** MJ03 encrypts and authenticates persistent framework keys in the journal with a key derived from the device-specific SCP03 management keys. The separate append-only generation anchor rejects an older journal snapshot during normal boot. A one-way word in the same erase page as the management keys rejects blank durable state after ownership and forces page erase plus fresh-key provisioning. The management-key flash page depends on reset-scoped ACL protection, and debug recovery remains enabled. Tamper resistance, production firmware verification and sealed root-key storage remain work. Until debug is locked, a physical attacker can erase and rewrite the key page or bypass the flash anchor.

## Evidence

`key_store` tests exercise domain/incarnation ownership, wrong algorithms, entropy failure, quota checks, persistence and revoked handles. `scripts/scp03_acceptance.py` loads the original `KeyOperations` assembly over SCP03 and checks HMAC/CMAC against a separate Python/OpenSSL oracle using temporary simulator fixtures. It exercises CBC/CCM round trips, shared-key assemblies, reboot persistence and rollback after stale-handle use. The same cases run over text and firmware binary framing.
