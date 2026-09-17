# Default assembly profile

The default assembly set is the supported foundation for card applications. `Kdf108` and `Kdf108Consumer` are demonstration assemblies in the test corpus. They exercise dependency linking, signer constraints, opaque keys and native AES-CMAC. The default set excludes them, and they define no platform API.

The default set is provisioned into the ISD after `mscorlib` takes ownership. Each assembly has a fixed identity and version, is signed by the ISD ownership identity and publishes an explicit dependency export policy. SSD assemblies may call exported functions, but execution retains the caller SSD as the storage, key and capability identity. Default libraries never give a caller ISD storage access.

## Required assemblies

### `mscorlib`

Provide the supported ECMA-335 core surface for `Object`, primitive value types, arrays, strings when the bounded string representation is implemented, equality, comparison, checked conversion, basic math and bounded buffer operations. Methods must operate on caller-owned arrays by offset and length where returning a new array would create an avoidable copy.

Version 0.1.0 provides bounded byte and Int32 range checks, overlap-safe copy, fill and clear, constant-work byte equality, lexicographic byte comparison, big- and little-endian Int32 and UInt16 conversion, Int32 equality/comparison, min/max/clamp/sign/saturating absolute value and checked arithmetic. These APIs allocate no temporary arrays. The normal Rider/MSBuild reference is `MicroCard.Core`. `[DeviceAssemblyIdentity("mscorlib")]` makes the manifest and MC04 Assembly row exactly `mscorlib`, and a verified dependency reference rewrite changes only the matching AssemblyRef. The host rejects duplicate, unused, self and reserved-platform aliases. Build-only identity, dependency and export annotations do not enter the runtime image.

The 28-method assembly occupies 2,161 bytes as MC04 and 2,585 bytes as a representative signed package. A differently signed SSD consumer pins package version 1, assembly version 0.1.0 and the ISD signer, then exercises the managed calls through signed loading and after simulator restart. The desktop reference executable checks 42 range, overlap, endian and arithmetic cases.

### `MicroCard.Framework`

Provide the only general native ABI facade. It owns command and response APDU views, lifecycle context, caller security context, transactions, domain storage, randomness, opaque key handles and capability-checked hardware access. `CommandApdu.Length` and `CommandApdu.CopyTo` copy one validated range into the invocation arena. `ResponseApdu.Write` borrows one validated caller range and appends it to the bounded response. `ResponseApdu.SetStatus` sets the status word. Native IDs 11, 12 and 13 implement the bulk operations, ID 2 sets status, and IDs 46 through 48 implement domain-storage begin, commit and abort. IDs 0 and 1 are invalid, so packages built for the retired bytewise ABI are rejected. No public method accepts a domain identifier or raw native handle.

### `MicroCard.Iso7816`

Provide short command parsing, status-word constants, AID comparison, command routing and bounded BER-TLV readers and writers needed for `SELECT`, `GET DATA`, `PUT DATA`, `VERIFY`, `CHANGE REFERENCE DATA`, challenge-response and authentication flows. This follows ISO/IEC 7816-4:2020 command-response and APDU conventions while documenting the exact MicroCard subset.

Version 0.1.0 implements short cases 1 through 4, including the short `Le=0` value of 256, and rejects extended, truncated and inconsistent encodings. AIDs are limited to 5 through 16 bytes. BER-TLV accepts canonical definite lengths through 65,535 bytes and canonical tags up to three encoded bytes. Readers return offsets into caller-owned input through a fixed result array. Writers target caller-owned buffers, support overlapping input and output, and check the complete destination before mutation. The assembly contains no lifecycle entry points or native capabilities. Its `Int32` constants are folded into consumer CIL and removed from MC04 metadata.

The signed provisioning acceptance loads the library after `mscorlib` in the ISD, then loads a differently signed SSD consumer constrained to version 0.1.0 and the ISD ownership public key. It rejects a wrong provider signer before SSD binding, executes the verified dependency after installation, prevents provider removal while referenced, and repeats the call after journal recovery.

### `MicroCard.Cryptography`

Provide thin, idiomatic managed facades over native SHA-256, HMAC-SHA-256, AES-CMAC, AES-CBC, AES-CCM, random generation and Ed25519 verification. Add native opaque-key P-256 generation, ECDSA signing and verification, and ECDH so a card application can implement a practical asymmetric credential without exposing private key bytes. Cryptographic primitives, secret-dependent operations, key validation and constant-time comparisons execute in trusted Rust or a hardware-backed HAL provider, never as interpreted CIL. The managed assembly contains API shape and non-secret policy composition only. Algorithms, key usage, export policy and native work budgets are explicit. Optional algorithms such as RSA use separately budgeted native providers and managed facades.

Version 0.1.0 provides managed `Sha256`, `Ed25519`, `HmacSha256`, `AesCmac`, `AesCbc`, `AesCcm`, `P256`, caller-buffer random fill and opaque domain-key lifecycle facades. P-256 private scalars remain in the native encrypted key store. Managed code receives only opaque handles, uncompressed SEC1 public keys, fixed-width signatures and ECDH results. ECDSA uses SHA-256 and 64-byte IEEE P1363 signatures. Random fill validates one caller-owned offset/length range before invoking platform entropy and clears that range if the provider fails. The assembly contains no lifecycle entry points. Its verified calls resolve to the pinned framework ABI, which dispatches native operations through the caller SSD's `CryptoProvider` and key ownership. The 1,691-byte assembly has a 2,176-byte representative signed package. Signed simulator acceptance provisions it in the ISD, loads a differently signed exact-pinned SSD consumer, exercises valid, invalid and malformed signature inputs, P-256 public-key export, ECDSA, ECDH, random fill and the symmetric operations, and verifies key continuity after journal recovery.

### `MicroCard.Security`

Provide a managed facade over native transactional PIN and PUK state, bounded retry counters, constant-time secret verification and invocation-scoped authorization results. Persistent verifiers, private values and secret-dependent comparisons stay in protected native services. Managed code may compose public access-condition policy, but it cannot read verifier material. Failed verification, reset, unblock and retry-counter changes must remain atomic across power loss.

Version 0.1.0 preprocesses as a 680-byte, seven-method managed facade with a 1,131-byte representative signed package. Native state uses independently salted SHA-256 PIN and PUK verifiers bound to the SSD incarnation and slot, bounded retry counters, constant-time digest comparison, and zeroization on drop. Verification authorization lives only in the current VM host invocation. Failed-attempt floors commit separately when managed code deliberately faults, while credential creation, PIN change and ordinary application state roll back. Signed text and binary SCP03 acceptance covers retry exhaustion, durable PIN and PUK failures followed by a managed fault, unblock, PIN change, provider unload protection, SSD isolation and reboot. A byte-granular interruption sweep proves retry-floor recovery exposes only the prior valid state or the complete consumed-attempt state.

### `MicroCard.Encoding`

Provide allocation-bounded BER-TLV and DER primitives for definite lengths, integers, bit and octet strings, object identifiers and constructed values. Readers borrow input slices. Writers target caller-provided buffers and return the written length or a failure result. CBOR and standard-specific object models are optional assemblies rather than default dependencies.

Version 0.1.0 now provides the DER core from ITU-T X.690: canonical identifiers bounded to three octets, canonical definite lengths through 65,535 bytes, canonical BOOLEAN/INTEGER/BIT STRING/NULL/OBJECT IDENTIFIER validation, minimal signed Int32 writing, and overlap-safe caller-buffer writers for INTEGER, BIT STRING, OCTET STRING, OBJECT IDENTIFIER and constructed values. Nonrecursive validation uses caller-provided Int32 scratch. `SET OF` writing requires lexicographically ordered complete DER encodings. The assembly declares no native capabilities. Signed provisioning loads it after `mscorlib` in the ISD, then executes a differently signed SSD consumer pinned to the exact provider signer and version across both simulator transports and reboot.

## Trust and compatibility rules

Only the pinned `mscorlib` and `MicroCard.Framework` identities may declare native imports. The other default assemblies are verified managed dependencies and can reach native operations only through the framework's typed public API. Namespace names and attributes do not grant trust.

The portable Rust core defines the cryptographic service contract. A board HAL uses a verified hardware implementation for every operation the processor can perform with the required semantics. A native Rust implementation is the fallback only when suitable hardware support is unavailable. Both paths preserve identical input validation, key ownership, zeroization, failure and work-budget behavior and pass the same known-answer and negative tests. Provider selection is fixed by the board build and provisioning policy. Managed code cannot select a weaker path or force fallback.

The provisioned default-bundle manifest fixes assembly identities, versions, public keys and package digests. A consumer dependency can add a narrower version, signer or digest constraint. Removing or replacing a default provider is rejected while a loaded assembly depends on its exact binding.

All public parsing and cryptographic APIs accept bounded views or caller-owned output buffers. Native calls borrow verified VM slices where lifetimes permit and write into prevalidated output regions. They do not create package-sized or input-sized bridge copies. Link validation records exact target methods and ABI shapes. Device verification repeats those checks before activation, during recovery and before execution.

## Minimum usefulness acceptance

The default set is sufficient only when an original credential assembly can, without declaring native imports:

1. Select by AID and return structured application data.
2. Persist a certificate or public data object and retrieve it with BER-TLV framing.
3. Create an opaque P-256 private key and return its public key.
4. Verify a PIN with durable retry limits and invocation-scoped authorization.
5. Sign a host challenge after authorization and reject unauthorized use.
6. Survive simulator and nRF52840 power-loss injection without exposing private key material or partially committing PIN, key or object state.

Acceptance compares native primitive results with independent known-answer vectors and desktop .NET where equivalent, runs malformed APDU/TLV and buffer-boundary suites, verifies signer and dependency policy, and records the flash, persistent-storage, arena, stack, instruction and native-work cost of every default assembly. Tests prove managed assemblies cannot substitute a primitive, obtain secret key bytes, select another domain's key or bypass native work limits. The credential demonstrates conformance to the MicroCard APIs. It makes no external credential conformance claim.

## References

- ECMA-335, sixth edition, Partition I §8 and Partition II §22, for the retained core type and assembly model.
- ISO/IEC 7816-4:2020, §§5.1–5.2, for command-response pairs and APDU syntax.
- GlobalPlatform Card Specification 2.3.1, for ISD, SSD and lifecycle terminology. The dependency and signer rules above are the MicroCard profile.
- NIST SP 800-186, for the P-256 domain parameters. FIPS 186-5 §6, for ECDSA. And NIST SP 800-56A Rev. 3 §5.7.1.2, for the ECC CDH primitive. MicroCard returns the raw shared secret. Protocol assemblies must apply their specified KDF.
