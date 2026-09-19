# Native cryptographic providers

Native capability 21 is reserved after removal of Ed25519 verification. It must remain rejected and must never be reassigned.

Cryptographic primitives execute outside interpreted CIL. Managed assemblies call the fixed native ABI with verified borrowed inputs and opaque domain-owned key handles. Provider selection belongs to the board build and cannot be requested by an assembly.

`crypto::CryptoProvider` is the portable native contract. `domains::Platform` extends it, so each simulator or board port supplies one provider. The default methods use the native Rust implementation. A board overrides each operation that has suitable verified hardware support.

The current provider path covers every VM-exposed primitive and package trust-boundary operation:

- SHA-256 and strict P-256 ECDSA verification.
- HMAC-SHA-256 and AES-CMAC using authorized domain key handles.
- AES-CBC encryption/decryption and AES-CCM authenticated encryption/decryption.
- P-256 public-key derivation, deterministic ECDSA/SHA-256 signing, ECDSA verification and raw ECC CDH using opaque domain key handles for private operations.
- Platform entropy filling one prevalidated caller-owned managed array range, with no bridge buffer and failure clearing.
- P-256 ECDSA package verification and package SHA-256 digests during staged activation and reboot recovery. A stored signer identity is the digest of a key rather than a key, so recovery has no curve point to revalidate.
- AES-CCM journal encryption during each durable commit and decryption during recovery.

SHA-256, HMAC-SHA-256, AES-CMAC, P-256 public-key export, P-256 signing and P-256 ECDH providers borrow their inputs and write fixed results into caller-owned arrays. AES-128 block encryption operates in place. Their convenience wrappers dispatch through the same methods, so a hardware implementation has one output path. Callers initialize fixed outputs to zero. Errors must never expose a partial result and must leave the caller-visible output all-zero. VM and key-service callers allocate one zeroizing result vector, lend its fixed slice to the provider, then move the allocation into the VM heap without copying.

The managed `MicroCard.Cryptography.SHA256` facade also exposes a profile-safe offset overload. It borrows one validated source range, writes 32 bytes into a prevalidated caller-owned destination range and returns the 32-byte written count through native capability 49. The runtime uses only a zeroizing 32-byte stack result between the provider and managed array, so this path allocates no transient VM object and works when source and destination are the same managed array. The array-returning overload remains available for ordinary C# use.

Source may use the exact platform API `System.Security.Cryptography.SHA256.HashData(byte[])`. The analyzer allows only that BCL signature. The independent preprocessor rewrites its TypeRef and MemberRef to `MicroCard.Framework.Cryptography.Sha256`, pins the framework hash, records capability 20 and omits the BCL cryptography AssemblyRef. The signed device image therefore contains no user-selected native binding or unresolved platform dependency. Use the MicroCard offset overload when a caller-owned destination avoids an allocation.

The same verified projection supports `System.Security.Cryptography.RandomNumberGenerator.GetBytes(int)` through capability 50. Embedded requests are limited to 1 KiB. The runtime reserves one exact result vector, charges work before provider dispatch, clears partial output on failure and moves successful ownership into the VM heap. `MicroCard.Cryptography.RandomNumberGenerator.Fill` writes into an existing array when avoiding that allocation matters.

`MicroCard.Cryptography.CryptographicOperations.FixedTimeEquals` uses capability 51. Its offset overload borrows two managed-array ranges without copying, bounds each range to 1 KiB, and compares equal-length inputs with the native `subtle` implementation. Different public lengths return false after both ranges are validated.

Focused pointer-identity coverage fixes the host boundary at zero input copies and one output allocation: the provider observes the stored key address and the original managed-heap message address, its output address becomes the returned key-service vector, and VM heap adoption preserves that vector's address. Fixed provider scratch remains stack-owned and zeroized where it can contain secret-derived bytes. Physical CC310 bridge and vendor-internal copy costs remain a separate device measurement.

CBC and CCM providers also borrow their inputs and write into caller-owned output buffers. The Rust fallback performs both operations in place within that buffer and clears recovered plaintext when padding or authentication fails. The domain key service allocates one bounded result buffer and rejects a provider-reported length outside it. `Heap::allocate_bytes` then moves that same vector allocation into the VM object table. A pointer-identity test proves the transfer does not copy the result buffer.

The domain key service validates the caller incarnation, opaque handle, algorithm, capability and work budget before invoking the provider. P-256 private scalars are generated from platform entropy, rejected if zero or outside the curve order, encrypted with the journal state, and zeroized when their native store entries drop. A provider error aborts the invocation transaction. It never triggers an automatic retry through a different provider.

The simulator, fuzz platform and default nRF52840 backend use the Rust fallback. Every provider entry point clears its complete caller-owned output before returning an error, including setup, bounds, driver, authentication and padding failures. `RuntimePlatform` applies the same rule to entropy even if a board entropy adapter fails after a partial write. The board's opt-in `cc310-sha256` feature links Nordic's pinned platform archive and overrides SHA-256 with its documented CC310 entry point. It uses fixed aligned DMA scratch, clears caller output on errors, and resets on a vendor abort. The opt-in `cc310-entropy` feature selects the documented CryptoCell TRNG path, requires complete output, clears partial output on failure, and rejects constant or repeated boot samples. The opt-in `cc310-cmac` and `cc310-hmac` features stream borrowed slices through the pinned TF-PSA multipart MAC wrapper and CC3XX driver. Their fixed 544-byte aligned operation state is wiped after every outcome, caller output changes only after an exact successful result, and the linked images contain no exact C `malloc`, `calloc`, `realloc` or `free` symbols. The opt-in `cc310-aes` feature borrows one AES-128 input block, clears it on failure and publishes its in-place result only after exact success. The opt-in `cc310-cbc` provider shares the core ISO 7816 padding implementation and performs CBC directly in the result allocation, wiping it on driver or padding failure. The opt-in `cc310-ccm` provider borrows every input and writes its exact result directly into caller-owned output through the one-shot AEAD wrapper. It maps tag rejection to authentication failure and wipes all output on every failure. The opt-in `cc310-p256` provider borrows fixed private-key, public-key and hash inputs and implements public-key derivation, deterministic ECDSA/SHA-256 sign/verify and ECDH through two exact pinned sdk-nrf CC3XX driver sources. It writes only into fixed caller-owned output, clears failure output, distinguishes invalid signatures or peer keys from provider failure, and retains raw private scalars only in the encrypted native key store. Boot adds exact RFC 6979 public-key/signature verification, changed-message rejection and a fixed ECDH answer to the symmetric known answers. Compile/link and memory evidence is recorded in `NRF52840_CC310_PLATFORM_SPIKE.json`. All eight features remain disabled by default and no hardware-execution claim is made until the self-tests and forced failures are observed on the DK. Each further hardware override must pass the same known-answer, malformed-input, authentication-failure and ownership tests, then record timing, memory, energy and copy behavior.

Activation and authenticated recovery verify every package through the platform provider. Successful verification retains immutable manifest metadata shared by transaction candidates. Execution, dependency resolution, and registry queries borrow that metadata and the stored image without parsing or verifying the package again. The cache is absent from journal snapshots and is rebuilt through the provider on every recovery. Provider errors fail activation or recovery.

The journal borrows its authenticated header and plaintext and lets the provider write ciphertext directly into the final record buffer. Recovery reads the exact ciphertext into one vector, authenticates and decrypts its message bytes in place, truncates the tag, and transfers that allocation to state decoding. Authentication failure clears the recovered message. An invalid tag marks that committed record corrupt. An unavailable or failed provider aborts recovery without trying another implementation.

SCP03 storage-key derivation, session KDF, command and response MACs, command IV generation, and command decryption use the card's platform provider. Provider failures remain distinct from authentication failures and tear down an in-progress session at the APDU endpoint. Focused tests compare the provider path with the independent SCP03 acceptance client at security levels `01`, `03`, `11`, and `13`.

AES-CMAC accepts a bounded list of borrowed input slices. SCP03 passes its chaining value, fixed header, command data and status bytes as separate slices, so storage-key derivation, session derivation, command MAC and response MAC do not allocate concatenation buffers. The software provider streams the slices through one CMAC state. Hardware providers must produce the same result for every segmentation of identical bytes.

The allocation-free `hal::conformance::run_crypto` runner applies the same standard known answers to any provider. It covers SHA-256, HMAC-SHA-256, one-piece and segmented AES-CMAC, AES-128 block encryption, padded CBC round trip, CCM encryption/decryption, P-256 ECDSA verification and changed-message rejection, plus P-256 public-key derivation, deterministic ECDSA sign/verify and ECDH. Negative cases require short CBC/CCM output, malformed CBC ciphertext, CBC padding failure and CCM tag rejection to clear the complete caller buffer. They also reject malformed P-256 inputs, map invalid P-256 private scalars consistently, reject invalid ECDH peers and expose no failed fixed output. The deterministic simulator passes this runner. Each board provider must pass it before physical failure-injection and timing acceptance.

SCP03 command verification consumes the parsed command. MAC validation borrows its payload, then removes the received MAC by truncating the existing vector. Unencrypted commands keep that allocation through trusted dispatch. Encrypted commands allocate only the separate plaintext buffer required by Rust's nonaliasing input and output contract.

Long-running validation follows the repository cadence: focused provider tests during development, the complete host and fault-injection gate after consolidated security batches or before device/release acceptance, and sustained fuzz campaigns only at dedicated fuzz checkpoints or release candidates.

## Reproducible build inputs

Install `arm-none-eabi-gcc` and GNU ARM binutils, then run:

```sh
python3 scripts/fetch_nrf_crypto_sources.py
python3 scripts/verify_nrf_crypto_sources.py
```

The fetch command uses the repository's lock files, performs shallow sparse checkouts
under ignored `work/`, and verifies the annotated tag, commit, tree, licenses, and
pinned file hashes before publishing each directory. Existing checkouts are verified
without reset, cleanup, or replacement. Cargo's build script separately validates every
compiled vendor dependency and archive. Fetching is explicit; Cargo does not download
vendor source. Linux CI runs this setup and all engine/layout replacement matrices.

## Replacement measurements

Run `python3 scripts/crypto_provider_matrix.py --output work/crypto-mc04-dk.json`.
Use `--engine jcvm` and `--layout dongle` to inspect the other engine/layout pairs.
Each stage has its own cached ELF and link map under `board/nrf52840/target/profiles/`;
the report records the ELF hash, actual Cargo dependencies, archive text/constant-data
contributions, and non-profile algorithm symbols. Hardware-only stages reject linked
RustCrypto implementation symbols as well as dependencies. All stages reject exact C
`malloc`, `calloc`, `realloc`, or `free` entry points.

[The MC04 DK record](CRYPTO_PROVIDER_MEASUREMENTS.json) measures 185,708 software text
bytes and 211,608 hardware text bytes. The latter excludes RustCrypto but still links
ChaCha20/Poly1305 through generic vendor dispatch. Cargo feature removal alone cannot
eliminate those archive branches. Compile/link evidence does not validate device
operation or justify removing cryptographic checks.
