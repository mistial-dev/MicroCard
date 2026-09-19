# nRF52840 cryptographic hardware inventory

Status: provider inventory and opt-in SHA-256, entropy, AES and P-256 integration complete for the repository's only physical board backend. Physical device evidence remains open.

The nRF52840 contains Arm CryptoCell 310. Nordic's product specification lists hardware support for the complete MicroCard baseline, but hardware support alone does not establish that a particular SDK artifact exposes the required operation safely or fits the firmware budget.

| MicroCard operation | Default nRF52840 provider | Hardware path and decision |
| --- | --- | --- |
| Entropy and random generation | nRF52840 RNG peripheral | Opt-in CryptoCell TRNG exists and compiles, but remains disabled until physical health, timeout and reset behavior passes. |
| SHA-256 | Portable Rust | Opt-in CC310 SHA-256 compiles and self-tests. It remains disabled pending physical and forced-failure evidence. |
| HMAC-SHA-256 | Portable Rust | Opt-in CC310 multipart HMAC compiles and self-tests. It remains disabled for the same evidence gap. |
| AES-CMAC | Portable Rust | Opt-in CC310 multipart CMAC compiles and self-tests. It remains disabled for the same evidence gap. |
| AES-128 block and CBC | Portable Rust | Opt-in CC310 cipher support compiles and self-tests. MicroCard keeps ISO 7816 padding validation and failure mapping in Rust. |
| AES-CCM | Portable Rust | Opt-in CC310 AEAD compiles for the fixed 13-byte nonce and 16-byte tag profile. It remains disabled pending physical rejection and reset tests. |
| P-256 ECDSA and ECDH | Portable Rust | Opt-in CC310 P-256 compiles and self-tests. Rust prevalidates private scalars so both providers map invalid stored keys identically. |
| Package signature verification | Portable Rust, with a CryptoCell override available | Package signatures are P-256 ECDSA over SHA-256, which the pinned `cc310-p256` path already implements and self-tests. Enabling it puts package verification on hardware. |
| SCP03 KDF | Rust framing with the selected AES-CMAC provider | The framing stays portable. Opt-in CC310 CMAC accelerates its primitive only when that provider is selected by the board build. |

Protocol formatting, ISO 7816 parsing, SCP03 chaining, KDF labels, padding policy, domain authorization and key-handle checks remain portable Rust responsibilities. The accelerator receives an operation only after those checks.

## Integration constraints

Nordic recommends using its SDK libraries with CryptoCell rather than treating the register description as a supported programming interface. The first candidate is the RTOS-independent `sdk-nrfxlib` CryptoCell library behind an nRF52840-only `CryptoProvider` adapter.

The nrfxlib repository uses `LicenseRef-Nordic-5-Clause`. It permits source and binary redistribution with conditions, restricts use to Nordic integrated circuits, and forbids reverse engineering or modification of supplied binaries. Before integration:

1. Pin an exact release, artifact digest, headers and license text.
2. Confirm the license on each selected source and binary file rather than relying only on the repository root.
3. Keep the dependency in the nRF52840 board crate. The portable core and other board ports must not inherit Nordic-only code.
4. Preserve required notices in firmware distributions and generated source bundles.
5. Use documented APIs only. Do not disassemble or adapt a binary by reverse engineering.

## Pinned candidate release

The integration baseline is the coherent nRF Connect SDK `v3.4.0` bundle. Its manifest pins nrfxlib `v3.4.0`, annotated tag object `f5e9596e66a8c5d11cebfc79ff45a9e6c45862e3`, commit `d4ce5fe1a7d8af29bc01a4e1ddf5540ef65b6a3b`, together with `ncs-v3.4.0` Mbed TLS, Oberon PSA Crypto and TF-M revisions. The immutable nrfxlib artifact and header hashes are recorded in [`board/nrf52840/nrfxlib-3.4.0.lock.json`](../board/nrf52840/nrfxlib-3.4.0.lock.json). The three selected Cortex-M4 hard-float, four-byte-`wchar_t`, no-interrupt archives are version 0.9.22 and occupy 427,100 bytes in the upstream checkout. That figure measures the archive. The linked firmware cost is smaller because the SHA-256 feature pulls only required platform objects.

The archives use ARM EABI 5, ARMv7E-M Thumb-2, VFPv4-D16 hard-float arguments, small enums and eight-byte stack alignment. Those properties match the board target at a high level, but ABI compatibility alone is insufficient.

The opt-in board feature `cc310-sha256` now uses Nordic's documented platform SHA-256 API rather than linking the mbedcrypto archive directly. It initializes without RNG, provides the required single-thread and abort hooks, and gives the CC310 API a fixed 16-byte word-aligned RAM buffer so inputs may reside in RAM or flash. The provider writes into a local result and publishes it only after success. Before key derivation or journal recovery, boot fails closed unless the accelerator returns the standard empty-input digest and the `abc` digest from both flash and stack RAM. The board build hashes the selected archive and rejects any size or SHA-256 mismatch even when the separate verification script is skipped.

The opt-in `cc310-entropy` feature uses the documented CryptoCell TRNG entry point and full platform initialization. The linked path has no unresolved allocator symbols. Every call requires the exact requested length and clears output after an error or short result. Boot rejects repeated, all-zero or all-one 256-bit samples before protected state opens. The library retains its own internal TRNG health processing. [`NRF52840_CC310_PLATFORM_SPIKE.json`](NRF52840_CC310_PLATFORM_SPIKE.json) records 2,868 flash and 160 aggregate RAM bytes for SHA-256, and 9,844 flash and 1,072 aggregate RAM bytes for SHA-256 plus entropy. `scripts/nrf_cc310_platform_spike.py --check` re-verifies both vendor pins, rebuilds all variants, checks required symbols and enforces aggregate limits.

The opt-in `cc310-cmac` feature is the first TF-PSA/CC3XX driver integration. A minimal local PSA configuration enables AES-CMAC only, while SHA-256 remains present solely for TF-PSA's required entropy configuration. The build compiles the exact pinned Nordic driver wrapper, verifies the complete 35-file external include closure by content digest, and links the pinned PSA, core and platform archives. The Rust adapter lends each input slice directly to one multipart operation, retains a fixed 544-byte, 8-byte-aligned state buffer, and publishes its local 16-byte result only after an exact successful finish. The state and failed result are wiped. The linked image contains no exact C allocator symbols. Its measured code is 320,216 bytes, a 17,652-byte increase over the default image. Initialized data plus BSS increases by 1,072 bytes. The compiler reports at most 64 bytes for a C shim frame, and disassembly records a 592-byte Rust frame including saved registers, for 656 bytes of bridge-owned peak stack before CC3XX internal callees. Vendor-internal and physical stack high-water measurements remain open.

Boot runs RFC 4493 examples 1 through 4, including three borrowed segments and a RAM-backed 64-byte message. This is compiled self-test coverage only. The feature remains disabled until those checks and forced setup, update, finish, timeout and reset failures are observed on the DK.

The opt-in `cc310-hmac` feature adds HMAC-SHA-256 through the same verified multipart boundary. It borrows the key and message directly, maps an empty HMAC key to its equivalent single zero byte for PSA import, shares the wiped fixed operation state, and withholds its local 32-byte result until an exact successful finish. Boot contains RFC 4231 case 1 with a RAM-backed message plus the empty-key and empty-message answer. Its measured code is 319,892 bytes, a 17,328-byte increase over the default image. Initialized data plus BSS increases by 1,072 bytes. Disassembly records 608 bytes for the Rust frame including saved registers and at most 64 nested shim bytes, for 672 bytes of bridge-owned peak stack before CC3XX internal callees.

The opt-in `cc310-aes` feature exposes AES-128 block encryption through the pinned TF-PSA cipher wrapper. The adapter borrows the key and input block, receives hardware output in one 16-byte local result, clears the caller's block on failure, and updates it only after the driver reports exactly 16 bytes. Boot checks the FIPS 197 AES-128 example. The cipher configuration expands the verified external include closure from 35 to 36 files by adding `cc3xx_psa_cipher.h`. Its measured code is 319,288 bytes, a 16,724-byte increase over the default image. Initialized data plus BSS increases by 1,076 bytes. Disassembly records a 48-byte Rust frame and the compiler reports an 88-byte C shim frame, for 136 bytes of bridge-owned peak stack before CC3XX internal callees.

The opt-in `cc310-cbc` feature shares the core's ISO 7816 padding helpers, copies input once into the result allocation already owned by the key service, and runs the pinned multipart CBC-no-padding driver in place. Encryption and decryption wipe the complete caller output on setup, bounds, driver or padding failure. Boot checks the first NIST SP 800-38A CBC block in both directions. Its measured code is 318,464 bytes, a 15,900-byte increase over the default image. Initialized data plus BSS increases by 1,076 bytes. The compiler reports 384 bytes for the C operation frame, and disassembly records 48-byte Rust encrypt and decrypt frames, for 432 bytes of bridge-owned peak stack before CC3XX internal callees.

The opt-in `cc310-ccm` feature fixes the MicroCard profile at a 13-byte nonce and 16-byte tag, borrows every input, and invokes the pinned one-shot AEAD driver directly into the caller-owned output. Exact output length is mandatory. Setup, bounds, driver and tag failures wipe the complete caller output. Ag rejection remains distinguishable as authentication failure. Boot checks an exact NIST CAVP encryption, decrypts it, then modifies the tag and requires rejection plus all-zero plaintext. The AEAD configuration expands the verified external include closure to 37 files by adding `cc3xx_psa_aead.h`. Its measured code is 327,160 bytes, a 24,596-byte increase over the default image. Initialized data plus BSS increases by 1,076 bytes. Disassembly records 56-byte Rust encrypt and decrypt frames and the compiler reports a 112-byte common C shim frame, for 168 bytes of bridge-owned peak stack before CC3XX internal callees.

The opt-in `cc310-p256` feature implements uncompressed SEC1 public-key derivation, fixed-width deterministic ECDSA/SHA-256 signing and verification, and raw ECDH. It compiles the exact sdk-nrf `v3.4.0` CC3XX signature and key-agreement driver sources under their Nordic license, then links only the required pinned nrfxlib objects. The bridge borrows fixed-size inputs, writes into caller-owned output, wipes all failed secret or signature output, rejects invalid private scalars as storage errors before hardware dispatch, and distinguishes invalid signatures or peer keys from provider failure. Boot verifies the exact RFC 6979 public key and deterministic `sample` signature, rejects that signature for a changed message, and checks a fixed ECDH secret. Its 48-file isolated dependency closure, 49-file cipher combination and 50-file AEAD combination have separate content pins. The measured image is 319,908 bytes, a 17,344-byte flash increase. Aggregate RAM rises 1,200 bytes. Rust plus C bridge frames peak between 88 and 152 bytes before vendor-internal callees. The combined SHA-256, entropy, CMAC, HMAC, AES, CBC, CCM and P-256 image uses 335,836 text bytes and 197,840 aggregate RAM bytes under 375,000/200,000 experimental ceilings. The default board retains its separate 350,000-byte release budget.

This feature remains disabled by default until physical known-answer, flash-input, error, timeout and reset tests pass. The compile and link evidence does not establish hardware execution or correct failure behavior on silicon.

The matching Nordic Oberon PSA Crypto source is pinned separately in [`board/nrf52840/oberon-psa-crypto-ncs-v3.4.0.lock.json`](../board/nrf52840/oberon-psa-crypto-ncs-v3.4.0.lock.json). The P-256 driver sources have their own [`board/nrf52840/sdk-nrf-3.4.0.lock.json`](../board/nrf52840/sdk-nrf-3.4.0.lock.json). The locks record annotated tags, commits, Git trees, licenses and every compiled source at the driver boundary. Run `python3 scripts/verify_nrf_crypto_sources.py` against the explicit ignored checkouts before using them. This proves source identity. Physical execution and failure evidence remain separate requirements.

Nordic's pinned documentation says the CC310 mbedcrypto library is used exclusively through the TF-PSA Crypto driver and explicitly directs applications not to link it directly. The PSA archive also has unresolved dependencies on the PSA driver hash wrappers, bounded allocation hooks and the C memory routines. Those two mbedcrypto archives therefore remain **inspection-only** outside the verified wrapper path. Further hardware operations must compile only the required algorithms from the pinned TF-PSA/Oberon boundary, provide fixed-capacity allocation, and measure the resulting board image before enabling each `CryptoProvider` override.

The driver headers carry BSD-3-Clause identifiers. The selected archives are covered by their adjacent `LicenseRef-Nordic-5-Clause` files. The lock records each license digest. Distributions must include the exact required notices.

CryptoCell must be disabled when idle for lowest power. The adapter owns enable/disable, clock, interrupt, DMA-buffer and timeout state and must clear partial outputs on every error. A provider error aborts the current command. It cannot trigger an implicit Rust retry because retrying a secret operation can change timing and fault behavior.

CryptoCell advertises an application derived-key model, but MicroCard does not yet treat it as persistent protected key storage. The selected library and device tests must establish reset behavior, key derivation inputs, accessibility from debug state and whether opaque domain keys can avoid RAM exposure. Until then, journal key protection remains a separate open requirement.

## Required evidence

- Run the same known-answer and negative vectors through Rust and CryptoCell providers for every enabled operation.
- Run the committed Wycheproof P-256 ECDSA corpus through both providers before enabling the hardware override for package verification.
- Verify caller ownership, algorithm/key mismatch, malformed lengths, provider-reported output bounds and plaintext clearing after authentication failure.
- Measure flash, BSS, native stack, latency and energy, including enable/disable overhead and break-even message sizes.
- Interrupt each operation through timeout, watchdog and reset scenarios. Verify no successful result or persistent mutation is exposed after failure.
- Confirm hardware use from authenticated diagnostic inventory and timing evidence. A linked vendor library alone is insufficient.

## Primary sources

- [Nordic nRF52840 product features](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/keyfeatures_html5.html)
- [Nordic CryptoCell 310 product specification](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/cryptocell.html)
- [Nordic RTOS-independent nrfxlib repository](https://github.com/nrfconnect/sdk-nrfxlib)
- [Pinned nRF Connect SDK v3.4.0 manifest](https://github.com/nrfconnect/sdk-nrf/blob/v3.4.0/west.yml)
- [Pinned nrfxlib v3.4.0 tree](https://github.com/nrfconnect/sdk-nrfxlib/tree/v3.4.0)
- [nrfxlib root license](https://raw.githubusercontent.com/nrfconnect/sdk-nrfxlib/master/LICENSE)
