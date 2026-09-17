# Reference provenance and implementation rules

Original MicroCard implementation and corpus. HIVE/.NET Card decompiled code, vendor lifecycle scripts and proprietary sample implementations are not inputs to this code. Reference Library documents remain at their original locations. Only paths, hashes, editions and clause references are committed.

## Normative reference map

- ECMA-335, sixth edition, June 2012: I.12.3 machine state, II.22 metadata tables, III.3 integer/control-flow operations, III.4 object/array operations. `image.rs`, `vm.rs`, the C# metadata reader and desktop differential corpus use this subset. The complete standard was downloaded unchanged under ignored `references/downloads/` with its copyright notices retained.
- ECMA-334, seventh edition, December 2023: C# syntax/semantics and attributes. Authoring uses a regular SDK compiler. MicroCard deliberately supports a constrained execution profile. Many C# and CLI libraries remain outside it. The unchanged PDF is locally available under ignored downloads.
- ISO/IEC 7816-4:2020, UK BSI adoption: §§5.1–5.2 command-response pairs and APDU syntax. `apdu.rs` and its short-case tests use these clauses. Extended-length commands are rejected.
- GlobalPlatform Card Specification 2.3.1, **March 2018**: §11.1.1 lifecycle coding, §11.1.2 privilege coding, §11.4 GET STATUS, and Appendix H.1.3's default ISD AID. MicroCard's signer pinning, shared domain store and synthetic registry AIDs are project-specific rules.
- GlobalPlatform SCP03 1.1.2, **March 2019**: §§4.1.4–4.1.5, 6.2.1–6.2.6, 7.1.1–7.1.2. Used by `crypto.rs`, `scp03.rs`, `transport.rs` and the separate Python client. The Reference Library filenames begin with 2023. That is not the publication year.
  - Session-key and card/host cryptogram fixed vectors were ported from the independently implemented Gp4Net corpus with the author's explicit copyright authorization. They cover sequential-pattern and all-zero inputs. MicroCard does not copy its implementation.
  - A retained GlobalPlatformPro trace against a physical SCP03 card fixes the static keys, challenges, session keys, both cryptograms, EXTERNAL AUTHENTICATE C-MAC and the next command C-MAC chain. The trace was imported from the same authorized Gp4Net corpus.
- NIST FIPS 180-4, August 2015 update: SHA-256 known-answer coverage. [Official publication](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
- NIST SP 800-38A, December 2001: appendices F.1 and F.2 provide AES-128 ECB and CBC known-answer vectors. [Official publication](https://csrc.nist.gov/pubs/sp/800/38/a/final).
- RFC 4493 §4 and RFC 4231 §4.2: independently published AES-CMAC and HMAC-SHA-256 known-answer vectors used by `crypto.rs`. [RFC 4493](https://www.rfc-editor.org/rfc/rfc4493.html), [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html).
- NIST CAVP CCM-VADT AES-128 vectors: the `Alen=0`, `Count=0` case matches MicroCard's 13-byte nonce and 16-byte tag profile. The unchanged official archive is stored under ignored downloads and pinned in `references/downloads.json`. [Official test-vector page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes).
- Nordic nRF52840 Product Specification: UART, RNG, TIMER, WDT, NVMC and ACL register tables. Official [product documentation](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/) and [v1.9 PDF](https://docs-be.nordicsemi.com/bundle/nRF52840_PS_v1.9/raw/resource/enus/nRF52840_PS_v1.9.pdf). Direct PDF download returned HTTP 403. The manifest records a link and no downloaded copy. The official ACL web page was inspected for register behavior.
- Nordic nRF52840 CryptoCell 310 Product Specification: candidate hardware implementations for SHA-256, HMAC, AES-128 CBC/CMAC/CCM, P-256, Ed25519 and RNG. [NRF52840_CRYPTO_INVENTORY.md](NRF52840_CRYPTO_INVENTORY.md) separates advertised capability from library and device acceptance. Nordic recommends its SDK library rather than treating the register descriptions as a supported integration API.
- ITU-T X.690 (02/2021) | ISO/IEC 8825-1:2021: §§8.1.2-8.1.3, 8.3, 8.6 and 11 define the identifier, definite-length, INTEGER, OBJECT IDENTIFIER and DER canonical rules used by `MicroCard.Encoding`. The unchanged official ITU PDF is stored in the Reference Library. Only its path, hash and clause map are committed.
- USB-IF CCID revision 1.1, April 22, 2005: §§3.1.3, 3.2.2, 5.1, 6.1.1-6.1.4, 6.1.13, 6.2.1-6.2.2 and 6.3.1 define the one-slot short-APDU transport framing in `ccid.rs` and [CCID_PROFILE.md](CCID_PROFILE.md). The unchanged official PDF is stored under ignored downloads with its copyright notice retained. Only its local path, hash, edition and clause map are committed.

## Short explanatory excerpts

ECMA-335 III.3.57, explaining the return-stack verifier: “The evaluation stack for the current method shall be empty except for the value to be returned.” © Ecma International 2012. See the unchanged standard's copyright notice.

SCP03 §6.2.3, explaining why EXTERNAL AUTHENTICATE is MAC-checked: “SCP03 mandates the use of a MAC on the EXTERNAL AUTHENTICATE command.” © GlobalPlatform 2009–2019. See the library copy's license terms.

All further descriptions here are original paraphrases. The repository license covers original project code. Standards and third-party dependencies retain their own terms. Dependency licenses and versions are recorded by Cargo.lock and NuGet packages.lock.json. No claim of FIPS validation, ISO certification or full GlobalPlatform compliance is made.
