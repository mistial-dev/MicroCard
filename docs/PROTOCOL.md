# MicroCard wire and persistence profile

This is a MicroCard profile inspired by smart-card lifecycle conventions. It does not claim GlobalPlatform card conformance. GP SCP03 v1.1.2.6, §§4.1.5, 6.2.1–6.2.7 define secure messaging, including S16 mode and the derived card challenge. Command identifiers below are project-specific management commands.

## Secure channel

Only the basic logical channel is supported. `80 50 00 00 <length> <host challenge> 00` initializes SCP03. The challenge is 16 bytes in S16 mode and 8 bytes otherwise, and a host offering the other width is answered 6700 so it can retry at the width the card wants. Key version 0 or 1 is accepted. The card returns ten zero diversification bytes, key version 1, SCP identifier 03, the implementation option this build advertises, a card challenge, a card cryptogram of the same width, and in derived-challenge mode a three-byte sequence counter. `84 82 <level> 00 <length> <host cryptogram><C-MAC>` authenticates. Levels 01, 03, 11, 13 and 33 are implemented, covering every combination that carries a command MAC. Management requires a command MAC and accepts any of them. A level requesting protection this build does not implement is refused with 6982.

S16 mode transmits the whole 16-byte AES-CMAC. S8 mode transmits its first eight bytes. Either way the full 16-byte command MAC chains subsequent commands and response MACs. C-ENC uses an incrementing counter starting at one after authentication. MAC verification precedes decryption. Authentication/MAC/padding failures discard the session. Error responses contain only their status, per SCP03 §6.2.5. R-ENCRYPTION follows §6.2.7: a response with a data field is encrypted under S-ENC in CBC, using the counter block of the command being answered with its most significant byte set to 80, and the R-MAC then covers the ciphertext. A response with no data field is never encrypted. No BEGIN/END R-MAC SESSION or key-diversification scheme is implemented.

Where the card challenge is derived, §6.2.2.1 applies. A three-byte sequence counter seeds AES-CMAC over the static ENC key with derivation constant 02 and a context of the counter followed by the ISD AID. The counter advances on every INITIALIZE UPDATE and is refused at saturation with 6985. Blocks of 64 values are made durable before any of them is issued, so a power cut skips the unused remainder and no value can seed two challenges.

## Authenticated commands

Standard GlobalPlatform discovery, registry and SSD lifecycle commands are specified separately in [GLOBALPLATFORM_PROFILE.md](GLOBALPLATFORM_PROFILE.md). They enter the same level-13 authorization and transactional domain-management paths as the project-specific commands below.

All have P1=P2=0, except EXTERNAL AUTHENTICATE. Management responses use 9000 on success, 6985 for rejected state/format/quota changes. Authentication and invocation faults currently use 6982 and terminate the session. This coarse status mapping is provisional.

| INS | Data and effect |
| --- | --- |
| E0 / E4 | UTF-8 SSD identifier. Create / delete. Create returns a fresh 16-byte incarnation and is refused until ISD ownership. `ISD` cannot be created or deleted. |
| E1 / E3 | Set an unbound SSD policy / read its policy. E1 uses the bounded binary policy request below. E3 data is the UTF-8 SSD identifier. |
| E2 | One-byte record index. Index zero is always ISD. Later records are SSDs ordered by identifier. |
| E6 / E8 / EA | Begin upload / append LE-u32 offset plus chunk / activate. E6 and EA have no data. |
| EC / EE / F0 | JSON `["domain","AID"]` installs/uninstalls, or `["domain","assembly"]` unloads. |
| A4 / 10 | Select binary AID / process plaintext assembly data. Both use the authenticated channel in this checkpoint. |

Use chunks of at most 200 bytes before the offset. SCP03 encryption/MAC overhead must fit a short APDU. Staging is bounded RAM and discarded on reboot. Identical append retries are accepted. No staged byte is executable before the complete signed package passes validation and activation commits.

### ISD ownership

A factory-empty journal contains one unbound ISD with a random incarnation. Its first activated package must target `ISD`, name the assembly exactly `mscorlib`, and declare no lifecycle entry points or dependencies. Successful activation atomically records the assembly and permanently pins its signer identity as the ISD ownership identity. Every later ISD assembly must use that exact signer. SSD creation is refused before this commit. ISD deletion and `mscorlib` unload are always refused. This profile has no reset, unbind, conversion, or upgrade path.

E2 returns one bounded public record: version, total record count (ISD plus at most eight SSDs), index, identifier, incarnation, binding flag, signing key or zeros, assembly count, installed-instance count, and application-record count. ISD is record zero.

### SSD policy wire format

E1 data is: version `01`, identifier length u8, UTF-8 identifier, capability bitmap u64 little-endian, maximum assemblies u8, maximum installed instances u8, maximum Int32 records u16, maximum byte records u8, maximum aggregate byte-record bytes u16, maximum framework key slots u8, and maximum active package bytes u16. E3 returns the same fields without identifier length and identifier. Reserved or unknown capability bits make the request invalid.

Only an empty, unbound SSD accepts E1. A later E1 may replace its policy until first successful load. After signer binding it returns a state error. Activation rejects packages whose native capabilities or package storage exceed policy. Installation, recovery, Int32/byte storage, and framework-key creation enforce their corresponding limits. See [domain policy](DOMAIN_POLICY.md).

## Signed package MP04

Little-endian header: magic `MP04`, fixed ASCII context `MicroCard signed package v4` followed by a zero byte, manifest length u32, assembly length u32. Then canonical UTF-8 manifest JSON, complete embedded assembly, 65-byte uncompressed SEC1 P-256 public key, and 64-byte P1363 ECDSA signature over SHA-256. The signed message is the single contiguous package slice from the magic through the public key. Keeping the context inside that slice provides protocol separation without constructing a second package-sized verification buffer. Earlier package magics and contexts are rejected. Here is no conversion or upgrade path.

Two shapes are refused before the signature is checked at all, so that a software and a hardware provider answer identically. A compressed SEC1 key is refused, because the card's hardware path accepts only the uncompressed form. A signature whose `s` is above half the group order is refused, because ECDSA admits two signatures for every message and accepting both would give one signed package two encodings, two digests and therefore two registry identities. Every packager produces the low form.

What a domain binds to is the SHA-256 digest of that 65-byte key rather than the key itself, which keeps every stored identity 32 bytes wide.

Manifest field order is fixed: `domain`, `incarnation` (16 JSON byte numbers), `assembly`, `assembly_version` (four u16 values), `version`, `export`, `entry_points`, `dependencies`, `capabilities`, `limits`. Export field order is `access`, `key`. Access is private (0), any signer (1), same signer (2), or the exact 32-byte caller key (3). Entry-point field order is `aid`, `process`, `install`, `uninstall`, `select`, `deselect`. Missing optional hooks are null. Dependency field order is `assembly`, `ranges`, `package_version`, `signer`, `digest`, `scope`. Version ranges carry bounded four-part minimum/maximum tuples and inclusivity flags. Limits order is `arena`, `stack`, `frames`, `instructions`. No whitespace or unknown fields. Dependencies and capabilities are strictly increasing and unique. Device verification reserializes to enforce the canonical representation.

Prior manifest schemas are rejected. There is no compatibility alias, decoder, conversion or upgrade route.

Maximum package 16 KiB, aggregate active package bytes 24 KiB, persistent serialized snapshot 48 KiB. These conservative checkpoint quotas are smaller than the transport field widths. Versions are positive u32 values. Same-version identical packages are retries. Any changed content at that version is rejected. Deleting an SSD is the only operation that removes its signing binding and version history.

## Embedded assemblies

[MC04](ASSEMBLY_FORMAT.md) is the active C# build and simulator-acceptance format. It retains compact ECMA-335 tables, tokens, signatures, heaps and CIL method bodies. Signed MC04 libraries and assemblies pass structural, signature, opcode, branch, exact-type, lifecycle and import verification before activation. Activation persists every external call as a fixed framework/native target or an exact provider package digest and MethodDef. Recovery recomputes those links, and the borrowed CIL interpreter executes only persisted targets. Counter, storage, key-service and cross-assembly Kdf108 scenarios run through MC04 on both simulator transports.

The public preprocessor, MSBuild integration, ISD bootstrap, signed loader acceptance, fuzz targets and DK smoke input use `.mca`. Release package verification refuses every other assembly magic, even when the envelope has a valid signature.

The device verifies all signed type metadata and method flags, instruction boundaries, branch targets, stack types at every control-flow join, local/argument access, direct-call signatures, constructor receivers, array operations, object layouts, field-owner/index bounds and exact native-service signatures before activation. A transactional method's complete local call graph is rejected if it reaches irreversible hardware output. The same verifier runs during persistent-state recovery and immediately before VM execution. Every pre-MC04 format is refused. No compatibility decoder exists.

The authoritative opcode table is generated from `spec/mc04-opcodes.json`. Debug method maps are separate `.map.json` files. The preprocessor resolves direct calls in the input assembly and rejects external calls outside the pinned framework ABI and declared verified dependencies.

Older experimental assembly formats are unsupported. Their parsers, executors, simulator commands, and fuzz entry points have been removed. Signed rejection tests retain representative old-format byte strings.

## Durable activation

The portable journal rotates through a fixed backend-reported count of two to eight slots. The nRF52840 profile uses three. An MJ02 record contains `MJ02`, a little-endian u64 generation, a little-endian u32 ciphertext-plus-tag length, and AES-CCM ciphertext with a 16-byte tag. The 16-byte header is authenticated as associated data. The 13-byte nonce is `MCJNL || generation_le64`. The storage key is `AES-CMAC(SCP03-ENC, "MicroCard journal AEAD v1\\0" || SCP03-MAC)`, keeping it separate from direct protocol key use and binding it to both provisioned management keys. Fresh management keys are mandatory whenever persistent state is provisioned from empty storage so a generation/nonce pair is never reused under the same key.

The final byte of the slot is the commit marker, programmed last. Before reusing the inactive slot, two bytes outside the record mark reclaim-started and reclaim-completed on the surviving slot. Recovery may ignore a corrupt peer only inside that explicit interval. After replacement completes, corruption remains fail-closed. Recovery chooses the highest valid authenticated generation, then re-verifies stored package signatures, domain targets, key binding, version digests and canonical unique registry AIDs. State is published in RAM only after all journal markers commit. MJ01 journal state and snapshots lacking registry AIDs are refused. There is no upgrade route.

AES-CCM detects unauthorized header, ciphertext and tag changes and hides application records and framework private keys in the journal. A separate append-only flash generation anchor rejects replay of an older valid slot image during normal boot. No secure element or tamper-proof storage is claimed. The anchor still depends on verified firmware and production debug lockout. Deletion is logical revocation. Old encrypted bytes can remain until reclamation.

## Authenticated domain inventory (INS E2)

Requires an authenticated SCP03 session carrying a command MAC, P1=P2=0, and exactly one data byte: zero-based record index. Domain IDs are sorted lexicographically. The response is at most 121 bytes: version=1, total domain-record count including the ISD, index, UTF-8 ID byte length, ID bytes, incarnation (16 bytes), bound flag (0/1), signing public key (32 bytes, zeros if unbound), assembly count (u8), installed-instance count (u8), application record count (u16 little-endian). The current bound is nine records: the ISD plus eight SSDs. No private key, management credential or application value is returned.

Inventory is read-only. Complete enumeration should not be interleaved with management mutations. It is not a multi-command snapshot. `scripts/domain_inventory.py` reads it over authenticated UART without deletion. Its optional `--empty-prefix` filter reports diagnostic candidates but never authorizes or performs deletion. This command is not yet available on the original first-flash firmware.
