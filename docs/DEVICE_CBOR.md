# Device CBOR contracts

Device records use a restricted subset of [RFC 8949 deterministic CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1): shortest integer and length encodings, definite lengths, and fixed-order arrays. Maps, tags, floats, indefinite-length values, and trailing bytes are rejected. Byte strings carry binary values directly. Each record decoder checks its version, exact field count, collection limits, and semantic constraints before accepting it.

## Management names, version 1

The payload for proprietary lifecycle instructions EC, EE, and F0 is the three-element array `[1, domain, target]`. Both names are text strings of 1 through 64 ASCII bytes matching `[A-Za-z0-9][A-Za-z0-9_.-]*`. The target is an AID in uppercase hexadecimal for install/uninstall and an assembly name for unload. Instruction-specific checks still apply. Maximum encoded length is 134 bytes.

The prior JSON array is rejected. There is no legacy decoder or format autodetection. Rust, Python acceptance clients, and the Java wallet consume [shared golden vectors](../format/management-names-v1.json). The existing .NET package tools do not send these lifecycle instructions.

## Package manifest, version 1

The manifest is a 12-element array in this exact order:

```text
[1, domain, incarnation, assembly, assembly_version, package_version,
 export, entry_points, dependencies, capabilities, storage, limits]
```

`domain` and `assembly` use the identifier grammar above. `incarnation` is a 16-byte string. `assembly_version` is four unsigned 16-bit integers; `package_version` is a nonzero unsigned 32-bit integer. `export` is `[access, key_hash_or_null]`, retaining the existing access-policy values; a present key hash is exactly 32 bytes.

Each entry point is `[aid, process, install, uninstall, select, deselect]`. AID is a raw byte string of 5 through 16 bytes. Method indices are unsigned 16-bit integers; every method except `process` may be null. At most four entry points are permitted, with distinct AIDs.

Each dependency is `[assembly, ranges, package_version, signer_hash_or_null, package_digest_or_null, scope]`. There are at most 16 dependencies, sorted strictly by assembly identifier. Each dependency has 1 through 8 version ranges. A range is `[min_or_null, min_inclusive, max_or_null, max_inclusive]`; present endpoints use four unsigned 16-bit integers, and inclusivity fields are booleans. Existing non-overlap and scope rules apply. Present signer hashes and package digests are exactly 32 bytes.

`capabilities` is a byte string of at most 35 strictly increasing capability identifiers. Capability 21 remains reserved and is rejected by package validation. `storage` contains at most 64 `[key, kind, max_bytes]` records, sorted strictly by nonnegative signed-32-bit key. Existing storage-kind and blob-size rules apply. `limits` is `[arena, stack, frames, instructions]` with widths uint32, uint16, uint8, and uint32; the runtime profile still fixes their supported values.

The manifest cannot exceed 16 KiB, and the package's total size bound remains separate. The Rust decoder rejects wrong field counts, unknown versions, duplicates, overflow, malformed binary lengths, noncanonical encodings, and trailing data before image-specific validation. The Rust, Python, .NET, and Java encoders share [manifest golden vectors](../format/manifest-cbor-v1.json). The two vectors encode to 58 and 233 bytes, versus 297 and 1,030 bytes as compact host JSON. These are format measurements, not firmware or latency measurements.

## MP05 signed envelope

The new envelope layout is:

```text
"MP05" | "MicroCard signed package v5\0" |
manifest_length:u32le | image_length:u32le |
manifest_cbor | image_sha256:32 | signer_sec1:65 | signature_p1363:64 | image
```

The P-256 signature covers every byte from the magic through the signer key, inclusive. SHA-256 of the trailing image must match the signed digest. This keeps the signed descriptor contiguous without copying the image into a separate signing buffer. MC04 packages are bounded to 16 KiB; JCVM packages to 60 KiB. The signer key must be uncompressed SEC1; signature scalars must have valid ranges and low S. Trailing bytes, inconsistent lengths, provider failures, and old magic are errors. Package identity remains SHA-256 of the entire envelope, including the image.

Envelope authentication does not establish that a manifest or image is supported. The selected engine must then decode and validate both before installation. [The shared MP05 vector](../format/package-envelope-v5.json) deliberately uses a synthetic image to test that boundary; it is not an installable application. Its private scalar is public test data. Independent Python/OpenSSL signing produces exactly the same deterministic envelope as Rust, .NET, and Java.

## JCVM manifest, version 1

The signed JCVM manifest is an eight-field array, distinct from the twelve-field MC04 record:

```
[1, 1, domain_aid:bytes, incarnation:bytes16, package_aid:bytes,
 [package_major:u8, package_minor:u8], rollback_version:u32,
 [heap_bytes, frame_words, buffer_bytes, instruction_budget]]
```

Both AIDs are 5–16 bytes. The second field identifies JCVM. The manifest is at most
128 bytes, rollback version is nonzero, and package AID/version must equal the CAP
Header. Heap size is even and 512–65,536 bytes; frame storage is 8–8,192 words; the
APDU buffer is 261 bytes; execution work budget is 1–4,000,000 (bytecode instructions plus charged native work). These are upper profile
bounds, not a promise that every permitted combination fits a board.

The verifier authenticates MP05, validates this record, resolves imports, and runs
structural bytecode verification. The management layer must additionally authorize
the signer, match the current domain/incarnation, enforce rollback and storage quotas,
and activate atomically. The [JCVM manifest vector](../format/jcvm-manifest-cbor-v1.json)
is checked by Rust, Python, .NET, and Java. The shared GlobalPlatform loading path
uses this contract for both managed simulator sessions and the separate JCVM board
profile. Physical execution remains unverified; see [release readiness](READINESS.md).

## Internal state snapshot, version 2

The authenticated MJ03 journal plaintext is `[2, 0, scp03_sequence, isd, domains]`.
The second field identifies MC04; other engines and versions are rejected. The sequence
is uint32. `domains` contains at most eight `[name, domain]` records in strictly
increasing identifier order, excluding the reserved `ISD` name. The entire snapshot
is bounded to 48 KiB. The journal authentication, monotonic generation, commit marker,
and interrupted-write recovery rules remain unchanged.

A domain has exactly 14 fields:

```text
[incarnation, registry_aid, signer_hash_or_null, policy, assemblies,
 bindings, imports, versions, storage_schema, instances, integers, blobs,
 keys, credentials]
```

Incarnation is 16 bytes, registry AID is 5 through 16 bytes, and a present signer hash
is 32 bytes. Policy is `[capabilities, max_assemblies, max_instances, max_int_records,
max_blob_records, max_blob_bytes, max_key_slots, max_package_bytes]`. Capabilities are
at most 44 strictly increasing supported identifiers; the existing policy quotas apply.

Assemblies, bindings, imports, and versions are arrays of at most eight `[name, value]`
records in strictly increasing name order. Assembly values are
`[slot_uint8, length_uint32, package_sha256_bytes32]` descriptors. Slots are below 64
and within the physical store. Package lengths are nonzero, bounded to 16 KiB each
and 24 KiB in total. Recovery hashes the separate image bytes, then verifies each MP05
package and its bindings. Bindings contain at most 16
32-byte package digests. Imports contain `[member_uint16, target]` records, bounded
by the MC04 member-reference limit. Targets are `[0]` for Object constructor, `[1]`
for current domain, `[2]` for storage, `[3]` for keys, `[4, native_id]`, or
`[5, dependency_index, method_index]`. Version values are `[uint32, digest_bytes32]`.
Recovery verifies these cached bindings and versions against authenticated packages.

Storage declarations retain the manifest's `[key, kind, max_bytes]` shape, sorted by
key and bounded by the domain declaration limit. Instances contain at most eight
`[aid_bytes, assembly_name]` records sorted by AID. Integer records are at most 512
`[int32_key, int32_value]` pairs. Blob records are at most 64 `[int32_key, bytes]`
pairs with at most 2,048 bytes each and the domain's total blob quota. Both record
lists are sorted strictly by key.

Keys contain at most eight `[slot, algorithm, nonce_bytes16, key_bytes32]` records,
sorted by slot in 0 through 7. Algorithm identifiers are 1 for HMAC-SHA-256, 2 for
AES-128, and 3 for P-256. AES padding, scalar validity, and nonce uniqueness are checked.
Credentials contain at most eight `[slot, owner_bytes16, pin_salt_bytes16,
pin_digest_bytes32, puk_salt_bytes16, puk_digest_bytes32, pin_retries, pin_max_retries,
puk_retries, puk_max_retries]` records, sorted by nonnegative int32 slot. Owner and
retry constraints are checked against the containing domain. Decoder failures and
encoder reallocations clear owned secret buffers before releasing them.

The [internal golden vector](../format/snapshot-cbor-v2.json) is shared by Rust and
the Python acceptance oracle. Java and .NET clients do not read journal plaintext.
Old JSON and version-1 inline-package snapshots return `IncompatibleState`, without
an erase, migration, or retry of an older authenticated generation. Only a committed
metadata descriptor activates an image. Current and pending descriptors protect slots
from erasure; unreferenced partial uploads can be reclaimed after reboot. An uncertain
metadata commit keeps its candidate slots protected until ownership is resolved.

## JCVM registry journal

The metadata store uses its own journal key and this seven-field v2 record:

```
[2, 1, reserved_scp03_sequence, domains[4], loads[8], instances[8], renewal_or_null]
domain   = [aid, incarnation_bytes16, signer_hash_bytes32_or_null]
load     = [domain_aid, package_aid, rollback_version, image_or_null]
image    = [slot, length, package_sha256_bytes32]
instance = [domain_aid, package_aid, module_aid, instance_aid,
            installation_bytes16, heap_bank]
renewal  = [instance_aid, heap_bank, old_identity_bytes16, new_identity_bytes16,
            package_sha256_bytes32, record_length, record_sha256_bytes32]
```

Unused slots are null. Slot zero in `domains` is the ISD. AIDs are 5–16 bytes;
registry AIDs, active image slots, installation identities, and heap banks cannot
collide. Every load belongs to an owned domain, and every instance references a
loaded package in that domain. The record is bounded to 4,096 bytes. The SCP03
reservation is at most `0xffffff` and must commit before any reserved value is used.

Deleting a load clears its image descriptor but retains its rollback version. A new
activation must advance that version. Child domains inherit the ISD signer; fresh
domain and installation identities come from the platform, not the package author.
Physical storage may impose lower quotas than these registry limits.

A pending renewal names an existing instance and its current bank, identity, and
package digest. The new identity must differ from every live installation identity.
The encrypted record length is 41–65,533 bytes, bounded by a 64 KiB slot minus its
three trailer bytes; recovery must also authenticate its contents and enforce the
actual snapshot quota before bank preparation. The staged record digest binds exact
ciphertext. Unknown versions, trailing data, malformed fields, and inconsistent
bindings are rejected. Registry v1 has no migration path.

While renewal is pending, ordinary registry operations return `Busy`. Card startup
resolves renewal before opening applets or resetting upload state. Recovery authenticates
the staged record and its applet binding before bank preparation, copies it without
re-encryption, and publishes the new identity only after normal journal recovery
succeeds. Missing or changed recovery data fails closed. The registry writer stages
live state and publishes ownership. Command-boundary maintenance invokes recovery
and hands the renewed journal to the existing live applet. See [the renewal transition](STORAGE.md#jcvm-counter-renewal).

Installation identities are a durably reserved registry nonce counter value (eight
little-endian bytes) followed by `JCVMv1\0\0`. Failed installations consume their
reservation. The registry counter must never reset during service. Installation
commits a fresh, unreferenced heap before publishing its metadata; cancellation or
failure leaves an orphan that a later installation may explicitly reclaim.

The store resolves uncertain commits with the reboot scan and disables state access
if recovery fails. Its caller must verify referenced image and heap storage before
execution, and must not reclaim formerly referenced storage before metadata commits.
The [registry vector](../format/jcvm-registry-cbor-v2.json) is checked by Rust and Python.

### JCVM domain discovery

Authenticated INS `E2`, P1/P2 zero, and one domain-index byte return:

```
[2, 1, domain_count, domain_index, domain_aid, incarnation_bytes16,
 signer_hash_bytes32_or_null, active_load_count, instance_count]
```

Version 2 and engine 1 distinguish this from MC04's earlier discovery record. Domains
use registry slot order, with the ISD at index zero; indexes outside the current count
fail. Counts have the registry bounds above and the response is at most 128 bytes.
Use the returned AID and incarnation when signing a package for that domain.
The [discovery vector](../format/jcvm-domain-cbor-v2.json) is checked by Rust and Python.

## Dedicated JCVM state journal

The JCVM store uses a separate journal region and key, with plaintext:

```
[1, 1, image_sha256_bytes32, installation_bytes16, root_uint16, heap_bytes, static_bytes]
```

The first two fields are the schema version and engine identifier. The image digest
covers the exact verified load-file bytes; the installation identity changes on
reinstallation. Neither mismatch permits automatic reset. The load file is not
included in this snapshot. Heap length is bounded by the configured applet heap,
static length must match the load file, and the complete record must fit the journal
payload capacity. Engine recovery validates object and reference structure and
requires volatile values to be cleared. Unknown versions and trailing bytes fail.

Transient symmetric key material is a byte array with its declared clear event and
an internal one-byte initialization prefix. The key object's persistent readiness
word remains zero. Persistent key arrays have no prefix and retain their readiness
word. Recovery rejects mismatched clear events and the previous transient-key layout;
it never reinterprets persisted key bytes as live transient data.

Each heap key is the first 16 bytes of HMAC-SHA256 under the root heap key over
`MicroCard JCVM heap key v1\0 || bank:u8 || installation_bytes16 || image_sha256_bytes32`.
Only an unreferenced bank may be erased, including its local counters, and it must
receive a fresh installation identity and derived key before reuse.

`jcvm_storage::Session` rolls back live mutations through authenticated recovery on
failure. The registry coordinator verifies code, commits installation before metadata,
and reopens only the committed heap. Missing or incompatible committed state fails
without reinstalling. The core transport adapter connects this coordinator to
authenticated GlobalPlatform management. Board partitioning remains incomplete.

## Migration status

MP05 packages, management names, and journal snapshots use these binary contracts.
The loader rejects MP04 and earlier envelopes. Rebuild packages and use matching
clients. Old persistent state fails explicitly and must be handled by an intentional
development reset. JSON remains permitted for host authoring, reports, and test vectors.
