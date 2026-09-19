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

## Migration status

Only management-name payloads currently use this contract on the wire. Manifest codecs and cross-language vectors are ready; activating them still requires the new signed package envelope and coordinated package-reader/fixture updates. Other management payloads and journal snapshots also remain to migrate. JSON remains permitted for host authoring, reports, and test-vector files.
