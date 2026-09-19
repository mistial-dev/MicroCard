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

The P-256 signature covers every byte from the magic through the signer key, inclusive. SHA-256 of the trailing image must match the signed digest. This keeps the signed descriptor contiguous without copying the image into a separate signing buffer. The total package is bounded to 16 KiB. The signer key must be uncompressed SEC1; signature scalars must have valid ranges and low S. Trailing bytes, inconsistent lengths, provider failures, and old magic are errors. Package identity remains SHA-256 of the entire envelope, including the image.

Envelope authentication does not establish that a manifest or image is supported. The selected engine must then decode and validate both before installation. [The shared MP05 vector](../format/package-envelope-v5.json) deliberately uses a synthetic image to test that boundary; it is not an installable application. Its private scalar is public test data. Independent Python/OpenSSL signing produces exactly the same deterministic envelope as Rust, .NET, and Java.

## Migration status

Only management-name payloads currently use this contract on the wire. Manifest and MP05 envelope codecs have cross-language vectors; activating them still requires coordinated package-reader and signed-fixture updates. Other management payloads and journal snapshots also remain to migrate. JSON remains permitted for host authoring, reports, and test-vector files.
