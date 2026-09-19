# Device CBOR contracts

Device records use a restricted subset of [RFC 8949 deterministic CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1): shortest integer and length encodings, definite lengths, and fixed-order arrays. Maps, tags, floats, indefinite-length values, and trailing bytes are rejected. Byte strings carry binary values directly. Each record decoder checks its version, exact field count, collection limits, and semantic constraints before accepting it.

## Management names, version 1

The payload for proprietary lifecycle instructions EC, EE, and F0 is the three-element array `[1, domain, target]`. Both names are text strings of 1 through 64 ASCII bytes matching `[A-Za-z0-9][A-Za-z0-9_.-]*`. The target is an AID in uppercase hexadecimal for install/uninstall and an assembly name for unload. Instruction-specific checks still apply. Maximum encoded length is 134 bytes.

The prior JSON array is rejected. There is no legacy decoder or format autodetection. Rust, Python acceptance clients, and the Java wallet consume [shared golden vectors](../format/management-names-v1.json). The existing .NET package tools do not send these lifecycle instructions.

## Migration status

Only management-name payloads currently use this contract. Package manifests, other management payloads, and journal snapshots still require their coordinated binary migration. JSON remains permitted for host authoring, reports, and test-vector files.
