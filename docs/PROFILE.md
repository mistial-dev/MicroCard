# MicroCard profile v1

The profile supports eight SSDs. Each domain policy permits at most eight active assemblies and eight installed assembly instances, with at most sixteen installed instances card-wide. An SSD's first successful load atomically binds its Ed25519 signer and configured policy. Unload never unbinds. Delete/recreate changes incarnation. Each SSD policy restricts native capabilities and persistent resources. Assemblies in the same SSD share transactional Int32 and bounded byte-record stores. Managed dependencies may resolve earlier assemblies in the same SSD or explicitly exported ISD libraries. Cross-SSD calls and shared references are forbidden. [DOMAIN_POLICY.md](DOMAIN_POLICY.md) and [STORAGE.md](STORAGE.md) define the current limits and behavior.

Managed entry points use attributes, never Main. Trusted framework native imports are lowered from a caller-approved SHA-256-pinned framework binary and fixed ABI and validated against the device service allowlist. Namespace names do not establish trust.

Static constructors are rejected because the runtime does not implement CLR type-initialization semantics. Instance constructors remain direct verified calls on sealed objects.

Execution limits: 256 evaluation slots, 32 call frames, 100000 instruction fuel, 16 KiB transient arena. The exact supported opcode set is generated from the MC04 schema and enforced independently by the preprocessor and Rust verifier.

The scalar profile supports Boolean, signed/unsigned 8-, 16- and 32-bit values on one 32-bit stack representation. It includes signed and unsigned arithmetic/comparisons, checked signed and unsigned add/subtract/multiply, and checked or truncating scalar conversions. Floating point and 64-bit values remain rejected.

MC04 assemblies carry ECMA-derived metadata types, CIL method bodies and signed method-effect flags. Activation, recovery and execution apply the device verifier described in [IMAGE_VERIFICATION.md](IMAGE_VERIFICATION.md). This follows the assignment-compatibility model in ECMA-335, 6th edition, Partition I §8.7 and the verification requirements in Partition III §1.8 for the smaller MicroCard instruction set. The [MC04 assembly format](ASSEMBLY_FORMAT.md) specifies the compact physical encoding.

Package authorization and package signatures are independent. Only an authenticated management session may mutate domain or package state.


The current framework relies on regular SDK core types while preprocessing their supported semantics. A device-focused `mscorlib` remains planned. Host and device heap allocation charge a fixed 16 bytes per primitive slot plus object overhead, so quota decisions agree across 32-bit and 64-bit platforms. Native cryptography has weighted work costs in addition to VM fuel.
