# On-device assembly verification

MicroCard treats the preprocessor as untrusted input. A valid P-256 ECDSA signature proves who signed an assembly. It does not prove that its bytecode is safe. The Rust runtime independently verifies the complete signed assembly before adding it to a domain.

## Verification boundary

`PackageView::verify` performs P-256 ECDSA verification, canonical manifest checks, manifest-to-Assembly identity comparison and MC04 static verification. MC04 validation covers metadata tables, coded indices, signatures, CIL operands and control flow, exact stack types, lifecycle MethodDefs and the fixed framework ABI. Activation resolves and persists exact external targets, builds the complete local and cross-assembly call graph, and rejects cycles or paths over 32 frames before changing durable state. `Card::open` repeats package, assembly, dependency, link and complete frame-depth verification for every persisted MC04 assembly. VM entry consumes borrowed verified assembly slices and only those persisted links.

The rules are based on ECMA-335, 6th edition, Partition I §8.7 (assignment compatibility) and Partition III §1.8 (correctness and verifiability), narrowed to MicroCard's instruction set. This document defines the MicroCard profile rather than claiming full CLI verification.

## Proven properties

- Every instruction and operand is fully contained in the image.
- Branches target instruction starts and all reachable stack joins have compatible types and equal depth.
- Argument and local indexes are bounded. Stores, returns and direct calls match their signed types.
- Integer, null, array and sealed-object values cannot substitute for one another except null where a reference is expected.
- Array loads/stores match the array kind and scalar element type.
- Field access carries and checks the declaring sealed-object type in both the verifier and VM.
- Every sealed-object tag has one signed field count. Constructors must allocate exactly that layout, and every field index must be within it.
- Native calls match a device-owned signature table. Package metadata can restrict capabilities but cannot redefine a native signature.
- Constructors consume their declared arguments and create only their declared sealed-object type.
- Stack, method, argument, local and code-size quotas are checked during verification.

Runtime reference-kind and bounds checks remain active after verification. Verification failure returns an error before durable state changes. Loader tests compare both live state and reopened journal state.

## Format transition

Release package verification accepts MC04 only. Earlier experimental formats are rejected before activation, with no conversion, migration, or mixed-format execution mode. Historical parser code remains behind `cfg(test)` solely for isolated verifier fixtures and cannot enter a release package.
