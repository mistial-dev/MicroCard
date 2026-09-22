# Managed profile enforcement

Rider diagnostics provide early feedback. The preprocessor and signed-image verifier enforce the corresponding lowered invariant without trusting analyzer output. Source-only warnings, such as allocation inside a loop, become authoritative runtime arena, object, instruction, and call-frame bounds because source structure is intentionally absent from MC04.

| Diagnostic | Rider meaning | Independent host enforcement | Device or runtime enforcement |
| --- | --- | --- | --- |
| MCA0001 | Unsupported language construct | Rejects emitted exception regions, state-machine shapes, modified signatures, and unsupported CIL operands | Rejects unsupported metadata, signatures, and CIL operands |
| MCA0002 | Unsupported managed type | Signature rewriting accepts only profile primitives, arrays, sealed local classes, and declared dependencies | Borrowed signature verifier accepts the same reduced type grammar |
| MCA0003 | Unsupported declaration shape | Rejects flags, inheritance, interfaces, nesting, static fields, non-Int32 fields, and unsupported constructors | Validates type, field, method, base-type, and table shapes before activation |
| MCA0004 | Call outside the trusted ABI | Resolves only pinned framework imports, same-assembly calls, or declared dependency MemberRefs | Import verifier accepts only signed capabilities and verified dependency links |
| MCA0005 | Invalid lifecycle declaration | Emits at most four validated lifecycle records with exact static signatures | Revalidates lifecycle MethodDef rows and entry bounds from the signed image |
| MCA0006 | Invalid dependency export | Canonical manifest construction validates policy encoding and optional public key | Package validation and linker enforce export policy against the caller signer |
| MCA0007 | Invalid dependency requirement | Normalizes bounded versions, identities, signer/digest pins, aliases, and scopes | Package parser and linker independently validate and resolve every signed requirement |
| MCA0008 | Transaction reaches irreversible output | Whole local call graph is checked after lowering, including constructors and explicit controls | Linked graph propagates effects across assemblies and rejects unsafe paths |
| MCA0009 | Recursive or over-depth call graph | Direct local calls are bounded before MC04 output | Linked graph rejects cycles and paths beyond 32 frames before activation and recovery |
| MCA0010 | More than 64 locals | Method-body emission rejects oversized local signatures | Signature verifier and VM frame creation enforce the same bound |
| MCA0011 | One static allocation exceeds 16 KiB | Emitted allocation lengths remain explicit checked CIL | Runtime charges every array and object before allocation against 16 KiB |
| MCA0012 | Allocation occurs in a loop | Emitted loop remains bounded by valid branch targets and instruction syntax | Runtime instruction, arena, and 256-object limits are authoritative |
| MCA0013 | One method's static allocations exceed 16 KiB | Each emitted allocation remains checked and explicit | Runtime aggregate arena charging is authoritative for every control-flow path |
| MCA0014 | Static call path allocations exceed 16 KiB | Direct-call targets and allocation instructions are preserved for verification | One invocation arena covers the complete linked call tree |
| MCA0015 | Switch exceeds 256 targets | Compact CIL writer rejects an oversized switch table | CIL parser validates count, operand extent, and every target boundary |
| MCA0016 | Static call path exceeds 256 objects | Object constructions remain explicit `newobj` instructions | Runtime object table rejects the 257th object before arena mutation |
| MCA0017 | More than 32 parameters | Signature rewriting rejects the 33rd parameter | Borrowed signature parser enforces 32 parameters before activation |
| MCA0018 | More than 16 dependencies | Manifest construction rejects the 17th dependency | Signed package validation rejects it before binding or activation |
| MCA0019 | More than four lifecycle entries | Manifest construction rejects the fifth entry | Signed package validation rejects it before binding or activation |
| MCA0020 | More than 256 MethodDef rows | MC04 table construction rejects the excess row | Generated schema ceiling is enforced while parsing the signed table directory |
| MCA0021 | More than 253 TypeDef rows | MC04 table construction rejects the excess row | Generated schema ceiling is enforced while parsing the signed table directory |
| MCA0022 | More than 1,022 retained Field rows | Constants removed into CIL are excluded. Remaining rows are bounded | Generated schema ceiling and field-shape verifier enforce the signed table |
| MCA0024 | Invalid persistent storage declaration | Manifest construction rejects negative or duplicate keys, invalid kinds, byte bounds outside 1 through 2,048, and more than 64 declarations | Signed package validation independently requires the same bounds and strict key ordering before activation |
| MCA0025 | Persistent storage access cannot be proved against the signed schema | Requires a non-negative constant key and a matching assembly declaration at each framework storage call | Runtime checks the executing assembly, domain incarnation, pinned domain declaration, value kind, and byte bound on every native storage call |

`scripts/profile_enforcement_audit.py` requires every active diagnostic in the analyzer, negative-build acceptance list, and this matrix. It also fixes the host and device enforcement anchors so a renamed or removed boundary fails the fast host gate. The writer retains its independent custom-attribute table ceiling; valid source cannot reach it after removing implicit transaction attributes and enforcing the lifecycle-entry limits.
