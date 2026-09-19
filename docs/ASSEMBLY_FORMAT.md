# MicroCard embedded assembly format

## Status and design rule

The only format accepted by package verification, activation, recovery, and execution is **MC04**. Older experimental parsers and executors have been deleted. No compatibility decoder, converter, migration, or mixed-format runtime exists.

MC04 is a compact physical representation of the ECMA-335 Common Language Infrastructure metadata and CIL model. A reader familiar with ECMA-335 and this document should recognize an Assembly, TypeDef, Field, MethodDef, signatures, metadata tokens, custom attributes, imports, and CIL method bodies without access to the C# source.

The logical model follows ECMA-335, 6th edition:

- Partition I §8.5 and §9: assemblies, members, signatures, and metadata tokens.
- Partition II §22: the logical metadata tables, including Assembly (§22.2), AssemblyRef (§22.5), CustomAttribute (§22.10), Field (§22.15), MemberRef (§22.25), MethodDef (§22.26), TypeDef (§22.37), and TypeRef (§22.38).
- Partition II §23: blob signatures and element types.
- Partition II §24.2: metadata streams, table masks, row counts, table indices, and coded indices.
- Partition II §25.4.6: method bodies.
- Partition III: CIL instruction encodings and stack behavior.

MicroCard changes the physical representation and narrows the legal rows, signatures, and instructions. It does not redefine their managed meaning.

## Removed desktop container data

MC04 omits PE/COFF headers and sections, the PE optional header, CLR data directory, CLI header, native entry-point stub, relocation/import tables, strong-name slot, resources, debug directory, and file/section alignment. Those structures launch and map a desktop CLI image. The MicroCard loader already receives a bounded signed assembly as bytes.

The metadata version string, stream names, GUID heap, user-string heap, padding, unused table masks, and reflection-only rows are also omitted. Debug names and source mappings remain in a separate unsigned `.map.json` file and never participate in execution.

## File header and sections

All integers are little-endian. Offsets are from byte zero of the assembly. Sections need no alignment and must be sorted, contiguous, non-overlapping, and wholly within `file_size`.

```text
MC04 header
  magic              byte[4] = "MC04"
  format_major       u8      = 4
  format_minor       u8      = 0
  flags              u16     = 0 in v1
  section_count      u8      = 4
  token_row_bytes    u8      = 2
  header_size        u16
  file_size          u32

section directory, section_count entries
  kind               u8
  flags              u8      = 0 in v1
  offset             u32
  length             u32
```

Exactly one of each section is required:

| Kind | ECMA-335 analogue | Contents |
| --- | --- | --- |
| 1 Tables | `#~` stream, II §24.2 | table mask, row counts, then rows in table-number order |
| 2 Strings | `#Strings`, II §24.2.3 | UTF-8 bytes referenced by bounded offsets |
| 3 Blob | `#Blob`, II §24.2.4 | signatures and custom-attribute values referenced by bounded offset/length pairs |
| 4 Code | method bodies, II §25.4.6 | CIL-derived bodies referenced by MethodDef RVA-as-offset fields |

The parser validates the directory once and stores offsets into the signed assembly bytes. Tables, heaps, signatures, and method bodies are borrowed slices. Loading must not build a second copy of the assembly.

## Tables and tokens

The Tables section starts with:

```text
schema_major        u8 = 2
schema_minor        u8 = 0
heap_sizes          u8 bit 0: string offsets are u16. Bit 1: blob offsets are u16
reserved            u8 = 0
valid_tables        u64
row_count           u16 for each set valid_tables bit, low table number first
rows                table data, table-number order
```

ECMA table numbers are preserved. A metadata token is encoded as `table:u8, row:u16`. Row zero is nil. This is the ECMA token split into its table and row components with the unused high row byte removed. Coded indices retain ECMA-335 II §24.2.6 tag assignments and use the smallest of u8 or u16 that can address every permitted target row.

MC04 initially retains Module `0x00`, TypeRef `0x01`, TypeDef `0x02`, Field `0x04`, MethodDef `0x06`, MemberRef `0x0A`, CustomAttribute `0x0C`, Assembly `0x20`, and AssemblyRef `0x23`. Rows use the same column order and logical values as ECMA-335 II §22, with these physical reductions:

- table and heap indices use their declared compact width.
- flags retain only profile-permitted bits and reject every reserved or unsupported bit.
- the single Module row omits generation, MVID, EncId, and EncBaseId.
- the single Assembly row omits hash algorithm, public key blob, culture, and processor/OS rows. The signed package carries the signing identity.
- AssemblyRef retains `PublicKeyOrToken`, `Culture`, and `HashValue`. Framework imports require the stable compiled-in Framework 1.0 ABI identity, while `System.Runtime` imports require its exact public-key token. The host tool separately checks the framework DLL file digest before emitting that ABI identity. Equivalent framework rebuilds therefore leave corpus fixtures unchanged. Other managed dependencies require empty identity extras and use signed package bindings.
- MethodDef's RVA is a Code-section offset and ParamList is absent until parameter metadata is supported.
- names are required only for externally linkable definitions. Private names may use string offset zero.
- CustomAttribute rows retain only MicroCard framework attributes that affect runtime behavior. Rows are canonicalized by parent, constructor, then encoded value. Dependency, export and device-identity annotations are translated into the signed manifest, Assembly row and verified AssemblyRef names, then removed from runtime metadata. The preprocessor rejects unrecognized security-relevant attributes and discards attributes proven irrelevant to execution.

The package manifest repeats the assembly name and four-part version. The loader must compare them with the Assembly row before activation. A mismatch is a format error.

`DeviceAssemblyIdentityAttribute` permits a desktop-safe build name when a device identity conflicts with a framework assembly name. `DependencyAttribute.ReferenceAssembly` names the exact desktop AssemblyRef to rewrite to the dependency's signed device identity. The host requires unique aliases and an actual matching reference. The device then performs its ordinary exact AssemblyRef, manifest, version, signer and digest checks. The alias itself is host-only and is absent from the signed dependency object and MC04 metadata.

## Signatures and types

MethodDef, Field, MemberRef, and local-variable blobs use the ECMA-335 Partition II §23 signature grammar with a bounded subset. MC04 accepts `VOID` for method returns, plus `BOOLEAN`, `I1`, `U1`, `I2`, `U2`, `I4`, `U4`, `STRING`, `OBJECT`, `CLASS`, `VALUETYPE`, and single-dimensional zero-based `SZARRAY`. `CLASS` and `VALUETYPE` carry compact TypeDefOrRef coded indices. Methods use only the default or instance calling convention. Parameter counts are limited to 32, local counts to 64, and nested type signatures to eight levels.

Generics, unmanaged calling conventions, varargs, pointers, byrefs, function pointers, typed references, multidimensional arrays, floating point, native-sized arithmetic, and 64-bit values are format errors. Signatures are parsed directly from the Blob section with explicit length bounds.

## Method bodies and CIL

MC04 method bodies preserve ECMA-335 CIL opcode bytes. The first profile accepts only the documented integer, branch, direct-call, object, field, and primitive-array subset. Short CIL forms remain short. The preprocessor selects a long form only when the operand cannot fit.

Method, field, and type operands use the compact three-byte metadata token described above instead of the four-byte CLI token. This is the only operand-width change. The generated [MC04 CIL opcode appendix](MC04_OPCODES.md) lists every accepted opcode, operand form, permitted token tables, ECMA stack transition and flow classification. Any opcode absent from that appendix is invalid.

A method body starts at its MethodDef `CodeOffset` and uses this header:

```text
flags                 u8    bit 0 Transaction. Bit 1 init-locals
reserved              u8    zero
max_stack             u16
code_length           u32
local_signature       u16   Blob offset, zero when there are no locals
resource_declaration  u16   zero until bounded declarations are enabled
code                  byte[code_length]
```

Exception-handler sections are absent because managed exception handlers are outside the first profile. Native calls are ordinary MemberRef calls whose AssemblyRef is the pinned framework assembly. A signed import table resolves those references to a fixed native ABI. User-created namespace or attribute names cannot create an import.

## Determinism and security validation

The preprocessor emits rows in deterministic token order, deduplicates heap entries, normalizes signatures, zeros every reserved field, and chooses the smallest legal index width. Canonical output has exactly one byte representation.

Before binding a signer or changing durable state, the device validates the header, all section arithmetic, canonical table order, row and heap bounds, coded-index tags, ownership/list ranges, duplicate identities, signatures, method bodies, CIL boundaries, branch targets, stack types, call signatures, imports, dependency bindings, capabilities, resource declarations, and manifest/Assembly-row equality. Recovery and execution repeat the signed-assembly checks required by the threat model.

## Implementation gate

MC04 is not accepted until the repository has:

1. one normative row-layout and opcode appendix generated from shared schema data.
2. a zero-copy Rust parser exposing validated offsets and borrowed slices.
3. deterministic C# emission from normal Roslyn assemblies.
4. an independent inspector that prints tables, tokens, signatures, and CIL.
5. malformed signed-assembly tests for every header, section, table, heap, token, signature, and method-body invariant.
6. size budgets for MC04 sections, build metadata and representative signed packages relative to the source PE assembly.

The checked-in schemas are `format/mc04-schema.json` and `format/mc04-opcodes.json`. Their generators produce the Rust and C# constants plus the normative [table](MC04_TABLES.md) and [opcode](MC04_OPCODES.md) appendices. The acceptance gate fails if generated files are stale. `assembly.rs` borrows structural metadata and uses bounded transient state for control-flow verification. `scripts/mcinspect.py` independently decodes tables, tokens and CIL. The Rust parser validates Field, MethodDef, MemberRef and local-variable signatures directly from borrowed Blob-section slices, including canonical compressed integers, profile type restrictions, bounded nesting and compact TypeDefOrRef targets. It validates opcode boundaries, compact token targets, exact branch destinations, stack height, argument/local types, array element types, field owners, calls, constructors, returns and merge assignability. Signed lifecycle indices must name static, parameterless, void MethodDef rows. Execution views resolve MethodDef, MemberRef, TypeRef and AssemblyRef rows while borrowing names, signatures, local signatures and method bodies from the signed image. The bounded direct interpreter executes the managed instruction subset from those views without translating or copying CIL. All 216 desktop differential cases pass. The preprocessor emits deterministic `.mca`, manifest and debug-map outputs. It removes TypeRef, MemberRef, AssemblyRef, signature, and string entries unreachable from code, signatures, base types, or retained MicroCard attributes, then rewrites every affected coded index. It collapses every field name and each non-public method name to one shared placeholder after linking records the public managed exports. Signed MC04 assemblies activate, recover, link and execute through fixed framework/native and managed dependency targets. [ASSEMBLY_BUDGETS.json](ASSEMBLY_BUDGETS.json) records the header, every section, retained table rows, build metadata, debug maps, fixed signature envelope and representative package size for all sixteen corpus assemblies and enforces ceilings in the host gate. The independent inspector and Rust tests cover each structural layer, while the signed malformed matrix proves those checks still run after successful P-256 ECDSA verification.
