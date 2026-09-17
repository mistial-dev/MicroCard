# MC04 metadata table appendix

Generated from `format/mc04-schema.json`. Column order is normative. ECMA references name the retained logical table. Physical reductions are defined in `ASSEMBLY_FORMAT.md`.

| ID | Table | Row limit | Columns | ECMA-335 |
| ---: | --- | ---: | --- | --- |
| 0x00 | Module | 1 | `Name:string` | II.22.30 |
| 0x01 | TypeRef | 256 | `ResolutionScope:coded:ResolutionScope`, `TypeName:string`, `TypeNamespace:string` | II.22.38 |
| 0x02 | TypeDef | 253 | `Flags:u32`, `TypeName:string`, `TypeNamespace:string`, `Extends:coded:TypeDefOrRef`, `FieldList:table:4`, `MethodList:table:6` | II.22.37 |
| 0x04 | Field | 1022 | `Flags:u16`, `Name:string`, `Signature:blob` | II.22.15 |
| 0x06 | MethodDef | 256 | `CodeOffset:u32`, `ImplFlags:u16`, `Flags:u16`, `Name:string`, `Signature:blob` | II.22.26 |
| 0x0A | MemberRef | 256 | `Class:coded:MemberRefParent`, `Name:string`, `Signature:blob` | II.22.25 |
| 0x0C | CustomAttribute | 256 | `Parent:coded:HasCustomAttribute`, `Type:coded:CustomAttributeType`, `Value:blob` | II.22.10 |
| 0x20 | Assembly | 1 | `MajorVersion:u16`, `MinorVersion:u16`, `BuildNumber:u16`, `RevisionNumber:u16`, `Flags:u32`, `Name:string` | II.22.2 |
| 0x23 | AssemblyRef | 17 | `MajorVersion:u16`, `MinorVersion:u16`, `BuildNumber:u16`, `RevisionNumber:u16`, `Flags:u32`, `PublicKeyOrToken:blob`, `Name:string`, `Culture:string`, `HashValue:blob` | II.22.5 |

Index widths are canonical. Strings and blobs use u8 through offset 255, otherwise u16. Table-list indices use u8 through row 255, otherwise u16. `coded_u16` is a bounded ECMA coded index with the original tag assignment.
