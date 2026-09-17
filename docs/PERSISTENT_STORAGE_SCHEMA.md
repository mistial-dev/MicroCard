# Persistent storage schema

Persistent storage keys are declared at assembly scope:

```csharp
[assembly: PersistentInt32(1)]
[assembly: PersistentBytes(2, 512)]
```

The preprocessor emits declarations into the canonical package manifest in ascending key order. The Ed25519 package signature therefore covers each key, value kind and byte bound. The device accepts at most 64 declarations per assembly, requires non-negative keys, uses kind `1` for Int32 with a zero byte bound, and kind `2` for byte strings from 1 through 2,048 bytes.

The field is mandatory. Packages created before this schema are rejected, and there is no conversion or upgrade path.

The schema is a security-domain contract. Multiple assemblies may declare the same key only when kind and bound match exactly. Once accepted, a declaration remains pinned until the SSD is deleted, even if every declaring assembly is unloaded. A conflicting declaration must fail atomically without changing the installed assembly set or existing storage.

The domain persists the merged schema until deletion. It accepts identical declarations from multiple assemblies and rejects conflicting declarations before activation commits. Every native storage call checks the currently executing assembly declaration, the caller domain incarnation, the pinned domain contract, the value kind and the byte bound. ISD dependencies therefore cannot use the caller SSD's storage.

Transactional candidate states share the immutable schema allocation. An assembly load that adds declarations creates one exactly reserved merged vector. Unchanged and conflicting loads retain the original allocation. The authenticated journal encodes declarations as compact `[key, kind, maxBytes]` tuples. Recovery rejects the earlier object form, malformed tuples, unsorted or duplicate keys and more than 512 domain declarations. There is no conversion path.

Rider diagnostic `MCA0025` requires a non-negative constant key and a matching declaration at each managed storage call. Device checks remain authoritative when analyzers are disabled or signed code is malformed.
