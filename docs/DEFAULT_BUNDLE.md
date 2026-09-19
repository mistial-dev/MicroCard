# Default bundle manifest

The per-device `MDB1` manifest records the exact default packages used to take ownership of an ISD incarnation. It is generated only after the MC04 assemblies have been packaged for that incarnation. Changing an assembly, package manifest, package version, signer or target incarnation changes the manifest bytes and signature.

`MicroCard.Bundle create OUTPUT SEED PACKAGE... --explicit-sign` verifies every package signature, requires one signer and ISD incarnation, requires dependency-free `mscorlib`, rejects external or cyclic dependencies, and emits a deterministic dependency-first order. The supplied signing seed must match the package signer. Private seeds remain outside version control.

The signed representation is:

```text
MDB1 | "MicroCard default bundle v1\0"
entry count | ISD incarnation | signer public key
repeated dependency-first entries:
  assembly UTF-8 identity
  four-part assembly version
  package version
  SHA-256(MC04 image)
  SHA-256(complete signed package)
P-256 ECDSA signature over every preceding byte
```

`MicroCard.Bundle verify BUNDLE PACKAGE...` verifies the manifest signature and every package signature, reconstructs the canonical representation, and requires an exact match. The package digest is the same full-package SHA-256 identity used by runtime dependency bindings.

Runtime dependency bindings already refuse removal or replacement of a provider while a consumer retains a verified binding. The manifest does not create a second mutable registry or an override path. It supplies reproducible provisioning evidence for the exact initial package set.
