# Kdf108 SCP03 profile

`Kdf108` is an ISD shared managed demonstration assembly in the original test corpus. The default platform set excludes it, and it defines no standard fixture. An SSD consumer passes an opaque SSD-owned AES key handle, a one-byte key-purpose value, and APDU-supplied context. The key bytes never enter managed code or the ISD domain. Native AES-CMAC executes using the caller SSD's identity.

The derivation follows [GlobalPlatform SCP03 v1.1.2 section 4.1.5](https://globalplatform.org/wp-content/uploads/2014/07/GPC_2.3_D_SCP03_v1.1.2_PublicRelease.pdf), which selects the counter-mode KDF from [NIST SP 800-108 Rev. 1](https://doi.org/10.6028/NIST.SP.800-108r1-upd1) and AES-CMAC from [NIST SP 800-38B](https://doi.org/10.6028/NIST.SP.800-38B). For each 16-byte result block, the CMAC input is:

```text
label[12] || 00 || L[2] || counter[1] || context
```

The first 11 label bytes are zero and byte 12 is the key-purpose/derivation constant. `L` is the requested output length in bits, big-endian. The counter begins at one. This field order is the SCP03-defined permutation permitted by SP 800-108.

The first profile accepts 8, 16, 24, or 32 output bytes and at most 239 context bytes. Invalid inputs return an empty array. The sample assembly maps that result to `6A80`.

The `Kdf108Consumer` C-APDU data is `keyPurpose || contextLength || context`. Installation creates AES-128 key slot zero in the assembly SSD. Processing opens only its opaque handle, calls the ISD `Kdf108` assembly, and returns a 16-byte derived value.

The consumer declares an exact `Kdf108` assembly version and pins its Ed25519 signer. Activation persists the resolved provider's exact signed-package digest. Bounded lookup recovers its canonical domain and assembly names. Recovery revalidates that binding, and provider replacement or unload is refused while the consumer remains active. The checked-in key is a public test identity only. Acceptance creates packages using two distinct test-only signing seeds: `11` repeated 32 times for `Kdf108`, and `22` repeated 32 times for the SSD assembly. Private test seeds are generated only in temporary directories.

Acceptance signs both MC04 assemblies and validates this relationship. Through SCP03, it takes ownership by loading `mscorlib` under the provider signer, activates `Kdf108` in the ISD, creates the SSD, and activates the differently signed consumer after validating its lifecycle MethodDef targets. It confirms the exact dependency blocks provider removal and recovers both assemblies and signer identities after restart. A second SSD loads `Kdf108` first under its own pinned signer, then loads and executes a same-SSD consumer pinned to that signer. Both paths derive through the persisted managed-call target while native AES-CMAC retains the invoking SSD identity.

Reference vector:

```text
AES-128 KIN = 404142434445464748494A4B4C4D4E4F
purpose     = 04
context     = 0102030405060708
L           = 0080
CMAC input  = 000000000000000000000004000080010102030405060708
derived     = 36A53A0E1D4183458EF52AB845E5DDC2
```
