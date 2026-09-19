# Runtime memory budgets

The portable-runtime unit test `representative_simulator_runtime_peaks_stay_within_budget` measures deterministic logical VM high-water marks while executing the compiled KeyOperations commands for HMAC, CMAC, CBC and CCM plus the KeyReader cross-method path. Measurement code exists only in Rust test builds, so it adds no counters or branches to device firmware.

| Resource | Measured peak | CI ceiling | Profile maximum |
| --- | ---: | ---: | ---: |
| Instructions per invocation | 256 | 512 | 100,000 |
| Evaluation slots | 7 | 8 | 256 |
| Active local slots | 10 | 16 | 2,048 |
| Managed call frames | 2 | 4 | 32 |
| Charged transient bytes | 126 | 128 | 16,384 |
| Transient objects | 7 | 8 | 256 |
| Native work units | 124 | 128 | 1,024 |

The test pins both the measured values and the ceilings. The current values reflect bounded bulk command buffering: it reduces bytecode instructions while adding one caller-owned command array and its local. A corpus or runtime change that moves either value requires explicit review and an update to this record.

The signed Credential profile has a separate deterministic test because it links through both default providers and exercises persistent state. Its maximum across provisioning, public-data read, public-key export, authenticated signing, failed PIN checks and PUK unblock is **78 instructions, 19 evaluation slots, 3 local slots, 3 frames, 152 transient bytes, 3 transient objects and 714 native work units**. The test ceilings are **128/24/8/4/160/8/768**. With `mscorlib`, `MicroCard.Cryptography`, `MicroCard.Security` and `Credential` active, exact signed packages occupy **5,792 bytes** and the provisioned CBOR metadata journal payload is **1,406 bytes**.

Arena accounting is architecture-independent. Each object has a six-byte slab header, a two-byte handle entry, and an even-sized payload. Byte elements occupy one byte; Int32 elements and sealed-object fields occupy four. Stable handles survive slab growth; clearing the heap retires its handles. Rust's platform-specific enum layout never changes the accepted workload.

Managed execution reserves the bounded 256-slot evaluation stack, two temporary constructor slots and all 32 call-frame slots with fallible allocation before running managed instructions. The shared-local buffer grows fallibly before its length changes. The handle directory and shared byte slab also grow fallibly before arena accounting changes. Slab growth copies live bytes to a bounded larger allocation and wipes the old allocation before releasing it. Native byte results are copied into the slab and their temporary owners are wiped. An allocator refusal therefore becomes a controlled `Quota` result instead of an allocation abort or a partially charged arena.

On-device CIL type verification independently reserves its complete 257 control-flow states and pending offsets before analysis. Each retained state stack reserves its exact cell count fallibly, with at most 4,096 cells across the method, while one reusable 256-slot work stack serves every visited block. This avoids tree-node allocation and repeated infallible stack cloning during package activation and recovery.

Native output paths reserve their exact bounded length before a provider or persistent-state mutation runs. This includes opaque handles, fixed hashes/MACs/P-256 results, variable CBC/CCM results, SCP03 plaintext, secured responses, journal recovery and application byte-record copies. Cryptographic and decrypted buffers use zeroizing owners until successful transfer. Replaced or deleted application byte records are wiped before release.

[ASSEMBLY_BUDGETS.json](ASSEMBLY_BUDGETS.json) separately pins aggregate assembly and representative signed-package sizes. The five-assembly default ISD bundle is **10,725 MC04 bytes / 12,109 package bytes**. The four-assembly Credential deployment is **6,538 / 7,810 bytes** before per-device manifest-length differences.

Native work units charge bulk copies and native services separately from bytecode fuel. They measure VM-accounted resources. Host allocator RSS and native Rust stack depth have separate measurements. The nRF52840 link-time flash/BSS gate remains in [BOARD_BUDGETS.json](BOARD_BUDGETS.json). Physical stack high-water, heap high-water and latency measurement on the DK remain hardware acceptance work.
