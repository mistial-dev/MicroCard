# Java Card profile

The target is a complete Java Card virtual machine. This document records what that means concretely, so the loader, the verifier and the interpreter can each be judged against a written target instead of against each other.

OpenFIPS201 is the first applet the engine has to run, and its measurements pin the first milestone. It is a test vehicle rather than the boundary of the work. Where a number below was measured from it, the text says so, and where a feature is absent from it the engine still implements the feature.

Implemented so far: the CAP container and the bytecode decoder in `crates/microcard-engine-jcvm`. The container reads a Load File Data Block in place and refuses one that disagrees with itself. The decoder measures every instruction the specification defines and builds the instruction-boundary map. There is no linker or interpreter, and nothing on the card reaches that crate.

## Version and container

| Item | Value |
| --- | --- |
| Java Card | Classic 3.0.5 as the first target version |
| CAP format | 2.1, compact |
| Instruction set | all 185 opcodes of JCVM section 8.1, including the 32-bit integer family |

Export file version 1.6 is the marker for 3.0.5. A card exporting 1.5 is a 3.0.4 card and rejects an applet built for 3.0.5 at link time, so the imported version numbers are the part of the profile that decides whether the target version is real.

The first test applet declares CAP 2.1 with header flags `0x04`, which is an applet package with no 32-bit integers, no Export component and no extended layout. Those are properties of that package. A package declaring 32-bit integers is a package this engine runs, and `ACC_INT` is read as the package's own declaration of what its methods may contain.

## Imported packages

Six, and no others.

| Package | AID | Version |
| --- | --- | --- |
| `java.lang` | `A0000000620001` | 1.0 |
| `javacard.framework` | `A0000000620101` | 1.6 |
| `javacard.security` | `A0000000620102` | 1.6 |
| `javacardx.crypto` | `A0000000620201` | 1.6 |
| `javacardx.apdu` | `A0000000620209` | 1.0 |
| `org.globalplatform` | `A00000015100` | 1.5 |

An import resolves when its major version matches and its minor version is at least the one requested.

## Order of work

Nothing here is a permanent exclusion. Each row says what the engine does today and what has to happen before it does more.

| Feature | Today | To finish |
| --- | --- | --- |
| The 32-bit integer family | decoded, and refused in a package whose `ACC_INT` is clear | interpreter arms |
| `jsr` and `ret` | decoded, and refused by policy | subroutine dataflow analysis in the verifier |
| The reserved opcodes | refused everywhere | nothing. They cannot appear in a CAP file, JCVM section 7.2 |
| Logical channels | absent | channel state in the secure channel and in selection |
| Shareable interfaces | absent | cross-context invocation through the firewall |
| `MultiSelectable` | absent | per-channel applet state |
| Java Card RMI | absent | the remote object layer above shareable interfaces |
| Garbage collection | absent | a compacting or mark-sweep pass over the object heap |

Until shareable interfaces and multiple channels exist, exactly two firewall contexts are reachable, so multi-applet isolation stays unproven until a second applet exists. That limitation is recorded here rather than discovered later.

## Components

Retained on card: Header metadata, Applet, Class, Method, and a resolved constant pool. Consumed at load and discarded: Directory, Import, ConstantPool, StaticField, RefLocation. Never retained: Descriptor and Debug.

The Load File Data Block is the components in the order of JCVM section 6.3, excluding Debug and Descriptor. Across the eight release variants it runs from 44,922 to 50,313 bytes, against `.cap` archives of 278 KB to 306 KB, because an archive also carries the original class files. The card only ever sees the smaller number.

| Variant | Load file | Method component |
| --- | --- | --- |
| standard CS2 without attestation | 44,922 | 35,859 |
| standard CS7 without attestation | 45,205 | 35,994 |
| fips CS2 without attestation | 45,492 | 36,354 |
| fips CS7 without attestation | 45,751 | 36,466 |
| standard CS2 with attestation | 49,484 | 39,617 |
| standard CS7 with attestation | 49,767 | 39,752 |
| fips CS2 with attestation | 50,054 | 40,112 |
| fips CS7 with attestation | 50,313 | 40,224 |

The first row is where the engine work starts. Reproduce this table with `scripts/jcvm_cap_inventory.py` against a directory of built CAP files. Adding `--load-file` to that command writes the blocks themselves, which is what the container parser is tested against through `MICROCARD_JCVM_LOAD_FILES`.

One detail that only real packages show. The Directory records a size for the Descriptor component, and a Load File Data Block leaves that component behind, so the two disagree by design. A loader comparing the whole table against the block refuses every genuine package.

## Memory placement

The journaled state caps a snapshot at 49,152 bytes and holds packages inside it, so neither a load file nor a Java Card heap can live there. Code images and heaps get dedicated flash regions with A and B banks, and the journaled state holds only descriptors.

## Verification

Structural verification is mandatory and runs in one streaming pass at load. It covers the header magic and flags, directory tiling without gaps or overlaps, import resolution, applet offsets landing on method headers, class consistency through a bounded acyclic superclass walk, constant pool tags and token ranges, per-method stack and local bounds, exception handler ranges on instruction boundaries, and an instruction-boundary bitmap built by linear decode that every branch, switch and handler target is checked against.

The bitmap is built already, by reachability rather than by a linear sweep. Branch offsets are signed and count from the address of their own opcode, and a target that misses a boundary is refused. That single check removes the whole class of attacks where a jump lands on an operand byte and turns a constant into an opcode. Switch tables are measured from their own operands before anything indexes into them, and lookup switch pairs must be sorted, which is what lets a card search them.

Reachability is a finding rather than a preference. A method in a CAP file records no length, and the offsets that name methods do not name all of them. The class method tables hold virtual methods, the constant pool holds static and constructor references, and the Applet component holds install entry points. All eight test packages still carry at least one method that none of those name, so the byte after a method's last instruction is not reliably the start of anything known. The Descriptor component would say, and a Load File Data Block leaves it behind. Decoding everything between two named offsets therefore decodes an unnamed method's header as though it were bytecode.

Decoding by reachability sidesteps that. Bytes no path reaches are never decoded, and because every branch target is checked against the map, execution cannot reach them either. A method is still bounded above by the next offset the package does name, which is what stops a branch from entering another method's body while running on the first method's frame.

Full type and dataflow verification is deferred. In its place the operand stack and the locals carry a one-bit reference tag per slot, checked on every push and pop, which makes reference and primitive confusion unrepresentable at runtime. This is the opposite trade from the MC04 engine, which verifies hard and runs lean, and it is deliberate.

## Cryptography

The API surface is the whole of Java Card 3.0.5. Required by the first test applet, and therefore first to be implemented: SHA-256 and SHA-384, ECDSA over P-256 and P-384, AES-CMAC-128, AES ECB and CBC at 128, 192 and 256, 3DES ECB, raw RSA at 1024, 2048 and 3072, EC SVDP-DH, and secure random.

Elliptic curve domain parameters arrive from the applet as explicit field values rather than as named curves. They are matched byte for byte against committed P-256 and P-384 tables and bound to the fixed-curve backend on a match, and an unrecognised parameter set raises an illegal value error.

RSA is the open risk. On a 64 MHz Cortex-M4 without a hardware accelerator, a 3072-bit private operation runs into tens of seconds and key generation runs into minutes, which exceeds any plausible command timeout and any watchdog window. The size range this profile actually commits to is settled before that work starts.

## Authorization

A Java Card package carries no signature of its own, so on-card verification and the secure channel are the whole safety boundary. That is a weaker position than the MC04 path, where every package carries an Ed25519 signature that binds it to a domain. GlobalPlatform DAP blocks are the standards-native way to restore an offline code signer, and the tooling already supports them.

## Sources

Version, container and import numbers come from reading the eight committed release variants of the OpenPhysical OpenFIPS201 fork at `build/matrix`. Opcode, component and verification clauses come from the Java Card 3.1 and 3.2 editions pinned in [REFERENCES.md](REFERENCES.md).

The 3.0.5 editions are not pinned yet, which is an open gap. Every clause this profile relies on has to be read in the edition that governs the target version before the verifier can claim to implement it. The same gap in the secure channel profile caused a mode to be implemented against an edition that predated it.
