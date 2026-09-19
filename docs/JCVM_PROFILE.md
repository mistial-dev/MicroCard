# Java Card profile

This document describes the supported Java Card subset and its current limitations.
Complete Java Card conformance and every OpenFIPS201 variant are outside this release
cleanup. [Release readiness](READINESS.md) tracks the remaining delivery blockers.

Implemented so far, in `crates/microcard-engine-jcvm`:

| Part | State |
| --- | --- |
| CAP container | reads a Load File Data Block in place and refuses one that disagrees with itself |
| Bytecode decoder | measures every instruction the specification defines and builds the instruction-boundary map |
| Structural verification | one pass at load, over a whole package |
| Object heap | objects and arrays, with the owner context checked on every access |
| Linking | constant pool entries resolved to field offsets and method bodies as each instruction runs |
| Interpreter | arithmetic, locals, the stack, control flow, arrays, fields, statics, invocation, casts, throw and catch |
| API tokens | the six imported packages, read out of their export files into a committed table |
| Native classes | Util, ISOException, APDU, JCSystem, Applet, OwnerPIN, and the key and algorithm objects |
| Applet lifecycle | install, register, select and process, driven from outside the engine |

The committed OpenFIPS201 standard-cs2 fixture installs, registers, accepts selection,
and answers the checked PIV commands through `microcard-sim serve-jcvm`. PIN retries
persist between commands. Other variants require separate evidence; unsupported cipher,
signature, and key-agreement requests now fail at their factories.

The shared core now connects authenticated GlobalPlatform loading and installation to
JCVM through `jcvm_card::Card` and `transport::Endpoint`. The host lifecycle test sends
real SCP03 messages, installs the committed PIV applet, selects it, checks PIN retries
across reboot, and deletes it. The simulator command still accepts raw load-file paths;
its persistent transport backend and the separate board image remain delivery gaps.

The shared C4 receiver now enforces container identity, an engine-specific size limit,
ordered blocks, and exact completion. A rejected block closes the upload and resets
staging. Both core adapters use the receiver. JCVM checks that the signed manifest
matches the requested load AID, security domain, and optional package hash before
writing an image. RAM and flash staging accept compile-time limits,
so the MC04 16 KiB bound does not constrain the JCVM profile. The JCVM package
verifier uses MP05 and its own [bounded signed manifest](DEVICE_CBOR.md#jcvm-manifest-version-1),
with a 60 KiB package limit. Raw CAP input remains a simulator convenience, not a signed package.

Installation, selection, and processing expose cancellation callbacks, checked before
execution and at each instruction boundary. Cancellation escapes as an engine error;
an applet cannot catch it or turn it into a successful response. Native calls finish
before the next poll. The durable applet session checks cancellation again before
committing and reloads authenticated state after an execution or persistence error.
If recovery fails, commands remain disabled until explicit recovery succeeds. Reloading
clears volatile state, so the transport adapter must discard selection on errors.
The session uses the reboot journal scan to resolve uncertain writes; a failed reply
can still correspond to a committed command. The raw engine API alone does not roll
back mutations.

The session accepts parsed GlobalPlatform installation requests, checks the load-file
AID, and frames instance AID, privileges, and C9 application data for the applet.
Explicit `Applet.register` calls must use the requested instance AID. Empty or short
registration AIDs and repeated registration are rejected. The bounded registry journal
now persists ownership, rollback history, image references, and installation identities.
The registry loader now authorizes signed packages before erasing, stages images in
unreferenced slots, verifies readback, and commits activation metadata. It protects
the old image through write failures and cancellation. Package reads verify both flash
and the current registry binding. Installation now commits a dedicated heap before
publishing its instance, using a fresh derived key even after an interrupted attempt.
Reopening verifies every committed image and heap without reinstalling. The adapter
serves GP status records, domain discovery, and the existing authenticated SELECT and
INS 10 application tunnel. SELECT calls `select()` and then `process()` with the
selection flag, returning the applet's data and status. A refusal leaves no selection;
a status from the subsequent `process()` does not undo accepted selection.

Selection changes call and commit `deselect()` before switching. Applet exceptions do
not prevent deselection; engine errors or failed commits trigger authenticated recovery.
Reset discards the live session without calling deselect. Reselecting the same instance
reuses its heap, but switching to another instance currently drops reset-scoped volatile
data. Preserving that data until reset and direct applet APDUs remain incomplete.

## What holds this claim up

One Load File Data Block is committed at `crates/microcard-engine-jcvm/tests/vectors`, with its MIT notice, the applet revision it was built from and the digests of both the CAP and the block. Twelve PIV commands and their expected status words are committed beside it. `scripts/piv_vector_acceptance.py` replays them with no argument, and the checkpoint gate and CI both run it.

Half of those commands are authentic encodings taken from NIST Special Database 33 contact captures. The captured responses are deliberately absent, because that card was personalised and the card under test is blank, so a captured response would disagree for a correct reason. What carries over is the command encoding. Every entry is the case 4 form a real host sends, carrying a trailing expected-length byte.

That form is worth the trouble. Reading the expected-length byte as a further byte of command data made the applet answer 6A80 to a GET DATA it should answer 6A82 to, and only the authentic encoding exposed it. A hand-written case 3 command passed throughout.

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

MC04 now journals image descriptors and stores code in dedicated flash slots. JCVM
has an authenticated applet-state journal bound to its image and installation, but
its image and heap regions still need board allocation and persistent simulator backends.

## Verification

Structural verification is mandatory and runs in one streaming pass at load. It covers the header magic and flags, directory tiling without gaps or overlaps, import resolution, applet offsets landing on method headers, class consistency through a bounded acyclic superclass walk, constant pool tags and token ranges, per-method stack and local bounds, exception handler ranges on instruction boundaries, and an instruction-boundary bitmap built by linear decode that every branch, switch and handler target is checked against.

The bitmap is built already, by reachability rather than by a linear sweep. Branch offsets are signed and count from the address of their own opcode, and a target that misses a boundary is refused. That single check removes the whole class of attacks where a jump lands on an operand byte and turns a constant into an opcode. Switch tables are measured from their own operands before anything indexes into them, and lookup switch pairs must be sorted, which is what lets a card search them.

Reachability is a finding rather than a preference. A method in a CAP file records no length, and the offsets that name methods do not name all of them. The class method tables hold virtual methods, the constant pool holds static and constructor references, and the Applet component holds install entry points. All eight test packages still carry at least one method that none of those name, so the byte after a method's last instruction is not reliably the start of anything known. The Descriptor component would say, and a Load File Data Block leaves it behind. Decoding everything between two named offsets therefore decodes an unnamed method's header as though it were bytecode.

Decoding by reachability sidesteps that. Bytes no path reaches are never decoded, and because every branch target is checked against the map, execution cannot reach them either. A method is still bounded above by the next offset the package does name, which is what stops a branch from entering another method's body while running on the first method's frame.

Full type and dataflow verification is deferred. In its place the operand stack and the locals carry a one-bit reference tag per slot, checked on every push and pop, which makes reference and primitive confusion unrepresentable at runtime. This is the opposite trade from the MC04 engine, which verifies hard and runs lean, and it is deliberate.

## Volatile and persistent memory

Array clear events occupy spare bits in the existing six-byte object header. The heap
can clear reset-scoped arrays across contexts and deselection-scoped arrays for one
context without reallocating objects or changing references. `JCSystem.isTransient`
reports the recorded event; invalid factory events raise `SystemException.ILLEGAL_VALUE`.
These event meanings follow [the Java Card API](https://docs.oracle.com/cd/E59935_01/api/javacard/framework/JCSystem.html).

CAP static array initializers and non-default primitive values are applied before
installation. Recovery restores the saved values rather than overwriting them with
their initial values. SELECT processing now returns the PIV application template and
applies its configured six-attempt contact PIN limit; the first two failed PIN checks
therefore return `63C5` and `63C4`.

`Card.reset()` clears both transient array kinds, the APDU buffer, execution words and
tags, and native OwnerPIN validation flags. It retains installed objects, persistent
array values, and PIN retry counts. `Card.save_into()` writes used heap bytes to a
caller-owned buffer and removes volatile values from that copy. `Card.restore()`
checks object boundaries, typed references, roots, ownership, and native PIN state
without running installation again. The committed PIV applet test verifies that PIN
retry counts survive restoration; saving does not clear the live session.

The shared core's `jcvm_storage::Store` wraps those APIs in an authenticated journal,
binding the snapshot to the exact code image and installation identity using the
[JCVM state contract](DEVICE_CBOR.md#dedicated-jcvm-state-journal). Board flash
partitioning, persistent simulator integration, inactive-instance volatile state, and transaction
undo still need integration before board delivery.

## Cryptography

The generated bindings describe Java Card API names; they do not establish algorithm support.
The simulator's default JCVM host now uses the shared platform provider for SHA-256
and entropy. The same adapter builds without MC04 or software crypto for future board
integration. Provider failures clear output and return an error without a software retry.
SHA-384 remains only in the engine's explicit test-reference host.

Algorithm factories consult host capabilities. Unsupported algorithms and shared-access
requests raise [CryptoException.NO_SUCH_ALGORITHM](https://docs.oracle.com/en/java/javacard/3.2/jcapi/api_classic/javacard/security/CryptoException.html).
Cipher, Signature, and KeyAgreement operations are not wired up, so their factories
reject requests rather than creating unusable objects. The committed PIV acceptance
still installs, selects, and exercises PIN retry behavior with this restriction.

Applet-owned GlobalPlatform secure channels are unavailable. `GPSystem.getSecureChannel`
throws `SystemException.NO_RESOURCE`; it never exposes the transport's management channel.

JCVM integration of existing P-256 and AES services remains required. Additional software
implementations of SHA-384, P-384, RSA, or 3DES are outside this release cleanup.

## Authorization

A Java Card package carries no signature of its own, so on-card verification and the secure channel are the whole safety boundary. That is a weaker position than the MC04 path, where every package carries an P-256 ECDSA signature that binds it to a domain. GlobalPlatform DAP blocks are the standards-native way to restore an offline code signer, and the tooling already supports them.

## Sources

Version, container and import numbers come from reading the eight committed release variants of the OpenPhysical OpenFIPS201 fork at `build/matrix`. Opcode, component and verification clauses come from the Java Card 3.1 and 3.2 editions pinned in [REFERENCES.md](REFERENCES.md).

The 3.0.5 editions are not pinned yet, which is an open gap. Every clause this profile relies on has to be read in the edition that governs the target version before the verifier can claim to implement it. The same gap in the secure channel profile caused a mode to be implemented against an edition that predated it.
