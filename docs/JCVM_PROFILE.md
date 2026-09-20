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
across reboot, and deletes it. `serve-jcvm-managed MANAGEMENT_KEYS STATE_DIR` uses this
path with persistent files; `serve-jcvm-managed-binary` uses the shared framed transport.
The separate `engine-jcvm` board build now uses the same adapter with NVMC storage.
Both DK and dongle layouts cross-link; physical execution remains unverified.

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
serves GP status records, domain discovery, and authenticated applet APDUs with their
original instruction, parameters, and data. Encrypted ISD applet commands retain their
protected CLA until the applet's secure-channel unwrap; other commands receive the
unprotected CLA. GP management commands are dispatched only in class `80` after
transport verification. Basic-channel plain `00`/`10` APDUs can select and invoke
applets without inheriting SCP03 authority; the applet enforces its own access policy.
Protected command chaining uses `14`/`94` with the complete CLA covered by C-MAC.
MC04 continues to require SCP03. The former JCVM INS 10 tunnel is no longer decoded.
SELECT calls `select()` and then `process()` with the
selection flag, returning the applet's data and status. A refusal leaves no selection;
a status from the subsequent `process()` does not undo accepted selection.

Selection changes call and commit `deselect()` before switching. Applet exceptions do
not prevent deselection; engine errors or failed commits trigger authenticated recovery.
Reset discards the live session without calling deselect. Reselecting the same instance
reuses its heap and runs deselect/select/process with
[`reSelectingApplet()`](https://docs.oracle.com/en/java/javacard/3.1/jc_api_srvc/api_classic/javacard/framework/Applet.html)
true.
Switching instances retains reset-scoped transient data in the bounded RAM cache
below; deselection-scoped data is cleared. A missing selection target leaves the
current selection intact. An applet secure-channel reset drops transport keys before
response protection; clients must establish a new SCP03 session for further management.

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
has an authenticated applet-state journal bound to its image and installation.
Its image and heap regions are allocated separately in both board layouts.

The managed simulator uses two 8 KiB registry journal slots, two 64 KiB image slots,
and two independent heap banks with two 64 KiB journal slots each. Every journal has
separate commit and nonce counters. These host capacities do not establish board
capacity or RAM bounds. A versioned layout marker rejects other engine layouts.
Missing committed files fail without recreation; only an authorized installation can
reclaim an unreferenced heap with a fresh identity and key. An exclusive directory
lock prevents simultaneous simulator writers. `scripts/jcvm_transport_acceptance.py`
exercises this path with the independent Python signer and SCP03 client; checkpoint
and CI run it. Set `MICROCARD_BINARY=1` to replay the same cases over framed transport.

JCVM sessions now retain checked image handles instead of owning a second code
buffer. A retained handle prevents its slot from being reclaimed, and every borrow
checks the complete signed package's descriptor hash before exposing its code range.
Overlapping reads and writes return an error. Board reads borrow memory-mapped flash;
the host backend reads only the stored package length. Handles never bypass package
signature and registry-binding verification when a session opens.

The [heap profiling command](VALIDATION_CADENCE.md#heap-measurements) reuses the
existing lifecycle workload. Host allocation results and their source baselines are
recorded below; allocator internals, stack use, and device latency are excluded.

| Change | Host peak bytes | Selected live bytes |
| --- | ---: | ---: |
| Baseline (`ed0d5f2`) | 174,663 | 155,397 |
| Direct CBOR snapshot (`3831e3e`) | 165,285 | 155,397 |
| Retained image handle (`e62fdc5`) | 160,806 | 110,651 |

The direct CBOR writer adds 120 bytes of JCVM firmware text. Retained image handles
add 3,696 bytes versus `3831e3e`, trading flash for 44,746 bytes less retained host
memory. The host backend allocates a temporary code-read buffer per command, unlike
the board, so its allocation traffic increases; no latency reduction is claimed.
Execution frames and applet heaps still occupy RAM. These results do not establish
a safe board heap size.

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
partitioning is checked for both board layouts. Inactive instances retain reset-scoped
array payloads in a zeroizing RAM cache with a shared 64 KiB limit. Installation and
selection bind these records to the installation identity; reset and deletion clear
them. Cache admission failure returns an error without evicting another instance.
Persistent snapshots continue to exclude all transient payloads. Worst-case live heap
plus cache usage still needs board measurement.

## Cryptography

Symmetric key objects keep transient initialization flags beside their key bytes, so
reset and deselection clear both together. Persistent keys retain both. This follows
[KeyBuilder's lifetime contract](https://docs.oracle.com/en/java/javacard/3.1/jc_api_srvc/api_classic/javacard/security/KeyBuilder.html).
Snapshots sanitize transient key data; RAM suspension retains reset-scoped keys only.
Restoration rejects the former layout that placed transient key material in persistent
arrays. This storage support does not enable unsupported cipher or signature algorithms.

The generated bindings describe Java Card API names; they do not establish algorithm support.
The simulator's default JCVM host now uses the shared platform provider for SHA-256
and entropy. The same adapter builds without MC04 or software crypto for the separate board
integration. Provider failures clear output and return an error without a software retry.
SHA-384 remains only in the engine's explicit test-reference host.

Algorithm factories consult host capabilities. Unsupported algorithms and shared-access
requests raise [CryptoException.NO_SUCH_ALGORITHM](https://docs.oracle.com/en/java/javacard/3.2/jcapi/api_classic/javacard/security/CryptoException.html).
[AES-128 ECB/CBC without padding](https://docs.oracle.com/en/java/javacard/3.1/jc_api_srvc/api_classic/javacardx/crypto/Cipher.html) (algorithms 14/13) supports encryption, decryption, split
`update`/`doFinal` input, and overlapping arrays through the shared provider. It accepts
128-bit AES keys and modes 1/2. CBC accepts a 16-byte IV or defaults to zero; ECB
rejects IV parameters. Other key sizes and algorithms are rejected. Reset clears pending
bytes and the CBC IV, while the key binding and direction persist. `doFinal` also clears
the CBC IV and rejects an operation that has received no input. Complete CBC blocks
are sent to the provider in one call; the interpreter does not implement chaining.
Transient-key clearing prevents further operations until the key is initialized again.
Cipher input consumes one work unit per byte including pending bytes; output uses one
bounded staging buffer so provider failure cannot publish partial output.
P-256 key objects accept the fixed SEC 2 curve parameters and validated private scalars
or 65-byte uncompressed public points. Parameter flags share the key material's lifetime;
reset/deselection clears transient parameters and values together. The cofactor is optional
for initialization. Other curves, key sizes, and encrypted-key interfaces are rejected.
KeyPair supports P-256 (algorithm 5, 256 bits) and containers of matching existing
public/private keys. Constructors leave key values uninitialized or preserve supplied
keys. Generation uses provider entropy, retains component references, and stages both
values before publication. Allocation capacity is checked before compound allocations;
failed regeneration preserves both previous values. Generation charges 97 work units.
Raw P-256 ECDH (KeyAgreement algorithm 3) accepts an initialized private key and a
65-byte uncompressed peer point, returning the 32-byte shared x-coordinate through
the provider. Output is staged until success, including overlapping buffers; each call
charges 65 work units and rechecks key initialization. Reset preserves the binding but
clears transient private keys. Other agreement algorithms and external access are rejected.
ECDSA/SHA-256 (Signature algorithm 33) supports sign/verify modes, split updates, and
precomputed 32-byte hashes. It retains a 256-byte CLEAR_ON_RESET provider state, stages
DER output before publication, and accepts overlapping input/output. Successful final
operations clear streaming state; a rejected signature also resets the verifier. Provider
failure publishes neither output nor changed intermediate state. Each input byte charges
one work unit. Other signature algorithms and external access are rejected.
### OpenFIPS201 provisioning

The managed acceptance now defines and imports an AES-128 management key through
OpenFIPS201's administrative APDUs. After reboot it completes PIV challenge-response
using that key and an independent host AES implementation. A MAC-only management-key
definition and an incorrect challenge response are rejected. The same flow provisions
a local PIN and generates a P-256 key in slot 9C. It verifies signatures independently
before and after reboot against the original public key, rejects signing without PIN
validation, and requires a fresh PIN verification for every signature. It stores a
DER X.509 certificate through chained encrypted PUT DATA commands, then retrieves the
exact object through plain GET DATA/GET RESPONSE before and after reboot. Signing
and PIN operations use plain PIV commands. Reselect preserves PIN validation; a missing
SELECT leaves it intact; selecting the ISD and returning to the applet clears it.

For ISD-owned applets, the shared transport passes encrypted, authenticated commands
with a command-scoped secure-channel grant. `GPSystem.getSecureChannel` returns a
reusable handle containing no authority. `getSecurityLevel` reads the current grant;
`unwrap` accepts the actual APDU buffer only, compares its complete header and data
with the verified command, and consumes the grant's unwrap permission once. It clears
the protected CLA bit without repeating cryptography. Changed bytes or repeated
unwrapping fail closed. No command authority enters persistent applet state.

MAC-only and plain commands retain ordinary applet semantics without an administrative
grant. SSD-owned applets do not receive ISD secure-channel authority. Platform services
provide a channel handle even without an active session; its security level is zero.
`resetSecurity` immediately removes the current command's grant and asks the shared
transport to discard the session before protecting a response. This also applies to
reset during deselection initiated by a management command. Without platform services,
`getSecureChannel` throws `SystemException.NO_RESOURCE`. Applet-initiated handshake,
wrap, and data-encryption operations remain unavailable and reject with `6982`;
transport handles its own handshake and response protection.

The runtime preserves bytes already sent when an applet completes through
`ISOException`, including success and response-chaining status words. Other exceptions
still discard response data. OpenFIPS201 uses this path for its authentication challenge;
previously it returned an empty `9000` response.

The fixture is pinned to OpenFIPS201 `9f3b99bd0f2600beea7e5c053613d8baef2b7716`.
Upstream tests mock the secure channel; this acceptance exercises the actual shared
transport. Physical Makerdiary execution and interrupted provisioning remain unverified.

## Transactions and remaining durability work

JCVM transaction natives now share an 8 KiB before-image log for heap payloads and
static fields, including record overhead. Space is reserved before begin and wiped
on commit or abort. Writes are admitted before mutation; exhaustion throws
`TransactionException.BUFFER_FULL`. Nested begin and unmatched commit/abort report
`IN_PROGRESS` and `NOT_IN_PROGRESS`. Commit-capacity queries include metadata cost.

Explicit abort restores conditional writes. Returning or throwing from an applet
callback with an unfinished transaction aborts it; process answers `6F00`. PIN
presentation counters and validation, transient arrays (including the APDU buffer),
and non-atomic copy/fill operations are excluded from rollback. PIN updates remain
conditional. An abort that allocated objects clears their storage and transient
references and ends the session before any stale frame references can execute;
reset or reopening the recovered session is required. This follows the allowed
session-termination behavior in [JCSystem.abortTransaction](https://docs.oracle.com/en/java/javacard/3.1/jc_api_srvc/api_classic/javacard/framework/JCSystem.html).
Older snapshots with a persistent APDU-buffer header are explicitly rejected by
runtime-layout validation; there is no automatic erase or conversion.

An in-command `commitTransaction()` now saves an authenticated snapshot before
discarding its undo log. Cancellation or failure afterward recovers that committed
state. A failed checkpoint stops execution and recovers the last valid journal record.
Installation publishes only after its complete callback succeeds. Storage serializes
a borrowed view into its existing staging buffer, clearing volatile contents there.
Host tests cover OpenFIPS201 object activation followed by cancellation and a failed
checkpoint, including reopening the journal and reading the object.

**Durability is still incomplete:** unconditional PIN retry updates and persistent
writes outside explicit transactions still rely on successful APDU completion.
Connect these boundaries to storage, finish native-API transaction auditing, and
test interrupted provisioning before
claiming Java Card transaction guarantees. A passing simulator workflow does not
establish those guarantees or physical execution.

Additional software implementations of SHA-384, P-384, RSA, or 3DES are outside this release cleanup.

## Authorization

A raw Java Card CAP carries no MicroCard signature. Device installation requires its
MP05 envelope, whose P-256 signature binds the image digest and versioned manifest,
including the security domain and incarnation. The authenticated transport, signed
package verification, and registry ownership checks are distinct requirements.
The raw simulator loader is a development entry point, not the board loading path.

## Sources

Version, container and import numbers come from reading the eight committed release variants of the OpenPhysical OpenFIPS201 fork at `build/matrix`. Opcode, component and verification clauses come from the Java Card 3.1 and 3.2 editions pinned in [REFERENCES.md](REFERENCES.md).

The 3.0.5 editions are not pinned yet, which is an open gap. Every clause this profile relies on has to be read in the edition that governs the target version before the verifier can claim to implement it. The same gap in the secure channel profile caused a mode to be implemented against an edition that predated it.
