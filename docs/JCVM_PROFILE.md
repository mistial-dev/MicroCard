# Java Card profile

This document describes the supported Java Card subset and its current limitations.
Complete Java Card conformance and every OpenFIPS201 variant are outside this release
cleanup. [Release readiness](READINESS.md) tracks the remaining delivery blockers.

Supported by `crates/microcard-engine-jcvm`:

| Part | State |
| --- | --- |
| CAP container | reads a Load File Data Block in place and refuses one that disagrees with itself |
| Bytecode decoder | measures every instruction the specification defines and builds the instruction-boundary map |
| Structural verification | one pass at load, over a whole package |
| Object heap | objects and arrays, with the owner context checked on every access |
| Linking | constant pool entries resolved to field offsets and method bodies as each instruction runs |
| Interpreter | arithmetic, locals, the stack, control flow, arrays, fields, statics, invocation, casts, throw and catch |
| API tokens | the six imported packages, read out of their export files into a committed table |
| Native classes | Util, card exceptions, APDU, JCSystem, Applet, OwnerPIN, and supported key/algorithm objects |
| Applet lifecycle | install, register, select/reselect, process, deselect and reset |

The committed OpenFIPS201 standard-cs2 fixture installs, registers, accepts selection,
and answers the checked PIV commands through `microcard-sim serve-jcvm`. PIN retries
persist between commands. Other variants require separate evidence; unsupported cipher,
signature, and key-agreement requests fail at their factories.

The shared core connects authenticated GlobalPlatform loading and installation to
JCVM through `jcvm_card::Card` and `transport::Endpoint`. The host lifecycle test sends
real SCP03 messages, installs the committed PIV applet, selects it, checks PIN retries
across reboot, and deletes it. `serve-jcvm-managed MANAGEMENT_KEYS STATE_DIR` uses this
path with persistent files; `serve-jcvm-managed-binary` uses the shared framed transport.
The separate `engine-jcvm` board build uses the same adapter with NVMC storage.
Both DK and dongle layouts cross-link; physical execution remains unverified.

The shared C4 receiver enforces container identity, an engine-specific size limit,
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
before the next poll. After a callback succeeds, the durable session commits its state before the final
cancellation check. Late cancellation suppresses the response while preserving that
commit. Execution or persistence errors reload authenticated state.
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
The registry loader authorizes signed packages before erasing, stages images in
unreferenced slots, verifies readback, and commits activation metadata. It protects
the old image through write failures and cancellation. Package reads verify both flash
and the current registry binding. Installation commits a dedicated heap before
publishing its instance, using a fresh derived key even after an interrupted attempt.
Reopening verifies every committed image and heap without reinstalling. The adapter
serves GP status records, domain discovery, and authenticated applet APDUs with their
original instruction, parameters, and data. Encrypted ISD applet commands retain their
protected CLA until the applet's secure-channel unwrap; other commands receive the
unprotected CLA. GP management commands are dispatched only in class `80` after
transport verification. Basic-channel plain `00`/`10` APDUs can select and invoke
applets without inheriting SCP03 authority; the applet enforces its own access policy.
Protected command chaining uses `14`/`94` with the complete CLA covered by C-MAC.
Native APDU CLA queries follow the [Java Card 3.0.5 encoding rules](https://docs.oracle.com/cd/E59935_01/api/javacard/framework/APDU.html):
secure messaging uses bits 4/3 for channels 0–3 and bit 6 for channels 4–19;
chaining uses bit 5. Both queries return false for reserved `20`–`3F` and invalid
`FF` classes. Decoding these flags does not authorize additional transport channels.
Incoming APDU data is fully buffered. `setIncomingAndReceive()` may be called once
per command; `getIncomingLength()` and `getOffsetCdata()` require that call and
remain valid only before switching to outgoing transfer. Invalid sequences throw
`APDUException.ILLEGAL_USE` using a reserved exception object, including when the
transaction undo capacity is exhausted. Each callback starts fresh receive state.
Outgoing setup and send calls report catchable `APDUException` reasons for invalid
sequences, response lengths, and source bounds. Rejected sends retain the previously
accepted response. A successful `setOutgoingAndSend()` forbids later sends, including
zero-length calls; source bounds are checked before publishing its outgoing state.
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

## Acceptance evidence

One Load File Data Block is committed at `crates/microcard-engine-jcvm/tests/vectors`, with its MIT notice, the applet revision it was built from and the digests of both the CAP and the block. Twelve PIV commands and their expected status words are committed beside it. `scripts/piv_vector_acceptance.py` replays them with no argument, and the checkpoint gate and CI both run it.

Half of those commands are authentic encodings taken from NIST Special Database 33 contact captures. The captured responses are deliberately absent, because that card was personalised and the card under test is blank, so a captured response would disagree for a correct reason. What carries over is the command encoding. Every entry is the case 4 form a real host sends, carrying a trailing expected-length byte.

## Version and container

| Item | Value |
| --- | --- |
| Java Card | Classic 3.0.5 as the first target version |
| CAP format | 2.1, compact |
| Instruction decoding | all 185 JCVM opcodes; execution excludes `jsr`/`ret` and requires `ACC_INT` for integer operations |

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

## Unsupported features

These features are outside the current executable profile. Full Java Card conformance
is outside this cleanup; [release readiness](READINESS.md) owns the delivery blockers.

| Feature | Current behavior |
| --- | --- |
| `jsr` and `ret` | decoded and rejected; subroutine dataflow verification is absent |
| Logical channels and `MultiSelectable` | basic channel only |
| Shareable interfaces and Java Card RMI | cross-context invocation is unsupported |
| Garbage collection | bounded bump allocation; no reclamation of individual live objects |

Reserved opcodes are always rejected. Each managed instance has separate heap state;
this does not establish support for Java Card shareable-object firewall semantics.

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

MC04 journals image descriptors and stores code in dedicated flash slots. JCVM
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

JCVM sessions retain checked image handles instead of owning a second code
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

Structural verification is mandatory at load. It covers the header magic and flags, directory tiling without gaps or overlaps, import resolution, applet offsets landing on method headers, class consistency through a bounded acyclic superclass walk, constant pool tags and token ranges, per-method stack and local bounds, exception handler ranges on instruction boundaries, and an instruction-boundary bitmap built by reachability that every branch, switch and handler target is checked against.

Branch offsets are signed and count from the address of their own opcode, and a target that misses a boundary is refused. That single check removes the whole class of attacks where a jump lands on an operand byte and turns a constant into an opcode. Switch tables are measured from their own operands before anything indexes into them, and lookup switch pairs must be sorted, which is what lets a card search them.

Reachability is a finding rather than a preference. A method in a CAP file records no length, and the offsets that name methods do not name all of them. The class method tables hold virtual methods, the constant pool holds static and constructor references, and the Applet component holds install entry points. All eight test packages still carry at least one method that none of those name, so the byte after a method's last instruction is not reliably the start of anything known. The Descriptor component would say, and a Load File Data Block leaves it behind. Decoding everything between two named offsets therefore decodes an unnamed method's header as though it were bytecode.

Decoding by reachability sidesteps that. Bytes no path reaches are never decoded, and because every branch target is checked against the map, execution cannot reach them either. A method is still bounded above by the next offset the package does name, which is what stops a branch from entering another method's body while running on the first method's frame.

Full type and dataflow verification is deferred. In its place the operand stack and the locals carry a one-bit reference tag per slot, checked on every push and pop, which makes reference and primitive confusion unrepresentable at runtime. This is the opposite trade from the MC04 engine, which verifies hard and runs lean, and it is deliberate.

## Volatile and persistent memory

Array clear events occupy spare bits in the existing six-byte object header. The heap
can clear reset-scoped arrays across contexts and deselection-scoped arrays for one
context without reallocating objects or changing references. `JCSystem.isTransient`
reports the recorded event. Negative factory lengths throw `NegativeArraySizeException`;
invalid events throw `SystemException.ILLEGAL_VALUE`, and exhausted transient storage
throws `SystemException.NO_TRANSIENT_SPACE`. VM exceptions and API `throwIt` exceptions occupy a reserved
120-byte runtime prefix allocation before applet installation. Null dereferences,
division by zero, array bounds, and allocation failures remain catchable with a full
heap and commit log. Operand-stack and structural errors remain interpreter failures.
Snapshots with an incompatible runtime prefix are explicitly rejected.
These event meanings follow [the Java Card API](https://docs.oracle.com/cd/E59935_01/api/javacard/framework/JCSystem.html).

CAP static array initializers and non-default primitive values are applied before
installation. Recovery restores the saved values rather than overwriting them with
their initial values. SELECT processing returns the PIV application template and
applies its configured six-attempt contact PIN limit; the first two failed PIN checks
therefore return `63C5` and `63C4`.

`Card.reset()` clears both transient array kinds, the APDU buffer, execution words and
tags, native OwnerPIN validation flags, and runtime exception reasons. It retains
installed objects, persistent array values, PIN retry counts, and explicit applet
exception reasons. `Card.save_into()` writes used heap bytes to a
caller-owned buffer and removes volatile values from that copy. `Card.restore()`
checks object boundaries, typed references, roots, ownership, and native PIN state
without running installation again. The committed PIV applet test verifies that PIN
retry counts survive restoration; saving does not clear the live session.

Card exception constructors, `throwIt`, `getReason`, and `setReason` share one native
implementation. Reason updates do not roll back. Runtime exceptions are reused per
class and context, separately from explicit applet-created exceptions. Applets may
hold runtime exceptions, the APDU object, and the shared APDU buffer in local variables;
field/static/array stores raise `SecurityException`. Recovery rejects saved applet
references to those temporary objects and nonzero saved runtime exception reasons.

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
Key-material creation checks allocation and undo capacity before publishing references.
Key-pair generation reserves both component updates together. Catching a capacity
failure and committing therefore cannot retain a partial first import or generation.
Cipher and signature initialization similarly reserve their complete metadata updates
before changing state. Provider results are staged before successful key or signature
publication; transient state follows its declared clear event.

Restoration rejects the former layout that placed transient key material in persistent
arrays. This storage support does not enable unsupported cipher or signature algorithms.

The generated bindings describe Java Card API names; they do not establish algorithm support.
The simulator's default JCVM host uses the shared platform provider for SHA-256
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

The managed acceptance defines and imports an AES-128 management key through
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
INITIALIZE UPDATE discards old transport authority and reloads the selected applet
from authenticated storage before opening the new channel. This preserves routing
for clients that select PIV before authenticating, while clearing PIN validation and
reset-scoped secrets. A failed reload fails the channel setup. Explicit transport
reset and authentication failures still discard selection. Root-management test
clients select the ISD explicitly before opening their channel.

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

JCVM transaction natives share an 8 KiB before-image log for heap payloads and
static fields, including record overhead. Space is reserved before begin and wiped
on commit or abort. Writes are admitted before mutation; exhaustion throws
`TransactionException.BUFFER_FULL`. Nested begin and unmatched commit/abort report
`IN_PROGRESS` and `NOT_IN_PROGRESS`. Commit-capacity queries include metadata cost.
New allocations need no before-images: abort wipes the allocation tail, and committed
projections exclude it. Key updates and algorithm initialization reserve complete
metadata before publishing values or changing active streaming state.

Explicit abort restores conditional writes. Returning or throwing from an applet
callback with an unfinished transaction aborts it; process answers `6F00`. PIN
presentation counters and validation, transient arrays (including the APDU buffer),
and non-atomic copy/fill operations are excluded from rollback. PIN updates remain
conditional. An abort that allocated objects clears their storage and transient
references and ends the session before any stale frame references can execute;
reset or reopening the recovered session is required. This follows the allowed
session-termination behavior in [JCSystem.abortTransaction](https://docs.oracle.com/en/java/javacard/3.1/jc_api_srvc/api_classic/javacard/framework/JCSystem.html).
Snapshots with a persistent APDU-buffer header or without the reserved framework
exception prefix are explicitly rejected by runtime-layout validation; there is no
automatic erase or conversion.

An in-command `commitTransaction()` saves an authenticated snapshot before
discarding its undo log. Cancellation or failure afterward recovers that committed
state. A failed checkpoint stops execution and recovers the last valid journal record.
Installation publishes only after its complete callback succeeds. Storage serializes
a borrowed view into its existing staging buffer, clearing volatile contents there.
Host tests cover OpenFIPS201 object activation followed by cancellation and sampled
byte-write failures during nonce reservation, erase, payload, commit marker, and
monotonic anchoring. Reopening the journal must expose the complete old or new object;
a completed checkpoint must expose the new object.
Transport acceptance also kills the simulator between encrypted certificate-upload
fragments, then checks the old certificate, a fresh replacement, and reboot recovery.
This does not simulate interruption inside an individual flash write.

Bytecode `newarray` and `anewarray` throw `NegativeArraySizeException` for negative
lengths. Failed `new`, `newarray` and `anewarray` allocations throw
`SystemException.NO_RESOURCE` through the same handler dispatch as explicit and
native throws (JCRE §10.1). Work or call-frame budget exhaustion and cancellation
still end execution; applet handlers cannot intercept them.

`Util.arrayCompare` validates both complete ranges before comparing, including empty
requests and ranges whose first byte differs. Utility bounds and null errors throw
catchable `ArrayIndexOutOfBoundsException` and `NullPointerException` objects, as
required by the 3.0.5 `Util` contract. Work-budget exhaustion still ends execution.
Bulk copy, fill and comparison charge one work unit per requested byte before the
operation. Insufficient work leaves fill/copy destinations unchanged; atomic fills
participate in rollback and non-atomic fills do not.

Cipher creation preflights its holder and streaming-state array together. If the heap
cannot fit both, it leaves no incomplete holder or consumed allocation tail.

`RandomData.generateData` returns no value; `nextBytes` returns the ending offset.
Both reject empty requests with `CryptoException.ILLEGAL_VALUE` before calling the
entropy provider, as required by the 3.0.5 API. Both charge one work unit per output
byte after validating the destination and before calling the provider.
`MessageDigest.doFinal` similarly charges input bytes after validating both ranges.
Insufficient work leaves the destination untouched and does not call either provider.

The protected `OwnerPIN` validation-flag accessors share the public validation
state. `setValidatedFlag` follows the default conditional-state rule in JCRE §9.3;
PIN presentation and reset methods retain their explicit API exceptions.
PIN replacement and reboot validation honor the configured maximum without a
separate 32-byte limit. It reserves the complete conditional update before changing PIN bytes or
metadata; invalid constructor limits and oversized replacements report
`PINException.ILLEGAL_VALUE`.
Invalid PIN presentations throw the API-specified null or bounds exception while
retaining the consumed retry across transaction abort (3.0.5 `OwnerPIN.check`).
PIN checks checkpoint their retry decrement before comparison and checkpoint a
successful counter reset before returning. Reset/unblock also checkpoint their
counter changes. During an active transaction these snapshots restore conditional
heap/static before-images in staging and exclude new allocations, preserving the
live transaction. PIN validation and transient buffers remain absent from snapshots.
Checkpoint failure stops execution; host cancellation tests confirm a consumed attempt
survives recovery. Installation still publishes only its completed state.

Each completed bytecode instruction checkpoints ordinary persistent writes before
execution advances, returns, or enters an exception handler. Native calls checkpoint
on return, with earlier PIN and transaction publication boundaries retained.
Cooperative cancellation saves any remaining writes using the same committed-state
projection. Successful checkpoints clear the write marker. Allocations outside transactions
mark their headers for persistence, including transient-array headers; failed
allocations do not. Transactional writes and transient payload writes alone do not
trigger another snapshot. Storage
failure stops execution instead of reporting a successful cancellation checkpoint.

A completed instruction cannot advance past a failed checkpoint. Power loss during
publication recovers the preceding committed state or the complete new record.
Checkpoints append small heap/static changes in authenticated 1,024-byte frames. Larger changes, transaction
commits, and exhausted append space use a full snapshot in the next journal slot.
Recovery replays complete frames, checks generation continuity and the rollback
anchor, and refuses to reuse partial tails. Interrupted rotation preserves the
previous committed chain or the completed replacement snapshot.

`PersistentView.save_range` stages bounded committed windows, projects undo records,
and clears transient payloads, PIN validation, and runtime exception reasons. The
fixed-size write tracker merges heap/static intervals and excludes uncommitted
allocation tails. Heap and static changes share one authenticated record. Both are
validated before replay mutates scratch state; the complete resulting snapshot must
fit its storage quota. A provider or flash failure stops the operation. Full snapshots
and records use the same providers, with no software retry.

The board still consumes one bit from separate 4 KiB generation and nonce counters
per commit/encryption attempt, limiting each to 32,768 values. Append records reduce
erases but do not extend these counters. Remaining work includes auditing internal
native bulk-write/allocation failure boundaries, counter lifetime, and the remaining
native-API transaction semantics.
A passing host workflow does not establish Java Card guarantees or physical execution.

To measure host flash traffic, build `microcard-sim` with `--features heap-metrics`,
set `MICROCARD_FLASH_REPORT` to a fresh JSONL path, and run
`scripts/jcvm_transport_acceptance.py`. Reports contain operation names, requested
byte counts, and slot sizes, never state contents. A missing report is not zero I/O.
Counts exclude partial failed writes, physical NVMC word traffic, image writes, and
counter-page initialization; they aggregate setup and all simulator sessions.

The matched lifecycle run passed with checkpoint appends: 97 slot erases
(5,783,552 bytes) and 392 program calls (958,294 bytes), versus 114 erases
(6,897,664 bytes) and 426 program calls (1,179,061 bytes) at baseline `95c5c37`.
Both used 110 nonce reservations and 108 generation advances. Raw reports are
`work/jcvm-mj04-checkpoints.jsonl` and `work/jcvm-flash-baseline-95c5c37.jsonl`.
With instruction-level publication, the same lifecycle passes with 102 erases
(6,111,232 bytes), 830 program calls (1,043,490 bytes), 324 nonce reservations and
322 generation advances (`work/jcvm-instruction-checkpoints.jsonl`, based on
`8caa8cb` with instruction checkpoints). This is the durability cost, not a space
optimization. These are workload totals, not a single-card lifetime estimate.

Additional software implementations of SHA-384, P-384, RSA, or 3DES are outside this release cleanup.

## Upstream test coverage

Our acceptance scripts do not run the complete OpenPhysical suite. The fixture and
this inventory use upstream revision `9f3b99bd0f2600beea7e5c053613d8baef2b7716`.

- **Applet unit tests:** upstream `ant test` and `test-all` execute Java classes in
  its JVM emulator. The eight variants cover standard/FIPS, CS2/CS7, and attestation
  on/off. Passing these upstream does not prove that our CAP interpreter works.
- **NIST command vectors:** the [upstream runner](https://github.com/OpenPhysical/OpenFIPS201/blob/9f3b99bd0f2600beea7e5c053613d8baef2b7716/tools/piv_test_runner/README.md)
  requires a separately installed NIST PIV Test Runner 5.0.1 package. Its harness
  accepts `emulator` or `pcsc`. Our `nist_acceptance.py` stages a transport-only
  adaptation for MicroCard without editing that checkout or vector expectations. The
  bridge implements `NistCardTransport` with the shared Java simulator transport.
  It pins a private simulator copy before creating the seed, so concurrent builds
  cannot change the executable between provisioning and reboot. It copies a closed
  seed per vector, preserves persistent state across reset, uses an explicitly
  synthetic ATR, and rejects contactless operations.
- **Personalized data and VCI:** upstream wrappers provision GSA ICAM objects and
  run SP 800-85B or CS2/CS7 matrices. These require matching credentials, objects,
  profiles, and crypto support. RSA, P-384, SHA-384, and 3DES gaps prevent claiming
  all-profile coverage; unsupported cases must remain explicit in results.
- **Current MicroCard evidence:** `piv_vector_acceptance.py` checks selected blank-card
  command status words, not captured personalized responses. `jcvm_transport_acceptance.py`
  exercises signed loading, authentication, PIN-gated P-256 signing, certificate
  replacement, and recovery using the standard CS2, attestation-disabled fixture.

The bridge lifecycle check passes against the pinned upstream interface: installed
applet selection, PIN retry persistence across reset, independent vector state, and
contactless rejection. The installed NIST PIV Test Runner 5.0.1 executes through this binding.
`SelectCommand:1` exposed a missing partial-AID selection path and passes after that
runtime fix, with unchanged upstream expectations. Selection chooses the bytewise
lowest matching installed AID, with exact matches preceding their extensions, and
passes the original requested AID bytes to the applet. Missing targets retain the
current selection. Next-occurrence selection remains unsupported.

### Run upstream acceptance

Build the simulator and wallet first. The upstream checkout must match the pinned
revision above; NIST modes also need its separately installed Test Runner 5.0.1 and
compiled tools. All output directories must be new. Each vector receives an isolated
copy of a closed seed. No physical card is accessed.

Check transport selection, retry persistence, state isolation, and contactless rejection
without NIST jars:

```sh
python3 scripts/nist_acceptance.py --upstream /path/to/OpenFIPS201 \
  --check-transport --out work/nist-transport
```

Run the original ECC256 configuration, with its matching published keys and certificates:

```sh
python3 scripts/nist_acceptance.py --upstream /path/to/OpenFIPS201 \
  --config /path/to/OpenFIPS201/tools/piv_test_runner/config/OpenFIPS201-ECC256.xml \
  --provision-config --suite card-contact --out work/nist-p256-contact
```

This profile reports **37 passed, 25 failed, 1 skipped**. It lacks identity/biometric
objects and still declares a 3DES 9E key, which is unsupported. Those failures remain
visible. Use `--test SelectCommand:1` for one vector, or `--seed DIR` containing
`keys` and `state` for an existing closed simulator with matching personalization.

The signed OpenFIPS201 package requests 4,000,000 execution work units; the engine
default remains 1,000,000. One measured ECDH request consumed 2,548,595 units,
including Java EC-point validation. This does not establish worst-case device latency.
The ordinary transport check covers independently verified ECDH after reboot and
rejection of an off-curve point without losing selection.

### Complete derived P-256 identity

The original GSA golden identities require RSA private keys. The following generator
preserves GSA 46 data objects and identity fields, issues matching P-256 certificates
from a public test-only CA, and writes a corresponding NIST configuration:

```sh
python3 scripts/nist_identity.py --upstream /path/to/OpenFIPS201 --out work/p256-identity
python3 scripts/nist_acceptance.py --upstream /path/to/OpenFIPS201 \
  --config work/p256-identity/config.xml --identity-folder work/p256-identity/identity \
  --provision-config --suite card-contact --out work/p256-identity-contact
```

The combined identity imports all 11 objects and four keys and passes exact
readback after reopening. This exposed and fixed persistent-heap growth from repeated
ISO status exceptions: runtime exceptions are reused without aliasing explicitly
created applet objects. The combined run reports **58 passed, 4 failed, 1 skipped**
(`work/nist-lifecycle-memory-contact`, clean revision `e7deab9`):
preparation took 29.434 seconds and vectors 124.308 seconds on the host. All 63
individual outcomes match the preceding native-audit run (29.494 / 125.272
seconds). This run includes persistent lifecycle and recovery-memory changes but does not
deliberately exhaust counters; transport acceptance covers renewal separately. Remaining failures concern the original CHUID’s
2032-12-02 expiry exceeding the six-year window on 2026-09-20, and certificate
policies under the NIST profile. Its 9D certificate binding check also requests
a signature from the agreement-only key; ECDH passes separately. These remain
failures, not exclusions, and the key role is not relaxed for the test.

The remaining cases have distinct causes:

- `CHECK_BER_TLV_conformance:2`: the unchanged signed CHUID expires on
  2032-12-02, beyond the runner's six-year window on the recorded run date.
  Editing its date alone would invalidate its signature.
- `CHECK_certificate_profile:4`: the signing certificate retains GSA test policy
  `2.16.840.1.101.3.2.1.48.9`; the runner accepts policies ending in `.3.16` or `.3.7`.
- `CHECK_certificate_profile:6`: the key-management certificate has the same
  policy mismatch (the runner also accepts `.3.6`). Its key-binding assertion
  sends a signing request to the agreement-only 9D key and receives `6A86`.
  Keep agreement permissions intact; a matching ECDH binding check is required.
- `CHECK_certificate_profile:8`: the card-authentication certificate retains test
  policy `2.16.840.1.101.3.2.1.48.13`; the runner expects
  `2.16.840.1.101.3.2.1.3.17`.

`SecureMessagingErrorHandling:1` is skipped because the SELECT response does not
advertise secure messaging. This is missing coverage, not a passing result.
Policy substitutions would create a different derived fixture; they would not
prove that the original GSA image passes or establish issuer trust.
The complete contact-suite run does not cover the separate upstream RSA-2048,
P-384, contactless, or VCI profiles.

This is a **derived test identity**, not an original golden image or production
credential. The manifest records source/output hashes and the public PKCS#12 password.
The configuration declares P-256 authentication and no symmetric 9E key; test code and
expected status words are unchanged. GSA signed objects retain their original dates,
signatures, and policies. The test issuer URLs use `.invalid`; live revocation and
chain trust are not established.

### Application lifecycle persistence

`GPSystem.getCardContentState` reads the authenticated runtime heap header.
`setCardContentState` accepts application-specific states from `07` through `7F`
with the low three bits set, rejects installation-time calls, and checkpoints before
returning success. A checkpoint error terminates execution through the existing
storage-failure path. Recreated callback state no longer resets the lifecycle.
Lifecycle writes survive Java Card transaction aborts while the checkpoint excludes
conditional applet writes. This follows GlobalPlatform's independent transaction
semantics ([API mapping guidelines, section 7](https://globalplatform.org/wp-content/uploads/2018/06/2.1.1_Mapping_guidelines_v1.0.1-Final.pdf)).

Native tests cover callback recreation, abort, committed projection, and failed storage;
engine recovery covers preserved lifecycle and rejected old or invalid headers.
The existing transport workload now personalizes OpenFIPS201 after provisioning.
Its own status command reports `07` before personalization and `0F` on subsequent
callbacks, after abrupt simulator termination/reboot, and after journal renewal.
The same workload continues certificate replacement, signing, and ECDH afterward.
It also installs a second instance, checks independent lifecycle states, and renews
the personalized instance with both heap banks occupied and the other instance's
reset-scoped arrays retained.
This covers completed personalization recovery, not interruption inside its setter.

### Original ICAM object recovery

Keep original object-storage evidence separate from private-key conformance:

```sh
python3 scripts/nist_acceptance.py --upstream /path/to/OpenFIPS201 \
  --check-objects /path/to/OpenFIPS201/test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV \
  --out work/icam-object-recovery
```

All **11 original objects**, including the 6,326-byte facial image, pass exact
upstream readback after closing SCP03 and reopening the simulator. This mode imports
no private keys and runs no NIST vectors. Its separate `object-results.json` records
fixture hashes, runtime identity, status, and elapsed host time.

NIST reports retain preparation/runner logs, JUnit results, source/configuration/simulator
hashes, separate preparation/execution timings, and a dirty-tree marker. Skips remain
separate from passes. Host timings and upstream JVM results are not hardware evidence.

## Authorization

A raw Java Card CAP carries no MicroCard signature. Device installation requires its
MP05 envelope, whose P-256 signature binds the image digest and versioned manifest,
including the security domain and incarnation. The authenticated transport, signed
package verification, and registry ownership checks are distinct requirements.
The raw simulator loader is a development entry point, not the board loading path.

## Sources

The OpenPhysical OpenFIPS201 release matrix supplies the observed CAP and import
versions. The governing Java Card Classic 3.0.5 VM and runtime specifications are
available unchanged in the Reference Library; their exact paths and verified SHA-256
hashes are recorded in [REFERENCES.md](REFERENCES.md). Later editions are comparison
material only.

The 3.0.5 source review covers these implementation boundaries:

- VM §6.3 defines CAP header versions and `ACC_INT`; chapter 7 defines instructions.
  The specification defines CAP **2.2**. This profile's **2.1** loader is a supported
  subset, not complete 3.0.5 container support.
- Runtime §§6.2.1–6.2.2 and 6.2.8 define temporary entry points, global arrays and
  reference-store checks. Global arrays include both the APDU buffer and installation
  parameters. Installation reuses the protected global APDU buffer rather than
  allocating an ordinary persistent parameter array. Access checks precede the
  bytecode's operation.
- Runtime §§7.1–7.9 define conditional persistent updates, callback transaction
  boundaries, abort, transient exclusions and commit capacity. Section 7.6.3 permits
  terminating a session after aborting a transaction that allocated objects.
- Runtime §§9.2–9.3 require temporary API exception objects and conditional updates
  to internal API state unless the particular API specifies an exception. Crypto
  intermediate-state exclusions must therefore be checked per API, not generalized
  to all native object metadata.

This establishes source provenance and the reviewed rules, not full conformance.
A complete loader/verifier and native API audit against 3.0.5 remains release work;
the unsupported features listed above remain outside this profile.

### Larger allocation qualification

Run the same two-instance workload with a larger certificate reservation:

```sh
cargo build --locked -p microcard-sim --features heap-metrics
python3 scripts/heap_profile.py --output work/jcvm-large-heap.json -- \
  python3 scripts/jcvm_transport_acceptance.py --certificate-capacity 20000
```

The default remains 4,096 bytes. OpenFIPS201 reserves both current and pending
certificate buffers. The 20,000-byte case passes functional acceptance but reaches
341,421 requested host bytes at revision `5e3efcc`; it does not fit the board heap
on that metric. This is a capacity stress workload, not a maximum-allocation proof.

Patch recovery validates both heap and static-field changes before allocating the
replacement snapshot. It copies the unchanged prefixes and applies spans directly
inside the final CBOR byte strings, avoiding separate heap/static scratch copies.
The original authenticated snapshot remains intact until the replacement is complete;
growth starts zeroed and shrinkage excludes the discarded tail.

On nRF52840, renewal borrows its ciphertext directly from the exclusively owned
staging flash bank. After staging and byte-for-byte verification, the writer drops
the owned ciphertext before authenticating the mapped copy. Recovery checks the
record digest and authentication before preparing the destination bank, then copies
that same immutable ciphertext without re-encryption. The borrow prevents staging
mutation; heap and registry writes use disjoint regions. This removes one record-sized
RAM allocation during authentication. File-backed staging retains the buffered path;
its 20,000-byte capacity workload still peaks at 251,517 requested host bytes.
This source-level allocation reduction is not a physical device heap measurement.

At the idle counter-renewal boundary, the live applet wipes and releases execution
words and reference tags. Heap objects, statics, selection, and reset-scoped arrays
remain owned by the same applet. After journal handoff, the runtime restores zeroed
execution buffers before permitting another callback. Any maintenance or allocation
failure follows the existing path that discards the session rather than executing
with incomplete scratch storage. The 8,192-word profile releases 17,408 requested
bytes during renewal; supported frame limits are unchanged.
