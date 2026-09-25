# Domain storage

Each SSD owns one persistent application store shared by all assemblies loaded into that SSD. The runtime derives the SSD from trusted execution context. Managed code cannot name another domain. Deleting the SSD revokes the store with the rest of that domain.

`AssemblyContext.Current.Storage` exposes `GetInt32` and `SetInt32` for up to
512 integer records. It also exposes `GetBytes`, `SetBytes`, `ContainsBytes`, and
`DeleteBytes` through typed `StorageId` values. Byte records are limited to 64 entries,
1,024 bytes per value, and 8,192 bytes total per SSD. A missing byte record reads as an
empty array, so callers use `ContainsBytes` when absence differs from an empty value.
Deleting a missing byte record faults the invocation.

Ordinary execution mutates the live command state without allocating a transaction
snapshot. A no-op writes no journal record. Changed state commits once when command
processing reaches a safe boundary, including an application-generated managed error
response. Cancellation, runtime corruption, unsafe termination, or persistence failure
reloads the last authenticated durable state. A journal interruption exposes either
the previous complete state or the new complete state after recovery.

An application allocates rollback state only by entering a
`System.Transactions.TransactionScope`. Disposing a completed scope publishes and
persists the candidate synchronously. Disposing without `Complete()`, reset,
deselection, expiry, or an unhandled application failure restores the saved state.
Transactions are lexical to one `Process` invocation, reject nesting, and cannot be
controlled by another applet. See [transactions](TRANSACTIONS.md).

Aborted transaction candidates and deleted domains zeroize application Int32 records
and byte-record allocations before releasing their memory. Replacing or deleting one
byte record wipes its released allocation immediately. Byte-record copies reserve
their exact length before state mutation. Native private-key entries and credential
verifier material have independent drop zeroization. Canonical serialization and
decrypted journal plaintext remain in zeroizing, fallibly reserved buffers.

The MJ03 journal encrypts and authenticates each snapshot with AES-CCM. The storage key is derived from both device-specific SCP03 management keys through a domain-separated AES-CMAC operation. Recovery rejects a wrong key and any changed authenticated header, ciphertext or tag, then revalidates all state invariants and stored package signatures.

An append-only generation anchor lives outside the journal slots. MJ03 management commits and JCVM PIN security checkpoints write and close an authenticated record before advancing that anchor. On recovery, a record exactly one anchor ahead finishes an interrupted advance. A record behind the anchor, more than one ahead, or absent after ownership was established fails closed. Anchor capacity is checked before any anchored mutation. The nRF52840 programs one previously erased 32-bit word per advance in a 4 KiB region. Recovery accepts only a contiguous programmed prefix followed by erased words; a hole, partial value, or other word is corruption. Each epoch has 1,024 anchor advances; the runtime never erases an anchor under the same key.

A second append-only counter reserves each snapshot encryption nonce before use.
Failed snapshot attempts consume nonce capacity without advancing the committed
generation. MJ07 appends derive unique nonces from that snapshot attempt and their
one-use offsets. The separate 4 KiB nonce region provides 1,024 snapshot attempts;
neither counter is erased under its current key. Exhausting either counter refuses
further anchored commits or snapshots until authenticated epoch renewal.
MJ01/MJ02 records are rejected rather than migrated. See [the wire contract](PROTOCOL.md#durable-activation).

MC04 rotates complete snapshots through three 64 KiB slots. JCVM uses two 8 KiB registry slots and two 64 KiB slots per heap bank. Before reusing a slot, the active record receives a reclaim-start marker. The target slot is erased and programmed, its commit marker is written last, and the prior active record then receives a reclaim-complete marker. Recovery accepts the prior record during an interrupted target erase or program and otherwise selects the highest authenticated generation. Host fault injection covers every byte mutation while recycling the three-slot ring. Earlier two-slot board layouts and word-per-generation anchors have no conversion path.

The JCVM slots alternate, spreading reuse across their 32 physical data pages.
NVMC skips pages that are already erased. This spreads wear within the allocated
slots but does not change the chip's finite page endurance. Historical per-page
measurements are in [the DK release record](JCVM_DK_RELEASE.md).

The simulator requires `monotonic.bin`, `nonces.bin`, and both slot files to appear as one storage set. Existing state without the nonce counter has no upgrade route. Removing the whole state directory represents fresh provisioning. On nRF52840, a one-way ownership word shares the management-key erase page. Firmware programs it before the first journal commit and rejects both markerless existing state and a programmed marker paired with completely erased journals and anchor. Because flash cannot restore a programmed bit without erasing the page and its keys, ordinary out-of-band persistent-state erasure requires fresh management keys. A debugger that can erase and rewrite the key page can still defeat this policy. Production debug lock and verified firmware boot remain required. Runtime management has no reset or anchor-erase command.

Once a commit starts modifying journal slots, any flash error disables further commits
until authenticated recovery succeeds. Clearing an injected I/O fault alone does not
authorize a retry or consume another nonce. The byte-cut recovery sweep checks this
alongside recovery of the previous or newly committed state.

JCVM checkpoint changes can follow a snapshot in bounded, word-aligned append
records. Append-enabled snapshots and records use the distinct MJ07 authenticated
header. Each record holds at most 980 plaintext bytes and ends with a four-byte
commit marker. Heap and
static patches share a bounded CBOR envelope tied to the base generation and
instance. Recovery validates the complete envelope before changing scratch state,
then selects the latest complete chain and reconciles its generation anchor.
Partially programmed tails require rotation to a new full snapshot. Oversized
changes and transaction commits also use snapshots. Snapshot-only readers reject
MJ07 even before the first append, so an interrupted
counter advance cannot hide an appended record. JCVM rejects old MJ03 heap journals
and MJ04/MJ05/MJ06 append journals without erasing them. MC04 retains MJ03 and does not include the append scanner.

Appending derives its AES-CCM nonce from the snapshot's reserved attempt and the
record's flash offset in a separate nonce domain. A torn append closes the epoch,
so an offset with any programmed bytes cannot be retried. Ordinary APDU completion
advances the authenticated record sequence without programming the monotonic
security anchor. OwnerPIN checkpoints advance both and must finish before their
methods return. Explicit transaction commits persist synchronously before return
without consuming a security anchor. Ordinary writes commit once at APDU
completion, including an applet-generated Java exception. Native internal failure
boundaries and counter lifetime remain under review. See [JCVM durability](JCVM_PROFILE.md#transactions-and-remaining-durability-work).

An OpenFIPS201 cold selection changes one applet-owned persistent byte, so it
does commit. A subsequent unchanged reselection after deselect performs no
flash program or erase and no journal encryption in the host fault model.

Java Card transient-array payloads stay in RAM and are cleared on reset or
deselection. Their headers and stable references remain persistent; ordinary
allocation patches carry only those headers, and recovery zero-fills the new
payload. A [`requestObjectDeletion()`](https://docs.oracle.com/cd/E59935_01/api/javacard/framework/JCSystem.html)
call is serviced after its callback and before the command's final checkpoint,
as required before the next `process()`.
If no object was reclaimed and the request marker returned to its authenticated
value, the command writes no heap record. A request already made durable by an
earlier checkpoint is still serviced after reboot, and its clearing is persisted.

The MJ07 delta plaintext is `[1, instance, heap_patch, static_patch]`, where each patch
is a CBOR byte string encoding `[1, base_generation, before_length, after_length,
[[offset, replacement_bytes], ...]]`. Each patch has at most 64 nonempty, ordered,
nonoverlapping spans. Replay checks both patches completely, exact base lengths and
generation, the instance, and the resulting snapshot quota before replacing state.
Growth is zero-initialized; truncation clears removed plaintext. Unknown versions,
noncanonical CBOR, malformed lengths, overlaps, and trailing bytes are rejected.

Records start at the next four-byte boundary after the encrypted snapshot record.
Each next offset follows the prior record's authenticated length, rounded up to
four bytes. The marker occupies the last word of that span; unused padding stays
erased. A torn record closes the epoch, so recovery never guesses where its
successor would have started. The record's
header, ciphertext, and tag use the existing 24-byte header and AES-CCM provider.
Snapshots use `MCJN3 || attempt_le64`; appends use `A || attempt_le64 ||
offset_le32`. MJ07 is authenticated in the header. The header generation stores the
security-anchor count in its high 32 bits and the record sequence in its low 32 bits.
Recovery accepts a sequence step with an unchanged anchor or one anchor step;
it rejects a lost anchored checkpoint when the physical counter is ahead.

## JCVM counter renewal

Snapshots and PIN checkpoints eventually exhaust the heap counters.
Resetting them under the existing key would reuse nonces and remove the rollback
anchor. Moving to a spare heap bank is insufficient: both supported board banks
may contain installed applets. Both JCVM layouts already reserve a separate 64 KiB
upload staging region, large enough for one complete encrypted heap record.

Registry v2 now encodes the pending owner and rejects inconsistent instance, bank,
identity, package, and record-length bindings. Ordinary operations and applet opening
fail closed while ownership is pending. Interrupted metadata publication retains the
old registry or the complete pending descriptor, verified by host fault tests.
Startup recovery now authenticates the staged digest, package, heap binding and
applet state, checks target geometry and registry counter capacity, then prepares
the bank. It copies the seed, verifies normal journal recovery, and publishes the
new identity before allowing execution or upload reset. Failures retain protected
pending ownership or recover a completed final publication. Host tests cover two
occupied banks, corrupted staging, wrong keys, partial bank copies, and interrupted
final publication; the recovery provider refuses heap-key encryption. The writer
now stages a live committed heap under a fresh reserved identity, verifies the
written record, and publishes pending ownership. It leaves the old bank and live
selection untouched. Encryption failure consumes its identity; an uncertain
publication retains staging until registry recovery decides ownership. JCVM storage owns
snapshot encoding and epoch-record encryption; registry renewal receives only a sealed
record to stage. The session handoff primitive reopens the authenticated journal and compares its
raw state with the live committed projection in bounded windows, then replaces only
the journal. It does not construct a second applet. It retains
the existing applet object, selection and transient state; mismatch prevents stale
execution. Seed validation and normal restore share a read-only validator. Validation borrows
the saved heap, allocating only the initial runtime layout and a reference bitmap.
It checks the configured quota before constructing that layout; no execution frames
or saved-heap copy are needed. The simulator invokes the explicit idle hook after
flushing its response. USB gives the `usbd-ccid` response a bounded drain interval
while continuing to poll, then invokes
the hook; the first pending deadline is retained under continuous traffic. The hook
compacts a nearly full append slot under the same key and reserves one fresh
snapshot nonce without touching the registry or security anchor. It rotates the
heap key through the authenticated registry protocol only when either local
counter is nearly exhausted. Active uploads defer maintenance
without aborting the upload. A maintenance failure drops selection; host processes
exit and the board reboots so startup recovery can resolve pending ownership. This
threshold does not guarantee that every command fits the remaining counter space.
`SeedRecord` now authenticates a bounded initial MJ07 record (anchor/sequence/attempt 1),
requires caller validation of its plaintext, and retains an immutable ciphertext
borrow. Its copy operation accepts only a wholly erased bank with empty counters,
reserves nonce 1, copies and reads back the exact record, publishes the marker, and
advances the generation to 1. It neither erases storage nor calls encryption.
Fault tests cover every publication cut and copying again after fresh preparation.
This primitive does not itself authorize bank preparation: registry recovery must
validate the pending descriptor, staged digest, applet state, and target geometry
before erasing anything.

Renewal uses that region as a recovery copy and the registry's existing durable
identity reservation as the root of a new heap-key epoch. It must preserve both
installed applets and their code, persistent state, and live volatile state.
The transition is serialized with uploads and management changes:

1. At a command boundary with no active transaction or upload, reserve a fresh
   identity from the registry nonce counter. Derive the new heap key from the root,
   bank, identity, and image digest using the existing heap-key derivation.
2. Serialize the committed heap with the new identity, encrypt its initial MJ07
   record exactly once, and write it to staging. Use generation/attempt 1 for this
   new key. Authenticate and validate the staged record before publishing metadata.
   A failed attempt abandons the identity; a later attempt reserves another one.
3. Commit a versioned pending-renewal descriptor in the registry. It binds the
   instance AID, bank, old/new identities, package digest, staged-record length and
   digest. This commit authorizes replacement of this bank and protects staging
   against upload, reset, deletion, or other reuse.
4. Authenticate the protected recovery copy before erasing any bank bytes. Erase
   the bank and its local counters, copy the exact encrypted record into its first
   slot, publish its marker, initialize nonce/generation counters to 1, and verify
   normal journal recovery. Retrying this phase copies the same ciphertext; it
   must never invoke encryption again under that identity.
5. Commit normal registry metadata pointing to the renewed bank and identity,
   retaining the same logical applet. Only then release staging. Rebind the live
   volatile cache through this trusted transition; do not treat renewal as deletion
   or replay initialization callbacks.

Recovery resolves pending renewal before opening applet sessions or accepting new
uploads. Before the pending registry commit, the old bank remains authoritative.
After that commit, the authenticated staging copy is authoritative until normal
metadata is published. Missing or changed staging data fails closed, without erase.
A completed bank copy is not exposed for execution while metadata is still pending.
Thus restart may repeat bank preparation without losing newer applet writes or
reusing a nonce for different plaintext. Registry commit uncertainty must be resolved
before choosing either phase.

Startup reads staging using the authenticated record length, independently of the
volatile upload length, and resolves ownership before resetting upload state.
The registry writer requires idle durable staging and capacity for identity
reservation plus both metadata commits. It releases unowned staging on preparation
failure, and retains it whenever publication ownership is pending or uncertain. The JCVM simulator now uses a fixed 64 KiB `staging.bin`
with synced writes and the same clear-bits-only programming rule as flash. Layout
v2 requires this file; v1 layouts and missing/truncated staging fail without repair.
Card opening preserves its bytes, although it discards incomplete upload lengths.
An integration test covers reopening, bounds, forbidden bit restoration, and
incompatible/incomplete storage sets. Volatile-only staging explicitly refuses
pending renewal recovery; both board and simulator builds provide durable staging.
Counter renewal happens between commands. A command that exhausts its remaining
budget fails normally, with committed ordinary writes retained and an open
transaction rolled back; renewal must not silently replay the command.

Acceptance must cover both occupied banks, interrupted staging, both registry
commits, bank erase/copy/counter initialization, repeated recovery, stale staged
records, provider failure, and resumed applet behavior with retained volatile state.
Combine fault cuts around distinct publication phases rather than duplicating
low-level journal byte sweeps. Verify that resumed copying performs no encryption.
The registry's own counters remain finite and must retain capacity for both metadata
commits and uncertain attempts. This design does not establish an unlimited service
life or prove flash endurance; those limits still need measured budgets.
