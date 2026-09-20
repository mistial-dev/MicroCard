# Domain storage

Each SSD owns one persistent application store shared by all assemblies loaded into that SSD. The runtime derives the SSD from trusted execution context. Managed code cannot name another domain. Deleting the SSD revokes the store with the rest of that domain.

`DomainStorage` supports `GetInt32` and `SetInt32` for up to 512 integer records. It also supports `GetBytes`, `SetBytes`, `ContainsBytes` and `DeleteBytes` with integer keys. Byte records are limited to 64 entries, 1,024 bytes per value and 8,192 bytes total per SSD. A missing byte record reads as an empty array, so callers use `ContainsBytes` when absence differs from an empty value. Deleting a missing byte record faults the invocation.

Every assembly invocation operates on a private state copy. The complete mutation set commits only after successful execution and journal persistence. Explicit `DomainStorage` transaction controls may retain that candidate across at most sixteen basic-channel commands. The candidate remains volatile until commit. Abort, fault, reset, selection change, management traffic or reboot discards it. A journal interruption exposes either the old complete state or the new complete state after recovery.

Discarded state copies and deleted domains zeroize application Int32 records and byte-record allocations before releasing their memory. Replacing or deleting one byte record wipes its released allocation immediately. Byte-record copies reserve their exact length before state mutation. Native private-key entries and credential verifier material have independent drop zeroization. Canonical serialization and decrypted journal plaintext remain in zeroizing, fallibly reserved buffers.

The MJ03 journal encrypts and authenticates each snapshot with AES-CCM. The storage key is derived from both device-specific SCP03 management keys through a domain-separated AES-CMAC operation. Recovery rejects a wrong key and any changed authenticated header, ciphertext or tag, then revalidates all state invariants and stored package signatures.

An append-only generation anchor lives outside the journal slots. A commit writes and closes the authenticated journal record before advancing the anchor. On recovery, a journal exactly one generation ahead finishes that interrupted advance. A journal behind the anchor, more than one generation ahead, or absent after ownership was established fails closed. Anchor capacity is checked before any journal mutation. The nRF52840 clears one bit per generation, least-significant bit first, in a 4 KiB region. Any cleared bit after an erased bit is corruption. This provides 32,768 runtime commits and the runtime never erases the anchor.

A second append-only counter reserves each encryption nonce before use. Failed attempts
consume nonce capacity without advancing the committed generation. Its separate 4 KiB
region provides 32,768 attempts; neither counter is erased in service. Exhausting either
counter refuses further commits, while the last committed snapshot remains readable.
MJ01/MJ02 records are rejected rather than migrated. See [the wire contract](PROTOCOL.md#durable-activation).

The nRF52840 rotates complete snapshots through three 64 KiB slots. Before reusing a slot, the active record receives a reclaim-start marker. The target slot is erased and programmed, its commit marker is written last, and the prior active record then receives a reclaim-complete marker. Recovery accepts the prior record during an interrupted target erase or program and otherwise selects the highest authenticated generation. Host fault injection covers every byte mutation while recycling the three-slot ring. Earlier two-slot board layouts and word-per-generation anchors have no conversion path.

The simulator requires `monotonic.bin`, `nonces.bin`, and both slot files to appear as one storage set. Existing state without the nonce counter has no upgrade route. Removing the whole state directory represents fresh provisioning. On nRF52840, a one-way ownership word shares the management-key erase page. Firmware programs it before the first journal commit and rejects both markerless existing state and a programmed marker paired with completely erased journals and anchor. Because flash cannot restore a programmed bit without erasing the page and its keys, ordinary out-of-band persistent-state erasure requires fresh management keys. A debugger that can erase and rewrite the key page can still defeat this policy. Production debug lock and verified firmware boot remain required. Runtime management has no reset or anchor-erase command.

Once a commit starts modifying journal slots, any flash error disables further commits
until authenticated recovery succeeds. Clearing an injected I/O fault alone does not
authorize a retry or consume another nonce. The byte-cut recovery sweep checks this
alongside recovery of the previous or newly committed state.

JCVM checkpoint changes can follow a snapshot in fixed 1,024-byte append frames.
Append-enabled snapshots and frames use the distinct MJ04 authenticated header.
Each append frame holds at most 980 plaintext bytes and has a four-byte commit
marker at a fixed position at the frame end. Heap and
static patches share a bounded CBOR envelope tied to the base generation and
instance. Recovery validates the complete envelope before changing scratch state,
then selects the latest complete chain and reconciles its generation anchor.
Partially programmed tails require rotation to a new full snapshot. Oversized
changes and transaction commits also use snapshots. Snapshot-only readers reject
MJ04 even before the first append, so an interrupted
counter advance cannot hide an appended record. JCVM rejects old MJ03 heap journals
without erasing them. MC04 retains MJ03 and does not include the append scanner.

Appending reserves a fresh nonce and advances the generation counter just as a full
snapshot does. It avoids a slot erase but does not extend counter lifetime. These
records currently serve existing JCVM checkpoints; persistence after each ordinary
operation remains unfinished. See [JCVM durability](JCVM_PROFILE.md#transactions-and-remaining-durability-work).

The MJ04 delta plaintext is `[1, instance, heap_patch, static_patch]`, where each patch
is a CBOR byte string encoding `[1, base_generation, before_length, after_length,
[[offset, replacement_bytes], ...]]`. Each patch has at most 64 nonempty, ordered,
nonoverlapping spans. Replay checks both patches completely, exact base lengths and
generation, the instance, and the resulting snapshot quota before replacing state.
Growth is zero-initialized; truncation clears removed plaintext. Unknown versions,
noncanonical CBOR, malformed lengths, overlaps, and trailing bytes are rejected.

Frames start at the next four-byte boundary after the encrypted snapshot record,
then advance in 1,024-byte steps without overlapping the slot's three trailer bytes.
Their marker is at frame offset 1,020. Unused padding stays erased. The frame's
header, ciphertext, and tag use the existing 24-byte header, AES-CCM provider, and
`MCJN3 || attempt_le64` nonce construction; MJ04 is authenticated in the header.
