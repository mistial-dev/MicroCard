# Managed transactions

`[Transaction]` declares that a managed method and every managed call it makes join the current command transaction. Nested annotated calls join the outer transaction. They never commit independently. Transaction scope cannot be suspended.

The Rust command dispatcher executes assembly processing against staged records, keys,
and credentials for its owning domain. It borrows immutable package metadata and leaves
other domains untouched. Selection stages at most the old and new domains, reusing
one stage when both callbacks share a domain. Both callbacks commit together;
failure preserves the previous selection and live fields. Domain creation/deletion,
policy updates, and SCP03 sequence reservation use small undo records. Package
activation and instance installation/removal still copy the complete state;
removing those copies remains release work.
Successful execution journals the candidate
before publishing it. A journal error restores live mutable fields; after an uncertain
write, reboot recovery may select either complete committed generation, never a partial
mixture. Credential retry floors are the deliberate exception to application rollback.

APDU response construction is buffered until execution returns and may occur in a transaction. Irreversible hardware output cannot be rolled back. The analyzer walks local calls and constructors and reports `MCA0008` when an annotated method or a method reaching explicit transaction controls can also reach `Hardware.Write`. The preprocessor independently recomputes both effects from compiled method bodies. MC04 signs the annotation effect in each method body header, and the Rust verifier propagates irreversible-output effects over the complete verified local and cross-assembly call graph before activation, recovery or execution. Runtime sequencing checks remain authoritative for a validly signed image that bypassed both host checks.

The attribute describes one atomic command. For a transaction spanning commands, managed code calls `SecurityDomain.Current.Store.BeginTransaction()`, then ends it with `CommitTransaction()` or `AbortTransaction()`. These methods bind through native ABI IDs 46 through 48 only from the pinned framework identity.

The pending mutable fields exist only in RAM and belong to the selected domain incarnation and assembly-instance AID. Later commands from that same instance see the pending writes. Other durable state readers do not. A commit journals the complete candidate atomically. Abort discards it. Reboot, transport reset, SCP03 teardown, selection, management, cancellation, a managed fault, an invalid control sequence or command-budget exhaustion discards it. Credential retry floors remain monotonic and commit separately even when application changes are discarded; their commit stages only the owning credential store.

The basic-channel profile permits one pending transaction and requires commit or abort by its sixteenth successful command, counting begin. Commit and abort are terminal storage operations for their invocation. Only response bytes or status may be emitted afterward. Lifecycle hooks cannot open a transaction. Irreversible hardware output and transaction controls cannot occur in the same invocation in either order.
