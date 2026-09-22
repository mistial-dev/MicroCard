# Managed transactions

Ordinary MC04 commands do not open a transaction. Persistent writes use the direct
command path and become durable at its safe completion boundary. They do not receive
rollback or multi-resource atomicity merely because a lifecycle or public method made
them.

Code that needs rollback explicitly uses the local `System.Transactions` profile:

```csharp
using var scope = new TransactionScope();
UpdatePersistentState();
scope.Complete();
```

The supported surface is the parameterless `TransactionScope` constructor and
`Complete()` in one compiler-generated using declaration. Leaving the scope after
`Complete()` commits synchronously. Leaving it without `Complete()` aborts. Nested
scopes, constructor options, escaped scopes, arbitrary enlistment, ambient flow, async
flow, promotion, and distributed transactions are outside the MC04 profile.
`Transaction.Current` is null outside a live scope. Inside it, applications may read
`Transaction.Current.TransactionInformation.Status`, which reports `Active`. The
canonical method-ending using declaration does not expose terminal state before the
engine has durably committed or aborted it.

MC04 does not implement managed exception handling. The preprocessor validates the
exact Roslyn disposal `finally`, lowers it to straight-line begin plus commit or abort,
and rejects every other exception region. A VM, native, cancellation, or storage failure
aborts an active transaction at the engine boundary. Application code cannot throw and
catch an exception to control durability.

Projected scope controls and ambient queries use internal native IDs 55 through 60.
Packages retain the stable transaction capability bits 46 through 48; runtime
authorization aliases the query calls to capability 46. The retired public
`DomainStorage` transaction methods and
`[Transaction]` annotation are not part of the managed API.

The public scope is lexical: it begins and ends inside one `Process` invocation. The
runtime retains a device-side compatibility shim for already-installed signed packages
that used the retired `DomainStorage` controls. The current framework no longer exposes
those methods, so new source cannot create that state. Reset, transport teardown,
selection, management, cancellation, runtime failure, or command-budget exhaustion
discards it. Credential retry floors remain monotonic and persist separately.

Lifecycle hooks cannot open a transaction. Response construction remains buffered, and
the analyzer plus preprocessor reject an explicit transaction path that can reach
irreversible `Hardware.Write`.

## Ordinary-path measurement

Run the focused host measurement with:

```sh
cargo test -p microcard-core --features mc04,software-crypto \
  ordinary_commands_avoid_rollback_state_and_commit_only_changes -- --nocapture
```

The post-change debug build measured the following on the host. Latency is diagnostic,
not a device budget.

| Command | Rollback snapshots | Journal commits | Programmed | Erased | Host latency |
| --- | ---: | ---: | ---: | ---: | ---: |
| No-op | 0 | 0 | 0 B | 0 B | 1.34 ms |
| Integer write | 0 | 1 | 951 B | 16 KiB | 1.86 ms |
| Blob write | 0 | 1 | 957 B | 16 KiB | 2.12 ms |

Zero snapshot reservations also means zero bytes allocated for transaction rollback.
The measurements prove that implicit staging is gone. They also expose the remaining
cost: the current two-slot snapshot journal erases a slot for every changed command.
No comparable pre-change counter trace was retained, so this document does not invent a
historical delta. Physical flash latency remains a board measurement.
