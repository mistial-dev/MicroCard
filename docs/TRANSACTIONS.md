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
`Transaction`, `Transaction.Current`, and `TransactionStatus` are deliberately rejected
until the device has a typed, query-only ambient-state ABI.

MC04 does not implement managed exception handling. The preprocessor validates the
exact Roslyn disposal `finally`, lowers it to straight-line begin plus commit or abort,
and rejects every other exception region. A VM, native, cancellation, or storage failure
aborts an active transaction at the engine boundary. Application code cannot throw and
catch an exception to control durability.

Projected scope calls use internal static native IDs 55 through 57. Packages retain the
stable transaction capability bits 46 through 48, and runtime authorization aliases the
internal calls to those bits. The retired public `DomainStorage` transaction methods and
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
