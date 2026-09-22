# Device-verifier fixtures

`transaction_records.mca` is deterministic output from `samples/TransactionRecords` and must match a fresh run of the current preprocessor.

`transaction_runtime_negative.mca` is the retained deterministic output from
`tests/TransactionRuntimeNegative` at the current assembly ABI, captured without the
preprocessor's transaction-effect rejection. The current analyzer and preprocessor must reject
that source because an explicit transaction reaches `AssemblyContext.Current.Runtime.WriteHardware`.
The unsigned image is packaged and signed only with a test key inside the Rust test so the device
runtime still proves it rejects a host-check bypass.
