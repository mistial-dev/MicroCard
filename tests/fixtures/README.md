# Device-verifier fixtures

`transaction_records.mca` is deterministic output from `samples/TransactionRecords` and must match a fresh run of the current preprocessor.

`transaction_runtime_negative.mca` is the last deterministic output from `tests/TransactionRuntimeNegative` before the independent preprocessor learned to reject explicit transaction paths to `Hardware.Write`. The current analyzer and preprocessor must reject that source. Its framework reference uses the stable Framework 1.0 ABI identity, so rebuilding the host framework does not alter the fixture. The retained unsigned MC04 image is packaged and signed only with a test key inside the Rust test so the device runtime still proves it rejects a host-check bypass.
