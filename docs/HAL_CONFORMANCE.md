# HAL conformance

The `hal-conformance` feature provides one portable scenario runner for board and simulator test adapters. It checks observable behavior rather than implementation details.

The current deterministic simulator adapter covers:

- repeatable seeded entropy and cleared output after entropy failure.
- logical GPIO capability denial.
- stable caller-buffer device identity and reset-reason reporting.
- monotonic time and watchdog expiry.
- a short APDU split across transport fragments and a bounded response send.
- a partial flash program that remains visible after a simulated power cycle, including rejection of an attempted zero-to-one bit transition without further mutation.
- fixed-buffer FIPS 180-4 SHA-256, RFC 4231 HMAC-SHA-256, RFC 4493 AES-CMAC including segmented input, NIST SP 800-38A AES-128 block/CBC, NIST CAVP AES-CCM, and P-256 public-key, deterministic ECDSA and ECDH known answers through the selected crypto provider.
- CBC padding and CCM tag rejection with cleared plaintext, malformed P-256 verification inputs, invalid P-256 private-scalar failure mapping, invalid ECDH peer rejection and cleared fixed outputs.

The simulator fault controls are test-only. Normal simulator runs continue to use operating-system entropy. `conformance::run_crypto` is reusable independently of the full HAL adapter. Both runners use fixed arrays and caller-owned buffers, so future board adapters can reuse them without adding heap requirements to firmware.

Run the simulator adapter with:

```sh
cargo test -p microcard-sim --locked
```

Physical nRF52840 conformance still requires a host adapter that can inject transport faults, observe watchdog reset reasons and interrupt flash programming without erasing the board.
