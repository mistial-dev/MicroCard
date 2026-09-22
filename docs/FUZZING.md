# Coverage-guided fuzzing

Sustained campaigns provide explicit release evidence. Development and security-checkpoint gates omit them. Build an affected target when its interface changes. Run a short reproducer only for a concrete regression. Reserve the commands below for a dedicated fuzz checkpoint or release candidate.

Install the runner inside the ignored project work directory:

```sh
cargo install cargo-fuzz --locked --root work/fuzz-tools
python3 scripts/fuzz_campaign.py signed_packages --seconds 300
python3 scripts/fuzz_campaign.py boundaries --seconds 300
python3 scripts/fuzz_campaign.py crypto_arguments --seconds 300
python3 scripts/fuzz_campaign.py domain_sequences --seconds 300
```

The required `--seconds` argument prevents an accidental invocation from starting a sustained default run. The runner uses `nightly-2026-09-19` explicitly without changing the default toolchain. Install that toolchain separately if absent. Logs, source/lock hashes, source revision, dirty status, duration, seed hashes and corpus counts go to `artifacts/fuzz/`. Each run passes its `input-corpus` directory explicitly to libFuzzer and writes new discoveries there. An existing `fuzz/corpus/<target>` is retained as an additional input; crashes remain under ignored `fuzz/artifacts/`. Before this wiring correction, runner-created seeds were not supplied to libFuzzer and recorded corpus counts described unused seed directories. Historical execution statistics remain in the actual run logs. Retain minimized crash inputs as regression fixtures if a failure is found. A wall-clock timeout also bounds startup/build hangs.

## Targets

- `boundaries`: raw signed-package, MC04 assembly and short-APDU parsing plus SCP03 authentication/unwrap with public test-only keys.
- `signed_packages`: starts from the compiled MC04 Counter assembly, then signs intact, structurally mutated, replaced-image or replaced-manifest cases with a public test-only P-256 seed. Accepted packages are parsed again and their process entries execute with native calls rejected. This reaches validation behind the signature gate. VM fuel and allocation limits still apply.
- `crypto_arguments`: derives bounded keys, IVs, nonces, AAD, messages, signatures and public keys from each input. It exercises round trips and tamper rejection for the crypto operations exposed by managed native bindings.
- `domain_sequences`: takes ISD ownership with the compiled MC04 `mscorlib`, loads the Kdf108 provider in the ISD, then loads compiled MC04 Counter, KeyOperations and Kdf108Consumer assemblies in one SSD. It fills the domain's eight-instance limit and evolves the SSD through HMAC, CMAC, CBC, CCM, KDF calls, stale key handles, byte records, install, uninstall, select, process, provider unload guards, dependency replacement/relink, malformed staging, deletion/recreation, reopen and injected journal failures. Deterministic corpus entries invoke every KeyOperations and BlobRecords command and a complete provider replacement. The checked-in fixtures are compared byte-for-byte with fresh preprocessor output by `scripts/check.py --checkpoint`. The target uses a compile-time fuzz-only authenticated-management entry point. Normal builds cannot call it. Its 64 KiB memory journal matches one production nRF52840 journal slot so the complete multi-assembly domain is exercised under the device storage envelope.

Seed generation is reproducible. Current preprocessed Counter, KeyOperations, Kdf108, Kdf108Consumer and `mscorlib` images are checked byte-for-byte by the host gate. The stateful target covers byte storage, HMAC and AES key handles, CMAC, CBC, CCM, managed cross-assembly calls and the core management state machine.

## Initial campaign evidence

On 2026-09-16, two 121-second non-sanitized campaigns completed without a crash:

- `boundaries`: 72,690,693 executions, 600,749 average executions/second, 368 coverage edges, 987 features, 28 MiB peak RSS.
- `signed_packages`: 520,459 executions, 4,301 average executions/second, 1,103 coverage edges, 2,300 features, 29 MiB peak RSS.
- `crypto_arguments`: 1,443,129 executions, 11,926 average executions/second, 273 coverage edges, 638 features, 27 MiB peak RSS.

These figures come from retained libFuzzer final statistics under `artifacts/fuzz/`. They provide useful initial evidence. A sustained production campaign remains pending.

## Stateful campaign checkpoint

The first `domain_sequences` campaign found a deterministic power-loss failure after 19 executions: interrupting erase of a previously committed inactive slot left its old commit marker programmed, causing startup to reject the intact newer slot. The journal now records a bounded reclaim interval on the surviving slot. A regression test interrupts every mutation while reusing a slot and requires recovery to expose the complete old or new value. Post-completion corruption still fails closed.

The original crashing input passed after the fix. A fresh 31-second non-sanitized campaign completed 5,636 executions without another crash, reaching 1,626 coverage edges and 7,525 features with 33 MiB peak RSS. This short run validates the regression and target operation. It is not the pending sustained campaign.

After adding HMAC key-handle ABI operations, another 31-second run completed 5,424 executions without a crash, reaching 1,775 coverage edges and 8,159 features with 31 MiB peak RSS. Both post-fix runs used the retained evolving corpus.

## Five-minute host campaign checkpoint

On 2026-09-16, all four targets completed bounded 300-second non-sanitized campaigns without a crash:

- `boundaries`: 48,271,019 executions, 160,368 average executions/second, 1,126 coverage edges, 3,772 features and 34 MiB peak RSS. Evidence: `artifacts/fuzz/boundaries-1789578809883706000`.
- `signed_packages`: 1,174,441 executions, 3,901 average executions/second, 1,710 coverage edges, 3,521 features and 29 MiB peak RSS. Every generated package was signed with the public test fixture key before verification. Evidence: `artifacts/fuzz/signed_packages-1789579122726201000`.
- `crypto_arguments`: 2,008,915 executions, 6,674 average executions/second, 273 coverage edges, 642 features and 29 MiB peak RSS. Evidence: `artifacts/fuzz/crypto_arguments-1789579431879284000`.
- `domain_sequences`: 14,247 executions, 47 average executions/second, 2,766 coverage edges, 13,765 features and 33 MiB peak RSS. Evidence: `artifacts/fuzz/domain_sequences-1789579741295184000`.

The aggregate is 51,463,622 executions over 1,204 seconds of libFuzzer time. Each `result.json` records the exact command, `nightly-2025-08-31`, target and lock hashes, source revision `edb47e9179808d4316607ac8d02903040f923683`, elapsed time, exit code and corpus count. The first campaign synchronized a missing direct `base64ct` entry into `fuzz/Cargo.lock`. Later records therefore say the tree was dirty, while their recorded target hashes show no target-source change. The lock update is retained with this checkpoint.

These runs satisfy the tracked five-minute host campaign checkpoint. They predate the
current binary-format targets and do not supply AddressSanitizer evidence. Current
sanitizer evidence appears below; a sustained sanitizer-backed production campaign
remains pending.

## Expanded stateful crypto checkpoint

After adding the second signed assembly and all eight installed instances, the retained corpus replayed without a crash and reached 3,386 coverage edges and 17,866 features. A subsequent 121-second run completed 2,415 sequences without a crash, added 152 corpus units, and reached 3,404 edges and 18,453 features with 32 MiB peak RSS. Evidence: `artifacts/fuzz/domain_sequences-1789580301460063000`.

The deterministic `crypto-services` seed directly executes commands 0 through 5 for both KeyOperations and BlobRecords. A one-input replay completed in 22 ms. This closes stateful HMAC, CMAC, CBC, CCM, stale-handle and byte-record coverage.

## Cross-assembly dependency checkpoint

The stateful target now installs Kdf108 in the ISD under the ISD signing identity and Kdf108Consumer in the SSD under its different pinned identity. The `dependency-replacement` seed proves that an active consumer blocks provider unload, then removes the instance and consumer assembly, replaces the provider with package version 2, reloads the exact consumer package, relinks it to the new provider digest and reinstalls the consumer. The consumer removes its SSD-owned AES key during uninstall, allowing an intentional reinstall while preserving the domain's other keys.

A 121-second non-sanitized run completed 2,329 sequences without a crash, added 206 corpus units, and reached 3,910 coverage edges and 19,535 features with 33 MiB peak RSS. Evidence: `artifacts/fuzz/domain_sequences-1789581140550326000`. Two failures found while extending the target were retained as lessons in the harness: SSD recreation must not reload an older ISD provider version, and a rebooted fake entropy stream can legitimately cause duplicate-nonce key creation to fail closed.

## Historical macOS sanitizer limitation

On macOS 26.6.2 with `nightly-2025-08-31`, AddressSanitizer stalled in its initializer before libFuzzer's input loop. A process sample showed nested AsanInitFromRtl and StaticSpinMutex::LockSlow during dyld/malloc initialization. The stalled processes were terminated. They do not count as completed campaigns.

`nightly-2026-09-19` starts correctly on the same host and is now the runner default.
Non-sanitized runs remain available for high-throughput coverage guidance, but do not
provide AddressSanitizer memory-error detection. Longer campaigns are still required
before production acceptance. Exhaustive testing and a security audit remain separate.

## Corpus wiring verification

After passing runner-created seeds explicitly, a 30-second `boundaries` campaign
without a sanitizer completed 4,303,626 executions in 31 libFuzzer seconds, with
75 new units and 32 MiB peak RSS. Its output corpus contains 77 files, including
the two supplied seeds; the recorded paths and count match the actual output.
Evidence: `artifacts/fuzz/boundaries-1789922912978765000`.

The matching AddressSanitizer attempt with `nightly-2025-08-31` compiled but produced
no libFuzzer startup statistics and hit the runner's 210-second wall-clock limit
(exit 124). A minimal sanitized program also hung before `main`, isolating this to
the sanitizer runtime on macOS 26 rather than MicroCard. Evidence:
`artifacts/fuzz/boundaries-1789922857083664000`.

With `nightly-2026-09-19`, the same 30-second AddressSanitizer campaign completed
2,265,961 executions, added 169 units, and reached 472 MiB peak RSS without a crash.
Evidence: `artifacts/fuzz/boundaries-1789924031712618000`. The runner now pins that
working nightly.

The first full target pass exposed stale PoC framing in `signed_packages` and
`domain_sequences`: both still generated MP04/JSON packages, so one only exercised
the rejection path and the other failed during bootstrap. Their fixtures now use
the production MP05 envelope, CBOR manifest, image digest, and CBOR management-name
contract. The unused fuzz-only `serde_json` dependency was removed.

After that correction, bounded AddressSanitizer campaigns completed without a
crash: `crypto_arguments` ran 11,389 inputs and added 79 units
(`artifacts/fuzz/crypto_arguments-1789924157317665000`); `signed_packages` ran
16,269 inputs and added 50 units
(`artifacts/fuzz/signed_packages-1789924802085719000`); and `domain_sequences`
replayed all 1,165 retained inputs
(`artifacts/fuzz/domain_sequences-1789924640081167000`). The domain corpus alone
took 87 seconds to initialize, so that run did not reach mutation despite a
30-second libFuzzer limit. Sustained campaigns remain separate from the ordinary
validation loop.

## Sustained sanitizer checkpoint

At clean revision `205b88a`, all four targets completed five-minute
AddressSanitizer campaigns with `nightly-2026-09-19` and no crash or sanitizer
finding:

- `boundaries`: 18,008,843 executions, 1,935 coverage edges, 5,343 features,
  324 new units, and 478 MiB peak RSS. Evidence:
  `artifacts/fuzz/boundaries-1790058420939172000`.
- `signed_packages`: 147,099 executions, 2,349 coverage edges, 4,629 features,
  240 new units, and 428 MiB peak RSS. Evidence:
  `artifacts/fuzz/signed_packages-1790058424203910000`.
- `crypto_arguments`: 103,080 executions, 1,041 coverage edges, 2,564 features,
  349 new units, and 471 MiB peak RSS. Evidence:
  `artifacts/fuzz/crypto_arguments-1790058430039865000`.
- `domain_sequences`: 3,596 executions, 6,880 coverage edges, 34,248 features,
  221 new units, and 472 MiB peak RSS. Evidence:
  `artifacts/fuzz/domain_sequences-1790058429642291000`.

Together the campaigns executed 18,262,618 inputs over 1,204 libFuzzer seconds.
Every `result.json` records the clean revision, target and lock hashes, exact
command, input corpora, sanitizer, elapsed time, and successful exit status.
