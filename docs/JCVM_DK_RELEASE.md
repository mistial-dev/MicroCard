# Java Card DK release contract

The nRF52840 DK Java Card build is a separate firmware profile. It must accept a
standard Java Card Load File Data Block through an authenticated GlobalPlatform
SCP03 administrator session. An applet author does not sign a MicroCard envelope.
Firmware update trust and administrator credentials remain separate requirements.
MC04's signed-package format is unaffected.

The compatibility target is Java Card Classic 3.0.5 and the **supported** entries
in the published JCOP4 P71D321 JCAlgTest result. This target does not make
MicroCard a P71D321 card. A factory may report support only when its key import,
generation, operation, failure, and reboot behavior passes. Algorithms marked
unsupported in that result are not implementation targets.

The source result is pinned in `vendor/jcalgtest/p71d321-reference.csv.gz` and
identified by `vendor/jcalgtest/client.lock.json`. Run
`python3 scripts/jcalgtest_profile.py` to expand its 22 sections into a JSON
support matrix. The pinned result contains **8,607 probes, 288 supported**.
The upstream applet is v1.8.2 with the optional-DES allocation patch described
in its vendor README. The published P71D321 result used client v1.8.3; the
release run must use a pinned build of that client, not silently substitute
the older v1.8.2 release JAR.

Build the pinned upstream desktop client with its own Ant project:

```sh
git clone https://github.com/crocs-muni/JCAlgTest.git work/jcalgtest-client-src
git -C work/jcalgtest-client-src checkout 4c9d2906e358818f6ab6fdfb3286f168d4936f60
python3 scripts/jcalgtest_client.py --source work/jcalgtest-client-src --build-only
```

The helper checks the full commit and reported client version. It launches the
upstream main class with the required dependency JARs; upstream's
`package-for-store` JAR omits JCommander and json-simple. Pass upstream client
arguments after `--`, including the exact PC/SC reader and an output path.

Run the unmodified upstream client against the host JCVM through the
`javax.smartcardio` adapter. The runner provisions the pinned applet through
SCP03, saves the raw client output, CSV, log, and run metadata, and fails if a
CSV contains a transport or crash result:

```sh
python3 scripts/jcalgtest_host_client.py \
  --source work/jcalgtest-client-src \
  --output /private/tmp/microcard-jcalgtest-extended \
  --mode ALG_SUPPORT_EXTENDED
```

At the current host revision, the upstream basic and extended scans completed
without transport-error rows. This verifies that unsupported `KeyBuilder` types
raise a catchable Java Card exception and the applet remains selected. It does
not imply P71D321 support; the supported entries still require real operations,
failure, and reboot checks on the DK.

The extended host scan reports **55 supported** probes against the P71D321
reference's **288**. There are **233 missing supported** probes and **zero support
claims outside the profile**. Both `OwnerPINBuilder` extended variants now
construct real PIN objects. The host's pinned upstream client reported both as
supported in a complete 8,607-probe extended scan; the physical DK passed the
two targeted factory probes. The runner writes
the exact differences to `profile-comparison.json`; a factory result alone is
not an algorithm acceptance. An extended run with missing or extra probes fails
instead of passing as a partial result.

## Conformance work

| Area | Current evidence | Release gate |
| --- | --- | --- |
| CAP loading | Host accepts unsigned LFDB under SCP03; CAP 2.1 structural checks | Complete supported CAP 2.2 type/dataflow verification |
| VM | OpenFIPS201 and JCAlgTest execute host-side | Type/dataflow verification and every admitted opcode; no verifier bypass |
| Runtime | Basic-channel lifecycle and two distinct heaps | Logical channels, shareable interfaces, firewall, reset, transactions, and object lifetime tests |
| API | 104 JCAlgTest factory probes | Complete declared 3.0.5 method behavior and real operations for every claimed algorithm |
| GlobalPlatform | Host SCP03 unsigned OpenFIPS201 and JCAlgTest load/install/select; earlier physical signed OpenFIPS201 selection | Unsigned load, install/delete, interruption and recovery on DK |
| USB and storage | MakerDiary CCID smoke at an earlier revision | DK PC/SC, abort/disconnect, controlled interruption, endurance and measured latency |

Optional Java Card features must be declared explicitly. They cannot be inferred
from the imported API version or a passing JCAlgTest support scan. A full result
keeps the upstream CSV and log untouched and treats a transport error, timeout,
crash, or unfinished mode as an invalid measurement, never as an algorithmic
"no".

## Tiny-crypto-c backfill

The merged upstream `tiny-crypto-c` revision is pinned at
[`c485a1e3fb6c8f632f3523ce314e49c3312e3c0c`](https://github.com/mistial-dev/tiny-crypto-c/commit/c485a1e3fb6c8f632f3523ce314e49c3312e3c0c). It adds
caller-workspace ECDSA digest signing and bounded key-pair generation for the
library's P-192, P-256, and P-384 curves with injected entropy. The signing
change passed RFC 6979 sample vectors, negative cases, sanitizer runs, and all
179 configured CTest cases; the subsequent key-generation change passed focused
EC and sanitizer suites. Optional external vector corpora were not supplied.
For a Cortex-M4 `-Os` object with these three curves enabled, `ec.c` grew from
4,827 to 6,045 text bytes before link-time dead-code elimination. The EC source
is vendored as an exact slice in `vendor/tiny-crypto-c`. Its no-std Rust
bridge passes host and ARM compilation and a focused cross-language lifecycle
test. The bridge now covers public-key derivation and validation plus raw ECDH
for both curves, with malformed-point rejection and cleared failed outputs.
The DK firmware does not link this bridge yet, and Java Card P-192/P-384
signing and key generation remain unsupported. Before enabling it, connect a
fail-closed board provider and pass key import, operation, failure, and reboot
acceptance.

The P71D321 result also reports on-card EC prime-field generation at 128, 160,
224, and 521 bits, beyond CC310 P-256 and this library's P-192/P-384 slice.
Those sizes remain implementation gaps; the bridge alone does not close the
declared compatibility target.

## Baseline before unsigned loading

At source revision `4c8c095d48d793a5b823f7efab21ab81e33eb8b5`, the DK
JCVM USB/CCID profile linked with **230,388 text, 148 data, and 198,284 BSS
bytes**. Reproduce it with the `measure` helper in `scripts/board_budgets.py`
using `engine-jcvm` and `usb-ccid`. The host JCAlgTest factory scan passed 104
probes in **0.13 s** and the 12-command PIV vector scan passed in **0.07 s** on
this machine. These are whole-process host timings, not device APDU latency.
Flash operations, device install/selection timing, heap high-water, and power
loss behavior have no current-DK measurement. Do not fill those cells from the
MakerDiary or host figures.

After the host unsigned-load change, the DK USB/CCID profile links at **229,192
text, 148 data, and 198,284 BSS bytes**. This is a link measurement, not a
physical timing result.

The DK release gate also needs sealed provisioning, secure boot/update policy,
debug lockout, and independent cryptographic review before deployment as a
production secure element. A robust USB DK test target is the nearer milestone.

On 2026-09-24 the external J-Link EDU Mini V2 connected to DK P18 Debug In read
the nRF52840 SWD ID. Nordic recovery, key provisioning, and verified JCVM ELF
download then succeeded. With the target powered at J3, this command passed on
the physical DK:

```sh
python3 scripts/jcvm_board_acceptance.py \
  --reader 'MicroCard MicroCard virtual smart card' \
  --management-key .keys/first-test-management.key
```

It authenticated SCP03, loaded the unsigned OpenFIPS201 CAP, installed it, and
selected its PIV applet. The `usbd-ccid` 0.5.0 crate initially rejected the
`SetDataRateAndClockFrequency` request sent by macOS after a fresh reset. The
local library patch responds with the fixed descriptor values; three consecutive
SWD resets followed by SCP03 and PIV selection passed. Allow about two seconds
after reset for macOS reader enumeration. The linked development image uses
**231,184 text, 148 data, and 198,284 BSS bytes**.

After adding the two extended PIN types, the same DK loaded the pinned JCAlgTest
CAP through SCP03 and passed its version, digest, `OWNER_PIN_X`, and
`OWNER_PIN_X_WITH_PREDECREMENT` probes. Reproduce the targeted check with:

```sh
python3 scripts/jcalgtest_gp_acceptance.py \
  --reader 'MicroCard MicroCard virtual smart card' \
  --management-key .keys/first-test-management.key --select-only
```

### JCAlgTest latency on the DK

The performance baseline is local unsigned commit
`572ea69a8fb5419501c69fff36dd2c7268786713`, running at the supported
**64 MHz** CPU clock through the PC/SC reader
`MicroCard MicroCard virtual smart card`. The pinned desktop client is
`4c9d2906e358818f6ab6fdfb3286f168d4936f60`; the installed LFDB SHA-256
is `f11c20bb665d15b40b28b99707da7f0e007e2ca8877f20eca0bd860a30d01393`.
Reproduce the targeted host-observed selection and factory times with:

```sh
python3 scripts/jcalgtest_gp_acceptance.py \
  --reader 'MicroCard MicroCard virtual smart card' \
  --management-key .keys/first-test-management.key \
  --select-only --timings --repeat 12
```

At that baseline, warm digest and OwnerPINx factories were about **17–19 ms**
through PC/SC, with a genuine heap-journal rollover at **1.47 s**. The
available trace counted **31 programmed words and zero erases** for one
77-byte append patch. Cold selection, no-op, persistent write, PIN failure,
transaction commit, install, and recovery did not yet have comparable
per-workload percentiles; those are measurement gaps, not zero-cost paths.

The original image never started TIMER0, so its microsecond timeout and idle
maintenance deadlines stayed at zero. A live SWD capture confirmed two reads a
second apart both returned zero. The corrected image starts a 32-bit, 1 MHz
timer before crystal startup. With opt-in `latency-trace` counters, a physical
JCAlgTest probe showed that an ordinary applet APDU took about 292 ms while
deferred maintenance spent 5.5 s, including 4.5 s erasing flash. The maintenance
trigger compared remaining program-once counter words with 1024 even though
each counter page holds only 1024 words, so it renewed after every eligible APDU.
It now checks remaining append frames in the active heap journal.

The next trace found a separate 1.45 s cost on JCAlgTest factory probes: a
single dirty interval spanned 3,756 heap bytes, exceeding the 1 KiB patch frame.
That forced a full snapshot and a 64 KiB heap-slot erase on every probe. A bounded
eight-interval dirty tracker preserves sparse writes; a matching bounded encoder
now appends their separate ranges. On the same physical DK, digest and two
OwnerPINx factory APDUs fell from about **1,454 ms to 17 ms** each. A 120-APDU
repeat stayed near 17–19 ms for those probes, apart from one 1.47 s full
snapshot when the journal actually filled. This is a measured latency result,
not an algorithm-conformance claim.
The ordinary `development-debug` link is **231,832 text, 148 data, and 198,284
BSS bytes**; the latency counters are not linked into that image.

Reproduce host-observed APDU timings with `--timings --repeat 12` on the targeted
command above. For flash and VM-boundary counters, build with
`--features usb-ccid,latency-trace` in `scripts/prepare_first_flash.py`, flash
the resulting ELF, run the targeted command, then read the counters:

```sh
python3 scripts/read_jcvm_latency_trace.py \
  --probe 1366:1020:000802009660
```

The trace feature is excluded from the ordinary image. SWD attachment can
interrupt an active PC/SC session; finish the probe before reading counters.
The pinned upstream extended scan advanced through the key-builder section,
then lost the PC/SC reader at its `OwnerPINBuilder` type-1 probe. A software
reset restored the reader and the targeted probes still passed. The incomplete
CSV and log in `/private/tmp/microcard-jcalgtest-dk-latency-20260924` are
diagnostics, not a valid JCAlgTest result. The failure needs a fresh trace
covering USB, flash, and reset reason before any further timing changes.
An independently built applet must still exercise OwnerPINx methods, transaction
behavior, and reset state through Java bytecode. Full physical JCAlgTest,
flash interruption, and production provisioning remain release work. The
physical smoke result does not imply P71D321 compatibility.

Classify a completed raw DK scan without changing its upstream CSV or log:

```sh
python3 scripts/analyze_jcalgtest_dk.py \
  --result /private/tmp/microcard-jcalgtest-dk-run \
  --elf /private/tmp/microcard-jcalgtest-dk-run/firmware.elf \
  --source work/jcalgtest-client-src
```

The analyzer pins the firmware and applet hashes, reader, ATR, client
revision, PC/SC latency distribution, the complete 8,607-probe matrix, and
all unexpected statuses. It rejects a scan that merely reaches its final
line after the applet has failed: `6982`, `6A82`, timeouts, and transport
errors cannot be counted as unsupported algorithms.
