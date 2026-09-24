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

The full physical extended scan is not yet a release result: early key probes
took about 1.4 seconds each, and the run was interrupted. An independently built
applet must still exercise OwnerPINx methods, transaction behavior, and reset
state through Java bytecode. Full JCAlgTest, flash interruption, and production
provisioning remain release work. The physical smoke result does not imply
P71D321 compatibility.
