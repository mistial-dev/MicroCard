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

Ordinary applet writes now remain in RAM until the idle maintenance task
authenticates and publishes them, normally two seconds after the last response
in a burst. Several commands can share one flash record. A later command can
read those writes before publication, but an unexpected power cut or VM failure
can lose them. Selecting a different applet flushes the old applet first. `OwnerPIN`
checkpoints, explicit `JCSystem.commitTransaction()`, and administrator security
state still publish synchronously before their operations return. An applet that
needs a durable atomic update must use an explicit transaction. This deliberate
power-cut relaxation means the ordinary-write path does **not** meet Java Card's
usual persistent-memory durability guarantee; it must be disclosed with test
results rather than claimed as full Java Card conformance.

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

The latest extended host and DK scans report **57 supported** probes against the
P71D321 reference's **288**. There are **231 missing supported** probes and
**zero support claims outside the profile**. Both ISO 3309 checksum factories
now work, and their operations pass focused host vectors and a DK smoke test.
Both `OwnerPINBuilder` extended variants now
construct real PIN objects. The host's pinned upstream client reported both as
supported in a complete 8,607-probe extended scan; the physical DK later
completed the same extended support scan. The runner writes
the exact differences to `profile-comparison.json`; a factory result alone is
not an algorithm acceptance. An extended run with missing or extra probes fails
instead of passing as a partial result.

## Conformance work

| Area | Current evidence | Release gate |
| --- | --- | --- |
| CAP loading | Host accepts unsigned LFDB under SCP03; CAP 2.1 structural checks | Complete supported CAP 2.2 type/dataflow verification |
| VM | OpenFIPS201 and JCAlgTest execute host-side | Type/dataflow verification and every admitted opcode; no verifier bypass |
| Runtime | Basic-channel lifecycle and two distinct heaps | Logical channels, shareable interfaces, firewall, reset, transactions, and object lifetime tests |
| API | 57 supported JCAlgTest probes; CRC16/CRC32 operations tested | Complete declared 3.0.5 method behavior and real operations for every claimed algorithm |
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
The first pinned upstream extended scan advanced through the key-builder section,
then lost the PC/SC reader at its `OwnerPINBuilder` type-1 probe. The incomplete
CSV and log in `/private/tmp/microcard-jcalgtest-dk-latency-20260924` remain
diagnostics, not a JCAlgTest result. An opt-in retained RAM/SWD trace showed
that the watchdog was fed during commands but not while the USB main loop idled.
The heap bank's 1,024 program-once counter words were also exhausted: renewal
returned early precisely when the bank needed renewal, and reboot recovery could
not map the single staging bank until it had been selected by a new upload.
The fixes feed the watchdog in the main loop, permit heap-bank renewal when its
counters are nearly exhausted, and map the existing staging bank after reset.
Flash page erases and batches of programmed words now return NVMC to read mode
and poll USB, using the existing CCID time-extension path when needed.

With the first corrected diagnostic image, the unmodified upstream v1.8.3
desktop client completed `ALG_SUPPORT_EXTENDED` on the DK: **8,607/8,607 probes,
zero error rows, and no reader loss**. Its host PC/SC APDUs had a **19 ms median,
21 ms p95, and 6,178 ms maximum**. The maximum is an actual heap-bank renewal;
ordinary factory probes remain near 19 ms. The run is preserved under
`/private/tmp/microcard-jcalgtest-fixed-20260924`, including untouched CSV and
console log, `analysis.json`, and the exact traced firmware ELF. The analyzer
pins firmware SHA-256 `57820defebd91bbb26b61daa5a4b78674e3acb9bbc36a7d65450e84f697e47f9`.
It reports **55 supported** probes against the target's **288**, leaving **233
P71D321-supported probes unimplemented**. A complete scan establishes transport
stability and a valid support result; it does not establish those missing
algorithms or their operation, failure, and reboot behavior. That diagnostic
run did not qualify the later normal image.
An independently built applet must still exercise OwnerPINx methods, transaction
behavior, and reset state through Java bytecode. Full physical JCAlgTest
performance modes, flash interruption, and production provisioning remain
release work. The physical smoke result does not imply P71D321 compatibility.

A later range-GC image stopped its extended scan after roughly 6,500 CSV rows;
that partial CSV is diagnostic only. SWD showed that the applet image and heap
journal authenticated on restart, but selection could not pass the pre-command
renewal check. A full append slot reopened with no append offset, and
`remaining_append_frames` incorrectly reported a storage error instead of zero.
After that fix, the next check exposed a separate resource limit: the registry
had used all **1,024 nonce words**, including one extra nonce for each heap
identity reservation, while only **684 commit words** were used. Installation
and renewal now use their reserved identity nonce for the same registry
publication, without reusing it for another encryption. The one-time counter
pages still have finite capacity; repeated full scans need a tested registry
epoch rollover or a fresh development-card provision. No incomplete scan is a
release result.

After the full-slot and nonce-reservation fixes in unsigned commit `52ed5b4`,
a freshly provisioned DK completed the pinned upstream v1.8.3
`ALG_SUPPORT_EXTENDED` scan on the **normal, non-traced firmware**. The untouched
CSV and console log, analysis, and exact ELF are in
`/private/tmp/microcard-jcalgtest-nonce-fix-dk-20260924`. The ELF SHA-256 is
`9370dd1c2e15f30bc791c814fc8aae91177c9a076771c3803f946e5d82c43ade`.
The analyzer accepted **8,607/8,607 probes with zero error rows**. The card
reported **55 supported** probes, leaving **233** positive P71D321 probes
missing. Host PC/SC timing over 17,222 APDUs was **23 ms median, 24 ms p95,
5,278 ms maximum**. Applet selection and the targeted factories passed again
after an SWD reset. SWD counter reads after the scan showed **911/1,024**
registry commit and nonce words used. This proves one complete support run,
not sustainable repeated scans; registry counter epoch renewal remains required.
Ordinary APDUs do not directly consume registry counters. They append to the
selected applet's heap journal; when that epoch fills, renewal uses two registry
records. The full scan's counter use therefore reflects repeated heap renewals,
not a Java Card requirement to increment a global counter for every write.
Renewal is currently checked on the command path, which also explains the
multi-second tail. A replacement design must prove nonce uniqueness across
interrupted writes and erased-slot reuse without charging ordinary commands
against a finite global registry counter page.
MJ05 replaces the fixed 1,024-byte append frame with a bounded, word-aligned
record. Old MJ04 heap media is rejected without erasure. After a development
factory reset, the normal DK image with ELF SHA-256
`009c6e0aad163c1f5c55cb94be42764f981a78f30471d747e84ce7ba164115df`
completed the same upstream extended scan. The untouched CSV and upstream log,
the recorded client exit code, analyzer result, and exact ELF are in
`/private/tmp/microcard-jcalgtest-mj05-dk-20260925`. It again produced
**8,607/8,607 probes and zero error rows**. Host PC/SC timing was **21 ms
median, 23 ms p95, 5,277 ms maximum**. SWD reads after the scan showed
**76/1,024** registry commit and nonce words used, versus **911/1,024** on
MJ04. Selection and targeted factories passed after an SWD reset. The smaller
records extend usable lifetime, but the finite registry and slow heap erase
remain release blockers.
MJ07 separates the authenticated heap record sequence from its physical
security anchor. Ordinary APDU writes and explicit transaction commits do not
program an anchor word; OwnerPIN checkpoints do. Idle append-slot compaction
uses a new snapshot nonce under the current key, reserving registry-backed key
renewal for a nearly exhausted local counter. Old heap formats are rejected.
On 2026-09-25, a freshly provisioned DK ran the same pinned upstream extended
scan with ELF SHA-256
`0618b26938fa787bf35a55fb20bcd628530b7cf1ca099e139d16313b1f8f4795`.
The untouched CSV and upstream log, analyzer result, exit code, and exact ELF
are in `/private/tmp/microcard-jcalgtest-mj07-dk-20260925`. The analyzer
accepted **8,607/8,607 probes, zero error rows**, and found **55 supported**
with **233 P71D321-positive probes still missing**. Across 17,222 host PC/SC
APDUs, latency was **20 ms median, 21 ms p95, 1,460 ms maximum**. These are
host observations, not isolated device execution times. SWD reads after
installation showed heap-bank 0 at **1 anchor / 2 nonce words** and the
registry at **4 / 4**. After the full scan they showed **1 / 44** and
**4 / 4**, respectively. An SWD reset followed by selection, version, digest
factory, and both OwnerPIN factory probes passed. Selection after reboot took
1,598 ms; the three factory probes took about 18 ms each. The finite local
nonce page and flash-erase endurance still need a workload-based lifetime
budget before claiming an always-on production target.
The scan used 42 additional snapshot attempts. Each completed rollover erases
one 64 KiB slot (16 flash pages); two slots alternate, so this workload is
approximately 21 erase cycles per page per full scan. Nordic specifies
[10,000 erase cycles per nRF52840 page](https://docs.nordicsemi.com/r/bundle/ps_nrf52840/page/nvmc.html).
That suggested roughly 476 identical scans to the rated limit in the MJ07
baseline, before margins, other writes, and failed attempts. It was a workload
estimate, not a safe service-life guarantee, and does **not** apply to the
current deletion-request behavior. Normal crypto APDUs that do not change
persistent state do not use this budget. Continuous write-heavy use still needs
a measured service-life target or higher-endurance storage.

An opt-in SWD wear trace on the same installed JCAlgTest applet identified the
cause: the client requests object deletion before nearly every probe. Servicing
each request on a later APDU journaled both setting and clearing a runtime bit.
The traced baseline completed all **8,607 probes** with **17,309 append
commits**, **29 idle compactions**, **451,058 programmed heap words**, and
**464 physical heap-page erases**. Each of the 32 data pages in the two slots
received 14 or 15 erases, so the existing slot alternation distributed this
wear evenly. A new page allocator would not address the unnecessary writes.

Servicing the request before the command-boundary checkpoint and omitting a
net-zero marker patch produced another complete **8,607/8,607** run with zero
error rows. Its SWD trace counted **186 append commits**, **zero idle
compactions**, **5,595 programmed heap words**, and **zero heap-page erases**.
The untouched CSV, upstream log, analyzer output, exact ELF, and trace are in
`/private/tmp/microcard-jcalgtest-wearfix-direct-dk-20260925`; the ELF SHA-256
is `8bf4a03947e72a46640ee9c0d1995d85c70b80247592057f68d9021fdae2f74b`.
These figures cover a previously installed applet, not a fresh provisioning
run. They measure this scan, not a general bound on persistent write traffic.
The per-page SWD counters were diagnostic code for these measurements and were
removed afterward. Normal firmware carries no per-page counters.
The subsequent build also omits transient-array payloads from allocation
patches. Its exact ELF SHA-256 is
`7f9c7732ff5211a32db7bfb6d45a863fa5692834a9a145ebb0c954cfd0aa837b`.
The untouched result and analysis in
`/private/tmp/microcard-jcalgtest-wearfix-final-dk-20260925` confirm
**8,607/8,607 probes and zero error rows** with **15.5 ms host PC/SC median,
17 ms p95, and 645 ms maximum** across 17,222 APDUs. The declared P71D321
gap remains 233 probes. The target's debug port did not permit an SWD counter
read after this flash, so the preceding build's wear counts must not be
attributed to this exact ELF.

After installing the applet with `scripts/jcalgtest_gp_acceptance.py`, the
physical scan used this command. Reader index `2` was the MicroCard reader on
this host; check the client's reader list before repeating it elsewhere.

```sh
printf '2\n' | python3 scripts/jcalgtest_client.py \
  --source work/jcalgtest-client-src -- \
  -op ALG_SUPPORT_EXTENDED -cardname MicroCard-DK \
  -outpath /private/tmp/microcard-jcalgtest-nonce-fix-dk-20260924 -fresh
```

For MJ05, use `-cardname MicroCard-DK-MJ05` and
`-outpath /private/tmp/microcard-jcalgtest-mj05-dk-20260925` after flashing the
MJ05 image and factory resetting old heap media. The client wrapper records its
exit status beside the untouched upstream CSV and log.
For MJ07, use `-cardname MicroCard-DK-MJ07` and
`-outpath /private/tmp/microcard-jcalgtest-mj07-dk-20260925`. The recorded run
invoked the pinned upstream main class with Microsoft OpenJDK 17 in an
interactive terminal and selected reader index `2`. A redirected client launch
on this host reported no readers while returning exit code zero; the wrapper
now rejects such runs when no new CSV was written.

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

On 2026-09-26, the DK's FICR reported QI package (`0x2004`) and AAF0 variant
(`0x41414630`), so Nordic erratum 199 applies. The pinned `nrf-usbd` driver now
enables its USB task workaround only around EasyDMA on affected silicon.
Firmware SHA-256 `6ff7d9ac95edaf9415519a5ba79a802f31ceb5452ac86165e854187c9232cb9c`
passed a complete physical extended scan: **8,607/8,607 probes, zero error
rows, no reader loss**. The raw CSV, upstream log, console transcript, exact
ELF, and analyzer report are preserved under
`artifacts/physical/microcard-jcalgtest-mj09-errata199-dk-20260926/`.
The CSV SHA-256 is
`2327e4fa33438fe2911d339631c4e70f976b0b30cfc38c45285e2da8c265c132`.
Host PC/SC latency across 17,222 APDUs was 14 ms median, 16 ms p95, and
642 ms maximum. The result still lacks 233 P71D321-supported probes, so it
does not establish profile compatibility.

An opt-in SWD trace of 100 deletion/factory cycles found two page erases,
7,906 programmed words since boot, and an 84,559 µs maximum USB polling gap.
The cycles passed with no reader loss; their host-observed factory latency was
18.44 ms median, 18.63 ms p95, and 285.82 ms maximum. Partial erase remains
conditional on a measured deadline or reconnect failure. USB unplug/replug
and physical power-cut publication tests remain open.

A second complete scan used opt-in `latency-trace` firmware SHA-256
`c5588ea9b4d45e42b2afa84c8053cbacefa38a3a8e59e10c7d18cddbdee120ea`.
It again passed all 8,607 probes with zero error rows or reader loss. Its
untouched CSV, upstream log, analysis, exact ELF, and SWD counter dump are in
`artifacts/physical/microcard-jcalgtest-mj09-trace-dk-20260926/`. The scan's
SWD totals were 13 page erases and 45,102 programmed words since boot;
maximum USB polling gap was 84,623 µs. The diagnostic image was replaced by
the normal image, and both installed applets selected after reset.

A software-controlled hub port disconnect interrupted an active PC/SC call;
a new SCP03 session and OpenFIPS201 selection then passed. This is a data-path
disconnect result. The nRF52840 `POWER.USBREGSTATUS` remained `0x3` when
both companion hub ports were switched off, so the test did not remove VBUS.
True VBUS removal and power-cut publication checks still need a physical
power-control path.

On 2026-09-26, a development-debug USB image added Java Card 3.0.5 ISO 3309
CRC16 and CRC32. The checksum holder keeps its intermediate state in a
reset-cleared transient array, so `update` creates no journal-dirty state.
Host tests compare default and seeded results with independent CRC vectors,
including overlapping output, reset, and transaction abort. The host runner
now rebuilds its simulator before scanning; the first same-day scan used a
stale binary and is not evidence for the change. Its corrected scan reported
57 supported probes, 231 P71D321-positive probes missing, and no extra claims.

Firmware SHA-256 `316e59f8927e6d6a84ca141dbb8fcd82004303d70c6a593d9b9cec7b3b2686b7`
then completed the pinned upstream extended scan on the DK: **8,607/8,607
probes, zero error rows, no reader loss**. The untouched CSV and upstream log,
exact ELF, analyzer report, and a focused Java probe are preserved in the
ignored local `artifacts/physical/microcard-jcalgtest-crc-dk-20260926/`
directory. The probe ran both checksum algorithms' `update` and `doFinal`
methods on the physical applet and repeated them successfully after reset.
Host PC/SC latency across 17,222 APDUs was 14 ms median, 16 ms p95, and
519 ms maximum. This is a valid support scan and a focused operation smoke,
not full P71D321 compatibility or an independent physical checksum vector.

The focused physical operation check is reproducible after the pinned JCAlgTest
applet is installed and selected:

```sh
java scripts/JCAlgTestCryptoProbe.java "MicroCard MicroCard virtual smart card"
probe-rs reset --chip nRF52840_xxAA --probe 1366:1020:000802009660
java scripts/JCAlgTestCryptoProbe.java "MicroCard MicroCard virtual smart card"
```

The pinned upstream static performance scan also completed on that CRC image,
but its result is **invalid**: four of 1,900 method rows have negative
baseline-adjusted times. The untouched CSV and log are under
`artifacts/physical/microcard-jcalgtest-performance-static-dk-20260926/`.
`scripts/analyze_jcalgtest_performance.py` classifies these separately from
unsupported algorithms, unmeasured operations, and transport failures.

The first variable performance attempt then reset the DK during a checksum
`doFinal` APDU. SWD trace on the exact diagnostic image recorded an attempted
63,082-byte allocation, 114,360 free bytes in total, a panic, and a software
reset. `AppletInstance::release_idle_memory` called `Vec::shrink_to_fit` before
heap-journal maintenance; that infallible reallocation can panic in fragmented
RAM. Keeping the already allocated heap buffer removed the panic. The same
physical checksum sequence then completed all four `update` and `doFinal`
operations without a reset. The diagnostic trace showed that a near-full
64 KiB heap slot still needs roughly two seconds for a snapshot/rollover.
That latency and the full variable performance scan remain release work.

A later diagnostic build, ELF SHA-256
`75914568c8697c8f0f2e6c8a90ec42cacec899c8689919c2274002be1d50d25c`,
kept a reusable snapshot buffer and queued ordinary writes for idle publication.
The physical CRC16, CRC32, and SHA-224 operation probe completed before and
after reset without a storage error. Its 12 APDUs produced one 167-byte heap
patch during a 10.7 ms idle maintenance call, with 53 programmed words and no
erase in that run. This is a focused smoke measurement, not an endurance result
or a complete upstream performance scan.

Repeating that probe on the same installed JCAlgTest applet eventually exhausted
its 64 KiB persistent heap. Before the allocation ceiling was corrected, a
response could succeed even though its later idle snapshot would not fit; idle
maintenance then reset USB. The heap ceiling now accounts for the applet's
static data, snapshot encoding, and record framing. The same near-full media
returned a quota error before publication, and the reader stayed available.
The native crypto factory now reports a catchable
`SystemException.NO_RESOURCE`; on the same near-full DK media, JCAlgTest
returned its `F205` exception result while the reader stayed available.
A fresh installation and complete upstream performance run followed.

For the full scan, pass `ALG_SUPPORT_EXTENDED` to
`scripts/jcalgtest_client.py` with the pinned client checkout and an empty
`-outpath` directory. Select the MicroCard reader when prompted. Analyze the
untouched result with `scripts/analyze_jcalgtest_dk.py` and the exact flashed
ELF. The physical test result above used a normal SWD attach; this external
probe did not attach under reset, though read, flash, and reset worked without
that option.

The normal USB link grew from 239,884 to **241,172 text bytes** and the dongle
link from 241,256 to **242,544**, an exact 1,288-byte cost for the two new
algorithms. At that revision, the ceilings left 328 and 206 bytes of headroom.
The separate flash-layout
check still enforces the actual image partition.

After SHA-224, RAM-first ordinary commits, and catchable native allocation
failure, the measured JCVM links are **242,696 text / 204,836 BSS bytes** for
DK USB and **244,044 text / 204,852 BSS bytes** for the dongle. The updated
text ceilings leave 304 and 306 bytes of headroom. These are link sizes, not
measured flash endurance or power-cut durability.

The pinned upstream static performance scan now completes on the DK with
firmware ELF SHA-256
`89202803793daa196b318435c2a00eb7a70d33e8bf029ad94744bc61dcff2d52`.
Its untouched CSV and log are in the ignored local
`artifacts/physical/microcard-jcalgtest-static-byte-dk-20260926/static/`
directory. The analyzer reports **1,900 completed method rows**, 64 measured,
1,824 unsupported algorithms, 12 illegal values, and no unmeasured rows,
negative timings, transport errors, or lost sessions. The PC/SC transcript has
2,545 APDUs, 19 ms median, 64 ms p95, and 35.255 s maximum. The maximum is
JCAlgTest's Java software-AES test, 50 blocks per command at 704.63 ms per
block. The diagnostic trace recorded 9 erases, 32,282 programmed words, 47
CCID time extensions, and no JCVM session error. Applet selection and its
probe passed again after a debugger reset.

Earlier scans failed at the software-AES preparation command with `6982` and
then `6A82`. The VM treated a byte static field as two image bytes. JCAlgTest
accesses one at the last byte of its static image, so the VM raised a bounds
error and discarded selection. Byte statics now use one image byte, with
sign extension on read, as Java Card specifies. The performance analyzer also
checks the raw APDU log so a lost session cannot appear as merely unmeasured.
Moving idle maintenance to two seconds after the **last** response in a burst
reduced the previous incomplete run's flash totals from 31 erases and 267,867
programmed words to 8 and 16,006. The later complete run used 9 and 32,282;
these runs differ in successful work, so they are not a controlled wear ratio.
Continuous command traffic can keep ordinary writes in RAM until traffic
pauses. The power-cut exposure remains intentional and unbounded in that case;
PIN, explicit transaction, and administrator boundaries still publish before
returning. Variable, ECC, and fingerprint performance modes remain unverified.
