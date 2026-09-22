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

## Conformance work

| Area | Current evidence | Release gate |
| --- | --- | --- |
| CAP loading | Host accepts unsigned LFDB under SCP03; CAP 2.1 structural checks | Complete supported CAP 2.2 type/dataflow verification |
| VM | OpenFIPS201 and JCAlgTest execute host-side | Type/dataflow verification and every admitted opcode; no verifier bypass |
| Runtime | Basic-channel lifecycle and two distinct heaps | Logical channels, shareable interfaces, firewall, reset, transactions, and object lifetime tests |
| API | 104 JCAlgTest factory probes | Complete declared 3.0.5 method behavior and real operations for every claimed algorithm |
| GlobalPlatform | Host SCP03 unsigned load/install/select; earlier physical signed OpenFIPS201 selection | Unsigned load, install/delete, interruption and recovery on DK |
| USB and storage | MakerDiary CCID smoke at an earlier revision | DK PC/SC, abort/disconnect, controlled interruption, endurance and measured latency |

Optional Java Card features must be declared explicitly. They cannot be inferred
from the imported API version or a passing JCAlgTest support scan. A full result
keeps the upstream CSV and log untouched and treats a transport error, timeout,
crash, or unfinished mode as an invalid measurement, never as an algorithmic
"no".

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

After the host unsigned-load change, the DK USB/CCID profile links at **229,184
text, 148 data, and 198,284 BSS bytes**. This is a link measurement, not a
physical timing result.

The DK release gate also needs sealed provisioning, secure boot/update policy,
debug lockout, and independent cryptographic review before deployment as a
production secure element. A robust USB DK test target is the nearer milestone.
