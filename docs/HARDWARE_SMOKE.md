# Hardware smoke results

## Makerdiary JCVM USB acceptance

Date: 2026-09-21. Firmware source revision:
`ec39ff17725121ac64a99ba890f90eb099c3084d`. Development UF2 SHA-256:
`541b2ff7234caa8b19624e876d5c845a1812d264c2f0ef1d61a6b66714b2f830`.

The Makerdiary nRF52840 MDK USB Dongle booted the JCVM image without a cable power
cycle and enumerated as `MicroCard MicroCard virtual smart card`. OpenSC read ATR
`3B 80 01 81`; an ISD SELECT returned valid GlobalPlatform FCI and `9000`.

The physical acceptance client opened SCP03 at security level 33 with the documented
development key, streamed the committed signed OpenFIPS201 load file, installed its
applet, and selected the full PIV AID. The applet returned its 149-byte PIV selection
response. CCID time-extension replies kept the same PC/SC command alive during the
long JCVM install and select callbacks. Package deletion retained its rollback
tombstone as designed: reloading version 1 returned `6985`, while signed version 2
loaded, installed, and selected successfully.

The authenticated `80 FE 55 AA` management command entered UF2. Copying the new image
returned to the application automatically, and the installed applet remained usable
after that firmware restart. The image passed its boot-time CC310 SHA-256, entropy,
CMAC, HMAC, AES, CBC, CCM, and P-256 checks. This establishes execution of those fixed
known answers on this board; it does not replace independent hardware vector, forced
failure, timing, memory, or side-channel work.

The current physical result does not run the complete NIST suite on the board. Full
personalization, interrupted writes, USB abort/suspend, sustained throughput, heap and
stack high-water, and both-engine hardware acceptance remain release blockers.

## nRF52840 DK first smoke test

Firmware revision: `128d83b82695b209f5fb9b01b7b2dd9fda7f352a`.
Target: nRF52840_xxAA through an on-board J-Link probe.
Firmware and separate development management-key page downloaded with readback verification. No mass erase or recovery used. Attach under reset timed out. Normal attach succeeded. User physically power-cycled the board after provisioning.

## Result

`scripts/dk_smoke.py` exited 0 over the DK serial interface with domain `first-test`:

```text
PASS: UART SCP03, signed loading, installation, persistent key operations and shared domain state
```

The test authenticated SCP03, created the SSD, signed a package for its returned incarnation, staged and activated the assembly, and installed instances at AIDs F04D430010 and F04D430011. It checked HMAC/CMAC response lengths, CBC/CCM round trips and matching output from the same-domain reader entry.

## Remaining validation

This first development smoke test provides limited evidence. Production acceptance still requires reboot persistence after installation, deliberate power interruption, independent hardware cryptographic vectors, peak memory, timing, watchdog and ACL enforcement tests. Development journal key material remains plaintext at rest. Debug recovery remains available. No credentials are included in this report.

## Post-install power cycle

After the user power-cycled the board again, a fresh SCP03 session selected and invoked both existing assembly instances without loading, installing or generating keys. HMAC/CMAC lengths, CBC/CCM round trips and matching same-domain reader output passed. This demonstrates recovery of usable assembly-instance registrations and key slots. Exact key identity across this first reboot was not measured because the initial smoke test did not save output fingerprints. The counter value is not exposed by this sample, so exact key-value retention remains unmeasured. Post-reboot cryptographic-output fingerprints are now saved in the local artifact report for a subsequent comparison.

## Second reboot: saved fingerprint comparison

After another user-confirmed power cycle, a fresh SCP03 session selected the existing assemblies. SHA-256 fingerprints of both the HMAC and AES-CMAC outputs matched the saved pre-reboot baseline. CBC/CCM round trips and the same-domain reader also passed. No assembly load, installation, key generation or reprovisioning occurred. These results provide key-continuity evidence across reboot for both persistent key slots. Exact application counter retention remains unmeasured because the sample does not return its counter value. Local evidence: `artifacts/first-flash/reboot-comparison.json`.

## Adversarial signed loading

`scripts/signing_acceptance.py` passed 20 SCP03 loading scenarios on UART against the original first-flash firmware. It covers unsigned/tampered packages, wrong context/key/target/incarnation, signed malformed content, rollback after unload, retries and old-incarnation replay. Successful runs delete only their newly created SSD. Existing sample HMAC and CMAC fingerprints were separately checked unchanged.

Debugger reset was attempted but the core is locked. Probe-rs refused its requested erase-all operation. No erase occurred. This invalidates the earlier assumption that probe enumeration alone established usable reset access. Hardware reboot coverage of this adversarial sequence is pending. One empty bound test SSD remains from the first failure due to a test cleanup bug, now fixed. See the implementation checklist for safe reclamation.

## SCP03 profile over USB CCID

Firmware revision: `a6f5ada5bdaeb85b4e12c7d735e16e92e06c75d4`, built with `usb-ccid` and `development-debug`.

GlobalPlatformPro v25.10.20 reports `GP SCP03 (i=71)` from the card recognition data, which is S16 mode, the derived card challenge, R-MAC and R-ENCRYPTION. It reaches the card as a PC/SC reader over the board USB port with ATR `3B800181`.

The host offers an 8-byte challenge first. The card answers 6700, GlobalPlatformPro logs its S16 retry and reissues INITIALIZE UPDATE with a 16-byte challenge, and the 48-byte response carries key information `010371`, a 16-byte challenge, a 16-byte cryptogram and the three-byte sequence counter. Three consecutive sessions returned counters `000008`, `000009` and `00000A`, each with a different challenge.

GlobalPlatformPro recomputes the derived challenge from the static ENC key and warns when it disagrees. No such warning appeared in any authenticated run, so an independent implementation reproduces the card challenge byte for byte.

`gp -l -v` listed the same six registry entries at every security level carrying a command MAC, requested through EXTERNAL AUTHENTICATE P1 values `01`, `03`, `11`, `13` and `33`.

## Remaining validation for this profile

Sequence counter behaviour at saturation and across a deliberate power interruption at the reservation boundary is covered on the host only. Flash wear from one reservation write per boot is unmeasured on hardware.
