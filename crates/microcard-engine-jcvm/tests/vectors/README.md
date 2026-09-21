# Java Card engine vectors

## JCAlgTest load file

`jcalgtest-v1.8.2-jc305.lfdb` is generated from the licensed, patched source and
CAP in `vendor/jcalgtest`. `scripts/jcalgtest_acceptance.py` installs it, reads
the applet version, and checks representative supported and unsupported
cryptographic algorithms through JCAlgTest's own APDU protocol.

## OpenFIPS201 load file

`openfips201-standard-cs2.lfdb` is a Load File Data Block extracted from a build of the
OpenPhysical fork of OpenFIPS201. It is committed so the Java Card acceptance run works on a
clean checkout with no external build and no path argument.

| Item | Value |
| --- | --- |
| Applet source | OpenPhysical/OpenFIPS201 at commit `9f3b99bd0f2600beea7e5c053613d8baef2b7716` |
| Build profile | standard, VCI suite CS2, attestation disabled, FIPS mode off |
| Package AID | `A00000030800001000` version 1.10 |
| Applet AID | `A000000308000010000100` |
| CAP | format 2.1, header flags `0x04`, archive 278,161 bytes |
| CAP SHA-256 | `cb11dff8efb93eb3fb26257fbc51108a3f987c71a5314ed98c2bae276e567d86` |
| Load file | 44,922 bytes |
| Load file SHA-256 | `7c7df5c78941d7a03b040105ee8859cd50a503c1bee6ea106b184dc9cc690acf` |

OpenFIPS201 is MIT licensed and its notice is preserved in `OPENFIPS201_LICENSE`. This is a
build output used as a test fixture rather than a deployment artifact.

SELECT processing applies the contact PIN retry limit of six from the pinned
[Config.java](https://github.com/OpenPhysical/OpenFIPS201/blob/9f3b99bd0f2600beea7e5c053613d8baef2b7716/src/com/makina/security/openfips201/Config.java).
The first two wrong PINs therefore return `63C5` and `63C4`; the earlier `63C9`/`63C8`
expectations reflected a missing SELECT `process()` call in the engine.

Regenerate it from a CAP with the inventory script, which writes the components in JCVM
section 6.3 order and excludes the Debug and Descriptor components.

```sh
python3 scripts/jcvm_cap_inventory.py OpenFIPS201-standard-CS2-attestation-false.cap --load-file .
```

The applet is built from its own tree with Ant.

```sh
ant -f build/build.xml compile -Dvci.suite=CS2 -Dattestation.enabled=false
```

## PIV commands on a blank card

`piv_blank_card.json` fixes what OpenFIPS201 answers when the engine runs it on a card that
holds no personalised data. Each entry records the command, the expected status word, where
the command encoding came from and why the answer is what it is.

SHA-256 of `piv_blank_card.json`: `77ef278ef1c2e025024a35f329d755d1fd38999902bceb2c528365fe8a91814a`.

Two kinds of command appear. Some are authentic encodings taken from NIST Special Database 33
contact captures of an ID-One PIV 2.4 card, released under MIT-0 by OpenPhysical. Others are
original, built from the SP 800-73-4 clause named in the entry.

**The captured responses are deliberately absent.** The SD33 card was personalised and the
card under test is blank, so a captured response would disagree for a correct reason and
would prove nothing. What carries over is the command encoding, which is where real cards and
hand-written tests differ most. Every entry here is the case 4 form that a real host sends,
with a trailing expected-length byte. That form is what exposed the engine reading Le as a
further byte of command data.

A blank card answering that an object is absent is still the applet's own answer. It reaches
that answer through its own dispatch, its own data model and its own PIN state, so a wrong
status word means the engine mis-ran the applet. This fixture does not exercise personalised data or cryptographic operations.
Those paths are covered separately by `scripts/jcvm_transport_acceptance.py`; neither
script runs the complete upstream suite. See the [coverage boundary](../../../../docs/JCVM_PROFILE.md#upstream-test-coverage).

Replay it with `python3 scripts/piv_vector_acceptance.py`, which takes no arguments.
