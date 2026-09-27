# Practical JCVM crypto profile

The generated [matrix](JCVM_CRYPTO_PROFILE.json) declares **110 proposed operation and key-size rows**. Its source is the pinned JCAlgTest 1.8.3 P71D321 result in `vendor/jcalgtest/p71d321-reference.csv.gz`, checked against `vendor/jcalgtest/client.lock.json`. P71D321 is a comparison reference. A `yes` in its factory scan does not establish MicroCard support.

Each row records the candidate provider, key size, exact legacy and OneShot factory probes, P71 key-builder and on-card key-pair generation results, and separate MicroCard evidence slots for key import, generation, real operation, invalid input/provider failure, and reboot. **All MicroCard rows start pending and unadvertised.** Update evidence only with a reproducible run, firmware identity, and raw result path. The applicable factory becomes supported only when every relevant slot passes on the selected build and the DK. Unsupported factories must return the Java Card exception specified for that API.

| Family | Proposed scope | Provider candidate |
| --- | --- | --- |
| AES-128 | ECB/CBC with P71 padding variants, CTR, CBC-MAC, CMAC | CC310 where the pinned driver and DK prove the operation; otherwise tiny-crypto-c for CTR |
| DES/3DES | ECB/CBC and P71 MAC variants, 1-key DES and 2/3-key 3DES | tiny-crypto-c; included by default, excluded by the compact build |
| EC | P-256/P-384 ECDSA-SHA-256/384 and ECDH plain/XY | CC310 for proven P-256 paths, tiny-crypto-c for P-384 and other unexposed paths |
| RSA | 1024/2048-bit raw, PKCS#1, OAEP, PKCS#1 signatures and PSS with SHA-1/224/256/384/512 | CC310 if the pinned driver works on the DK; otherwise tiny-crypto-c |

SHA-1/224/256 use CC310 when proven. SHA-384/512 use tiny-crypto-c. Digest, initialized-digest, and OneShot forms share their respective validated primitive. Factory spellings are recorded separately because the P71 result can disagree across API forms. For example, P71 reports `ALG_DES_MAC4_NOPAD` unsupported through the legacy `Signature` factory but supported through OneShot; the matrix preserves both observations.

The scope excludes uncommon RSA sizes, other EC curves, PACE, SEED, ISO9796, and additional random-service aliases. A compact build excludes legacy DES/3DES rows, and its link map must show the implementation absent. The default build includes them. The provider candidate is a design selection, not hardware execution evidence; a CC310 failure must fail the operation without a software retry.

Regenerate and verify the committed result with:

```sh
python3 scripts/generate_jcvm_crypto_profile.py
python3 scripts/generate_jcvm_crypto_profile.py --check
python3 scripts/generate_jcvm_crypto_profile_test.py
```

The full upstream JCAlgTest CSV remains separate. Each provider group needs an untouched full scan, with unsupported entries, Java Card errors, and reader loss classified separately. Operation evidence requires key setup, encrypt/decrypt or sign/verify or agreement as applicable, invalid-input and provider-failure behavior, and a reset/reinstall check before any row is marked advertised.
