# Cryptographic verification vectors

## Ed25519

Unmodified C2SP Wycheproof vectors at commit `3fa63dd0344abb611f1fb1d77e119938603ea230`.

Source: https://github.com/C2SP/wycheproof/blob/3fa63dd0344abb611f1fb1d77e119938603ea230/testvectors_v1/ed25519_test.json

Apache-2.0 license is preserved in WYCHEPROOF_LICENSE. These are public verification fixtures, not deployment credentials. Tests require all valid cases to pass and all invalid cases to fail through the same strict verification function used by packages and managed native calls.

SHA-256 of `ed25519_test.json`: `752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536`. All 151 cases are classified valid or invalid; unknown classifications fail the test instead of silently passing. Small-order key and malformed public-key length checks are additional original tests.

## SCP03 level 13

`scp03_gp4net_level13.json` was independently generated with the user-authorized Gp4Net SCP03 implementation at revision `add447a082f3ac3d6cd0fc552052f3108912661c`. It fixes test-only session keys, the initial command chaining value, a plaintext command and response, the encrypted and authenticated command, the complete command MAC chaining value, and the response MAC. The Rust card-side implementation must decrypt the exact command and reproduce the exact secured response. These test keys are not deployment credentials.

SHA-256 of `scp03_gp4net_level13.json`: `2dc8984d29c2713c76d1674b4e947b45a77f0dc36fa6aeb58e56e78d91919340`.
