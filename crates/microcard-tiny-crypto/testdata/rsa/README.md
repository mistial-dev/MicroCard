RSA-1024 and RSA-2048 PKCS#1 DER key pairs were generated with OpenSSL.
The signatures are `openssl dgst -sha256 -sign` over `message.txt`.
They verify the software bridge against an independent implementation.

The private keys are test fixtures only. They must never be used for card keys.
