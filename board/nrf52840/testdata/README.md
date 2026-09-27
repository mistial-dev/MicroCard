# CC310 RSA boot vectors

The RSA-1024 and RSA-2048 key pairs are public test material generated with
OpenSSL 3.6.3. The `*-private.der` files use PKCS#1 `RSAPrivateKey` encoding;
the `*-public.der` files use PKCS#1 `RSAPublicKey` encoding. Each `*-abc.sig`
is an OpenSSL RSASSA-PKCS1-v1_5 signature over SHA-256 of `abc`.

The boot self-test signs the same digest with CC310, compares the full signature
to OpenSSL's output, verifies it, and rejects a tampered signature. These keys
are only for testing and must never be used for card identity or provisioning.
