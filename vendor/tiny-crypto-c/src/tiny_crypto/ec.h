/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_EC_H_
#define TINY_CRYPTO_EC_H_
#include <tiny_crypto/common.h>

#if TC_EC_SMALL || defined(__AVR__)
typedef uint8_t TC_EC_word;
#define TC_EC_WORD_BITS 8
#else
typedef uint32_t TC_EC_word;
#define TC_EC_WORD_BITS 32
#endif
#if TC_EC_ENABLE_P384
#define TC_EC_MAX_BYTES 48
#else
#define TC_EC_MAX_BYTES 32
#endif
#define TC_EC_MAX_WORDS (TC_EC_MAX_BYTES / (TC_EC_WORD_BITS / 8))

/* Scratch storage for one operation. Members are private to the implementation.
 * Each concurrent operation needs its own workspace. */
typedef struct {
  TC_EC_word fields[30][TC_EC_MAX_WORDS];
  TC_EC_word product[2 * TC_EC_MAX_WORDS + 2];
  TC_EC_word reduced[TC_EC_MAX_WORDS];
} TC_EC_workspace;

typedef struct {
  TC_EC_workspace ec;
  TC_EC_word scalars[2][TC_EC_MAX_WORDS];
  TC_EC_word point[3][TC_EC_MAX_WORDS];
} TC_ECDSA_workspace;

#ifdef __cplusplus
extern "C" {
#endif

/* Scalars and coordinates are fixed-width, big-endian (24, 32 or 48 bytes).
 * Public keys use SEC 1 uncompressed encoding, 04 || X || Y. Lengths must
 * match the selected curve exactly. Output and workspace must not overlap
 * each other or any input. On failure output is unchanged. Scratch is wiped
 * after use. Unsupported curves return TC_ERROR. */
TC_status TC_EC_public_key(TC_EC_curve curve, const uint8_t* scalar, size_t scalar_len,
    uint8_t* output, size_t output_len, TC_EC_workspace* workspace);
/* Generate a private scalar and matching SEC 1 public key. The RNG must be
 * cryptographically secure and fill the whole request. Invalid scalar draws
 * are retried up to max_attempts (1..16). Outputs remain unchanged on failure.
 * After input validation, temporary scalar and public-key storage are wiped
 * on return when TC_ZEROIZE=1. Outputs and workspace must be disjoint; the
 * RNG context must not overlap them. */
TC_status TC_EC_generate_key_pair(TC_EC_curve curve,
    uint8_t* private_key, size_t private_key_len,
    uint8_t* public_key, size_t public_key_len,
    TC_random_source random, unsigned max_attempts,
    TC_EC_workspace* workspace);
TC_status TC_EC_validate_public_key(TC_EC_curve curve, const uint8_t* public_key,
    size_t public_key_len, TC_EC_workspace* workspace);
/* Returns the shared point's X coordinate, including leading zero bytes.
 * Pass this value through the protocol's key derivation function before use. */
TC_status TC_ECDH(TC_EC_curve curve, const uint8_t* scalar, size_t scalar_len,
    const uint8_t* public_key, size_t public_key_len, uint8_t* output,
    size_t output_len, TC_EC_workspace* workspace);

/* Verify a precomputed digest with a SEC 1 uncompressed public key.
 * Signature encoding is fixed-width big-endian r || s, not DER. Digests
 * longer than the curve order are truncated to their leftmost bytes.
 * TC_MISMATCH means the signature or public key is invalid; TC_ERROR means
 * an invalid argument or unsupported curve. Workspace must be disjoint
 * from all inputs and is wiped after use. Both high and low s are accepted. */
TC_status TC_ECDSA_verify_digest(TC_EC_curve curve,
    const uint8_t* public_key, size_t public_key_len,
    const uint8_t* digest, size_t digest_len,
    const uint8_t* signature, size_t signature_len,
    TC_ECDSA_workspace* workspace);

/* Sign a precomputed digest with a fixed-width private scalar. The RNG supplies
 * an independent secret nonce on each attempt; it must be cryptographically
 * secure and fill the entire request. At most 16 attempts are allowed. Signature
 * encoding is fixed-width big-endian r || s. Digests longer than the order are
 * truncated to their leftmost bytes. Output remains unchanged on failure.
 * After input validation, workspace and nonce storage are wiped on return when
 * TC_ZEROIZE=1. Inputs, output and workspace must be pairwise disjoint. The
 * RNG context must not overlap them. */
TC_status TC_ECDSA_sign_digest(TC_EC_curve curve,
    const uint8_t* private_key, size_t private_key_len,
    const uint8_t* digest, size_t digest_len,
    uint8_t* signature, size_t signature_len,
    TC_random_source random, unsigned max_attempts,
    TC_ECDSA_workspace* workspace);

#ifdef __cplusplus
}
#endif
#endif
