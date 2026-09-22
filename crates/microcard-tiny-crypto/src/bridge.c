/* The C library owns workspace layout and curve identifiers. Rust passes one
 * aligned, caller-owned buffer and only the curve size across this boundary. */
#include <tiny_crypto/ec.h>
#include <stddef.h>

#define MC_EC_SCRATCH_BYTES 2048
typedef char mc_ec_scratch_size_check[
    sizeof(TC_ECDSA_workspace) <= MC_EC_SCRATCH_BYTES ? 1 : -1];
typedef struct { char prefix; TC_ECDSA_workspace workspace; } mc_ec_alignment;
typedef char mc_ec_scratch_alignment_check[
    offsetof(mc_ec_alignment, workspace) <= 8 ? 1 : -1];

static TC_EC_curve curve_for_bits(unsigned bits)
{
  if (bits == 192) return TC_EC_P192;
  if (bits == 384) return TC_EC_P384;
  return TC_EC_UNKNOWN;
}

int mc_tc_ec_generate(unsigned bits, uint8_t* private_key, size_t private_len,
    uint8_t* public_key, size_t public_len, TC_random_fn fill,
    void* context, void* scratch)
{
  TC_random_source random = {fill, context};
  return TC_EC_generate_key_pair(curve_for_bits(bits), private_key, private_len,
      public_key, public_len, random, 16, (TC_EC_workspace*)scratch);
}

int mc_tc_ec_public_key(unsigned bits, const uint8_t* private_key,
    size_t private_len, uint8_t* public_key, size_t public_len, void* scratch)
{
  return TC_EC_public_key(curve_for_bits(bits), private_key, private_len,
      public_key, public_len, (TC_EC_workspace*)scratch);
}

int mc_tc_ec_valid_public(unsigned bits, const uint8_t* public_key,
    size_t public_len, void* scratch)
{
  return TC_EC_validate_public_key(curve_for_bits(bits), public_key,
      public_len, (TC_EC_workspace*)scratch);
}

int mc_tc_ec_agree(unsigned bits, const uint8_t* private_key,
    size_t private_len, const uint8_t* peer_key, size_t peer_len,
    uint8_t* secret, size_t secret_len, void* scratch)
{
  return TC_ECDH(curve_for_bits(bits), private_key, private_len,
      peer_key, peer_len, secret, secret_len, (TC_EC_workspace*)scratch);
}

int mc_tc_ecdsa_sign(unsigned bits, const uint8_t* private_key, size_t private_len,
    const uint8_t* digest, size_t digest_len, uint8_t* signature,
    size_t signature_len, TC_random_fn fill, void* context, void* scratch)
{
  TC_random_source random = {fill, context};
  return TC_ECDSA_sign_digest(curve_for_bits(bits), private_key, private_len,
      digest, digest_len, signature, signature_len, random, 16,
      (TC_ECDSA_workspace*)scratch);
}

int mc_tc_ecdsa_verify(unsigned bits, const uint8_t* public_key,
    size_t public_len, const uint8_t* digest, size_t digest_len,
    const uint8_t* signature, size_t signature_len, void* scratch)
{
  return TC_ECDSA_verify_digest(curve_for_bits(bits), public_key, public_len,
      digest, digest_len, signature, signature_len,
      (TC_ECDSA_workspace*)scratch);
}
