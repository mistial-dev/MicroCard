#include <tiny_crypto/rsa.h>

#define MC_RSA_MAX_WORK 1000000u

int mc_tc_rsa_keygen(size_t bits, uint8_t* n, uint8_t* e, uint8_t* d,
    uint8_t* p, uint8_t* q, TC_random_fn fill, void* random_context,
    TC_RSA_word* scratch, size_t scratch_words)
{
  TC_RSA_keygen_state state = {0};
  TC_RSA_keygen_output output;
  TC_RSA_workspace workspace = {scratch, scratch_words};
  TC_RSA_keygen_limits limits = {5000u, 20000u};
  TC_RSA_result status;
  uint32_t total_work = 50000000u;
  const size_t length = bits / 8u;
  if ((bits != 1024 && bits != 2048) || !n || !e || !d || !p || !q ||
      !fill || !scratch) return -1;
  output.modulus = (TC_buffer){n, length};
  output.exponent = (TC_buffer){e, 3};
  output.d = (TC_buffer){d, length};
  output.p = (TC_buffer){p, length / 2u};
  output.q = (TC_buffer){q, length / 2u};
  status = TC_RSA_keygen_init(&state, bits, &output, limits, &workspace);
  while (status == TC_RSA_OK || status == TC_RSA_IN_PROGRESS) {
    TC_work_budget work = {10000u};
    if (total_work < work.remaining) { status = TC_RSA_LIMIT; break; }
    status = TC_RSA_keygen_step(&state,
        (TC_random_source){fill, random_context}, NULL, NULL, &work);
    total_work -= 10000u - work.remaining;
    if (status == TC_RSA_OK) break;
  }
  TC_RSA_keygen_clear(&state);
  TC_secure_zero(scratch, scratch_words * sizeof *scratch);
  return status == TC_RSA_OK ? 0 : -1;
}

int mc_tc_rsa_derive_crt(size_t bits, const uint8_t* n, const uint8_t* e,
    const uint8_t* d, const uint8_t* p, const uint8_t* q,
    uint8_t* dp, uint8_t* dq, uint8_t* qi,
    TC_RSA_word* scratch, size_t scratch_words)
{
  const size_t length = bits / 8u;
  TC_RSA_private_key key = {
    {{n, length}, {e, 3}}, {d, length}, {p, length / 2u},
    {q, length / 2u}, NULL
  };
  TC_RSA_crt_output output = {
    {dp, length / 2u}, {dq, length / 2u}, {qi, length / 2u}
  };
  TC_RSA_workspace workspace = {scratch, scratch_words};
  TC_work_budget work = {48u * (uint32_t)length + 3u};
  TC_RSA_result status;
  if ((bits != 1024 && bits != 2048) || !n || !e || !d || !p || !q ||
      !dp || !dq || !qi || !scratch) return -1;
  status = TC_RSA_derive_crt(&key, &output, &workspace, &work);
  TC_secure_zero(scratch, scratch_words * sizeof *scratch);
  return status == TC_RSA_OK ? 0 : -1;
}

int mc_tc_rsa_sign_sha256(const uint8_t* n, size_t n_len,
    const uint8_t* e, size_t e_len, const uint8_t* d, size_t d_len,
    const uint8_t* p, size_t p_len, const uint8_t* q, size_t q_len,
    const uint8_t hash[32], uint8_t* signature, size_t signature_len,
    TC_random_fn fill, void* random_context,
    TC_RSA_word* scratch, size_t scratch_words)
{
  TC_RSA_private_key key = {
    {{n, n_len}, {e, e_len}}, {d, d_len}, {p, p_len}, {q, q_len}, NULL
  };
  TC_RSA_workspace workspace = {scratch, scratch_words};
  TC_RSA_execution execution = {{fill, random_context}, 128, {MC_RSA_MAX_WORK}};
  TC_RSA_v15_options options = {TC_HASH_SHA256};
  TC_RSA_result status;
  if (n_len != 128 && n_len != 256) return -1;
  if (signature_len != n_len || !hash || !signature) return -1;
  status = TC_RSA_validate_private_key(&key, &workspace, &execution);
  if (status == TC_RSA_OK) {
    execution.work.remaining = MC_RSA_MAX_WORK;
    status = TC_RSA_sign_v15_digest(&key, &options, (TC_bytes){hash, 32},
        &workspace, (TC_buffer){signature, signature_len}, &execution);
  }
  TC_secure_zero(scratch, scratch_words * sizeof *scratch);
  return status == TC_RSA_OK ? 0 : -1;
}

int mc_tc_rsa_verify_sha256(const uint8_t* n, size_t n_len,
    const uint8_t* e, size_t e_len, const uint8_t hash[32],
    const uint8_t* signature, size_t signature_len,
    TC_RSA_word* scratch, size_t scratch_words)
{
  TC_RSA_public_key key = {{n, n_len}, {e, e_len}};
  TC_RSA_workspace workspace = {scratch, scratch_words};
  TC_RSA_v15_options options = {TC_HASH_SHA256};
  TC_work_budget work = {MC_RSA_MAX_WORK};
  TC_RSA_result status;
  if ((n_len != 128 && n_len != 256) || signature_len != n_len ||
      !hash || !signature) return -1;
  status = TC_RSA_verify_v15_digest(&key, &options, (TC_bytes){hash, 32},
      (TC_bytes){signature, signature_len}, &workspace, &work);
  TC_secure_zero(scratch, scratch_words * sizeof *scratch);
  if (status == TC_RSA_OK) return 0;
  if (status == TC_RSA_INVALID) return 1;
  return -1;
}
