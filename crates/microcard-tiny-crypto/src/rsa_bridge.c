#include <tiny_crypto/rsa.h>

#define MC_RSA_MAX_WORK 1000000u

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
