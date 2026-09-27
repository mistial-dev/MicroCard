#include <tiny_crypto/aes.h>

int mc_tc_aes128_ctr(const uint8_t key[16], const uint8_t counter[16],
    uint8_t* buffer, size_t length)
{
  struct TC_AES_ctx ctx;
  TC_status status;
  if (!key || !counter || (length && !buffer)) return -1;
  status = TC_AES_init_ctx_iv(&ctx, key, counter);
  if (status == TC_OK) status = TC_AES_CTR_crypt(&ctx, buffer, length);
  TC_AES_ctx_clear(&ctx);
  return status == TC_OK ? 0 : -1;
}
