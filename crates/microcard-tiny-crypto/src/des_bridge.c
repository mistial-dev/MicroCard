/* Own the C context here, so Rust never depends on its compile-time layout. */
#include <tiny_crypto/des.h>
#include <stddef.h>
#include <string.h>

#define MC_ISO9797_CONTEXT_BYTES 384
typedef char mc_iso9797_context_size[
    sizeof(struct TC_DES_ISO9797_ctx) <= MC_ISO9797_CONTEXT_BYTES ? 1 : -1];
typedef struct { char prefix; struct TC_DES_ISO9797_ctx ctx; } mc_iso9797_alignment;
typedef char mc_iso9797_context_alignment[
    offsetof(mc_iso9797_alignment, ctx) <= 8 ? 1 : -1];

int mc_tc_des_crypt(const uint8_t* key, size_t key_len, const uint8_t* iv,
                    uint8_t* data, size_t data_len, int encrypt)
{
  if (!key || !data || data_len == 0 || (data_len & 7) != 0 ||
      (key_len != 8 && key_len != 16 && key_len != 24)) return TC_ERROR;
  if (key_len == 8) {
    struct TC_DES_ctx ctx = {0};
    TC_status status = iv ? TC_DES_init_ctx_iv(&ctx, key, iv)
                          : TC_DES_init_ctx(&ctx, key);
    if (status == TC_OK) {
      if (iv) status = encrypt ? TC_DES_CBC_encrypt(&ctx, data, data_len)
                               : TC_DES_CBC_decrypt(&ctx, data, data_len);
      else {
        for (size_t offset = 0; offset < data_len && status == TC_OK; offset += 8)
          status = encrypt ? TC_DES_ECB_encrypt(&ctx, data + offset)
                           : TC_DES_ECB_decrypt(&ctx, data + offset);
      }
    }
    TC_DES_ctx_clear(&ctx);
    return status;
  }
  struct TC_DES3_ctx ctx = {0};
  TC_status status = iv ? TC_DES3_init_ctx_iv(&ctx, key, key_len, iv)
                        : TC_DES3_init_ctx(&ctx, key, key_len);
  if (status == TC_OK) {
    if (iv) status = encrypt ? TC_DES3_CBC_encrypt(&ctx, data, data_len)
                             : TC_DES3_CBC_decrypt(&ctx, data, data_len);
    else {
      for (size_t offset = 0; offset < data_len && status == TC_OK; offset += 8)
        status = encrypt ? TC_DES3_ECB_encrypt(&ctx, data + offset)
                         : TC_DES3_ECB_decrypt(&ctx, data + offset);
    }
  }
  TC_DES3_ctx_clear(&ctx);
  return status;
}

int mc_tc_des_iso9797_mac(unsigned algorithm, unsigned padding,
                           const uint8_t* key, size_t key_len,
                           const uint8_t* message, size_t message_len,
                           uint8_t* tag, size_t tag_len)
{
  return TC_DES_ISO9797_MAC((TC_DES_ISO9797_algorithm)algorithm,
                            (TC_DES_ISO9797_padding)padding,
                            key, key_len, message, message_len, tag, tag_len);
}

int mc_tc_des_iso9797_verify(unsigned algorithm, unsigned padding,
                              const uint8_t* key, size_t key_len,
                              const uint8_t* message, size_t message_len,
                              const uint8_t* tag, size_t tag_len)
{
  return TC_DES_ISO9797_verify((TC_DES_ISO9797_algorithm)algorithm,
                               (TC_DES_ISO9797_padding)padding,
                               key, key_len, message, message_len, tag, tag_len);
}

int mc_tc_des_iso9797_init(void* context, unsigned algorithm, unsigned padding,
                            const uint8_t* key, size_t key_len)
{
  return TC_DES_ISO9797_init((struct TC_DES_ISO9797_ctx*)context,
                             (TC_DES_ISO9797_algorithm)algorithm,
                             (TC_DES_ISO9797_padding)padding, key, key_len);
}

int mc_tc_des_iso9797_update(void* context, const uint8_t* message, size_t len)
{
  return TC_DES_ISO9797_update((struct TC_DES_ISO9797_ctx*)context, message, len);
}

int mc_tc_des_iso9797_final(void* context, uint8_t tag[8])
{
  return TC_DES_ISO9797_final((struct TC_DES_ISO9797_ctx*)context, tag);
}

void mc_tc_des_iso9797_clear(void* context)
{
  TC_DES_ISO9797_clear((struct TC_DES_ISO9797_ctx*)context);
}

int mc_tc_des_iso9797_resume(const void* context, unsigned algorithm,
                              unsigned padding, const uint8_t* key,
                              size_t key_len)
{
  struct TC_DES_ISO9797_ctx saved = {0};
  struct TC_DES_ISO9797_ctx fresh = {0};
  unsigned diff = 0;
  if (!context || !key) return TC_ERROR;
  memcpy(&saved, context, sizeof saved);
  if (saved.active != 1 || saved.used >= 8 ||
      saved.total % 8 != saved.used || saved.keylen != key_len ||
      saved.algorithm != algorithm || saved.padding != padding ||
      TC_DES_ISO9797_init(&fresh, (TC_DES_ISO9797_algorithm)algorithm,
                          (TC_DES_ISO9797_padding)padding, key, key_len) != TC_OK)
  {
    TC_DES_ISO9797_clear(&saved);
    return TC_ERROR;
  }
  for (size_t i = 0; i < sizeof saved.sk; ++i)
    diff |= ((const uint8_t*)saved.sk)[i] ^ ((const uint8_t*)fresh.sk)[i];
  TC_DES_ISO9797_clear(&saved);
  TC_DES_ISO9797_clear(&fresh);
  return diff == 0 ? TC_OK : TC_ERROR;
}

int mc_tc_des_iso9797_initial_chain(void* context, const uint8_t iv[8])
{
  struct TC_DES_ISO9797_ctx* ctx = (struct TC_DES_ISO9797_ctx*)context;
  if (!ctx || !iv || !ctx->active || ctx->total != 0 || ctx->used != 0)
    return TC_ERROR;
  for (size_t i = 0; i < 8; ++i) ctx->mac[i] = iv[i];
  return TC_OK;
}

size_t mc_tc_des_iso9797_total(const void* context)
{
  const struct TC_DES_ISO9797_ctx* ctx =
      (const struct TC_DES_ISO9797_ctx*)context;
  return ctx && ctx->active ? ctx->total : 0;
}
