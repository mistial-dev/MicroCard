/* Keep the C hash context aligned while the VM owns its serialized bytes. */
#include <tiny_crypto/hash.h>
#include <string.h>

#define MC_HASH_STATE_BYTES 256u
#define MC_HASH_CONTEXT_OFFSET 8u

typedef union {
  struct TC_SHA384_ctx sha384;
  struct TC_SHA512_ctx sha512;
} mc_hash_context;
typedef char mc_hash_state_size_check[
    sizeof(mc_hash_context) <= MC_HASH_STATE_BYTES - MC_HASH_CONTEXT_OFFSET ? 1 : -1];

int mc_tc_sha512_stream(unsigned algorithm, uint8_t *state, size_t state_len,
    const uint8_t *input, size_t input_len, uint8_t *output)
{
  mc_hash_context context;
  int status = TC_ERROR;
  unsigned marker = algorithm == 384 ? 1u : algorithm == 512 ? 2u : 0u;

  if (marker == 0 || state == NULL || state_len != MC_HASH_STATE_BYTES ||
      (input_len != 0 && input == NULL))
    return TC_ERROR;

  if (state[0] == 0)
  {
    for (size_t i = 1; i < state_len; ++i)
      if (state[i] != 0) goto clear;
    status = algorithm == 384
        ? TC_SHA384_init(&context.sha384)
        : TC_SHA512_init(&context.sha512);
  }
  else if (state[0] == marker)
  {
    memcpy(&context, state + MC_HASH_CONTEXT_OFFSET, sizeof(context));
    status = TC_OK;
  }
  if (status != TC_OK) goto clear;

  status = algorithm == 384
      ? TC_SHA384_update(&context.sha384, input, input_len)
      : TC_SHA512_update(&context.sha512, input, input_len);
  if (status != TC_OK) goto clear;

  if (output != NULL)
  {
    status = algorithm == 384
        ? TC_SHA384_final(&context.sha384, output)
        : TC_SHA512_final(&context.sha512, output);
    goto clear;
  }

  memset(state, 0, state_len);
  state[0] = (uint8_t)marker;
  memcpy(state + MC_HASH_CONTEXT_OFFSET, &context, sizeof(context));
  TC_secure_zero(&context, sizeof(context));
  return TC_OK;

clear:
  memset(state, 0, state_len);
  TC_secure_zero(&context, sizeof(context));
  return status == TC_OK ? TC_OK : TC_ERROR;
}
