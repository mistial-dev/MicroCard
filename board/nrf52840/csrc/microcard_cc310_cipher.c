#include <stddef.h>
#include <stdint.h>

#include "psa/crypto.h"
#include "psa_crypto_driver_wrappers.h"

#define MICROCARD_AES_BLOCK_BYTES 16u
#define MICROCARD_CCM_NONCE_BYTES 13u
#define MICROCARD_CCM_TAG_BYTES 16u

_Static_assert(sizeof(psa_cipher_operation_t) <= 512u,
               "pinned TF-PSA cipher state exceeds the bridge bound");

static void microcard_wipe(void *buffer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)buffer;
    while (length != 0u) {
        *bytes++ = 0u;
        --length;
    }
}

int32_t microcard_cc310_aes128_encrypt_block(const uint8_t *key,
                                              size_t key_size,
                                              const uint8_t *input,
                                              size_t input_size,
                                              uint8_t *output,
                                              size_t output_size)
{
    if (key == NULL || key_size != MICROCARD_AES_BLOCK_BYTES ||
        input == NULL || input_size != MICROCARD_AES_BLOCK_BYTES ||
        output == NULL || output_size != MICROCARD_AES_BLOCK_BYTES) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128u);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECB_NO_PADDING);

    size_t written = 0u;
    psa_status_t status = psa_driver_wrapper_cipher_encrypt(
        &attributes, key, key_size, PSA_ALG_ECB_NO_PADDING,
        NULL, 0u, input, input_size, output, output_size, &written);
    if (status == PSA_SUCCESS && written != MICROCARD_AES_BLOCK_BYTES) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status != PSA_SUCCESS) {
        microcard_wipe(output, output_size);
    }
    return status;
}

int32_t microcard_cc310_aes128_cbc_in_place(const uint8_t *key,
                                             size_t key_size,
                                             const uint8_t *iv,
                                             size_t iv_size,
                                             uint8_t *buffer,
                                             size_t buffer_size,
                                             int32_t encrypt)
{
    if (key == NULL || key_size != MICROCARD_AES_BLOCK_BYTES ||
        iv == NULL || iv_size != MICROCARD_AES_BLOCK_BYTES ||
        buffer == NULL || buffer_size == 0u ||
        (buffer_size % MICROCARD_AES_BLOCK_BYTES) != 0u ||
        (encrypt != 0 && encrypt != 1)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128u);
    psa_set_key_usage_flags(
        &attributes, encrypt != 0 ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);

    psa_cipher_operation_t operation = psa_cipher_operation_init();
    psa_status_t status;
    if (encrypt != 0) {
        status = psa_driver_wrapper_cipher_encrypt_setup(
            &operation, &attributes, key, key_size, PSA_ALG_CBC_NO_PADDING);
    } else {
        status = psa_driver_wrapper_cipher_decrypt_setup(
            &operation, &attributes, key, key_size, PSA_ALG_CBC_NO_PADDING);
    }
    if (status == PSA_SUCCESS) {
        status = psa_driver_wrapper_cipher_set_iv(&operation, iv, iv_size);
    }

    size_t written = 0u;
    while (status == PSA_SUCCESS && written < buffer_size) {
        size_t block_written = 0u;
        status = psa_driver_wrapper_cipher_update(
            &operation,
            buffer + written,
            MICROCARD_AES_BLOCK_BYTES,
            buffer + written,
            MICROCARD_AES_BLOCK_BYTES,
            &block_written);
        if (status == PSA_SUCCESS && block_written != MICROCARD_AES_BLOCK_BYTES) {
            status = PSA_ERROR_CORRUPTION_DETECTED;
        } else if (status == PSA_SUCCESS) {
            written += block_written;
        }
    }
    size_t tail = 0u;
    if (status == PSA_SUCCESS) {
        status = psa_driver_wrapper_cipher_finish(
            &operation, NULL, 0u, &tail);
    }
    if (status == PSA_SUCCESS && (written != buffer_size || tail != 0u)) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    (void)psa_driver_wrapper_cipher_abort(&operation);
    microcard_wipe(&operation, sizeof(operation));
    if (status != PSA_SUCCESS) {
        microcard_wipe(buffer, buffer_size);
    }
    return status;
}

static int32_t microcard_cc310_aes128_ccm(const uint8_t *key,
                                           size_t key_size,
                                           const uint8_t *nonce,
                                           size_t nonce_size,
                                           const uint8_t *aad,
                                           size_t aad_size,
                                           const uint8_t *input,
                                           size_t input_size,
                                           uint8_t *output,
                                           size_t output_size,
                                           int32_t decrypt)
{
    if (key == NULL || key_size != MICROCARD_AES_BLOCK_BYTES ||
        nonce == NULL || nonce_size != MICROCARD_CCM_NONCE_BYTES ||
        (aad == NULL && aad_size != 0u) ||
        (input == NULL && input_size != 0u) || output == NULL ||
        (decrypt != 0 && decrypt != 1)) {
        return -1;
    }
    size_t expected;
    if (decrypt != 0) {
        if (input_size < MICROCARD_CCM_TAG_BYTES) {
            return 1;
        }
        expected = input_size - MICROCARD_CCM_TAG_BYTES;
    } else {
        if (input_size > SIZE_MAX - MICROCARD_CCM_TAG_BYTES) {
            return -1;
        }
        expected = input_size + MICROCARD_CCM_TAG_BYTES;
    }
    if (output_size != expected) {
        return -1;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128u);
    psa_set_key_usage_flags(
        &attributes, decrypt != 0 ? PSA_KEY_USAGE_DECRYPT : PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CCM);

    /* Rust represents an empty slice with a non-null dangling pointer. Do not pass that
     * sentinel into a hardware driver even though its length is zero. */
    if (aad_size == 0u) {
        aad = NULL;
    }

    size_t written = 0u;
    psa_status_t status;
    if (decrypt != 0) {
        status = psa_driver_wrapper_aead_decrypt(
            &attributes, key, key_size, PSA_ALG_CCM, nonce, nonce_size,
            aad, aad_size, input, input_size, output, output_size, &written);
    } else {
        status = psa_driver_wrapper_aead_encrypt(
            &attributes, key, key_size, PSA_ALG_CCM, nonce, nonce_size,
            aad, aad_size, input, input_size, output, output_size, &written);
    }
    if (status == PSA_SUCCESS && written != expected) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status != PSA_SUCCESS) {
        microcard_wipe(output, output_size);
        return status == PSA_ERROR_INVALID_SIGNATURE ? 1 : -1;
    }
    return 0;
}

int32_t microcard_cc310_aes128_ccm_encrypt(const uint8_t *key,
                                            size_t key_size,
                                            const uint8_t *nonce,
                                            size_t nonce_size,
                                            const uint8_t *aad,
                                            size_t aad_size,
                                            const uint8_t *plaintext,
                                            size_t plaintext_size,
                                            uint8_t *ciphertext,
                                            size_t ciphertext_size)
{
    return microcard_cc310_aes128_ccm(
        key, key_size, nonce, nonce_size, aad, aad_size,
        plaintext, plaintext_size, ciphertext, ciphertext_size, 0);
}

int32_t microcard_cc310_aes128_ccm_decrypt(const uint8_t *key,
                                            size_t key_size,
                                            const uint8_t *nonce,
                                            size_t nonce_size,
                                            const uint8_t *aad,
                                            size_t aad_size,
                                            const uint8_t *ciphertext,
                                            size_t ciphertext_size,
                                            uint8_t *plaintext,
                                            size_t plaintext_size)
{
    return microcard_cc310_aes128_ccm(
        key, key_size, nonce, nonce_size, aad, aad_size,
        ciphertext, ciphertext_size, plaintext, plaintext_size, 1);
}
