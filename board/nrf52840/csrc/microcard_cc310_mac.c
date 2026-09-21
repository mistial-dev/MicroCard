#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "psa/crypto.h"
#include "psa_crypto_driver_wrappers.h"

#define MICROCARD_MAC_STATE_BYTES 544u
#define MICROCARD_SHA256_BYTES 32u
#define MICROCARD_DMA_CHUNK_BYTES 64u

_Static_assert(sizeof(psa_mac_operation_t) == MICROCARD_MAC_STATE_BYTES,
               "pinned TF-PSA MAC state size changed");
_Static_assert(_Alignof(psa_mac_operation_t) <= 8u,
               "pinned TF-PSA MAC state alignment changed");

static void microcard_wipe(void *buffer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)buffer;
    while (length != 0u) {
        *bytes++ = 0u;
        --length;
    }
}

static psa_mac_operation_t *microcard_operation(void *storage, size_t storage_size)
{
    if (storage == NULL || storage_size != MICROCARD_MAC_STATE_BYTES ||
        ((uintptr_t)storage & 7u) != 0u) {
        return NULL;
    }
    return (psa_mac_operation_t *)storage;
}

int32_t microcard_cc310_hmac_sha256_begin(void *storage, size_t storage_size,
                                          const uint8_t *key, size_t key_size)
{
    static const uint8_t empty_key_equivalent = 0u;
    psa_mac_operation_t *operation = microcard_operation(storage, storage_size);
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    microcard_wipe(storage, storage_size);
    if (key == NULL || key_size > (SIZE_MAX / 8u)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (key_size == 0u) {
        key = &empty_key_equivalent;
        key_size = 1u;
    }
    *operation = psa_mac_operation_init();
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, key_size * 8u);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    psa_status_t status = psa_driver_wrapper_mac_sign_setup(
        operation, &attributes, key, key_size, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        microcard_wipe(storage, storage_size);
    }
    return status;
}

int32_t microcard_cc310_cmac_begin(void *storage, size_t storage_size,
                                   const uint8_t *key, size_t key_size)
{
    psa_mac_operation_t *operation = microcard_operation(storage, storage_size);
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    microcard_wipe(storage, storage_size);
    if (key == NULL || key_size != 16u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *operation = psa_mac_operation_init();
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128u);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_CMAC);

    psa_status_t status = psa_driver_wrapper_mac_sign_setup(
        operation, &attributes, key, key_size, PSA_ALG_CMAC);
    if (status != PSA_SUCCESS) {
        microcard_wipe(storage, storage_size);
    }
    return status;
}

int32_t microcard_cc310_mac_update(void *storage, size_t storage_size,
                                   const uint8_t *input, size_t input_size)
{
    psa_mac_operation_t *operation = microcard_operation(storage, storage_size);
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (input == NULL && input_size != 0u) {
        (void)psa_driver_wrapper_mac_abort(operation);
        microcard_wipe(storage, storage_size);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (input_size == 0u) {
        return PSA_SUCCESS;
    }

    /* CryptoCell 310 symmetric inputs must be in DMA-accessible RAM. Callers may
     * pass Rust static data from flash, so adapt that contract at the provider edge. */
    _Alignas(4) uint8_t dma_input[MICROCARD_DMA_CHUNK_BYTES];
    psa_status_t status = PSA_SUCCESS;
    while (input_size != 0u) {
        size_t chunk_size = input_size;
        if (chunk_size > sizeof(dma_input)) {
            chunk_size = sizeof(dma_input);
        }
        memcpy(dma_input, input, chunk_size);
        status = psa_driver_wrapper_mac_update(operation, dma_input, chunk_size);
        if (status != PSA_SUCCESS) {
            break;
        }
        input += chunk_size;
        input_size -= chunk_size;
    }
    microcard_wipe(dma_input, sizeof(dma_input));
    if (status != PSA_SUCCESS) {
        (void)psa_driver_wrapper_mac_abort(operation);
        microcard_wipe(storage, storage_size);
    }
    return status;
}

int32_t microcard_cc310_cmac_finish(void *storage, size_t storage_size,
                                    uint8_t *output, size_t output_size)
{
    psa_mac_operation_t *operation = microcard_operation(storage, storage_size);
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (output == NULL || output_size != 16u) {
        (void)psa_driver_wrapper_mac_abort(operation);
        microcard_wipe(storage, storage_size);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t written = 0u;
    psa_status_t status = psa_driver_wrapper_mac_sign_finish(
        operation, output, output_size, &written);
    if (status == PSA_SUCCESS && written != output_size) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status != PSA_SUCCESS) {
        (void)psa_driver_wrapper_mac_abort(operation);
    }
    microcard_wipe(storage, storage_size);
    return status;
}

int32_t microcard_cc310_hmac_sha256_finish(void *storage, size_t storage_size,
                                           uint8_t *output, size_t output_size)
{
    psa_mac_operation_t *operation = microcard_operation(storage, storage_size);
    if (operation == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (output == NULL || output_size != MICROCARD_SHA256_BYTES) {
        (void)psa_driver_wrapper_mac_abort(operation);
        microcard_wipe(storage, storage_size);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t written = 0u;
    psa_status_t status = psa_driver_wrapper_mac_sign_finish(
        operation, output, output_size, &written);
    if (status == PSA_SUCCESS && written != output_size) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status != PSA_SUCCESS) {
        (void)psa_driver_wrapper_mac_abort(operation);
    }
    microcard_wipe(storage, storage_size);
    return status;
}
