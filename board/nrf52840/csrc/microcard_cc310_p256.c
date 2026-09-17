#include <stddef.h>
#include <stdint.h>

#include "psa/crypto.h"
#include "cc3xx_psa_asymmetric_signature.h"
#include "cc3xx_psa_key_agreement.h"
#include "cc3xx_psa_key_generation.h"

#define MICROCARD_P256_PRIVATE_BYTES 32u
#define MICROCARD_P256_PUBLIC_BYTES 65u
#define MICROCARD_P256_HASH_BYTES 32u
#define MICROCARD_P256_SIGNATURE_BYTES 64u

static void microcard_wipe(void *buffer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)buffer;
    while (length != 0u) {
        *bytes++ = 0u;
        --length;
    }
}

static psa_key_attributes_t microcard_p256_attributes(
    psa_key_type_t type, psa_key_usage_t usage, psa_algorithm_t algorithm)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, type);
    psa_set_key_bits(&attributes, 256u);
    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, algorithm);
    return attributes;
}

int32_t microcard_cc310_p256_public_key(const uint8_t *private_key,
                                         size_t private_key_size,
                                         uint8_t *public_key,
                                         size_t public_key_size)
{
    if (private_key == NULL || private_key_size != MICROCARD_P256_PRIVATE_BYTES ||
        public_key == NULL || public_key_size != MICROCARD_P256_PUBLIC_BYTES) {
        return -1;
    }
    psa_key_attributes_t attributes = microcard_p256_attributes(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
        PSA_KEY_USAGE_EXPORT, PSA_ALG_ECDH);
    size_t written = 0u;
    psa_status_t status = cc3xx_internal_export_ecc_wrst_public_key(
        &attributes, private_key, private_key_size,
        public_key, public_key_size, &written);
    if (status == PSA_SUCCESS &&
        (written != MICROCARD_P256_PUBLIC_BYTES || public_key[0] != 0x04u)) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status != PSA_SUCCESS) {
        microcard_wipe(public_key, public_key_size);
        return -1;
    }
    return 0;
}

int32_t microcard_cc310_p256_sign_hash(const uint8_t *private_key,
                                        size_t private_key_size,
                                        const uint8_t *hash,
                                        size_t hash_size,
                                        uint8_t *signature,
                                        size_t signature_size)
{
    if (private_key == NULL || private_key_size != MICROCARD_P256_PRIVATE_BYTES ||
        hash == NULL || hash_size != MICROCARD_P256_HASH_BYTES ||
        signature == NULL || signature_size != MICROCARD_P256_SIGNATURE_BYTES) {
        return -1;
    }
    const psa_algorithm_t algorithm =
        PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
    psa_key_attributes_t attributes = microcard_p256_attributes(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
        PSA_KEY_USAGE_SIGN_HASH, algorithm);
    size_t written = 0u;
    psa_status_t status = cc3xx_sign_hash(
        &attributes, private_key, private_key_size, algorithm,
        hash, hash_size, signature, signature_size, &written);
    if (status == PSA_SUCCESS && written != MICROCARD_P256_SIGNATURE_BYTES) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status != PSA_SUCCESS) {
        microcard_wipe(signature, signature_size);
        return -1;
    }
    return 0;
}

int32_t microcard_cc310_p256_verify_hash(const uint8_t *public_key,
                                          size_t public_key_size,
                                          const uint8_t *hash,
                                          size_t hash_size,
                                          const uint8_t *signature,
                                          size_t signature_size)
{
    if (public_key == NULL || public_key_size != MICROCARD_P256_PUBLIC_BYTES ||
        public_key[0] != 0x04u || hash == NULL ||
        hash_size != MICROCARD_P256_HASH_BYTES || signature == NULL ||
        signature_size != MICROCARD_P256_SIGNATURE_BYTES) {
        return 1;
    }
    const psa_algorithm_t algorithm =
        PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
    psa_key_attributes_t attributes = microcard_p256_attributes(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1),
        PSA_KEY_USAGE_VERIFY_HASH, algorithm);
    psa_status_t status = cc3xx_verify_hash(
        &attributes, public_key, public_key_size, algorithm,
        hash, hash_size, signature, signature_size);
    if (status == PSA_SUCCESS) {
        return 0;
    }
    return status == PSA_ERROR_INVALID_SIGNATURE ||
                   status == PSA_ERROR_INVALID_ARGUMENT
               ? 1
               : -1;
}

int32_t microcard_cc310_p256_ecdh(const uint8_t *private_key,
                                   size_t private_key_size,
                                   const uint8_t *peer_public_key,
                                   size_t peer_public_key_size,
                                   uint8_t *secret,
                                   size_t secret_size)
{
    if (private_key == NULL || private_key_size != MICROCARD_P256_PRIVATE_BYTES ||
        peer_public_key == NULL ||
        peer_public_key_size != MICROCARD_P256_PUBLIC_BYTES ||
        peer_public_key[0] != 0x04u || secret == NULL ||
        secret_size != MICROCARD_P256_PRIVATE_BYTES) {
        if (secret != NULL && secret_size == MICROCARD_P256_PRIVATE_BYTES) {
            microcard_wipe(secret, secret_size);
        }
        return 1;
    }
    psa_key_attributes_t attributes = microcard_p256_attributes(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
        PSA_KEY_USAGE_DERIVE, PSA_ALG_ECDH);
    size_t written = 0u;
    psa_status_t status = cc3xx_key_agreement(
        &attributes, private_key, private_key_size,
        peer_public_key, peer_public_key_size, secret, secret_size, &written,
        PSA_ALG_ECDH);
    if (status == PSA_SUCCESS && written != MICROCARD_P256_PRIVATE_BYTES) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status != PSA_SUCCESS) {
        microcard_wipe(secret, secret_size);
        return status == PSA_ERROR_INVALID_ARGUMENT ? 1 : -1;
    }
    return 0;
}
