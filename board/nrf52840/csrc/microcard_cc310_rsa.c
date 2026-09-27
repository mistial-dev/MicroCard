#include <stddef.h>
#include <stdint.h>

#include "psa/crypto.h"
#include "cc3xx_psa_asymmetric_signature.h"
#include "cc3xx_psa_key_generation.h"
#include "cc3xx_psa_rsa_util.h"

#define MICROCARD_RSA_HASH_BYTES 32u
#define MICROCARD_RSA_PRIVATE_DER_MAX 1250u
#define MICROCARD_RSA_PUBLIC_DER_MAX 300u

static void microcard_wipe(void *buffer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)buffer;
    while (length != 0u) {
        *bytes++ = 0u;
        --length;
    }
}

static int microcard_rsa_bits_valid(size_t bits)
{
    return bits == 1024u || bits == 2048u;
}

int32_t microcard_cc310_rsa_generate_key_pair(
    size_t key_bits, uint8_t *private_der, size_t private_capacity,
    size_t *private_length, uint8_t *public_der, size_t public_capacity,
    size_t *public_length)
{
    if (private_length == NULL || public_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *private_length = 0u;
    *public_length = 0u;
    if (!microcard_rsa_bits_valid(key_bits) || private_der == NULL || public_der == NULL ||
        private_capacity < MICROCARD_RSA_PRIVATE_DER_MAX ||
        public_capacity < MICROCARD_RSA_PUBLIC_DER_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_status_t status = cc3xx_internal_gen_rsa_keypair(
        &attributes, private_der, private_capacity, private_length);
    if (status == PSA_SUCCESS && (*private_length == 0u ||
        *private_length > MICROCARD_RSA_PRIVATE_DER_MAX)) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status == PSA_SUCCESS) {
        status = cc3xx_rsa_psa_priv_to_psa_publ(
            private_der, *private_length, public_der, public_capacity, public_length);
    }
    if (status != PSA_SUCCESS || *public_length == 0u ||
        *public_length > MICROCARD_RSA_PUBLIC_DER_MAX) {
        microcard_wipe(private_der, private_capacity);
        microcard_wipe(public_der, public_capacity);
        *private_length = 0u;
        *public_length = 0u;
        return status == PSA_SUCCESS ? PSA_ERROR_CORRUPTION_DETECTED : status;
    }
    return PSA_SUCCESS;
}

int32_t microcard_cc310_rsa_pkcs1v15_sha256_sign(
    const uint8_t *private_der, size_t private_der_size, size_t key_bits,
    const uint8_t *hash, size_t hash_size,
    uint8_t *signature, size_t signature_size)
{
    if (private_der == NULL || private_der_size == 0u ||
        private_der_size > MICROCARD_RSA_PRIVATE_DER_MAX ||
        !microcard_rsa_bits_valid(key_bits) ||
        hash == NULL || hash_size != MICROCARD_RSA_HASH_BYTES ||
        signature == NULL || signature_size != key_bits / 8u) {
        if (signature != NULL && signature_size <= 256u) {
            microcard_wipe(signature, signature_size);
        }
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const psa_algorithm_t algorithm = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, algorithm);

    size_t written = 0u;
    psa_status_t status = cc3xx_sign_hash(
        &attributes, private_der, private_der_size, algorithm,
        hash, hash_size, signature, signature_size, &written);
    if (status == PSA_SUCCESS && written != signature_size) {
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }
    if (status != PSA_SUCCESS) {
        microcard_wipe(signature, signature_size);
    }
    return status;
}

int32_t microcard_cc310_rsa_pkcs1v15_sha256_verify(
    const uint8_t *public_der, size_t public_der_size, size_t key_bits,
    const uint8_t *hash, size_t hash_size,
    const uint8_t *signature, size_t signature_size)
{
    if (public_der == NULL || public_der_size == 0u ||
        public_der_size > MICROCARD_RSA_PUBLIC_DER_MAX ||
        !microcard_rsa_bits_valid(key_bits) ||
        hash == NULL || hash_size != MICROCARD_RSA_HASH_BYTES ||
        signature == NULL || signature_size != key_bits / 8u) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const psa_algorithm_t algorithm = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, algorithm);
    psa_status_t status = cc3xx_verify_hash(
        &attributes, public_der, public_der_size, algorithm,
        hash, hash_size, signature, signature_size);
    if (status == PSA_SUCCESS) {
        return 0;
    }
    return status == PSA_ERROR_INVALID_SIGNATURE ? 1 : -1;
}
