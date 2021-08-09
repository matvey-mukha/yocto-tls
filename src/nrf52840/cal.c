/**
 * @file
 * @author  Matvey Mukha
 */

#include "cal.h"

#include "osal.h"

#define CHECK_ERROR(x)                                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((x) != NRF_SUCCESS)                                                                                        \
        {                                                                                                              \
            osal_fatal_error();                                                                                        \
        }                                                                                                              \
    } while (0)

#define CHECK_ERROR_NOT_FATAL(x)                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((x) != NRF_SUCCESS)                                                                                        \
        {                                                                                                              \
            ret_val = false;                                                                                           \
            goto END;                                                                                                  \
        }                                                                                                              \
    } while (0)

#define CAL_ASSERT(x)                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(x))                                                                                                      \
        {                                                                                                              \
            osal_fatal_error();                                                                                        \
        }                                                                                                              \
    } while (0)

static int sha256;
static int aes;

void cal_init(void)
{
    CHECK_ERROR(nrf_crypto_init());
}

void cal_get_random(uint8_t *buffer, uint32_t buffer_length)
{
    /*
     * When porting this function, please make sure that a sufficiently random source is used here.
     * Srand and rand should not be used in actual implementations.
     */

    uint32_t i;

#ifdef FIXED_RANDOM_FOR_TESTING_ONLY
    for (i = 0; i < buffer_length; i++)
    {
        buffer[i] = 0x77;
    }
#else
    nrf_crypto_rng_vector_generate(buffer, buffer_length);
#endif
}

void cal_hash_init(CAL_HASH_CONTEXT *context)
{
    CHECK_ERROR(nrf_crypto_hash_init(context, &g_nrf_crypto_hash_sha256_info));
}

void cal_hash_update(CAL_HASH_CONTEXT *context, uint8_t *buffer, uint32_t buffer_length)
{
    CHECK_ERROR(nrf_crypto_hash_update(context, buffer, buffer_length));
}

void cal_hash_get_intermediate_result(CAL_HASH_CONTEXT *context, uint8_t *digest)
{
    CAL_HASH_CONTEXT temp_context;
    uint32_t digest_len = 32;

    temp_context = *context;

    CHECK_ERROR(nrf_crypto_hash_finalize(&temp_context, digest, &digest_len));
    CAL_ASSERT(digest_len == 32);
}

void cal_hmac(uint8_t *key, uint8_t *data, uint32_t data_length, uint8_t *result)
{
    nrf_crypto_hmac_context_t hmac;
    uint32_t hmac_length = 32;

    CHECK_ERROR(nrf_crypto_hmac_init(&hmac, &g_nrf_crypto_hmac_sha256_info, key, 32));
    CHECK_ERROR(nrf_crypto_hmac_update(&hmac, data, data_length));
    CHECK_ERROR(nrf_crypto_hmac_finalize(&hmac, result, &hmac_length));
    CAL_ASSERT(hmac_length == 32);
}

void cal_hkdf_extract(uint8_t *salt, uint8_t *in, uint8_t *out)
{
    nrf_crypto_hmac_context_t hmac;
    uint32_t out_length = 32;

    CHECK_ERROR(nrf_crypto_hmac_calculate(&hmac, &g_nrf_crypto_hmac_sha256_info, out, &out_length, salt, 32, in, 32));
    CAL_ASSERT(out_length == 32);
}

void cal_hkdf_expand(uint8_t *info, uint32_t info_length, uint8_t *in, uint8_t *out, uint32_t out_length)
{
    nrf_crypto_hmac_context_t hmac;
    uint32_t real_out_length = out_length;

    CHECK_ERROR(nrf_crypto_hkdf_calculate(&hmac, &g_nrf_crypto_hmac_sha256_info, out, &real_out_length, in, 32, NULL, 0,
                                          info, info_length, NRF_CRYPTO_HKDF_EXPAND_ONLY));
    CAL_ASSERT(out_length == real_out_length);
}

void cal_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *header, uint32_t header_length, uint8_t *data_in,
                 uint8_t *data_out, uint32_t data_length, uint8_t *tag)
{
    nrf_crypto_aead_context_t aes;
    uint32_t tag_length = 8;

    CHECK_ERROR(nrf_crypto_aead_init(&aes, &g_nrf_crypto_aes_ccm_128_info, key));

    CHECK_ERROR(nrf_crypto_aead_crypt(&aes, NRF_CRYPTO_ENCRYPT, nonce, 12, header, header_length, data_in, data_length,
                                      data_out, tag, 8));

    CHECK_ERROR(nrf_crypto_aead_uninit(&aes));
}

bool cal_decrypt(uint8_t *key, uint8_t *nonce, uint8_t *header, uint32_t header_length, uint8_t *data_in,
                 uint8_t *data_out, uint32_t data_length, uint8_t *tag)
{
    bool ret_val = false;

    nrf_crypto_aead_context_t aes;
    uint32_t tag_length = 8;

    CHECK_ERROR(nrf_crypto_aead_init(&aes, &g_nrf_crypto_aes_ccm_128_info, key));

    CHECK_ERROR_NOT_FATAL(nrf_crypto_aead_crypt(&aes, NRF_CRYPTO_DECRYPT, nonce, 12, header, header_length, data_in,
                                                data_length, data_out, tag, 8));

    CHECK_ERROR(nrf_crypto_aead_uninit(&aes));

    ret_val = true;

END:
    return ret_val;
}
