/**
 * @file
 * @author  Matvey Mukha
 */

#include "cal.h"

#include "osal.h"

#define CHECK_ERROR(x)                                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        if (x != CRYPT_OK)                                                                                             \
        {                                                                                                              \
            osal_fatal_error();                                                                                        \
        }                                                                                                              \
    } while (0)

#define CHECK_ERROR_NOT_FATAL(x)                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if (x != CRYPT_OK)                                                                                             \
        {                                                                                                              \
            ret_val = false;                                                                                           \
            goto END;                                                                                                  \
        }                                                                                                              \
    } while (0)

#define CAL_ASSERT(x)                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!x)                                                                                                        \
        {                                                                                                              \
            osal_fatal_error();                                                                                        \
        }                                                                                                              \
    } while (0)

static int sha256;
static int aes;

void cal_init(void)
{
    register_all_ciphers();
    register_all_hashes();

    sha256 = find_hash("sha256");
    aes = find_cipher("aes");

    srand((unsigned int)time(NULL));
}

void cal_get_random(uint8_t *buffer, uint32_t buffer_length)
{
    /*
     * When porting this function, please make sure that a sufficiently random source is used here.
     * Srand and rand should not be used in actual implementations.
     */

    uint32_t i;

    for (i = 0; i < buffer_length; i++)
    {
#ifdef FIXED_RANDOM_FOR_TESTING_ONLY
        buffer[i] = 0x77;
#else
        buffer[i] = rand();
#endif
    }
}

void cal_hash_init(CAL_HASH_CONTEXT *context)
{
    CHECK_ERROR(sha256_init(context));
}

void cal_hash_update(CAL_HASH_CONTEXT *context, uint8_t *buffer, uint32_t buffer_length)
{
    CHECK_ERROR(sha256_process(context, buffer, buffer_length));
}

void cal_hash_get_intermediate_result(CAL_HASH_CONTEXT *context, uint8_t *digest)
{
    hash_state temp_state;

    temp_state = *context;

    CHECK_ERROR(sha256_done(&temp_state, digest));
}

void cal_hmac(uint8_t *key, uint8_t *data, uint32_t data_length, uint8_t *result)
{
    hmac_state hmac;
    unsigned long hmac_length = 32;

    CHECK_ERROR(hmac_init(&hmac, sha256, key, 32));
    CHECK_ERROR(hmac_process(&hmac, data, data_length));
    CHECK_ERROR(hmac_done(&hmac, result, &hmac_length));
    CAL_ASSERT(hmac_length == 32);
}

void cal_hkdf_extract(uint8_t *salt, uint8_t *in, uint8_t *out)
{
    unsigned long out_length = 32;
    CHECK_ERROR(hkdf_extract(sha256, salt, 32, in, 32, out, &out_length));
    CAL_ASSERT(out_length == 32);
}

void cal_hkdf_expand(uint8_t *info, uint32_t info_length, uint8_t *in, uint8_t *out, uint32_t out_length)
{
    CHECK_ERROR(hkdf_expand(sha256, info, info_length, in, 32, out, out_length));
}

void cal_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *header, uint32_t header_length, uint8_t *data_in,
                 uint8_t *data_out, uint32_t data_length, uint8_t *tag)
{
    unsigned long tag_length = 8;

    CHECK_ERROR(ccm_memory(aes, key, 16, NULL, nonce, 12, header, header_length, data_in, data_length, data_out, tag,
                           &tag_length, CCM_ENCRYPT));
    CAL_ASSERT(tag_length == 8);
}

bool cal_decrypt(uint8_t *key, uint8_t *nonce, uint8_t *header, uint32_t header_length, uint8_t *data_in,
                 uint8_t *data_out, uint32_t data_length, uint8_t *tag)
{
    bool ret_val = false;
    unsigned long tag_length = 8;

    CHECK_ERROR_NOT_FATAL(ccm_memory(aes, key, 16, NULL, nonce, 12, header, header_length, data_out, data_length,
                                     data_in, tag, &tag_length, CCM_DECRYPT));
    CAL_ASSERT(tag_length == 8);

    ret_val = true;

END:
    return ret_val;
}
