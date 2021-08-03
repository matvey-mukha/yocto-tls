/**
 * @file
 * @author  Matvey Mukha
 */

#pragma once

#include <tomcrypt.h>

#include "stdbool.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define CAL_HASH_CONTEXT hash_state

    void cal_init(void);
    void cal_get_random(uint8_t *buffer, uint32_t buffer_length);
    void cal_hash_init(CAL_HASH_CONTEXT *context);
    void cal_hash_update(CAL_HASH_CONTEXT *context, uint8_t *buffer, uint32_t buffer_length);
    void cal_hash_get_intermediate_result(CAL_HASH_CONTEXT *context, uint8_t *digest);
    void cal_hmac(uint8_t *key, uint8_t *data, uint32_t data_length, uint8_t *result);
    void cal_hkdf_extract(uint8_t *salt, uint8_t *in, uint8_t *out);
    void cal_hkdf_expand(uint8_t *info, uint32_t info_length, uint8_t *in, uint8_t *out, uint32_t out_length);
    void cal_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *header, uint32_t header_length, uint8_t *data_in,
                     uint8_t *data_out, uint32_t data_length, uint8_t *tag);
    bool cal_decrypt(uint8_t *key, uint8_t *nonce, uint8_t *header, uint32_t header_length, uint8_t *data_in,
                     uint8_t *data_out, uint32_t data_length, uint8_t *tag);

#ifdef __cplusplus
}
#endif