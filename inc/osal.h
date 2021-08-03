/**
 * @file
 * @author  Matvey Mukha
 */

#pragma once

#include "stdbool.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C"
{
#endif

    void osal_init(void);
    void osal_fatal_error(void);
    void osal_memset(uint8_t *buffer, uint8_t value, uint32_t size);
    void osal_memcpy(uint8_t *dst, const uint8_t *src, uint32_t size);
    bool osal_memcmp(const uint8_t *buffer_1, const uint8_t *buffer_2, uint32_t size);
    bool osal_compare_arrays_with_mask(const uint8_t *tmplt, const uint8_t *mask, uint32_t tmplt_length,
                                       uint8_t *candidate, uint32_t candidate_length);

#ifdef __cplusplus
}
#endif