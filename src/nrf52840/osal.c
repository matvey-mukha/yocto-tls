/**
 * @file
 * @author  Matvey Mukha
 */

#include "osal.h"

#include "string.h"

#include "app_error.h"

void osal_init(void)
{
    return;
}

void osal_fatal_error(void)
{
    /*
     * When porting this function, please make sure that it does not return.
     */

    APP_ERROR_HANDLER(0);
}

void osal_memset(uint8_t *buffer, uint8_t value, uint32_t size)
{
    memset(buffer, value, size);
}

void osal_memcpy(uint8_t *dst, const uint8_t *src, uint32_t size)
{
    /*
     * When porting this function, please make sure buffers can overlap.
     */
    memmove(dst, src, size);
}

bool osal_memcmp(const uint8_t *buffer_1, const uint8_t *buffer_2, uint32_t size)
{
    /*
     * When porting this function, please make sure that the execution is time invariant.
     */

    uint32_t i;
    const volatile uint8_t *a = buffer_1;
    const volatile uint8_t *b = buffer_2;
    uint8_t x = 0;

    for (i = 0; i < size; i++)
    {
        x |= a[i] ^ b[i];
    }

    if (x != 0)
    {
        return false;
    }
    else
    {
        return true;
    }
}

bool osal_compare_arrays_with_mask(const uint8_t *tmplt, const uint8_t *mask, uint32_t tmplt_length, uint8_t *candidate,
                                   uint32_t candidate_length)
{
    uint32_t i;
    const volatile uint8_t *a = tmplt;
    const volatile uint8_t *b = candidate;
    const volatile uint8_t *c = mask;
    uint8_t x = 0;

    if (tmplt_length != candidate_length)
    {
        return false;
    }

    for (i = 0; i < tmplt_length; i++)
    {
        x |= (a[i] & c[i]) ^ (b[i] & c[i]);
    }

    if (x != 0)
    {
        return false;
    }
    else
    {
        return true;
    }
}