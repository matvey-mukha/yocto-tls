/**
 * @file
 * @author  Matvey Mukha
 */

#include "tls.h"

#include "cal.h"
#include "osal.h"

#define TLS_ASSERT(x)                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(x))                                                                                                      \
        {                                                                                                              \
            osal_fatal_error();                                                                                        \
        }                                                                                                              \
    } while (0)

#define CHECK_BOOL_ERROR(x)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((x) != true)                                                                                               \
        {                                                                                                              \
            ret_val = false;                                                                                           \
            goto END;                                                                                                  \
        }                                                                                                              \
    } while (0)

#define CHECK_MIN_FRAME_LENGTH(x)                                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((x) < MIN_ENCRYPTED_DATA_SIZE)                                                                             \
        {                                                                                                              \
            ret_val = false;                                                                                           \
            goto END;                                                                                                  \
        }                                                                                                              \
    } while (0)

#define CHECK_EXACT_LENGTH(x, y)                                                                                       \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((x) != (y))                                                                                                \
        {                                                                                                              \
            ret_val = false;                                                                                           \
            goto END;                                                                                                  \
        }                                                                                                              \
    } while (0)

#define YOCTO_TLS_STATE_INITIALIZED (0)

#define YOCTO_TLS_STATE_CLIENT_HELLO_GENERATED (1)
#define YOCTO_TLS_STATE_SERVER_HELLO_PROCESSED (2)
#define YOCTO_TLS_STATE_SERVER_ENC_EXTENSIONS_PROCESSED (3)
#define YOCTO_TLS_STATE_SERVER_FINISHED_PROCESSED (4)

#define YOCTO_TLS_CLIENT_HELLO_PREPROCESSED (5)
#define YOCTO_TLS_CLIENT_HELLO_PROCESSED (6)
#define YOCTO_TLS_STATE_SERVER_HELLO_GENERATED (7)
#define YOCTO_TLS_STATE_SERVER_ENCRYPTED_EXTENSIONS_GENERATED (8)
#define YOCTO_TLS_STATE_SERVER_FINISHED_GENERATED (9)

#define YOCTO_TLS_STATE_HANDSHAKE_DONE (10)

#define TLS_HEADER_LENGTH (5)
#define TLS_TAIL_LENGTH (1)
#define TAG_LENGTH (8)

#define TLS_TAIL_SIXTEEN (0x16)
#define TLS_TAIL_SEVENTEEN (0x17)

#define MIN_ENCRYPTED_DATA_SIZE (TLS_HEADER_LENGTH + TAG_LENGTH)

#define CLIENT_HELLO_TEMPLATE_RANDOM_OFFSET (11)
#define CLIENT_HELLO_TEMPLATE_BINDER_OFFSET (95)
#define CLIENT_HELLO_TEMPLATE_CLIENT_IDENTITY_OFFSET (73)
#define CLIENT_HELLO_TEMPLATE_DATA_UNTIL_BINDER_LENGTH (87)

#define SERVER_HELLO_TEMPLATE_RANDOM_OFFSET (11)

#define CLIENT_HANDSHAKE_SECRET_DIGEST_OFFSET (22)
#define SERVER_HANDSHAKE_SECRET_DIGEST_OFFSET (22)
#define CLIENT_TRAFFIC_SECRET_DIGEST_OFFSET (22)
#define SERVER_TRAFFIC_SECRET_DIGEST_OFFSET (22)

#define SERVER_ENC_EXTENSIONS_FRAME_SIZE (20)
#define SERVER_OR_CLIENT_FINISHED_FRAME_SIZE (50)
#define DECRYPTED_SERVER_FINISHED_HEADER_SIZE (4)

#define INTERNAL_BUFFER_SEZE (64)

/* Some vectors below are not declared const because some crypto abstraction layers might require operands to be located
 * in RAM. If that does not apply to your system, you can declare everything as const to save some RAM.
 */

static const uint8_t client_hello_template[] = {
    0x16, 0x03, 0x03, 0x00, 0x7A, 0x01, 0x00, 0x00, 0x76, 0x03, 0x03, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x00, 0x00, 0x02, 0x13, 0x05, 0x01, 0x00, 0x00, 0x4b, 0x00, 0x2d, 0x00, 0x02, 0x01,
    0x00, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x29, 0x00, 0x3a, 0x00, 0x15, 0x00, 0x0f, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x20,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};

static const uint8_t client_hello_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t server_hello_template_variant_1[] = {
    0x16, 0x03, 0x03, 0x00, 0x38, 0x02, 0x00, 0x00, 0x34, 0x03, 0x03, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x00, 0x13, 0x05, 0x00, 0x00,
    0x0c, 0x00, 0x29, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};

static const uint8_t server_hello_template_variant_2[] = {
    0x16, 0x03, 0x03, 0x00, 0x38, 0x02, 0x00, 0x00, 0x34, 0x03, 0x03, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x00, 0x13, 0x05, 0x00, 0x00,
    0x0c, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x29, 0x00, 0x02, 0x00, 0x00};

static const uint8_t server_hello_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static const uint8_t server_extentions_to_encrypt[] = {0x17, 0x03, 0x03, 0x00, 0x0f, 0x08,
                                                       0x00, 0x00, 0x02, 0x00, 0x00, 0x16};

static const uint8_t decrypted_server_extensions[] = {0x08, 0x00, 0x00, 0x02, 0x00, 0x00, 0x16};

static const uint8_t decrypted_server_finished_template[] = {
    0x14, 0x00, 0x00, 0x20, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};

static const uint8_t decrypted_server_finished_mask[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t client_or_server_finished_header[] = {0x17, 0x03, 0x03, 0x00, 0x2d, 0x14, 0x00, 0x00, 0x20};

static const uint8_t client_data_message_header[] = {0x17, 0x03, 0x03, 0x5a, 0x5a};

static uint8_t zero_vector[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static uint8_t derive_binder_key_info[] = {
    0x00, 0x20, 0x10, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x65, 0x78, 0x74, 0x20, 0x62, 0x69, 0x6e, 0x64, 0x65,
    0x72, 0x20, 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

static uint8_t derive_finished_message_secret_info[] = {0x00, 0x20, 0x0e, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20,
                                                        0x66, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x00};

static uint8_t derive_handshake_secret_info[] = {
    0x00, 0x20, 0x0d, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64, 0x20,
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27,
    0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

static const uint8_t client_handshake_secret_info_template[] = {
    0x00, 0x20, 0x12, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63, 0x20, 0x68, 0x73, 0x20, 0x74, 0x72, 0x61, 0x66,
    0x66, 0x69, 0x63, 0x20, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};

static const uint8_t server_handshake_secret_info_template[] = {
    0x00, 0x20, 0x12, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x73, 0x20, 0x68, 0x73, 0x20, 0x74, 0x72, 0x61, 0x66,
    0x66, 0x69, 0x63, 0x20, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
    0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};

static uint8_t client_server_key_info[] = {0x00, 0x10, 0x09, 0x74, 0x6c, 0x73, 0x31,
                                           0x33, 0x20, 0x6b, 0x65, 0x79, 0x00};

static uint8_t client_server_iv_info[] = {0x00, 0x0c, 0x08, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x69, 0x76, 0x00};

static uint8_t write_mac_secret_info[] = {0x00, 0x20, 0x0e, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20,
                                          0x66, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x00};

static const uint8_t client_traffic_secret_info_template[] = {
    0x00, 0x20, 0x12, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63, 0x20, 0x61, 0x70, 0x20, 0x74, 0x72, 0x61, 0x66,
    0x66, 0x69, 0x63, 0x20, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};

static const uint8_t server_traffic_secret_info_template[] = {
    0x00, 0x20, 0x12, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x73, 0x20, 0x61, 0x70, 0x20, 0x74, 0x72, 0x61, 0x66,
    0x66, 0x69, 0x63, 0x20, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5};

static uint8_t interbal_buffer[INTERNAL_BUFFER_SEZE];

static void update_nonce(uint8_t *nonce, uint64_t seq)
{
    uint8_t seq_array[8] = {(uint8_t)(seq >> 56), (uint8_t)(seq >> 48), (uint8_t)(seq >> 40), (uint8_t)(seq >> 32),
                            (uint8_t)(seq >> 24), (uint8_t)(seq >> 16), (uint8_t)(seq >> 8),  (uint8_t)(seq >> 0)};

    for (uint32_t i = 0; i < 8; i++)
    {
        nonce[4 + i] ^= seq_array[i];
    }
}

static void generate_handshake_keys(YOCTO_TLS_CONTEXT *context)
{
    uint8_t digest[32];
    uint8_t client_handshake_secret_info[sizeof(client_handshake_secret_info_template)];
    uint8_t server_handshake_secret_info[sizeof(server_handshake_secret_info_template)];
    uint8_t client_handshake_secret[32];
    uint8_t server_handshake_secret[32];

    cal_hash_get_intermediate_result(&context->handshake_hash_context, digest);

    osal_memcpy(client_handshake_secret_info, client_handshake_secret_info_template,
                sizeof(client_handshake_secret_info));
    osal_memcpy(client_handshake_secret_info + CLIENT_HANDSHAKE_SECRET_DIGEST_OFFSET, digest, 32);

    cal_hkdf_expand(client_handshake_secret_info, sizeof(client_handshake_secret_info), context->handshake_secret,
                    client_handshake_secret, 32);

    osal_memcpy(server_handshake_secret_info, server_handshake_secret_info_template,
                sizeof(server_handshake_secret_info));
    osal_memcpy(server_handshake_secret_info + SERVER_HANDSHAKE_SECRET_DIGEST_OFFSET, digest, 32);

    cal_hkdf_expand(server_handshake_secret_info, sizeof(server_handshake_secret_info), context->handshake_secret,
                    server_handshake_secret, 32);

    cal_hkdf_expand(client_server_key_info, sizeof(client_server_key_info), client_handshake_secret,
                    context->client_key, 16);
    cal_hkdf_expand(client_server_key_info, sizeof(client_server_key_info), server_handshake_secret,
                    context->server_key, 16);
    cal_hkdf_expand(client_server_iv_info, sizeof(client_server_iv_info), client_handshake_secret,
                    context->client_nonce, 12);
    cal_hkdf_expand(client_server_iv_info, sizeof(client_server_iv_info), server_handshake_secret,
                    context->server_nonce, 12);

    cal_hkdf_expand(write_mac_secret_info, sizeof(write_mac_secret_info), client_handshake_secret,
                    context->client_write_mac_secret, 32);
    cal_hkdf_expand(write_mac_secret_info, sizeof(write_mac_secret_info), server_handshake_secret,
                    context->server_write_mac_secret, 32);

    osal_memset(client_handshake_secret, 0x00, 32);
    osal_memset(server_handshake_secret, 0x00, 32);
}

static void generate_traffic_keys(YOCTO_TLS_CONTEXT *context, uint8_t *digest)
{
    uint8_t master_key_salt[32];
    uint8_t master_key[32];
    uint8_t client_traffic_secret_info[sizeof(client_traffic_secret_info_template)];
    uint8_t client_traffic_secret[32];
    uint8_t server_traffic_secret_info[sizeof(server_traffic_secret_info_template)];
    uint8_t server_traffic_secret[32];

    cal_hkdf_expand(derive_handshake_secret_info, sizeof(derive_handshake_secret_info), context->handshake_secret,
                    master_key_salt, 32);
    cal_hkdf_extract(master_key_salt, zero_vector, master_key);

    osal_memcpy(client_traffic_secret_info, client_traffic_secret_info_template, sizeof(client_traffic_secret_info));
    osal_memcpy(client_traffic_secret_info + CLIENT_TRAFFIC_SECRET_DIGEST_OFFSET, digest, 32);

    cal_hkdf_expand(client_traffic_secret_info, sizeof(client_traffic_secret_info), master_key, client_traffic_secret,
                    32);

    osal_memcpy(server_traffic_secret_info, server_traffic_secret_info_template, sizeof(server_traffic_secret_info));
    osal_memcpy(server_traffic_secret_info + SERVER_TRAFFIC_SECRET_DIGEST_OFFSET, digest, 32);

    cal_hkdf_expand(server_traffic_secret_info, sizeof(server_traffic_secret_info), master_key, server_traffic_secret,
                    32);
    cal_hkdf_expand(client_server_key_info, sizeof(client_server_key_info), client_traffic_secret, context->client_key,
                    16);
    cal_hkdf_expand(client_server_key_info, sizeof(client_server_key_info), server_traffic_secret, context->server_key,
                    16);
    cal_hkdf_expand(client_server_iv_info, sizeof(client_server_iv_info), client_traffic_secret, context->client_nonce,
                    12);
    cal_hkdf_expand(client_server_iv_info, sizeof(client_server_iv_info), server_traffic_secret, context->server_nonce,
                    12);

    context->server_seq = 0;
    context->client_seq = 0;

    osal_memset(master_key_salt, 0x00, 32);
    osal_memset(master_key, 0x00, 32);
    osal_memset(client_traffic_secret, 0x00, 32);
    osal_memset(server_traffic_secret, 0x00, 32);
}

/*
 * Functions common to client and server
 */

void yocto_tls_preprocess_static_keys(uint8_t *pre_shared_key, uint8_t *binder_key, uint8_t *handshake_secret)
{
    uint8_t early_secret[32];

    cal_hkdf_extract(zero_vector, pre_shared_key, early_secret);
    cal_hkdf_expand(derive_binder_key_info, sizeof(derive_binder_key_info), early_secret, binder_key, 32);
    cal_hkdf_expand(derive_finished_message_secret_info, sizeof(derive_finished_message_secret_info), binder_key,
                    binder_key, 32);
    cal_hkdf_expand(derive_handshake_secret_info, sizeof(derive_handshake_secret_info), early_secret, handshake_secret,
                    32);
    cal_hkdf_extract(handshake_secret, zero_vector, handshake_secret);
}

void yocto_tls_init(void)
{
    osal_init();
    cal_init();
}

void yocto_tls_init_context(YOCTO_TLS_CONTEXT *context)
{
    osal_memset((uint8_t *)context, 0x00, sizeof(YOCTO_TLS_CONTEXT));

    context->state = YOCTO_TLS_STATE_INITIALIZED;
}

void yocto_tls_encrypt(YOCTO_TLS_CONTEXT *context, bool is_client, uint8_t *in_buffer, uint32_t in_buffer_length,
                       uint8_t *out_buffer)
{
    uint32_t plain_data_length;
    uint8_t *key;
    uint8_t *nonce;
    uint64_t *sequence;

    TLS_ASSERT(context->state == YOCTO_TLS_STATE_HANDSHAKE_DONE);

    if (is_client == true)
    {
        key = context->client_key;
        nonce = context->client_nonce;
        sequence = &context->client_seq;
    }
    else
    {
        key = context->server_key;
        nonce = context->server_nonce;
        sequence = &context->server_seq;
    }

    osal_memcpy(out_buffer + sizeof(client_data_message_header), in_buffer, in_buffer_length);
    osal_memcpy(out_buffer, client_data_message_header, sizeof(client_data_message_header));
    out_buffer[sizeof(client_data_message_header) + in_buffer_length] = TLS_TAIL_SEVENTEEN;

    plain_data_length = sizeof(client_data_message_header) - TLS_HEADER_LENGTH + in_buffer_length + TLS_TAIL_LENGTH;

    out_buffer[3] = (uint8_t)((plain_data_length + TAG_LENGTH) >> 8);
    out_buffer[4] = (uint8_t)(plain_data_length + TAG_LENGTH);

    update_nonce(nonce, *sequence);
    *sequence += 1;

    cal_encrypt(key, nonce, out_buffer, TLS_HEADER_LENGTH, out_buffer + TLS_HEADER_LENGTH,
                out_buffer + TLS_HEADER_LENGTH, plain_data_length, out_buffer + TLS_HEADER_LENGTH + plain_data_length);
}

bool yocto_tls_decrypt(YOCTO_TLS_CONTEXT *context, bool is_client, uint8_t *in_buffer, uint32_t in_buffer_length,
                       uint8_t *out_buffer)
{
    bool ret_val = false;
    uint32_t plain_text_length;
    uint8_t *key;
    uint8_t *nonce;
    uint64_t *sequence;

    TLS_ASSERT(context->state == YOCTO_TLS_STATE_HANDSHAKE_DONE);

    if (is_client == true)
    {
        key = context->server_key;
        nonce = context->server_nonce;
        sequence = &context->server_seq;
    }
    else
    {
        key = context->client_key;
        nonce = context->client_nonce;
        sequence = &context->client_seq;
    }

    CHECK_MIN_FRAME_LENGTH(in_buffer_length);

    plain_text_length = in_buffer_length - TLS_HEADER_LENGTH - TAG_LENGTH;

    update_nonce(nonce, *sequence);
    *sequence += 1;

    CHECK_BOOL_ERROR(cal_decrypt(key, nonce, in_buffer, TLS_HEADER_LENGTH, in_buffer + TLS_HEADER_LENGTH, out_buffer,
                                 plain_text_length, in_buffer + in_buffer_length - TAG_LENGTH));

    ret_val = true;

END:
    return ret_val;
}

/*
 * Client handshake functions
 */

void yocto_tls_client_generate_client_hello(YOCTO_TLS_CONTEXT *context, uint8_t *buffer, uint32_t *client_hello_length,
                                            uint8_t *binder_key, uint8_t *handshake_secret, uint8_t *identity)
{
    uint8_t client_hello_until_binder_digest[32];

    TLS_ASSERT(context->state == YOCTO_TLS_STATE_INITIALIZED);

    osal_memcpy(buffer, client_hello_template, sizeof(client_hello_template));

    cal_get_random(buffer + CLIENT_HELLO_TEMPLATE_RANDOM_OFFSET, 32);

    osal_memcpy(buffer + CLIENT_HELLO_TEMPLATE_CLIENT_IDENTITY_OFFSET, identity, YOCTO_TLS_CLIENT_IDENTITY_LENGTH);

    cal_hash_init(&context->handshake_hash_context);
    cal_hash_update(&context->handshake_hash_context, buffer + TLS_HEADER_LENGTH,
                    CLIENT_HELLO_TEMPLATE_DATA_UNTIL_BINDER_LENGTH);
    cal_hash_get_intermediate_result(&context->handshake_hash_context, client_hello_until_binder_digest);

    cal_hmac(binder_key, client_hello_until_binder_digest, 32, buffer + CLIENT_HELLO_TEMPLATE_BINDER_OFFSET);

    *client_hello_length = sizeof(client_hello_template);

    osal_memcpy(context->handshake_secret, handshake_secret, 32);

    cal_hash_update(&context->handshake_hash_context,
                    buffer + TLS_HEADER_LENGTH + CLIENT_HELLO_TEMPLATE_DATA_UNTIL_BINDER_LENGTH,
                    sizeof(client_hello_template) - TLS_HEADER_LENGTH - CLIENT_HELLO_TEMPLATE_DATA_UNTIL_BINDER_LENGTH);

    context->state = YOCTO_TLS_STATE_CLIENT_HELLO_GENERATED;
}

bool yocto_tls_client_process_server_hello(YOCTO_TLS_CONTEXT *context, uint8_t *buffer, uint32_t server_hello_length)
{
    bool ret_val = false;
    bool res;

    TLS_ASSERT(context->state == YOCTO_TLS_STATE_CLIENT_HELLO_GENERATED);

    res = osal_compare_arrays_with_mask(server_hello_template_variant_1, server_hello_mask,
                                        sizeof(server_hello_template_variant_1), buffer, server_hello_length);
    if (res != true)
    {
        CHECK_BOOL_ERROR(osal_compare_arrays_with_mask(server_hello_template_variant_2, server_hello_mask,
                                                       sizeof(server_hello_template_variant_2), buffer,
                                                       server_hello_length));
    }

    cal_hash_update(&context->handshake_hash_context, buffer + TLS_HEADER_LENGTH,
                    server_hello_length - TLS_HEADER_LENGTH);

    generate_handshake_keys(context);

    context->state = YOCTO_TLS_STATE_SERVER_HELLO_PROCESSED;

    ret_val = true;

END:
    return ret_val;
}

bool yocto_tls_client_process_server_encrypted_extensions(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                                          uint32_t encrypted_extensions_length)
{
    bool ret_val = false;
    uint32_t plain_text_length;

    TLS_ASSERT(context->state == YOCTO_TLS_STATE_SERVER_HELLO_PROCESSED);

    CHECK_EXACT_LENGTH(encrypted_extensions_length, SERVER_ENC_EXTENSIONS_FRAME_SIZE);

    plain_text_length = encrypted_extensions_length - TLS_HEADER_LENGTH - TAG_LENGTH;

    update_nonce(context->server_nonce, context->server_seq++);

    CHECK_BOOL_ERROR(cal_decrypt(context->server_key, context->server_nonce, buffer, TLS_HEADER_LENGTH,
                                 buffer + TLS_HEADER_LENGTH, interbal_buffer, plain_text_length,
                                 buffer + encrypted_extensions_length - TAG_LENGTH));

    CHECK_BOOL_ERROR(osal_memcmp(interbal_buffer, decrypted_server_extensions, plain_text_length));

    cal_hash_update(&context->handshake_hash_context, interbal_buffer, plain_text_length - TLS_TAIL_LENGTH);

    context->state = YOCTO_TLS_STATE_SERVER_ENC_EXTENSIONS_PROCESSED;

    ret_val = true;

END:
    return ret_val;
}

bool yocto_tls_client_process_server_finished(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                              uint32_t server_finished_length)
{
    bool ret_val = false;
    uint32_t plain_text_length;
    uint8_t server_finished_verification_digest[32];
    uint8_t server_finished_mac[32];

    TLS_ASSERT(context->state == YOCTO_TLS_STATE_SERVER_ENC_EXTENSIONS_PROCESSED);

    CHECK_EXACT_LENGTH(server_finished_length, SERVER_OR_CLIENT_FINISHED_FRAME_SIZE);

    cal_hash_get_intermediate_result(&context->handshake_hash_context, server_finished_verification_digest);

    plain_text_length = server_finished_length - TLS_HEADER_LENGTH - TAG_LENGTH;

    update_nonce(context->server_nonce, context->server_seq++);

    CHECK_BOOL_ERROR(cal_decrypt(context->server_key, context->server_nonce, buffer, TLS_HEADER_LENGTH,
                                 buffer + TLS_HEADER_LENGTH, interbal_buffer, plain_text_length,
                                 buffer + server_finished_length - TAG_LENGTH));

    CHECK_BOOL_ERROR(osal_compare_arrays_with_mask(decrypted_server_finished_template, decrypted_server_finished_mask,
                                                   sizeof(decrypted_server_finished_template), interbal_buffer,
                                                   plain_text_length));

    cal_hash_update(&context->handshake_hash_context, interbal_buffer, plain_text_length - TLS_TAIL_LENGTH);

    cal_hmac(context->server_write_mac_secret, server_finished_verification_digest, 32, server_finished_mac);

    CHECK_BOOL_ERROR(osal_memcmp(server_finished_mac, interbal_buffer + DECRYPTED_SERVER_FINISHED_HEADER_SIZE, 32));

    context->state = YOCTO_TLS_STATE_SERVER_FINISHED_PROCESSED;

    ret_val = true;

END:
    return ret_val;
}

void yocto_tls_client_generate_client_finished(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                               uint32_t *client_finished_length)
{
    uint8_t traffic_keys_generation_digest[32];
    uint32_t plain_text_length;

    TLS_ASSERT(context->state == YOCTO_TLS_STATE_SERVER_FINISHED_PROCESSED);

    cal_hash_get_intermediate_result(&context->handshake_hash_context, traffic_keys_generation_digest);

    osal_memcpy(buffer, client_or_server_finished_header, sizeof(client_or_server_finished_header));
    cal_hmac(context->client_write_mac_secret, traffic_keys_generation_digest, 32,
             buffer + sizeof(client_or_server_finished_header));
    buffer[sizeof(client_or_server_finished_header) + 32] = TLS_TAIL_SIXTEEN;

    plain_text_length = sizeof(client_or_server_finished_header) - TLS_HEADER_LENGTH + 32 + TLS_TAIL_LENGTH;

    update_nonce(context->client_nonce, context->client_seq++);

    cal_encrypt(context->client_key, context->client_nonce, buffer, TLS_HEADER_LENGTH, buffer + TLS_HEADER_LENGTH,
                buffer + TLS_HEADER_LENGTH, plain_text_length, buffer + TLS_HEADER_LENGTH + plain_text_length);

    *client_finished_length = sizeof(client_or_server_finished_header) + 32 + TLS_TAIL_LENGTH + TAG_LENGTH;

    generate_traffic_keys(context, traffic_keys_generation_digest);

    context->state = YOCTO_TLS_STATE_HANDSHAKE_DONE;
}

/*
 * Server handshake functions
 */

bool yocto_tls_server_preprocess_client_hello(YOCTO_TLS_CONTEXT *context, uint8_t *buffer, uint32_t client_hello_length,
                                              uint8_t *client_identity)
{
    bool ret_val = false;

    TLS_ASSERT(context->state == YOCTO_TLS_STATE_INITIALIZED);

    CHECK_BOOL_ERROR(osal_compare_arrays_with_mask(client_hello_template, client_hello_mask,
                                                   sizeof(client_hello_template), buffer, client_hello_length));

    osal_memcpy(client_identity, buffer + CLIENT_HELLO_TEMPLATE_CLIENT_IDENTITY_OFFSET,
                YOCTO_TLS_CLIENT_IDENTITY_LENGTH);

    context->state = YOCTO_TLS_CLIENT_HELLO_PREPROCESSED;

    ret_val = true;

END:
    return ret_val;
}

bool yocto_tls_server_process_client_hello(YOCTO_TLS_CONTEXT *context, uint8_t *buffer, uint32_t client_hello_length,
                                           uint8_t *binder_key, uint8_t *handshake_secret)
{
    bool ret_val = false;
    uint8_t client_hello_until_binder_digest[32];
    uint8_t binder[32];

    TLS_ASSERT(context->state == YOCTO_TLS_CLIENT_HELLO_PREPROCESSED);

    CHECK_BOOL_ERROR(osal_compare_arrays_with_mask(client_hello_template, client_hello_mask,
                                                   sizeof(client_hello_template), buffer, client_hello_length));

    cal_hash_init(&context->handshake_hash_context);
    cal_hash_update(&context->handshake_hash_context, buffer + TLS_HEADER_LENGTH,
                    CLIENT_HELLO_TEMPLATE_DATA_UNTIL_BINDER_LENGTH);
    cal_hash_get_intermediate_result(&context->handshake_hash_context, client_hello_until_binder_digest);

    cal_hmac(binder_key, client_hello_until_binder_digest, 32, binder);

    CHECK_BOOL_ERROR(osal_memcmp(binder, buffer + CLIENT_HELLO_TEMPLATE_BINDER_OFFSET, 32));

    osal_memcpy(context->handshake_secret, handshake_secret, 32);

    cal_hash_update(&context->handshake_hash_context,
                    buffer + TLS_HEADER_LENGTH + CLIENT_HELLO_TEMPLATE_DATA_UNTIL_BINDER_LENGTH,
                    sizeof(client_hello_template) - TLS_HEADER_LENGTH - CLIENT_HELLO_TEMPLATE_DATA_UNTIL_BINDER_LENGTH);

    context->state = YOCTO_TLS_CLIENT_HELLO_PROCESSED;

    ret_val = true;

END:
    return ret_val;
}

void yocto_tls_server_generate_server_hello(YOCTO_TLS_CONTEXT *context, uint8_t *buffer, uint32_t *server_hello_length)
{
    TLS_ASSERT(context->state == YOCTO_TLS_CLIENT_HELLO_PROCESSED);

    osal_memcpy(buffer, server_hello_template_variant_1, sizeof(server_hello_template_variant_1));

    cal_get_random(buffer + SERVER_HELLO_TEMPLATE_RANDOM_OFFSET, 32);

    cal_hash_update(&context->handshake_hash_context, buffer + TLS_HEADER_LENGTH,
                    sizeof(server_hello_template_variant_1) - TLS_HEADER_LENGTH);

    *server_hello_length = sizeof(server_hello_template_variant_1);

    generate_handshake_keys(context);

    context->state = YOCTO_TLS_STATE_SERVER_HELLO_GENERATED;
}

void yocto_tls_server_generate_server_encrypted_extensions(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                                           uint32_t *encrypted_extensions_length)
{

    TLS_ASSERT(context->state == YOCTO_TLS_STATE_SERVER_HELLO_GENERATED);

    osal_memcpy(buffer, server_extentions_to_encrypt, sizeof(server_extentions_to_encrypt));

    cal_hash_update(&context->handshake_hash_context, buffer + TLS_HEADER_LENGTH,
                    sizeof(server_extentions_to_encrypt) - TLS_HEADER_LENGTH - TLS_TAIL_LENGTH);

    update_nonce(context->server_nonce, context->server_seq++);

    cal_encrypt(context->server_key, context->server_nonce, buffer, TLS_HEADER_LENGTH, buffer + TLS_HEADER_LENGTH,
                buffer + TLS_HEADER_LENGTH, sizeof(server_extentions_to_encrypt) - TLS_HEADER_LENGTH,
                buffer + sizeof(server_extentions_to_encrypt));

    *encrypted_extensions_length = sizeof(server_extentions_to_encrypt) + TAG_LENGTH;

    context->state = YOCTO_TLS_STATE_SERVER_ENCRYPTED_EXTENSIONS_GENERATED;
}

void yocto_tls_server_generate_server_finished(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                               uint32_t *server_finished_length)
{
    uint8_t server_finished_generation_digest[32];
    uint32_t plain_text_length;

    TLS_ASSERT(context->state == YOCTO_TLS_STATE_SERVER_ENCRYPTED_EXTENSIONS_GENERATED);

    cal_hash_get_intermediate_result(&context->handshake_hash_context, server_finished_generation_digest);

    osal_memcpy(buffer, client_or_server_finished_header, sizeof(client_or_server_finished_header));
    cal_hmac(context->server_write_mac_secret, server_finished_generation_digest, 32,
             buffer + sizeof(client_or_server_finished_header));
    buffer[sizeof(client_or_server_finished_header) + 32] = TLS_TAIL_SIXTEEN;

    plain_text_length = sizeof(client_or_server_finished_header) - TLS_HEADER_LENGTH + 32 + TLS_TAIL_LENGTH;

    cal_hash_update(&context->handshake_hash_context, buffer + TLS_HEADER_LENGTH, plain_text_length - TLS_TAIL_LENGTH);

    update_nonce(context->server_nonce, context->server_seq++);

    cal_encrypt(context->server_key, context->server_nonce, buffer, TLS_HEADER_LENGTH, buffer + TLS_HEADER_LENGTH,
                buffer + TLS_HEADER_LENGTH, plain_text_length, buffer + TLS_HEADER_LENGTH + plain_text_length);

    *server_finished_length = sizeof(client_or_server_finished_header) + 32 + TLS_TAIL_LENGTH + TAG_LENGTH;

    context->state = YOCTO_TLS_STATE_SERVER_FINISHED_GENERATED;
}

bool yocto_tls_server_process_client_finished(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                              uint32_t client_finished_length)
{
    bool ret_val = false;
    uint32_t plain_text_length;
    uint8_t client_finished_verification_digest[32];
    uint8_t client_finished_mac[32];

    TLS_ASSERT(context->state == YOCTO_TLS_STATE_SERVER_FINISHED_GENERATED);

    CHECK_EXACT_LENGTH(client_finished_length, SERVER_OR_CLIENT_FINISHED_FRAME_SIZE);

    cal_hash_get_intermediate_result(&context->handshake_hash_context, client_finished_verification_digest);

    plain_text_length = client_finished_length - TLS_HEADER_LENGTH - TAG_LENGTH;

    update_nonce(context->client_nonce, context->client_seq++);

    CHECK_BOOL_ERROR(cal_decrypt(context->client_key, context->client_nonce, buffer, TLS_HEADER_LENGTH,
                                 buffer + TLS_HEADER_LENGTH, interbal_buffer, plain_text_length,
                                 buffer + client_finished_length - TAG_LENGTH));

    CHECK_BOOL_ERROR(osal_compare_arrays_with_mask(decrypted_server_finished_template, decrypted_server_finished_mask,
                                                   sizeof(decrypted_server_finished_template), interbal_buffer,
                                                   plain_text_length));

    cal_hmac(context->client_write_mac_secret, client_finished_verification_digest, 32, client_finished_mac);

    CHECK_BOOL_ERROR(osal_memcmp(client_finished_mac, interbal_buffer + DECRYPTED_SERVER_FINISHED_HEADER_SIZE, 32));

    generate_traffic_keys(context, client_finished_verification_digest);

    context->state = YOCTO_TLS_STATE_HANDSHAKE_DONE;

    ret_val = true;

END:
    return ret_val;
}
