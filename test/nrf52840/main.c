#include "app_error.h"
#include "boards.h"
#include <stdbool.h>
#include <stdint.h>

#include <string.h>

#include "tls.h"

static uint8_t pre_shared_key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
                                   0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                                   0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

static uint8_t server_hello[] = {0x16, 0x03, 0x03, 0x00, 0x38, 0x02, 0x00, 0x00, 0x34, 0x03, 0x03, 0x77, 0x77,
                                 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                                 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                                 0x77, 0x77, 0x77, 0x77, 0x00, 0x13, 0x05, 0x00, 0x00, 0x0c, 0x00, 0x29, 0x00,
                                 0x02, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};

static uint8_t server_enc_ext[] = {0x17, 0x03, 0x03, 0x00, 0x0f, 0x3d, 0xf4, 0x31, 0x3d, 0x95,
                                   0xfd, 0x4c, 0x84, 0xb8, 0x29, 0x81, 0x02, 0x30, 0xe0, 0x86};

static uint8_t server_finished[] = {0x17, 0x03, 0x03, 0x00, 0x2d, 0x87, 0x29, 0xe6, 0x2f, 0xb5, 0x79, 0x3c, 0x98,
                                    0x5f, 0xf5, 0x86, 0xb4, 0x4c, 0x2c, 0xa2, 0x25, 0x20, 0x90, 0x8d, 0xf7, 0x3c,
                                    0x9b, 0x64, 0x68, 0xae, 0x2e, 0x34, 0x34, 0xe2, 0x64, 0xee, 0xce, 0xad, 0xa8,
                                    0x81, 0x3e, 0xa3, 0xd7, 0x4e, 0x1e, 0x0f, 0x07, 0x6f, 0x26, 0x87};

static uint8_t server_data_message[] = {0x17, 0x03, 0x03, 0x00, 0x0a, 0x9f, 0x66, 0xc4,
                                        0xc4, 0x54, 0x29, 0x93, 0x39, 0x04, 0x7a};

static uint8_t client_hello[] = {
    0x16, 0x03, 0x03, 0x00, 0x7a, 0x01, 0x00, 0x00, 0x76, 0x03, 0x03, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
    0x77, 0x77, 0x77, 0x77, 0x77, 0x00, 0x00, 0x02, 0x13, 0x05, 0x01, 0x00, 0x00, 0x4b, 0x00, 0x2d, 0x00, 0x02, 0x01,
    0x00, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x29, 0x00, 0x3a, 0x00, 0x15, 0x00, 0x0f, 0x43, 0x6c, 0x69,
    0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x20,
    0xc0, 0xf0, 0x3e, 0xde, 0xe5, 0xfa, 0xfd, 0xdb, 0x1e, 0xee, 0xc1, 0xb6, 0x88, 0xfa, 0x26, 0x0a, 0x98, 0x4b, 0xce,
    0x27, 0x16, 0x0b, 0x30, 0xe8, 0x6a, 0xf8, 0x33, 0x80, 0xea, 0xd0, 0x1b, 0x48};

static uint8_t client_finished[] = {0x17, 0x03, 0x03, 0x00, 0x2d, 0x56, 0x21, 0x8a, 0x82, 0xb0, 0x76, 0x81, 0x4f,
                                    0x76, 0x10, 0x7b, 0xfd, 0x94, 0x44, 0x63, 0x3d, 0x51, 0xf4, 0xcc, 0xda, 0xda,
                                    0x5b, 0x9b, 0x11, 0xb3, 0x55, 0x7b, 0xd6, 0x3d, 0xa8, 0x6f, 0x01, 0x2b, 0x44,
                                    0x57, 0xe3, 0x97, 0xc0, 0x93, 0xdf, 0x5f, 0xde, 0xac, 0x4a, 0x61};

static uint8_t plain_text[] = {0x0A};

static uint8_t client_data_message[] = {0x17, 0x03, 0x03, 0x00, 0x0a, 0xdf, 0xaf, 0xa5,
                                        0xc1, 0xb1, 0x6c, 0x03, 0x06, 0x87, 0x58};

static uint8_t buffer[256];

static void check_array_contents(uint8_t *array_1, uint32_t array_1_size, uint8_t *array_2, uint32_t array_2_size)
{
    int cmp_res;

    if (array_1_size != array_2_size)
    {
        APP_ERROR_HANDLER(0);
    }

    cmp_res = memcmp(array_1, array_2, array_1_size);

    if (cmp_res != 0)
    {
        APP_ERROR_HANDLER(0);
    }
}

static void check_res(bool res)
{
    if (res != true)
    {
        APP_ERROR_HANDLER(0);
    }
}

void client_test(void)
{
    YOCTO_TLS_CONTEXT context;
    uint8_t binder_key[32];
    uint8_t handshake_secret[32];
    uint32_t client_hello_length;
    uint32_t client_finished_length;
    uint8_t *identity = (uint8_t *)"Client_identity";
    bool res;

    yocto_tls_init();
    yocto_tls_preprocess_static_keys((uint8_t *)pre_shared_key, binder_key, handshake_secret);
    yocto_tls_init_context(&context);
    yocto_tls_client_generate_client_hello(&context, buffer, &client_hello_length, binder_key, handshake_secret,
                                           identity);
    check_array_contents(buffer, client_hello_length, client_hello, sizeof(client_hello));
    res = yocto_tls_client_process_server_hello(&context, (uint8_t *)server_hello, sizeof(server_hello));
    check_res(res == true);
    res = yocto_tls_client_process_server_encrypted_extensions(&context, (uint8_t *)server_enc_ext,
                                                               sizeof(server_enc_ext));
    check_res(res == true);
    res = yocto_tls_client_process_server_finished(&context, (uint8_t *)server_finished, sizeof(server_finished));
    check_res(res == true);
    yocto_tls_client_generate_client_finished(&context, buffer, &client_finished_length);
    check_array_contents(buffer, client_finished_length, client_finished, sizeof(client_finished));
    yocto_tls_encrypt(&context, true, (uint8_t *)plain_text, sizeof(plain_text), buffer);
    check_array_contents(buffer, sizeof(plain_text) + YOCTO_TLS_ENCRYPTED_DATA_LENGTH_DELTA, client_data_message,
                         sizeof(client_data_message));
    res = yocto_tls_decrypt(&context, true, (uint8_t *)server_data_message, sizeof(server_data_message), buffer);
    check_res(res == true);
}

void server_test(void)
{
    YOCTO_TLS_CONTEXT context;
    uint8_t binder_key[32];
    uint8_t handshake_secret[32];
    uint8_t buffer[1024];
    uint8_t client_identity[YOCTO_TLS_CLIENT_IDENTITY_LENGTH];
    uint32_t server_hello_length;
    uint32_t server_encrypted_extensions_length;
    uint32_t server_finished_length;
    bool res;

    yocto_tls_init();
    yocto_tls_preprocess_static_keys((uint8_t *)pre_shared_key, binder_key, handshake_secret);
    yocto_tls_init_context(&context);
    res = yocto_tls_server_preprocess_client_hello(&context, client_hello, sizeof(client_hello), client_identity);
    check_res(res == true);
    res = yocto_tls_server_process_client_hello(&context, client_hello, sizeof(client_hello), binder_key,
                                                handshake_secret);
    check_res(res == true);
    yocto_tls_server_generate_server_hello(&context, buffer, &server_hello_length);
    check_array_contents(buffer, server_hello_length, server_hello, sizeof(server_hello));
    yocto_tls_server_generate_server_encrypted_extensions(&context, buffer, &server_encrypted_extensions_length);
    check_array_contents(buffer, server_encrypted_extensions_length, server_enc_ext, sizeof(server_enc_ext));
    yocto_tls_server_generate_server_finished(&context, buffer, &server_finished_length);
    check_array_contents(buffer, server_finished_length, server_finished, sizeof(server_finished));
    res = yocto_tls_server_process_client_finished(&context, client_finished, sizeof(client_finished));
    check_res(res == true);
    yocto_tls_encrypt(&context, false, (uint8_t *)plain_text, sizeof(plain_text), buffer);
    check_array_contents(buffer, sizeof(plain_text) + YOCTO_TLS_ENCRYPTED_DATA_LENGTH_DELTA, server_data_message,
                         sizeof(server_data_message));
    res = yocto_tls_decrypt(&context, false, (uint8_t *)client_data_message, sizeof(client_data_message), buffer);
    check_res(res == true);
}

int main(void)
{

    /*
     * WARNING!
     * This is a test project
     * This project has FIXED_RANDOM_FOR_TESTING_ONLY defined. With that known answer tests can pass.
     * This define should never be used in non-test code as it completely defeats the security of the protocol.
     */

    client_test();
    server_test();

    while (1)
    {
    };
}
