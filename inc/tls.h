/**
 * @file
 * @author  Matvey Mukha
 */

#pragma once

#include "cal.h"
#include "osal.h"
#include "stdbool.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define YOCTO_TLS_CLIENT_IDENTITY_LENGTH (15)

#define YOCTO_TLS_ENCRYPTED_DATA_LENGTH_DELTA (5 + 1 + 8)

#define YOCTO_TLS_MAX_OUTGOING_HANDSHAKE_MESSAGE_SIZE (256)

    typedef struct
    {
        uint32_t state;
        CAL_HASH_CONTEXT handshake_hash_context;
        uint8_t handshake_secret[32];
        uint8_t client_key[16];
        uint8_t client_nonce[12];
        uint8_t server_key[16];
        uint8_t server_nonce[12];
        uint8_t client_write_mac_secret[32];
        uint8_t server_write_mac_secret[32];
        uint64_t server_seq;
        uint64_t client_seq;

    } YOCTO_TLS_CONTEXT;

    /*
     * Functions common to client and server
     */

    /**
     * Preprocess static keys
     *
     * Derives a number of static keys that do not change their values from one session to another.
     * The aim is to shorten the handshake time as much as possible.
     * Takes a pre-shared key as input and outputs a binder key and a handshake secret.
     * Can be called once for a given pre-shared key. After the binder key and the handshake secret are derived,
     * they can be stored in non-volatile memory instead of the pre-shared key.
     * Alternatively can be called before every handshake.
     *
     * @param[in]  pre_shared_key Pre shared key, 32 bytes
     * @param[out]  binder_key Binder key, 32 bytes
     * @param[out]  handshake_secret Handshake secret, 32 bytes
     */
    void yocto_tls_preprocess_static_keys(uint8_t *pre_shared_key, uint8_t *binder_key, uint8_t *handshake_secret);

    /**
     * Initialize the library
     *
     * Call this function once before calling any other APIs.
     */
    void yocto_tls_init(void);

    /**
     * Initialize a context
     *
     * Call this function before performing a handshake or any data exchange.
     *
     * @param[in,out]  context Context structure
     */
    void yocto_tls_init_context(YOCTO_TLS_CONTEXT *context);

    /**
     * Encrypt data
     *
     * This function should only be called after a successful handshake.
     * Encrypts data to be sent to the peer.
     * Buffers can overlap.
     * The size of the output is always the size of input plus YOCTO_TLS_ENCRYPTED_DATA_LENGTH_DELTA.
     *
     * @param[in,out]  context Context structure
     * @param[in]  is_client True if encrypting on the client side, false if encrypting on the server side
     * @param[in]  in_buffer Buffer with plain text
     * @param[in]  in_buffer_length Length of the buffer with plain text
     * @param[out]  out_buffer Buffer with encrypted data
     */
    void yocto_tls_encrypt(YOCTO_TLS_CONTEXT *context, bool is_client, uint8_t *in_buffer, uint32_t in_buffer_length,
                           uint8_t *out_buffer);

    /**
     * Decrypt data
     *
     * This function should only be called after a successful handshake.
     * Decrypts data received from the peer.
     * Buffers can overlap.
     * The size of the output is always the size of input minus YOCTO_TLS_ENCRYPTED_DATA_LENGTH_DELTA.
     *
     * @param[in,out]  context Context structure
     * @param[in]  is_client True if decrypting on the client side, false if decrypting on the server side
     * @param[in]  in_buffer Buffer with encrypted data
     * @param[in]  in_buffer_length Length of the buffer with encrypted data
     * @param[out]  out_buffer Buffer with plain text
     * @return true if the message has been successfully processed, false otherwise
     */
    bool yocto_tls_decrypt(YOCTO_TLS_CONTEXT *context, bool is_client, uint8_t *in_buffer, uint32_t in_buffer_length,
                           uint8_t *out_buffer);

    /*
     * Client handshake functions
     */

    /**
     * Generate client hello
     *
     * The first function to be called when performing a handshake on the client-side.
     * Generates a "client hello" message to be sent to the server.
     *
     * @param[in,out]  context Context structure
     * @param[out]  buffer Buffer to write the message to. Providing a buffer with the size of
     * YOCTO_TLS_MAX_OUTGOING_HANDSHAKE_MESSAGE_SIZE bytes is always enough.
     * @param[out]  client_hello_length Length of the generated message
     * @param[in]  binder_key Binder key, 32 bytes
     * @param[in]  handshake_secret Handshake secret, 32 bytes
     * @param[in]  identity Client identity, YOCTO_TLS_CLIENT_IDENTITY_LENGTH bytes
     */
    void yocto_tls_client_generate_client_hello(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                                uint32_t *client_hello_length, uint8_t *binder_key,
                                                uint8_t *handshake_secret, uint8_t *identity);

    /**
     * Process server hello
     *
     * The second function to be called when performing a handshake on the client-side.
     * Processes a "server hello" message received from the server.
     *
     * @param[in,out]  context Context structure
     * @param[in]  buffer Buffer with the message
     * @param[in]  server_hello_length Length of the message in the buffer
     * @return true if the message has been successfully processed, false otherwise
     */
    bool yocto_tls_client_process_server_hello(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                               uint32_t server_hello_length);

    /**
     * Process encrypted server extensions
     *
     * The third function to be called when performing a handshake on the client-side.
     * Processes an "encrypted extensions" message received from the server.
     *
     * @param[in,out]  context Context structure
     * @param[in]  buffer Buffer with the message
     * @param[in]  encrypted_extensions_length Length of the message in the buffer
     * @return true if the message has been successfully processed, false otherwise
     */
    bool yocto_tls_client_process_server_encrypted_extensions(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                                              uint32_t encrypted_extensions_length);

    /**
     * Process server finished
     *
     * The fourth function to be called when performing a handshake on the client-side.
     * Processes a "server finished" message received from the server.
     *
     * @param[in,out]  context Context structure
     * @param[in]  buffer Buffer with the message
     * @param[in]  server_finished_length Length of the message in the buffer
     * @return true if the message has been successfully processed, false otherwise
     */
    bool yocto_tls_client_process_server_finished(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                                  uint32_t server_finished_length);

    /**
     * Generate client finished
     *
     * The fifth function to be called when performing a handshake on the client-side.
     * Generates a "client finished" message to be sent to the server.
     *
     * @param[in,out]  context Context structure
     * @param[in]  buffer Buffer with the message
     * @param[out]  client_finished_length Length of the generated message
     */
    void yocto_tls_client_generate_client_finished(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                                   uint32_t *client_finished_length);

    /*
     * Server handshake functions
     */

    /**
     * Pre-process client hello
     *
     * The first function to be called when performing a handshake on the server-side.
     * Performs some sanity checks on the received client hello message and extracts the client identity.
     * The server can decide which keys to use based on the client's identity.
     *
     * @param[in,out]  context Context structure
     * @param[in]  buffer Buffer with the message
     * @param[in]  client_hello_length Length of the message in the buffer
     * @param[out]  client_identity Client identity, YOCTO_TLS_CLIENT_IDENTITY_LENGTH bytes
     * @return true if the message has been successfully processed, false otherwise
     */
    bool yocto_tls_server_preprocess_client_hello(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                                  uint32_t client_hello_length, uint8_t *client_identity);

    /**
     * Process client hello
     *
     * The second function to be called when performing a handshake on the server-side.
     * Processes a "client hello" message received from the client.
     *
     * @param[in,out]  context Context structure
     * @param[in]  buffer Buffer with the message
     * @param[in]  client_hello_length Length of the message in the buffer
     * @param[in]  binder_key Binder key, 32 bytes
     * @param[in]  handshake_secret Handshake secret, 32 bytes
     * @return true if the message has been successfully processed, false otherwise
     */
    bool yocto_tls_server_process_client_hello(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                               uint32_t client_hello_length, uint8_t *binder_key,
                                               uint8_t *handshake_secret);

    /**
     * Generate server hello
     *
     * The third function to be called when performing a handshake on the server-side.
     * Generates a "server hello" message to be sent to the client.
     *
     * @param[in,out]  context Context structure
     * @param[out]  buffer Buffer to write the message to. Providing a buffer with the size of
     * YOCTO_TLS_MAX_OUTGOING_HANDSHAKE_MESSAGE_SIZE bytes is always enough.
     * @param[out]  server_hello_length Length of the generated message
     */
    void yocto_tls_server_generate_server_hello(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                                uint32_t *server_hello_length);

    /**
     * Generate server encrypted extensions
     *
     * The fourth function to be called when performing a handshake on the server-side.
     * Generates a "server encrypted extensions" message to be sent to the client.
     *
     * @param[in,out]  context Context structure
     * @param[out]  buffer Buffer to write the message to. Providing a buffer with the size of
     * YOCTO_TLS_MAX_OUTGOING_HANDSHAKE_MESSAGE_SIZE bytes is always enough.
     * @param[out]  encrypted_extensions_length Length of the generated message
     */
    void yocto_tls_server_generate_server_encrypted_extensions(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                                               uint32_t *encrypted_extensions_length);

    /**
     * Generate server finished
     *
     * The fifth function to be called when performing a handshake on the server-side.
     * Generates a "server finished" message to be sent to the client.
     *
     * @param[in,out]  context Context structure
     * @param[out]  buffer Buffer to write the message to. Providing a buffer with the size of
     * YOCTO_TLS_MAX_OUTGOING_HANDSHAKE_MESSAGE_SIZE bytes is always enough.
     * @param[out]  server_finished_length Length of the generated message
     */
    void yocto_tls_server_generate_server_finished(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                                   uint32_t *server_finished_length);

    /**
     * Process client finished
     *
     * The sixth function to be called when performing a handshake on the server-side.
     * Processes a "client finished" message received from the client.
     *
     * @param[in,out]  context Context structure
     * @param[in]  buffer Buffer with the message
     * @param[in]  client_finished_length Length of the message in the buffer
     * @return true if the message has been successfully processed, false otherwise
     */
    bool yocto_tls_server_process_client_finished(YOCTO_TLS_CONTEXT *context, uint8_t *buffer,
                                                  uint32_t client_finished_length);

#ifdef __cplusplus
}
#endif