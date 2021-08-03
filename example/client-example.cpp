
#include "tls.h"

#include "sockpp/tcp_connector.h"

#include "stdexcept"

#define MAX_SUPPORTED_FRAME_LENGTH (512)

static const uint8_t pre_shared_key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
                                         0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                                         0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

static const uint8_t client_data[] = {0x0A};

using namespace sockpp;
using namespace std;

void read_tls_packet(tcp_connector &conn, uint8_t *data, uint32_t *data_length)
{
    uint32_t full_length;

    conn.read(data, 5);

    full_length = (data[3] << 8) | data[4];

    if ((full_length + 5) > MAX_SUPPORTED_FRAME_LENGTH)
    {
        throw new runtime_error("Invalid frame received");
    }

    conn.read(data + 5, full_length);

    *data_length = 5 + full_length;
}

void write_tls_packet(tcp_connector &conn, uint8_t *data, uint32_t data_length)
{
    conn.write(data, data_length);
}

int main()
{
    YOCTO_TLS_CONTEXT context;
    uint8_t binder_key[32];
    uint8_t handshake_secret[32];
    uint8_t buffer[MAX_SUPPORTED_FRAME_LENGTH];
    uint32_t client_hello_length;
    uint32_t client_finished_length;
    uint8_t *identity = (uint8_t *)"Client_identity";
    uint32_t received_packet_length;
    bool res;

    try
    {
        socket_initializer sockInit;
        tcp_connector conn({"127.0.0.1", 11111});

        cout << "Connecting... ";

        if (!conn)
        {
            throw runtime_error("Failed to connect to the server.");
        }

        cout << "done" << endl;

        cout << "Performing a handshake... ";

        yocto_tls_init();
        yocto_tls_preprocess_static_keys((uint8_t *)pre_shared_key, binder_key, handshake_secret);
        yocto_tls_init_context(&context);
        yocto_tls_client_generate_client_hello(&context, buffer, &client_hello_length, binder_key, handshake_secret,
                                               identity);

        write_tls_packet(conn, buffer, client_hello_length);
        read_tls_packet(conn, buffer, &received_packet_length);

        res = yocto_tls_client_process_server_hello(&context, buffer, received_packet_length);
        if (!res)
        {
            throw runtime_error("Invalid server hello received");
        }

        read_tls_packet(conn, buffer, &received_packet_length);

        res = yocto_tls_client_process_server_encrypted_extensions(&context, buffer, received_packet_length);
        if (!res)
        {
            throw runtime_error("Invalid server encrypted extensions received");
        }

        read_tls_packet(conn, buffer, &received_packet_length);

        res = yocto_tls_client_process_server_finished(&context, buffer, received_packet_length);
        if (!res)
        {
            throw runtime_error("Invalid server finished received");
        }

        yocto_tls_client_generate_client_finished(&context, buffer, &client_finished_length);

        write_tls_packet(conn, buffer, client_finished_length);

        cout << "done" << endl;

        cout << "Sending data to the server... ";

        yocto_tls_encrypt(&context, true, (uint8_t *)client_data, sizeof(client_data), buffer);

        write_tls_packet(conn, buffer, sizeof(client_data) + YOCTO_TLS_ENCRYPTED_DATA_LENGTH_DELTA);

        cout << "done" << endl;

        cout << "Receiving data from the server... ";

        read_tls_packet(conn, buffer, &received_packet_length);

        res = yocto_tls_decrypt(&context, true, buffer, received_packet_length, buffer);
        if (!res)
        {
            throw runtime_error("Invalid data received");
        }

        cout << "done" << endl;
    }
    catch (runtime_error e)
    {
        cout << e.what() << endl;
    }

    return 0;
}
