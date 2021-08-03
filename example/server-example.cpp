
#include "tls.h"

#include "sockpp/tcp_acceptor.h"

#include "stdexcept"

#define MAX_SUPPORTED_FRAME_LENGTH (512)

static const uint8_t pre_shared_key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
                                         0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                                         0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

static const uint8_t server_data[] = {0x0A};

using namespace sockpp;
using namespace std;

void read_tls_packet(tcp_socket &sock, uint8_t *data, uint32_t *data_length)
{
    uint32_t full_length;

    sock.read(data, 5);

    full_length = (data[3] << 8) | data[4];

    if ((full_length + 5) > MAX_SUPPORTED_FRAME_LENGTH)
    {
        throw new runtime_error("Invalid frame received");
    }

    sock.read(data + 5, full_length);

    *data_length = 5 + full_length;
}

void write_tls_packet(tcp_socket &sock, uint8_t *data, uint32_t data_length)
{
    sock.write(data, data_length);
}

int main()
{
    YOCTO_TLS_CONTEXT context;
    uint8_t binder_key[32];
    uint8_t handshake_secret[32];
    uint8_t buffer[MAX_SUPPORTED_FRAME_LENGTH];
    uint32_t server_hello_length;
    uint32_t server_encryted_extensions_length;
    uint32_t server_finished_length;
    uint8_t client_identity[YOCTO_TLS_CLIENT_IDENTITY_LENGTH];
    uint32_t received_packet_length;
    bool res;

    try
    {
        socket_initializer sockInit;
        tcp_acceptor acc({"127.0.0.1", 11111});

        if (!acc)
        {
            throw runtime_error("Failed to start the server.");
        }

        yocto_tls_init();
        yocto_tls_preprocess_static_keys((uint8_t *)pre_shared_key, binder_key, handshake_secret);

        while (true)
        {
            cout << "Waiting for connection... ";

            tcp_socket sock = acc.accept();

            try
            {
                if (!sock)
                {
                    throw runtime_error("Failed to accept a connection.");
                }

                cout << "done" << endl;

                cout << "Performing a handshake... ";

                yocto_tls_init_context(&context);

                read_tls_packet(sock, buffer, &received_packet_length);

                res =
                    yocto_tls_server_preprocess_client_hello(&context, buffer, received_packet_length, client_identity);
                if (!res)
                {
                    throw runtime_error("Invalid client hello received");
                }

                res = yocto_tls_server_process_client_hello(&context, buffer, received_packet_length, binder_key,
                                                            handshake_secret);
                if (!res)
                {
                    throw runtime_error("Invalid client hello received");
                }

                yocto_tls_server_generate_server_hello(&context, buffer, &server_hello_length);

                write_tls_packet(sock, buffer, server_hello_length);

                yocto_tls_server_generate_server_encrypted_extensions(&context, buffer,
                                                                      &server_encryted_extensions_length);

                write_tls_packet(sock, buffer, server_encryted_extensions_length);

                yocto_tls_server_generate_server_finished(&context, buffer, &server_finished_length);

                write_tls_packet(sock, buffer, server_finished_length);

                read_tls_packet(sock, buffer, &received_packet_length);

                res = yocto_tls_server_process_client_finished(&context, buffer, received_packet_length);
                if (!res)
                {
                    throw runtime_error("Invalid client finished received");
                }

                cout << "done" << endl;

                cout << "Receiving data from the client... ";

                read_tls_packet(sock, buffer, &received_packet_length);

                res = yocto_tls_decrypt(&context, false, buffer, received_packet_length, buffer);
                if (!res)
                {
                    throw runtime_error("Invalid data received");
                }

                cout << "done" << endl;

                cout << "Sending data to the client... ";

                yocto_tls_encrypt(&context, false, (uint8_t *)server_data, sizeof(server_data), buffer);

                write_tls_packet(sock, buffer, sizeof(server_data) + YOCTO_TLS_ENCRYPTED_DATA_LENGTH_DELTA);

                cout << "done" << endl;
            }
            catch (runtime_error e)
            {
                cout << e.what() << endl;
            }

            sock.close();
        }
    }
    catch (runtime_error e)
    {
        cout << e.what() << endl;
    }

    return 0;
}
