# Yocto TLS

![cmake](https://github.com/matvey-mukha/yocto-tls/actions/workflows/cmake.yml/badge.svg)

Yocto TLS is a minimalist implementation of the TLS 1.3 cryptographic protocol targeting deeply embedded systems.

The goal is to have a simple and straightforward secure channel implementation based on symmetric cryptography with the smallest code size and RAM consumption possible while being compliant with the TLS 1.3 specification.

Yocto TLS implements both the client and the server side of TLS 1.3.
One cipher suite is supported: TLS_AES_128_CCM_8_SHA256.
Only the PSK-only key exchange mode is supported.
With that, the secure channel is established using only AES and SHA256.

The client implementation will not be compliant with an arbitrary configured TLS server. However, it should be possible to configure the majority of TLS server implementations in a way that Yocto TLS client works with them.
At the moment Yocto TLS client is tested against OpenSSL and WolfSSL servers in addition to the Yocto TLS server.

The server implementation strictly restricts client features and extensions it accepts and is generally intended to only be used with the Yocto TLS client.

## Porting

The protocol implementation is located in the src/tls.c file.

To port the implementation for use in your system, reimplement the functions in src/port_name/cal.c and src/port_name/osal.c files. Cal.c contains functions responsible for cryptographic operations and random number generation. Osal.c contains auxiliary functions that might require porting from platform to platform.

Currently the repository contains two ports:

* A port using libtomcrypt and libtommath for cryptographic functions and "C" standard library for auxiliary functions. This port should mostly be used for testing purposes on Windows, Linux, or macOS.
* A Nordic nRF52840 port that uses the microcontroller's CC310 crypto accelerator for cryptographic functions and random number generation.

## Testing

### Libtomcrypt port

#### Client

An example TLS client application is provided with example/client-example.cpp. It performs a TLS handshake with the server over a socket and then sends and receives data over the secure channel.
The example client can be used with openssl as the server with the following command:

```bash
openssl s_server -nocert -psk 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -no_dhe -allow_no_dhe_kex -no_middlebox -num_tickets 0 -ciphersuites "TLS_AES_128_CCM_8_SHA256" -port 11111
```

#### Server

An example TLS server application is provided with example/server-example.cpp. It performs a TLS handshake with the client over a socket and then sends and receives data over the secure channel.
The example server can be used together with the Yocto TLS client example.

#### Unit tests

A unit test to verify the implementation against known vectors is provided in test\catch2\unit-test.cpp.

#### Building

All the components can be built with CMake.

```bash
mkdir build
cd build
cmake ..
```

### Nordic nRF52840 port

#### Unit tests

An example project that performs known vector tests on the implementation is provided in test/nrf52840. Please use the Segger Embedded Studio IDE to build and debug the project. Before building, please define the NRF_SDK variable in the "Global Macros" options filed of the IDE to point to a Nordic SDK forder (Tools menu -> Options -> Building -> Global Macros). Currently the project is tested with Nordic SDK 15.2.

## Documentation

You can find Doxygen-generated documentation in the doc folder.
