#ifndef __TLS_RECORD_H__
#define __TLS_RECORD_H__
#include <stdint.h>

#include "./win32/win32_sockets.h"
#include "./algorithm/tls_algorithm.h"

enum CiperType {
    Ciper_stream,
    Ciper_block,
    Ciper_aead
}; // CBC AEAD STREAM alogrithm header implemention.

struct TLS_RECORD_CONTEXT {
    SOCKET send_socket;
    HashAlgorithm hash_algorithm;
    CiperType ciper_type;
    BulkCipherAlgorithm bulk_ciper_algorithm;

    uint8_t *ctx_buffer;
    size_t send_seq_num, buffer_size;

    size_t mac_key_length;
    size_t enc_key_length;
    size_t fixed_iv_length;
    uint8_t *client_write_MAC_key, *server_write_MAC_key;
    uint8_t *client_write_key, *server_write_key;
    uint8_t *client_write_iv, *server_write_iv;

    uint8_t tls_inner_system_random[128];
};

struct ProtocolVersion {
    uint8_t major;
    uint8_t minor;
};
enum ContentType : uint8_t {
    change_cipher_spec = 20,
    alert,
    handshake,
    application_data
};

#pragma pack(1)
struct TLS_RECORD_MESSAGE_HEADER {
    ContentType type;
    ProtocolVersion ver;
    uint16_t length;
};
struct TLS_RECORD_MESSAGE {
    TLS_RECORD_MESSAGE_HEADER header;
    uint8_t fragment[];
};

#endif