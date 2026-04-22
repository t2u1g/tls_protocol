#ifndef __TLS_RECORD_H__
#define __TLS_RECORD_H__
#include <stdint.h>

#include "./win32/win32_sockets.h"
#include "./algorithm/tls_algorithm.h"

enum CiperType {
    Ciper_stream,
    Ciper_block,
    Ciper_aead
};

struct TLS_RECORD_CONTEXT {
    SOCKET send_socket;
    HashAlgorithm hash_algorithm;
    CiperType ciper_type;

    uint8_t *ctx_buffer1, *ctx_buffer2;
    size_t buffer_size;
    size_t server_seq, client_seq;

    size_t mac_key_length;
    uint8_t *client_write_MAC_key, *server_write_MAC_key;
    
    size_t enc_key_length;
    uint8_t *client_write_key, *server_write_key;
    
    uint8_t client_write_iv[4], server_write_iv[4];

    size_t tls_random_used, tls_random_max = 128;
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

void tls_record_handle_error(size_t tls_error);

// size_t tls_record_send_directly(
//     TLS_RECORD_CONTEXT *p_ctx, 
//     const TLS_RECORD_MESSAGE_HEADER *p_header, 
//     void *p_data);

// size_t tls_record_recv_directly(
//     TLS_RECORD_CONTEXT *p_ctx, 
//     TLS_RECORD_MESSAGE_HEADER *p_header, 
//     void *p_data);

size_t tls_record_send(
    TLS_RECORD_CONTEXT *p_ctx, 
    const TLS_RECORD_MESSAGE_HEADER *p_header, 
    const void *p_data);

size_t tls_record_recv(
    TLS_RECORD_CONTEXT *p_ctx, 
    TLS_RECORD_MESSAGE_HEADER *p_header, 
    void *p_data);

#endif