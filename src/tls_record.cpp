#include "tls_record.h"

static inline void reverse_bytes(void *p_byte, size_t length) {
    for (size_t i = 0; i < length / 2; i++) {
        uint8_t tmp = ((uint8_t *)p_byte)[i];
        ((uint8_t *)p_byte)[i] = ((uint8_t *)p_byte)[length - i - 1];
        ((uint8_t *)p_byte)[length - i - 1] = tmp;
    }
}

void tls_record_handle_error(size_t tls_error) {
}

size_t tls_recrd_send_directly(TLS_RECORD_CONTEXT *p_ctx, TLS_RECORD_MESSAGE_HEADER *p_header, void *p_data) {
    uint16_t length = p_header->length;
    reverse_bytes(&p_header->length, sizeof(uint16_t));
    size_t ret = win32sockets_send(p_ctx->send_socket, p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    if ((size_t)-1 != ret) {
        ret = win32sockets_send(p_ctx->send_socket, p_data, length);
    }
    if ((size_t)-1 == ret) {
        // handle socket-send data failed error.
        tls_record_handle_error(0);
    }
    return ret;
}

#include <assert.h>
size_t tls_record_hmac(TLS_RECORD_CONTEXT *p_ctx, const TLS_RECORD_MESSAGE_HEADER *p_header,
                       const void *p_data, void *hmac_buff) {
    assert(sizeof(uint64_t) + sizeof(TLS_RECORD_MESSAGE_HEADER) + p_header->length <= p_ctx->buffer_size);
    uint8_t *p_buff = p_ctx->ctx_buffer;
    memmove(&p_buff[sizeof(uint64_t) + sizeof(TLS_RECORD_MESSAGE_HEADER)], p_data, p_header->length);
    ((uint64_t *)p_buff)[0] = p_ctx->send_seq_num;
    reverse_bytes(p_buff, sizeof(uint64_t));
    memcpy(&p_buff[sizeof(uint64_t)], p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    TLS_RECORD_MESSAGE_HEADER *p_header_ =
        (TLS_RECORD_MESSAGE_HEADER *)&p_buff[sizeof(uint64_t)];
    reverse_bytes(&p_header_->length, sizeof(uint16_t));

    size_t hmac_bytes = tls_hmac(
        p_ctx->hash_algorithm,
        p_ctx->client_write_MAC_key, p_ctx->mac_key_length,
        p_buff, sizeof(uint64_t) + sizeof(TLS_RECORD_MESSAGE_HEADER) + p_header->length,
        hmac_buff);
    return hmac_bytes;
}

size_t tls_record_send(TLS_RECORD_CONTEXT *p_ctx, const TLS_RECORD_MESSAGE_HEADER *p_header, const void *p_data) {
    size_t ret = 0, data_length = p_header->length;
    if (application_data != p_header->type
        && 0 == data_length) {
        return ret;
    } else if (data_length > (1 << 14)) {
        return ret; // too long data.
    }
    if (Ciper_aead == p_ctx->ciper_type) {
        ; // do nothing. not support.
    } else {
        assert(128 >= HashResultSizeTable[p_ctx->hash_algorithm]
               && 0 != HashResultSizeTable[p_ctx->hash_algorithm]);
        uint8_t hmac_buff[128] = {0};
        size_t hmac_bytes = tls_record_hmac(
            p_ctx, p_header, p_data, hmac_buff);

        if (Ciper_stream == p_ctx->ciper_type) {
            // doing nothing, not support.
        } else if (Ciper_block == p_ctx->ciper_type) {
            const size_t encrypto_block_size = EncryptoBlockSizeTable[p_ctx->bulk_ciper_algorithm];
            size_t ciper_fragment_size = data_length + hmac_bytes + 1;
            assert(0 != encrypto_block_size && ((encrypto_block_size & (encrypto_block_size - 1)) == 0));
            ciper_fragment_size = (ciper_fragment_size + (encrypto_block_size - 1)) & ~encrypto_block_size;
            assert(ciper_fragment_size + encrypto_block_size <= p_ctx->buffer_size);
            uint8_t *p_buff = p_ctx->ctx_buffer;

            uint8_t padding_value = (uint8_t)(ciper_fragment_size - data_length + hmac_bytes + 1);
            assert(128 >= encrypto_block_size);
            memcpy(p_buff, p_ctx->tls_inner_system_random, encrypto_block_size);
            memcpy(&p_buff[encrypto_block_size], p_data, data_length);
            memcpy(&p_buff[encrypto_block_size + data_length], hmac_buff, hmac_bytes);
            uint8_t *p_padding = &p_buff[encrypto_block_size + data_length + hmac_bytes];
            for (size_t i = 0; i < padding_value + 1; i++) {
                p_padding[i] = padding_value;
            }
            tls_aes_128_CBC_encrypto(
                p_ctx->client_write_key, p_buff, &p_buff[encrypto_block_size], ciper_fragment_size);
            ret = win32sockets_send(p_ctx->send_socket, p_buff, ciper_fragment_size + encrypto_block_size);
            if ((size_t)-1 == ret) {
                // handle socket-send data failed error.
                tls_record_handle_error(0);
            }
        }
        p_ctx->send_seq_num++;
    }
    return ret;
}

// p_header->length is max_read_size, make sure it enough big to at least save one message packet.
size_t tls_record_recv(TLS_RECORD_CONTEXT *p_ctx, TLS_RECORD_MESSAGE_HEADER *p_header, void *p_data) {
    size_t read_max_bytes = p_header->length;
    if (read_max_bytes < (1 << 14)) {
        return 0; // buffer not enough big to save message.
    }
    // assert((1 << 14) + 2048 <= p_ctx->buffer_size);
    // NOTE: because tls not compression data, so it is max plus 1024, not 2048.
    assert((1 << 14) + 1024 <= p_ctx->buffer_size);
    uint8_t *p_buff = p_ctx->ctx_buffer;
    size_t ret = win32sockets_recv(p_ctx->send_socket, p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    if ((size_t)-1 == ret) {
        // handle socket-recv data failed error.
        tls_record_handle_error(1);
        return ret;
    }
    reverse_bytes(&p_header->length, sizeof(uint16_t));
    ret = win32sockets_recv(p_ctx->send_socket, p_buff, p_header->length);
    if ((size_t)-1 == ret) {
        // handle socket-recv data failed error.
        tls_record_handle_error(1);
        return ret;
    }

    if (Ciper_stream == p_ctx->ciper_type) {
        ; // doing nothing, not support.
    } else if (Ciper_block == p_ctx->ciper_type) {
        const size_t encrypto_block_size = EncryptoBlockSizeTable[p_ctx->bulk_ciper_algorithm];
        size_t ciper_fragment_size = p_header->length - encrypto_block_size;
        tls_aes_128_CBC_decrypto(p_ctx->server_write_key, p_buff, &p_buff[encrypto_block_size], ciper_fragment_size);
        uint8_t padding_value = p_buff[p_header->length - 1];
        size_t hmac_size = HashResultSizeTable[p_ctx->hash_algorithm];
        uint8_t *p_hmac_recv = &p_buff[p_header->length - (padding_value + 1) - hmac_size];

        p_header->length -= (encrypto_block_size + (padding_value + 1) + hmac_size);
        assert(128 >= HashResultSizeTable[p_ctx->hash_algorithm] && 0 != HashResultSizeTable[p_ctx->hash_algorithm]);
        uint8_t hmac_buff[128] = {0}; // BUG: seq_number might error.
        tls_record_hmac(p_ctx, p_header, &p_buff[encrypto_block_size], hmac_buff);
        // XXX: must check padding format here.
        if (strncmp((char *)p_hmac_recv, (char *)hmac_buff, hmac_size) != 0) {
            // hmac check failed, data destruction.
            tls_record_handle_error(2);
            return ret;
        } // XXX: not safe, might attack here. if hmac error position not same, strncmp returns time not same.
        if (p_header->length > read_max_bytes) {
            // read-buffer too small.
            tls_record_handle_error(3);
            return ret;
        }
        memcpy(p_data, &p_buff[sizeof(TLS_RECORD_MESSAGE_HEADER) + sizeof(uint64_t)], p_header->length);
        ret = p_header->length;
    } else if (Ciper_aead == p_ctx->ciper_type) {
        ; // doing nothing, not support.
    }

    return ret;
}