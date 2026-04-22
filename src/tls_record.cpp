#include <assert.h>

#include "tls_record.h"

static inline void reverse_bytes(void *p_byte, size_t length) {
    for (size_t i = 0; i < length / 2; i++) {
        uint8_t tmp = ((uint8_t *)p_byte)[i];
        ((uint8_t *)p_byte)[i] = ((uint8_t *)p_byte)[length - i - 1];
        ((uint8_t *)p_byte)[length - i - 1] = tmp;
    }
}

void tls_record_handle_error(size_t tls_error) {
    ;
}

size_t tls_record_send_directly(
    TLS_RECORD_CONTEXT *p_ctx,
    const TLS_RECORD_MESSAGE_HEADER *p_header,
    void *p_data) {
    ;
    uint16_t length = p_header->length;
    TLS_RECORD_MESSAGE_HEADER t_header;
    memcpy(&t_header, p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    reverse_bytes(&t_header.length, sizeof(uint16_t));
    size_t ret =
        win32sockets_send(
            p_ctx->send_socket,
            &t_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    if ((size_t)-1 != ret) {
        ret = win32sockets_send(p_ctx->send_socket, p_data, length);
    }
    if ((size_t)-1 == ret) {
        // handle socket-send data failed error.
        tls_record_handle_error(0);
    }
    return ret;
}
size_t tls_record_recv_directly(
    TLS_RECORD_CONTEXT *p_ctx,
    TLS_RECORD_MESSAGE_HEADER *p_header,
    void *p_data) {
    ;
    size_t read_max_bytes = p_header->length;
    if (read_max_bytes < (1 << 14)) {
        return 0; // buffer not enough big to save message.
    }

    size_t ret =
        win32sockets_recv(
            p_ctx->send_socket,
            p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    if ((size_t)-1 == ret) {
        // handle socket-recv data failed error.
        tls_record_handle_error(1);
        return ret;
    }
    reverse_bytes(&p_header->length, sizeof(uint16_t));
    if (read_max_bytes < p_header->length) {
        // read-buffer too small.
        tls_record_handle_error(3);
        // NOTE: if length error, then read packet and throws away it.
        win32sockets_recv(
            p_ctx->send_socket,
            p_ctx->ctx_buffer2, p_header->length);
        return (size_t)-1;
    }
    ret = win32sockets_recv(p_ctx->send_socket, p_data, p_header->length);
    if ((size_t)-1 == ret) {
        // handle socket-recv data failed error.
        tls_record_handle_error(1);
    }
    return ret;
}

/**
 * The non-cryptographic algorithm functions starting with tls all
 * use buffer1 in p_ctx as the input data source and
 * buffer2 as the return data buffer.
 *
 * Note that currently all input data to the tls_record_xxx function
 * is stored in buffer1 and has the length of the incoming TLS_RECORD_MESSAGE_HEADER
 */

/**
 * This function calculates hmac.
 * hmac_buff is a buffer where the results are stored.
 * The expected result length of hmac can be found from the HashResultSizeTable
 *
 * This function assumes that the fields in the input p_header are all little endian
 */
size_t tls_record_hmac(
    TLS_RECORD_CONTEXT *p_ctx,
    size_t send_seq_num,
    const TLS_RECORD_MESSAGE_HEADER *p_header,
    void *hmac_buff) {
    ;
    assert(
        sizeof(uint64_t) + sizeof(TLS_RECORD_MESSAGE_HEADER) + p_header->length
        <= p_ctx->buffer_size);
    uint8_t *p_buff = p_ctx->ctx_buffer2;

    memmove(
        &p_buff[sizeof(uint64_t) + sizeof(TLS_RECORD_MESSAGE_HEADER)],
        p_ctx->ctx_buffer1,
        p_header->length);

    ((uint64_t *)p_buff)[0] = send_seq_num;
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

/**
 * This function packages the raw data in buffer1 into a TLS record Block Encrypto block.
 * The client write sequence number in the context must be updated after it is called
 * only allowed block encrypto algorithm size 16.
 */
size_t tls_record_pack_block(
    TLS_RECORD_CONTEXT *p_ctx,
    const TLS_RECORD_MESSAGE_HEADER *p_header) {
    ;
    size_t data_length = p_header->length;
    if (application_data != p_header->type && 0 == data_length) {
        return 0;
    } else if (data_length > (1 << 14)) {
        return 0; // too long data.
    }

    assert(128 >= HashResultSizeTable[p_ctx->hash_algorithm]
           && 0 != HashResultSizeTable[p_ctx->hash_algorithm]);
    uint8_t hmac_buff[128] = {0};
    size_t hmac_bytes = tls_record_hmac(
        p_ctx, p_ctx->client_seq, p_header, hmac_buff);

    const size_t encrypto_block_size = 16;
    size_t ciper_fragment_size = data_length + hmac_bytes + 1;
    assert(0 != encrypto_block_size && ((encrypto_block_size & (encrypto_block_size - 1)) == 0));
    ciper_fragment_size = (ciper_fragment_size + (encrypto_block_size - 1)) & ~encrypto_block_size;
    assert(ciper_fragment_size + encrypto_block_size <= p_ctx->buffer_size);
    uint8_t *p_buff = p_ctx->ctx_buffer2;

    uint8_t padding_value = (uint8_t)(ciper_fragment_size - (data_length + hmac_bytes + 1));
    assert(128 >= encrypto_block_size);
    memmove(&p_buff[encrypto_block_size], p_ctx->ctx_buffer1, data_length);

    assert(p_ctx->tls_random_max - p_ctx->tls_random_used >= encrypto_block_size);
    uint8_t *p_tls_random = (uint8_t *)p_ctx->tls_inner_system_random;
    memcpy(p_buff, &p_tls_random[p_ctx->tls_random_used], encrypto_block_size);
    p_ctx->tls_random_used += encrypto_block_size;

    memcpy(&p_buff[encrypto_block_size + data_length], hmac_buff, hmac_bytes);
    uint8_t *p_padding = &p_buff[encrypto_block_size + data_length + hmac_bytes];
    for (size_t i = 0; i < padding_value + 1; i++) {
        p_padding[i] = padding_value;
    }
    tls_aes_128_CBC_encrypto(
        p_ctx->client_write_key, p_buff, &p_buff[encrypto_block_size], ciper_fragment_size);
    memmove(p_buff, &p_buff[encrypto_block_size], ciper_fragment_size);
    // p_ctx->client_seq++;

    return ciper_fragment_size + encrypto_block_size;
}

/**
 * This function assumes that the TLS Record Block encrypt block in buffer1,
 * and check whether its hmac and padding are correct, If a format error occurs,
 * tls_record_handle_error is internally called and the error code is passed in and the length is 0 is returned.
 * The server write sequence number in the context must be updated after it is called
 */
size_t tls_record_unpack_block(
    TLS_RECORD_CONTEXT *p_ctx,
    const TLS_RECORD_MESSAGE_HEADER *p_header) {
    ;
    assert((1 << 14) + 1024 <= p_ctx->buffer_size && p_header->length <= p_ctx->buffer_size);
    uint8_t *p_buff = p_ctx->ctx_buffer1;

    const size_t encrypto_block_size = 16;
    size_t ciper_fragment_size = p_header->length - encrypto_block_size;
    tls_aes_128_CBC_decrypto(
        p_ctx->server_write_key, p_buff, &p_buff[encrypto_block_size], ciper_fragment_size);
    uint8_t padding_value = p_buff[p_header->length - 1];
    size_t hmac_size = HashResultSizeTable[p_ctx->hash_algorithm];
    uint8_t *p_hmac_recv = &p_buff[p_header->length - (padding_value + 1) - hmac_size];

    assert(128 >= HashResultSizeTable[p_ctx->hash_algorithm]
           && 0 != HashResultSizeTable[p_ctx->hash_algorithm]);
    uint8_t hmac_buff[128] = {0};
    p_ctx->ctx_buffer1 = &p_buff[encrypto_block_size];
    TLS_RECORD_MESSAGE_HEADER t_header;
    memcpy(&t_header, p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    t_header.length = p_ctx->ctx_buffer1 - p_hmac_recv;
    tls_record_hmac(p_ctx, p_ctx->server_seq, &t_header, hmac_buff);
    p_ctx->ctx_buffer1 = p_buff;

    bool padding_check = true;
    for (size_t i = 0; i < padding_value + 1; i++) {
        padding_check = (p_buff[p_header->length - 1 - i] == padding_value);
    }
    bool hmac_check = true;
    for (size_t i = 0; i < hmac_size; i++) {
        hmac_check = (p_hmac_recv[i] == hmac_buff[i]);
    }
    if (!hmac_buff || !padding_check) {
        // hmac or padding error.
        tls_record_handle_error(0);
        return 0;
    }
    memcpy(p_ctx->ctx_buffer2, &p_buff[encrypto_block_size], t_header.length);

    return t_header.length;
}

/**
 * This function packages the data in buffer1 into a payload for AEAD authentication encryption.
 * The client write sequence number in the context must be updated after it is called
 */
size_t tls_record_pack_aead(
    TLS_RECORD_CONTEXT *p_ctx,
    const TLS_RECORD_MESSAGE_HEADER *p_header) {
    ;
    const size_t auth_length = sizeof(uint64_t) + sizeof(TLS_RECORD_MESSAGE_HEADER);
    uint8_t nonce[12] = {0}, auth_data[auth_length] = {0};
    assert(p_ctx->tls_random_max - p_ctx->tls_random_used >= 8);
    for (size_t i = 0; i < 8; i++) {
        uint8_t *p_sys_rand_read = &p_ctx->tls_inner_system_random[p_ctx->tls_random_used];
        nonce[4 + i] = p_sys_rand_read[i];
    } // not safe, must sure it not repair.
    p_ctx->tls_random_used += 8;
    for (size_t i = 0; i < 4; i++) {
        nonce[i] = p_ctx->client_write_iv[i];
    }
    ((uint64_t *)auth_data)[0] = p_ctx->client_seq;
    reverse_bytes(auth_data, sizeof(uint64_t));
    memcpy(&auth_data[sizeof(uint64_t)], p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    TLS_RECORD_MESSAGE_HEADER *p_header_ =
        (TLS_RECORD_MESSAGE_HEADER *)&auth_data[sizeof(uint64_t)];
    reverse_bytes(&p_header_->length, sizeof(uint16_t));

    uint8_t auth_tag[16] = {0};
    tls_aes_128_GCM_encrypto(
        p_ctx->client_write_key, nonce,
        auth_data, auth_length, p_ctx->ctx_buffer1, p_header->length,
        auth_tag);
    memcpy(p_ctx->ctx_buffer2, nonce, 12);
    memcpy(&p_ctx->ctx_buffer2[12], p_ctx->ctx_buffer1, p_header->length);
    memcpy(&p_ctx->ctx_buffer2[12 + p_header->length], auth_tag, 16);

    return p_header->length;
}

size_t tls_record_unpack_aead(
    TLS_RECORD_CONTEXT *p_ctx,
    const TLS_RECORD_MESSAGE_HEADER *p_header) {
    ;
    const size_t auth_length = sizeof(uint64_t) + sizeof(TLS_RECORD_MESSAGE_HEADER);
    uint8_t nonce[12] = {0}, auth_data[auth_length] = {0};
    if (p_header->length <= 16 + 8) {
        // there length of fragments not allowed smaller than it.
        tls_record_handle_error(0);
        return (size_t)0;
    }
    for (size_t i = 0; i < 4; i++) {
        nonce[i] = p_ctx->server_write_iv[i];
    }
    for (size_t i = 0; i < 8; i++) {
        nonce[i + 4] = p_ctx->ctx_buffer1[i];
    }
    ((uint64_t *)auth_data)[0] = p_ctx->server_seq;
    reverse_bytes(auth_data, sizeof(uint64_t));
    memcpy(&auth_data[sizeof(uint64_t)], p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    TLS_RECORD_MESSAGE_HEADER *p_header_ =
        (TLS_RECORD_MESSAGE_HEADER *)&auth_data[sizeof(uint64_t)];
    p_header_->length -= 8;
    reverse_bytes(&p_header_->length, sizeof(uint16_t));

    size_t decrypto_ret = tls_aes_128_GCM_decrypto(
        p_ctx->server_write_key, nonce, 
        auth_data, auth_length,
        &p_ctx->ctx_buffer1[8], p_header->length - 8 - 16,
        &p_ctx->ctx_buffer1[p_header->length - 16]);

    memcpy(p_ctx->ctx_buffer2, &p_ctx->ctx_buffer1[8], p_header->length - 8 - 16);
    return decrypto_ret;
}

// in code, if Cipertype is stream, then send directly. we donot provide stream encrypto trans
size_t tls_record_send(TLS_RECORD_CONTEXT *p_ctx, const TLS_RECORD_MESSAGE_HEADER *p_header, void *p_data) {
    size_t data_length = p_header->length;
    if (data_length > (1 << 14)) {
        return 0;
    }
    if (Ciper_stream == p_ctx->ciper_type) {
        tls_record_send_directly(p_ctx, p_header, p_data);
    } else if (Ciper_block == p_ctx->ciper_type) {
        // memcpy(p_ctx->buffer1, p_data, data_length);
        // tls_record_pack_block(p_ctx, p_header);
        // tls_record_send_directly(p_ctx, p_header, p_ctx->buffer1);
    } else if (Ciper_aead == p_ctx->ciper_type) {
        // memcpy(p_ctx->buffer1, p_data, data_length);
        // tls_record_pack_aead(p_ctx, p_header);
        // tls_record_send_directly(p_ctx, p_header, p_ctx->buffer1);
    }
}
size_t tls_record_recv(TLS_RECORD_CONTEXT *p_ctx, void *p_data, size_t data_length) {
    ; // do likely thingwith record_send().
}
