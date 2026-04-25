#include <assert.h>

#include "tls_record.h"

// reverse bytes, use to converse between big endian with little endian.
static inline void reverse_bytes(void *p_byte, size_t length) {
    for (size_t i = 0; i < length / 2; i++) {
        uint8_t tmp = ((uint8_t *)p_byte)[i];
        ((uint8_t *)p_byte)[i] = ((uint8_t *)p_byte)[length - i - 1];
        ((uint8_t *)p_byte)[length - i - 1] = tmp;
    }
}

static inline void reverse_record_head(void *p_head) {
    TLS_RECORD_MESSAGE_HEADER *p_head_ = 
        (TLS_RECORD_MESSAGE_HEADER*)p_head;
    reverse_bytes(&p_head_->length, sizeof(uint16_t));
}

// swap ctx_buff on record-context
static inline void swap_pointer(TLS_RECORD_CONTEXT *p_ctx) {
    uint8_t *tp = p_ctx->ctx_buffer1;
    p_ctx->ctx_buffer1 = p_ctx->ctx_buffer2;
    p_ctx->ctx_buffer2 = tp;
}

// dst and src is restrict pointer.
static inline void write_rvs_bytes(void *p_dst, const void *p_src, size_t size) {
    if (p_dst != p_src) {
        memcpy(p_dst, p_src, size);
    }
    reverse_bytes(p_dst, size);
}

// read random from context.
static inline void get_random(TLS_RECORD_CONTEXT *p_ctx, void *p_out, size_t size) {
    if (size + p_ctx->tls_random_used > p_ctx->tls_random_max) {
        abort(); // TODO: fill new random.
    }
    uint8_t *p_random = p_ctx->tls_inner_system_random;
    p_random = &p_random[p_ctx->tls_random_used];
    memcpy(p_out, p_random, size);
    p_ctx->tls_random_used += size;
}

void tls_record_handle_error(size_t tls_error) {
    ;
}

size_t tls_record_send_directly(
    TLS_RECORD_CONTEXT *p_ctx,
    const TLS_RECORD_MESSAGE_HEADER *p_header,
    const void *p_data) {
    ;
    uint16_t length = p_header->length;
    TLS_RECORD_MESSAGE_HEADER t_header;
    memcpy(&t_header, p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    reverse_record_head(&t_header);

    size_t ret = win32sockets_send(p_ctx->send_socket,
                                   &t_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    if ((size_t)-1 != ret) {
        ret = win32sockets_send(p_ctx->send_socket, p_data, length);
    }
    if ((size_t)-1 == ret) {
        tls_record_handle_error(0); // SOCKET_ERROR or timeout.
    }
    return ret;
}
size_t tls_record_recv_directly(
    TLS_RECORD_CONTEXT *p_ctx,
    TLS_RECORD_MESSAGE_HEADER *p_header,
    void *p_data) {
    ;
    size_t read_max_bytes = p_header->length;
    if (read_max_bytes < (1 << 14) + 2048) {
        return 0; // buffer not enough big to save message.
    }

    size_t ret = win32sockets_recv(p_ctx->send_socket,
                                   p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    if ((size_t)-1 == ret) {
        tls_record_handle_error(0); // SOCKET_ERROR or timeout.
        return ret;
    }
    reverse_record_head(p_header);
    if ((1 << 14) + 2048 < p_header->length){
        tls_record_handle_error(0);
        return (size_t)-1; // invalid length recved in record header.
    } 

    ret = win32sockets_recv(p_ctx->send_socket, p_data, p_header->length);
    if ((size_t)-1 == ret) {
        tls_record_handle_error(0); // SOCKET_ERROR or timeout.
    }
    return ret;
}

size_t tls_record_hmac(
    TLS_RECORD_CONTEXT *p_ctx,
    size_t send_seq_num,
    const TLS_RECORD_MESSAGE_HEADER *p_header,
    void *hmac_buff) {
    ;
    uint8_t *p_buff = p_ctx->ctx_buffer2;
    size_t offset = 0;

    write_rvs_bytes(&p_buff[offset], &send_seq_num, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    memcpy(&p_buff[offset], p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    reverse_record_head(&p_buff[offset]);
    offset += sizeof(TLS_RECORD_MESSAGE_HEADER);

    memcpy(&p_buff[offset], p_ctx->ctx_buffer1, p_header->length);
    offset += p_header->length;

    size_t hmac_bytes = tls_hmac(
        p_ctx->hash_algorithm,
        p_ctx->client_write_MAC_key, p_ctx->mac_key_length,
        p_buff, offset, hmac_buff);
    return hmac_bytes;
}

size_t tls_record_pack_block(
    TLS_RECORD_CONTEXT *p_ctx,
    const TLS_RECORD_MESSAGE_HEADER *p_header) {
    ;
    size_t data_length = p_header->length;
    if (application_data != p_header->type && 0 == data_length) {
        return 0;
    } else if (data_length > (1 << 14) && data_length > 0) {
        return 0; // invaild length data.
    }

    uint8_t hmac_buff[128] = {0};
    size_t hmac_bytes =
        tls_record_hmac(p_ctx, p_ctx->client_seq, p_header, hmac_buff);

    const size_t encry_blk_sz = 16;

    size_t frag_sz = data_length + hmac_bytes + 1;
    size_t pad_frag_sz = (frag_sz + (encry_blk_sz - 1)) & ~encry_blk_sz;
    assert(encry_blk_sz + pad_frag_sz <= (1 << 14) + 2048);

    uint8_t *p_buff = p_ctx->ctx_buffer2;
    size_t offset = 0;

    get_random(p_ctx, p_buff, encry_blk_sz); // fill random-iv.
    offset += encry_blk_sz;
    memcpy(&p_buff[offset], p_ctx->ctx_buffer1, data_length);
    offset += data_length;

    uint8_t padding_value = (uint8_t)(pad_frag_sz - frag_sz);
    memcpy(&p_buff[offset], hmac_buff, hmac_bytes);
    offset += hmac_bytes;
    for (size_t i = 0; i < padding_value + 1; i++) {
        p_buff[offset + i] = padding_value;
    }
    offset += padding_value + 1;
    tls_aes_128_CBC_encrypto(
        p_ctx->client_write_key, p_buff, &p_buff[encry_blk_sz], pad_frag_sz);
    swap_pointer(p_ctx);

    return offset;
}

size_t tls_record_unpack_block(
    TLS_RECORD_CONTEXT *p_ctx,
    const TLS_RECORD_MESSAGE_HEADER *p_header) {
    ;
    if (p_header->length < (1 << 14)) {
        return 0;
    }
    uint8_t *p_buff = p_ctx->ctx_buffer1;
    const size_t encry_blk_sz = 16;

    if (p_header->length <= encry_blk_sz) {
        tls_record_handle_error(0); // error length.
        return (size_t)-1;
    }
    size_t frag_sz = p_header->length - encry_blk_sz;
    tls_aes_128_CBC_decrypto(
        p_ctx->server_write_key, p_buff, &p_buff[encry_blk_sz], frag_sz);
    uint8_t padding_value = p_buff[p_header->length - 1];
    size_t hmac_size = HashResultSizeTable[p_ctx->hash_algorithm];
    if (p_header->length <= (padding_value + 1) - hmac_size) {
        tls_record_handle_error(0); // error format.
        return (size_t)-1;
    }
    uint8_t *p_hmac_recv = &p_buff[p_header->length - (padding_value + 1) - hmac_size];

    p_ctx->ctx_buffer1 = &p_buff[encry_blk_sz];
    TLS_RECORD_MESSAGE_HEADER t_header;
    memcpy(&t_header, p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    t_header.length = p_ctx->ctx_buffer1 - p_hmac_recv;

    uint8_t hmac_buff[128] = {0};
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
        tls_record_handle_error(0); // hmac or padding error.
        return (size_t)-1;
    }
    memcpy(p_ctx->ctx_buffer2, &p_buff[encry_blk_sz], t_header.length);
    swap_pointer(p_ctx);

    return t_header.length;
}

static inline void aead_get_auth_data(
    uint64_t seq, 
    const TLS_RECORD_MESSAGE_HEADER *p_header, 
    uint8_t* auth_data) {
    ;
    write_rvs_bytes(auth_data, &seq, sizeof(uint64_t));
    memcpy(&auth_data[sizeof(uint64_t)], p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));
    reverse_record_head(&auth_data[sizeof(uint64_t)]);
}

size_t tls_record_pack_aead(
    TLS_RECORD_CONTEXT *p_ctx,
    const TLS_RECORD_MESSAGE_HEADER *p_header) {
    ;
    const size_t auth_length = sizeof(uint64_t) + sizeof(TLS_RECORD_MESSAGE_HEADER);
    uint8_t nonce[12] = {0}, auth_data[auth_length] = {0};
    memcpy(nonce, p_ctx->client_write_iv, 4);
    get_random(p_ctx, &nonce[4], 8);

    aead_get_auth_data(p_ctx->client_seq, p_header, auth_data);

    uint8_t auth_tag[16] = {0};
    tls_aes_128_GCM_encrypto(p_ctx->client_write_key, nonce,
                             auth_data, auth_length,
                             p_ctx->ctx_buffer1, p_header->length,
                             auth_tag);

    uint8_t *p_buff = p_ctx->ctx_buffer2;
    size_t offset = 0;
    memcpy(p_buff, &nonce[4], 8);
    offset += 8;
    memcpy(&p_buff[offset], p_ctx->ctx_buffer1, p_header->length);
    offset += p_header->length;
    memcpy(&p_buff[offset], auth_tag, 16);
    offset += 16;

    return offset;
}

size_t tls_record_unpack_aead(
    TLS_RECORD_CONTEXT *p_ctx,
    const TLS_RECORD_MESSAGE_HEADER *p_header) {
    ;
    const size_t auth_length = sizeof(uint64_t) + sizeof(TLS_RECORD_MESSAGE_HEADER);
    uint8_t nonce[12] = {0}, auth_data[auth_length] = {0};
    if (p_header->length <= 8 + 16) {
        tls_record_handle_error(0); // invalid frag_sz received packet.
        return (size_t)-1;
    }
    memcpy(nonce, p_ctx->server_write_iv, 4);
    memcpy(&nonce[4], p_ctx->ctx_buffer1, 8);
    aead_get_auth_data(p_ctx->server_seq, p_header, auth_data);

    size_t decrypto_ret = tls_aes_128_GCM_decrypto(
        p_ctx->server_write_key, nonce,
        auth_data, auth_length,
        &p_ctx->ctx_buffer1[8], p_header->length - 8 - 16,
        &p_ctx->ctx_buffer1[p_header->length - 16]);

    if ((size_t)-1 == decrypto_ret) {
        tls_record_handle_error(0); // auth data failed.
    } else {
        memcpy(p_ctx->ctx_buffer2, &p_ctx->ctx_buffer1[8], p_header->length - 8 - 16);
    }

    return decrypto_ret;
}

// in code, if Cipertype is stream, then send directly. we donot provide stream encrypto trans
size_t tls_record_send(
    TLS_RECORD_CONTEXT *p_ctx,
    const TLS_RECORD_MESSAGE_HEADER *p_header, const void *p_data) {
    ;
    size_t data_length = p_header->length;
    if (data_length > (1 << 14)) {
        return 0;
    }
    if (Ciper_stream == p_ctx->ciper_type) {
        return tls_record_send_directly(p_ctx, p_header, p_data);
    } else {
        memcpy(p_ctx->ctx_buffer1, p_data, data_length);
        TLS_RECORD_MESSAGE_HEADER send_head;
        memcpy(&send_head, p_header, sizeof(TLS_RECORD_MESSAGE_HEADER));

        size_t frag_sz = 0;
        if (Ciper_block == p_ctx->ciper_type) {
            frag_sz = tls_record_pack_block(p_ctx, p_header);
        } else if (Ciper_block == p_ctx->ciper_type){
            frag_sz = tls_record_pack_aead(p_ctx, p_header);
        }
        if (frag_sz > (1 << 14) + 2048) {
            return 0; // after encrypto and compress, too long result length.
        }
        uint16_t length = (uint16_t)frag_sz;
        write_rvs_bytes(&send_head.length, &length, sizeof(uint16_t));
        return tls_record_send_directly(p_ctx, &send_head, p_ctx->ctx_buffer2);
    }
}
size_t tls_record_recv(
    TLS_RECORD_CONTEXT *p_ctx, 
    TLS_RECORD_MESSAGE_HEADER* p_header, void *p_data) {
    ; // do likely thingwith tls_record_send().
    size_t data_length = p_header->length;
    if (data_length < (1 << 14)) {
        return 0;
    }
    if (Ciper_stream == p_ctx->ciper_type) {
        return tls_record_recv_directly(p_ctx, p_header, p_data);
    } else if (Ciper_block == p_ctx->ciper_type){

    } else {

    } // aead_cipher.
}
