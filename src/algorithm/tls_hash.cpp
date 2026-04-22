#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "tls_algorithm.h"
#include "algorithm_consts.h"

size_t hash_null_func(const void *p_data, size_t length, void *p_ret) {
    return 0;
}

static inline uint32_t converse_bytes(uint32_t val) {
    return (val >> 24) | ((val >> 8) & 0xFF00) | ((val << 8) & 0xFF0000) | (val << 24);
}
static inline uint64_t converse_bytes_64(uint64_t val) {
    uint64_t ret = 0;
    uint8_t *p_read = (uint8_t *)&val, *p_write = (uint8_t *)&ret;
    for (size_t i = 0; i < 8; i++) {
        p_write[i] = p_read[7 - i];
    }
    return ret;
}
static inline uint32_t circular_left_shift(uint32_t x, size_t n) {
    return (x << n) | (x >> (32 - n));
}
static inline uint32_t circular_right_shift(uint32_t x, size_t n) {
    return (x >> n) | (x << (32 - n));
}

template <typename T>
void sha_calculate(
    const void *p_data, size_t length,
    void (*pf)(const void *, T *),
    T *p_ctx) {
    ;
    size_t i = 0;
    for (; i < length / 64; i++) {
        pf(&((const uint8_t *)p_data)[i * 64], p_ctx);
    }
    if (length % 64 != 0) {
        uint32_t buff[16] = {0};
        size_t last_length = length - i * 64;
        memcpy(buff, &((const uint8_t *)p_data)[i * 64], last_length);
        ((uint8_t *)buff)[last_length] = 0x80;
        if (last_length + 9 > 64) {
            pf(buff, p_ctx);
            memset(buff, 0, 64);
        }
        uint64_t *p_length_write = (uint64_t *)&buff[14];
        p_length_write[0] = converse_bytes_64(length * 8);
        pf(buff, p_ctx);
    }
}

struct sha1_context {
    uint32_t Hi[5] = {
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    };
};
void sha1_calculate_512block(const void *p_data, sha1_context *p_ctx) {
    uint32_t W[80] = {0};
    const uint32_t *p_read = (const uint32_t *)p_data;
    for (size_t i = 0; i < 16; i++) {
        W[i] = converse_bytes(p_read[i]);
    }
    for (size_t i = 16; i < 80; i++) {
        uint32_t tmp = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
        W[i] = circular_left_shift(tmp, 1);
    }
    uint32_t tmp_arr[5] = {0};
    memcpy(tmp_arr, p_ctx->Hi, sizeof(uint32_t) * 5);
    for (size_t i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            k = 0x5A827999;
            f = (tmp_arr[1] & tmp_arr[2]) | ((~tmp_arr[1]) & tmp_arr[3]);
        } else if (i < 40) {
            k = 0x6ED9EBA1;
            f = tmp_arr[1] ^ tmp_arr[2] ^ tmp_arr[3];
        } else if (i < 60) {
            k = 0x8F1BBCDC;
            f = (tmp_arr[1] & tmp_arr[2])
                | (tmp_arr[1] & tmp_arr[3])
                | (tmp_arr[2] & tmp_arr[3]);
        } else {
            k = 0xCA62C1D6;
            f = tmp_arr[1] ^ tmp_arr[2] ^ tmp_arr[3];
        } // i < 80
        uint32_t tmp = circular_left_shift(tmp_arr[0], 5) + f + tmp_arr[4] + W[i] + k;
        tmp_arr[4] = tmp_arr[3], tmp_arr[3] = tmp_arr[2];
        tmp_arr[2] = circular_left_shift(tmp_arr[1], 30);
        tmp_arr[1] = tmp_arr[0], tmp_arr[0] = tmp;
    }
    for (size_t i = 0; i < 5; i++) {
        p_ctx->Hi[i] += tmp_arr[i];
    }
}

size_t sha1_calculate(const void *p_data, size_t length, void *p_ret) {
    sha1_context sha1_ctx;
    sha_calculate<sha1_context>(
        p_data, length, sha1_calculate_512block, &sha1_ctx);
    uint32_t *p_ret_write = (uint32_t *)p_ret;
    for (size_t i = 0; i < 5; i++) {
        p_ret_write[i] = converse_bytes(sha1_ctx.Hi[i]);
    }
    return 20;
}

struct sha256_context {
    uint32_t Hi[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19};
};

void sha256_calculate_512block(const void *p_data, sha256_context *p_ctx) {
    uint32_t W[64] = {0};
    uint32_t tmp_arr[8] = {0};
    // uint8_t *p_u8_read =
    for (size_t i = 0; i < 16; i++) {
        W[i] = converse_bytes(((const uint32_t *)p_data)[i]);
    }
    for (size_t i = 16; i < 64; i++) {
        uint32_t sigma_0 = 0, sigma_1 = 0;
        sigma_0 = circular_right_shift(W[i - 15], 7)
                  ^ circular_right_shift(W[i - 15], 18)
                  ^ W[i - 15] >> 3;
        sigma_1 = circular_right_shift(W[i - 2], 17)
                  ^ circular_right_shift(W[i - 2], 19)
                  ^ W[i - 2] >> 10;
        W[i] = W[i - 16] + sigma_0 + W[i - 7] + sigma_1;
    }
    memcpy(tmp_arr, p_ctx->Hi, sizeof(uint32_t) * 8);
    for (size_t i = 0; i < 64; i++) {
        uint32_t Sigma_1 = circular_right_shift(tmp_arr[4], 6)
                           ^ circular_right_shift(tmp_arr[4], 11)
                           ^ circular_right_shift(tmp_arr[4], 25);
        uint32_t ch = (tmp_arr[4] & tmp_arr[5]) ^ ((~tmp_arr[4]) & tmp_arr[6]);
        uint32_t tmp_1 = tmp_arr[7] + Sigma_1 + ch + sha256_k[i] + W[i];
        uint32_t Sigma_0 = circular_right_shift(tmp_arr[0], 2)
                           ^ circular_right_shift(tmp_arr[0], 13)
                           ^ circular_right_shift(tmp_arr[0], 22);
        uint32_t maj =
            (tmp_arr[0] & tmp_arr[1])
            ^ (tmp_arr[0] & tmp_arr[2])
            ^ (tmp_arr[1] & tmp_arr[2]);
        uint32_t tmp_2 = Sigma_0 + maj;
        tmp_arr[7] = tmp_arr[6];
        tmp_arr[6] = tmp_arr[5];
        tmp_arr[5] = tmp_arr[4];
        tmp_arr[4] = tmp_arr[3] + tmp_1;
        tmp_arr[3] = tmp_arr[2];
        tmp_arr[2] = tmp_arr[1];
        tmp_arr[1] = tmp_arr[0];
        tmp_arr[0] = tmp_1 + tmp_2;
    }
    for (size_t i = 0; i < 8; i++) {
        p_ctx->Hi[i] += tmp_arr[i];
    }
}

size_t sha256_calculate(const void *p_data, size_t length, void *p_ret) {
    sha256_context sha256_ctx;
    sha_calculate<sha256_context>(
        p_data, length, sha256_calculate_512block, &sha256_ctx);
    uint32_t *p_ret_write = (uint32_t *)p_ret;
    for (size_t i = 0; i < 8; i++) {
        p_ret_write[i] = converse_bytes(sha256_ctx.Hi[i]);
    }
    return 32;
}

uint8_t *str_cat_(
    const void *str1, size_t l1,
    const void *str2, size_t l2,
    void *buffer) {
    ;
    uint8_t *p_ret;
    if (NULL == buffer) {
        p_ret = (uint8_t *)calloc(l1 + l2, 1);
    } else {
        p_ret = (uint8_t *)buffer;
    }
    memmove(p_ret, str1, l1);
    memmove(&p_ret[l1], str2, l2);
    return p_ret;
}

size_t tls_hmac(
    HashAlgorithm type,
    const void *key, size_t key_length,
    const void *p_data, size_t data_length,
    void *p_ret) {
    ;
    size_t block_size = HashBlockSizeTable[type];
    size_t result_size = HashResultSizeTable[type];
    pf_hash pf = HashFnucTable[type];
    uint8_t key_buff[128] = {0};
    assert(128 >= block_size && 128 >= result_size);
    if (key_length > block_size) {
        pf(key, key_length, key_buff);
    } else {
        memcpy(key_buff, key, key_length);
    }

    uint8_t i_buffer[128] = {0};
    uint8_t o_buffer[128] = {0};
    for (size_t i = 0; i < block_size; i++) {
        i_buffer[i] = 0x36 ^ key_buff[i];
        o_buffer[i] = 0x5C ^ key_buff[i];
    }
    uint8_t *tp_str1 = str_cat_(i_buffer, block_size, p_data, data_length, NULL);
    pf(tp_str1, block_size + data_length, i_buffer);
    free(tp_str1);
    uint8_t tmp_buffer[128 * 2] = {0};
    str_cat_(o_buffer, block_size, i_buffer, result_size, tmp_buffer);
    pf(tmp_buffer, block_size + result_size, i_buffer);
    memcpy(p_ret, i_buffer, result_size);
    return result_size;
}

void tls_prf(
    HashAlgorithm type,
    const void *secret, size_t secret_length,
    const void *label, size_t label_length,
    const void *seed, size_t seed_length,
    void *p_res, size_t res_length) {
    ;
    size_t result_size = HashResultSizeTable[type];
    uint8_t *prf_buff =
        (uint8_t *)malloc(label_length + seed_length + result_size);

    str_cat_(
        label, label_length,
        seed, seed_length,
        &prf_buff[result_size]);
    seed_length += label_length;
    tls_hmac(
        type,
        secret, secret_length,
        &prf_buff[result_size], seed_length,
        prf_buff);
    // NOTE: now, the prf_buff is [A(1) = HMAC_hash(secret, A(0))] | [seed]
    size_t generator_bytes = 0;
    uint8_t *p_write_res = (uint8_t *)p_res;
    uint8_t hmac_buff[128] = {0};
    assert(128 >= result_size);
    while (generator_bytes + result_size <= res_length) {
        tls_hmac(type, secret, secret_length,
                 prf_buff, seed_length + result_size,
                 &p_write_res[generator_bytes]);
        tls_hmac(type, secret, secret_length, prf_buff, result_size, hmac_buff);
        memcpy(prf_buff, hmac_buff, result_size);
        generator_bytes += result_size;
    }
    if (res_length - generator_bytes != 0) {
        tls_hmac(type, secret, secret_length,
                 prf_buff, seed_length + result_size,
                 hmac_buff);
        memcpy(&p_write_res[generator_bytes], hmac_buff, res_length - generator_bytes);
    }
    free(prf_buff);
}