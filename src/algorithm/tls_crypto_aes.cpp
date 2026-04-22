#include <stdlib.h>
#include <stdint.h>

#include "algorithm_consts.h"
#include "tls_algorithm.h"

static inline uint8_t aes_byte_exchange(uint8_t val, const uint8_t *box) {
    size_t y = val >> 4, x = val & 0x0F;
    return box[y * 16 + x];
}

static inline void line_right_shift(uint8_t *line, size_t offset) {
    uint8_t tmp_arr[4] = {0};
    for (size_t i = 0; i < 4; i++) {
        tmp_arr[i] = line[i];
    }
    for (size_t i = 0; i < 4; i++) {
        size_t new_idx = (i + offset) % 4;
        line[new_idx] = tmp_arr[i];
    }
}
static inline void aes_line_shift(uint8_t *mat) {
    for (size_t i = 0; i < 4; i++) {
        line_right_shift(&mat[i * 4], 4 - i);
    }
}
static inline void aes_line_shift_inverse(uint8_t *mat) {
    for (size_t i = 0; i < 4; i++) { line_right_shift(&mat[i * 4], i); }
}

static inline uint8_t byte_plus_2(uint8_t val) {
    return (val & 0x80) == 0 ? (val << 1) : ((val << 1) ^ 0x1B);
}
static inline uint8_t byte_plus(uint8_t a, uint8_t b) {
    uint8_t ret = ((a & 0x01) == 0 ? 0x00 : b);
    for (size_t i = 1; i < 8; i++) {
        bool tag = (a >> i) & 0x01;
        if (tag) {
            uint8_t tmp = b;
            for (size_t j = 0; j < i; j++) {
                tmp = byte_plus_2(tmp);
            }
            ret = tmp ^ ret;
        }
    }
    return ret;
}
static inline void mat_mul(const uint8_t *a, const uint8_t *b, uint8_t *res) {
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            uint8_t tmp = 0x00;
            for (size_t k = 0; k < 4; k++) {
                tmp ^= byte_plus(a[i * 4 + k], b[j + k * 4]);
            }
            res[i * 4 + j] = tmp;
        }
    }
}
static inline void aes_suffix_mat(uint8_t *mat) {
    uint8_t tmp[16] = {0};
    const uint8_t mul_[16] = {
        2, 3, 1, 1,
        1, 2, 3, 1,
        1, 1, 2, 3,
        3, 1, 1, 2};
    mat_mul(mul_, mat, tmp);
    for (size_t i = 0; i < 16; i++) {
        mat[i] = tmp[i];
    }
}
static inline void aes_suffix_inverse(uint8_t *mat) {
    uint8_t tmp[16] = {0};
    const uint8_t mul_[16] = {
        0x0E, 0x0B, 0x0D, 0x09,
        0x09, 0x0E, 0x0B, 0x0D,
        0x0D, 0x09, 0x0E, 0x0B,
        0x0B, 0x0D, 0x09, 0x0E};
    mat_mul(mul_, mat, tmp);
    for (size_t i = 0; i < 16; i++) {
        mat[i] = tmp[i];
    }
}

static inline void aes_plus(const uint8_t *a, const uint8_t *b, uint8_t *res) {
    for (size_t i = 0; i < 16; i++) {
        res[i] = a[i] ^ b[i];
    }
}

static inline void reverse_mat(const uint8_t *mat, uint8_t *res) {
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            res[i * 4 + j] = mat[i + j * 4];
        }
    }
}
static inline void key_extend_T(const uint8_t *val, size_t r, uint8_t *res) {
    uint8_t tmp[4] = {0};
    for (size_t i = 0; i < 4; i++) {
        tmp[i] = val[i];
    }
    line_right_shift(tmp, 3);
    for (size_t i = 0; i < 4; i++) {
        uint8_t tmp_ = aes_byte_exchange(tmp[i], s_box);
        tmp_ ^= rcon[r * 4 + i];
        res[i] = tmp_;
    }
}
// res is an uint8_t[44][4] array.
// NOTE: this function calculate an reverse extend-key-lines, must reverse it before use.
static inline void aes_key_extend(const uint8_t *key, uint8_t *res) {
    reverse_mat(key, res);
    for (size_t i = 4; i < 44; i++) {
        uint8_t tmp_arr[4] = {0};
        if (!(i % 4 == 0)) {
            for (size_t j = 0; j < 4; j++) {
                tmp_arr[j] = res[(i - 1) * 4 + j];
            }
        } else {
            key_extend_T(&res[(i - 1) * 4], i / 4 - 1, tmp_arr);
        }
        for (size_t j = 0; j < 4; j++) {
            res[i * 4 + j] = res[(i - 4) * 4 + j] ^ tmp_arr[j];
        }
    }
}

// data and key is uint8_t[16] array
void aes_128_encrypto(const uint8_t *data, const uint8_t *key, uint8_t *res) {
    uint8_t stat_mat[16] = {0}, key_mat[16] = {0};
    reverse_mat(data, stat_mat);
    reverse_mat(key, key_mat);
    uint8_t key_extend[44 * 4] = {0};
    aes_key_extend(key_mat, key_extend);
    aes_plus(stat_mat, key_mat, stat_mat);
    for (size_t i = 1; i <= 10; i++) {
        for (size_t j = 0; j < 16; j++) {
            stat_mat[j] = aes_byte_exchange(stat_mat[j], s_box);
        }
        aes_line_shift(stat_mat);
        if (i != 10) {
            aes_suffix_mat(stat_mat);
        }
        reverse_mat(&key_extend[i * 16], key_mat);
        aes_plus(key_mat, stat_mat, stat_mat);
    }

    reverse_mat(stat_mat, res);
}

void aes_128_decrypto(const uint8_t *data, const uint8_t *key, uint8_t *res) {
    uint8_t stat_mat[16] = {0}, key_mat[16] = {0};
    reverse_mat(data, stat_mat);
    reverse_mat(key, key_mat);
    uint8_t key_extend[44 * 4] = {0};
    aes_key_extend(key_mat, key_extend);
    reverse_mat(&key_extend[10 * 16], key_mat);
    aes_plus(stat_mat, key_mat, stat_mat);
    for (size_t i = 0; i < 10; i++) {
        for (size_t j = 0; j < 16; j++) {
            stat_mat[j] = aes_byte_exchange(stat_mat[j], s_box_inverse);
        }
        aes_line_shift_inverse(stat_mat);
        if (i != 9) {
            aes_suffix_inverse(stat_mat);
        }
        reverse_mat(&key_extend[(9 - i) * 16], key_mat);
        aes_suffix_inverse(key_mat);
        aes_plus(key_mat, stat_mat, stat_mat);
    }

    reverse_mat(stat_mat, res);
}

#include <assert.h>
void tls_aes_128_CBC_encrypto(
    const void *key, const void *iv, 
    void *p_data, size_t data_length) {
    ;
    const size_t block_size = 16;
    assert(data_length % block_size == 0);
    uint8_t *p_write_res = (uint8_t *)p_data;
    uint8_t encrypto_buff[16] = {0};
    assert(16 >= block_size);

    aes_plus((const uint8_t *)iv, (const uint8_t *)p_data, encrypto_buff);
    aes_128_encrypto(encrypto_buff, (const uint8_t *)key, p_write_res);
    for (size_t i = 1; i < data_length / block_size; i++) {
        aes_plus(&p_write_res[(i - 1) * block_size],
                 &((const uint8_t *)p_data)[i * block_size], encrypto_buff);
        aes_128_encrypto(
            encrypto_buff, 
            (const uint8_t *)key, 
            &p_write_res[i * block_size]);
    }
}

void tls_aes_128_CBC_decrypto(
    const void *key, const void *iv, 
    void *p_data, size_t data_length) {
    ;
    const size_t block_size = 16;
    assert(data_length % block_size == 0);
    uint8_t *p_write_res = (uint8_t *)p_data;
    uint8_t decrypto_buff[16] = {0};
    assert(16 >= block_size);

    aes_128_decrypto((const uint8_t *)p_data, (const uint8_t *)key, decrypto_buff);
    aes_plus((const uint8_t *)iv, decrypto_buff, p_write_res);
    for (size_t i = 1; i < data_length / block_size; i++) {
        aes_128_decrypto(
            &((const uint8_t *)p_data)[i * block_size], 
            (const uint8_t *)key, 
            decrypto_buff);
        aes_plus(&((const uint8_t *)p_data)[(i - 1) * block_size], decrypto_buff,
                 &p_write_res[i * block_size]);
    }
}

static inline void reverse_bytes(void *p_byte, size_t length) {
    for (size_t i = 0; i < length / 2; i++) {
        uint8_t tmp = ((uint8_t *)p_byte)[i];
        ((uint8_t *)p_byte)[i] = ((uint8_t *)p_byte)[length - i - 1];
        ((uint8_t *)p_byte)[length - i - 1] = tmp;
    }
}

// nonce is an size 12 array, inner counter is uint32_t type.
void tls_aes_128_CTR_encrypto(
    const void *key, const void *nonce, 
    void *p_data, size_t data_length) {
    ;
    const size_t block_size = 16;
    const size_t nonce_size = 12;
    const size_t counter_size = nonce_size + sizeof(uint32_t);
    assert(counter_size >= block_size);
    uint8_t *p_write_res = (uint8_t *)p_data;
    uint8_t encrypto_buff[16] = {0};
    assert(16 >= counter_size);

    for (size_t i = 0; i < data_length / block_size; i++) {
        for (size_t j = 0; j < 12; j++) {
            encrypto_buff[i] = ((uint8_t *)nonce)[i];
        }
        *(uint32_t *)&encrypto_buff[nonce_size] = (i + 1) % UINT32_MAX;
        reverse_bytes(&encrypto_buff[nonce_size], sizeof(uint32_t));
        aes_128_encrypto(encrypto_buff, (const uint8_t *)key, encrypto_buff);
        const size_t xor_size = 
            (i == data_length / block_size ? data_length % block_size : block_size);
        for (size_t j = 0; j < xor_size; j++) {
            p_write_res[i * block_size + j] ^= encrypto_buff[j];
        }
    }
}

void tls_aes_128_CTR_decrypto(
    const void *key, const void *nonce, 
    void *p_data, size_t data_length) {
    ;
    tls_aes_128_CTR_encrypto(key, nonce, p_data, data_length);
}

// size 16, size 16, size 16
#define READ_BITS(x, y) ((((const uint8_t *)(x))[(y) / 8] >> (7 - ((y) % 8))) & 0x01)
void ghash_multiplication(const void *a, const void *b, void *res) {
    // uint8_t Z_buff[129][16] = {0}, V_buff[129][16] = {0};
    uint8_t Z_buff[16] = {0}, V_buff[16] = {0};
    for (size_t i = 0; i < 16; i++) {
        V_buff[i] = ((const uint8_t *)b)[i];
    }
    for (size_t i = 0; i < 128; i++) {
        if (READ_BITS(a, i)) {
            for (size_t j = 0; j < 16; j++) {
                Z_buff[j] ^= V_buff[j];
            }
        }
        bool shift_tag = false;
        for (size_t j = 0; j < 16; j++) {
            if (shift_tag) {
                shift_tag = V_buff[j] & 0x01;
                V_buff[j] >>= 1;
                V_buff[j] |= 0x80;
            } else {
                shift_tag = V_buff[j] & 0x01;
                V_buff[j] >>= 1;
            }
        }
        if (shift_tag) {
            V_buff[0] ^= 0xe1;
        }
    }
    for (size_t i = 0; i < 16; i++) {
        ((uint8_t *)res)[i] = Z_buff[i];
    }
}
#undef READ_BITS

static inline void ghash(
    const void *key,
    const void *auth, size_t auth_length,
    const void *encry, size_t encry_length,
    void *res) {
    ;
    const size_t auth_block_number = (auth_length + 15) / 16;
    const size_t encry_block_number = (encry_length + 15) / 16;
    uint8_t H_buff[16] = {0}, res_buff[16] = {0};
    const uint8_t *p_auth_read = (const uint8_t *)auth;
    const uint8_t *p_encry_read = (const uint8_t *)encry;
    aes_128_encrypto(H_buff, (const uint8_t *)key, H_buff);

    for (size_t k = 0; k < 2; k++) {
        size_t range_ = auth_block_number;
        size_t check = auth_length;
        const uint8_t *p_read = p_auth_read;
        if (k == 1) {
            range_ = encry_block_number;
            check = encry_length;
            p_read = p_encry_read;
        }
        for (size_t i = 1; i < range_; i++) {
            uint8_t tmp_arr[16] = {0};
            for (size_t j = 0; j < 16; j++) {
                tmp_arr[j] = p_read[j] ^ res_buff[j];
            }
            ghash_multiplication(tmp_arr, H_buff, res_buff);
            p_read = &p_read[16];
        }
        if (check % 16 != 0) {
            uint8_t tmp_arr[16] = {0};
            size_t i = 0;
            for (; i < check % 16; i++) {
                tmp_arr[i] = p_read[i] ^ res_buff[i];
            }
            for (; i < 16; i++) {
                tmp_arr[i] = res_buff[i];
            }
            ghash_multiplication(tmp_arr, H_buff, res_buff);
        }
    }
    uint8_t tmp_arr[16] = {0};
    ((uint64_t *)tmp_arr)[0] = auth_length;
    ((uint64_t *)tmp_arr)[1] = encry_length;
    reverse_bytes(tmp_arr, sizeof(uint64_t));
    reverse_bytes(&tmp_arr[sizeof(uint64_t)], sizeof(uint64_t));
    for (size_t i = 0; i < 16; i++) {
        tmp_arr[i] ^= res_buff[i];
    }
    ghash_multiplication(tmp_arr, H_buff, res_buff);
    for (size_t i = 0; i < 16; i++) {
        ((uint8_t *)res)[i] = res_buff[i];
    }
}

// nonce is an size 12 array.
void tls_aes_128_GCM_encrypto(
    const void *key, const void *nonce,
    const void *auth, size_t auth_length, 
    void *p_data, size_t data_length, 
    void *auth_tag) {
    ;
    tls_aes_128_CTR_encrypto(key, nonce, p_data, data_length);
    ghash(key, auth, auth_length, p_data, data_length, auth_tag);
}

size_t tls_aes_128_GCM_decrypto(
    const void *key, const void *nonce,
    const void *auth, size_t auth_length, 
    void *p_data, size_t data_length, 
    const void *auth_tag) {
    ;
    uint8_t auth_tag_buff[16] = {0};
    ghash(key, auth, auth_length, p_data, data_length, auth_tag_buff);
    bool auth_success = true;
    for (size_t i = 0; i < 16; i++) {
        if (auth_tag_buff[i] != ((const uint8_t *)auth_tag)[i]) {
            auth_success = false;
        }
    }
    tls_aes_128_CTR_decrypto(key, nonce, p_data, data_length);
    return auth_success ? data_length : (size_t)-1;
}
