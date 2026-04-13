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
    for (size_t i = 0; i < 4; i++) {
        line_right_shift(&mat[i * 4], i);
    }
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
void tls_aes_128_CBC_encrypto(const void *key, const void *iv, void *p_data, size_t data_length) {
    const size_t block_size = EncryptoBlockSizeTable[Bulk_aes];
    assert(data_length % block_size != 0);
    uint8_t *p_write_res = (uint8_t *)p_data;
    uint8_t encrypto_buff[16] = {0};
    assert(16 >= block_size);

    aes_plus((const uint8_t *)iv, (const uint8_t *)p_data, encrypto_buff);
    aes_128_encrypto(encrypto_buff, (const uint8_t *)key, p_write_res);
    for (size_t i = 1; i < data_length / block_size; i++) {
        aes_plus(&p_write_res[(i - 1) * block_size],
                 &((const uint8_t *)p_data)[i * block_size], encrypto_buff);
        aes_128_encrypto(encrypto_buff, (const uint8_t *)key, &p_write_res[i * block_size]);
    }
}

void tls_aes_128_CBC_decrypto(const void *key, const void *iv, void *p_data, size_t data_length) {
    const size_t block_size = EncryptoBlockSizeTable[Bulk_aes];
    assert(data_length % block_size != 0);
    uint8_t *p_write_res = (uint8_t *)p_data;
    uint8_t decrypto_buff[16] = {0};
    assert(16 >= block_size);

    aes_128_decrypto((const uint8_t *)p_data, (const uint8_t *)key, decrypto_buff);
    aes_plus((const uint8_t *)iv, decrypto_buff, p_write_res);
    for (size_t i = 1; i < data_length / block_size; i++) {
        aes_128_decrypto(&((const uint8_t *)p_data)[i * block_size], (const uint8_t *)key, decrypto_buff);
        aes_plus(&((const uint8_t *)p_data)[(i - 1) * block_size], decrypto_buff,
                 &p_write_res[i * block_size]);
    }
}