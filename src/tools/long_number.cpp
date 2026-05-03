#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "tools.h"

void long_number_extend(uint8_t **a, size_t a_bytes, size_t new_bytes, bool free_tag = true) {
    uint8_t *res = (uint8_t *)calloc(new_bytes, 1);
    if (a_bytes < new_bytes) {
        memcpy(&res[new_bytes - a_bytes], a[0], a_bytes);
    } else {
        memcpy(res, a[0], new_bytes);
    }
    if (free_tag) {
        free(a[0]);
    }
    a[0] = res;
}

bool long_number_is_zero(const uint8_t *a, size_t a_bytes) {
    for (size_t i = 0; i < a_bytes; i++) {
        if (a[i] != 0) {
            return false;
        }
    }
    return true;
}

// returns number's hitgt bits width
size_t long_number_bitwidth(const uint8_t *a, size_t a_bytes) {
    for (size_t i = 0; i < a_bytes; i++) {
        if (a[i] != 0) {
            if ((a[i] & 0x80) != 0) {
                return (a_bytes - i) * 8;
            }
            for (size_t j = 1; j < 8; j++) {
                if ((a[i] & (0x80 >> j)) != 0) {
                    return (a_bytes - i - 1) * 8 + (8 - j);
                }
            }
        }
    }
    return 0;
}

int long_number_compare(
    const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes) {
    ;
    size_t a_bits_ = long_number_bitwidth(a, a_bytes);
    size_t b_bits_ = long_number_bitwidth(b, b_bytes);
    if (a_bits_ > b_bits_) {
        return 1;
    } else if (a_bits_ < b_bits_) {
        return -1;
    } else if (a_bits_ != 0) {
        size_t real_bytes_ = (a_bits_ + 0x07) >> 3;
        for (size_t i = real_bytes_; i != 0; i--) {
            if (a[a_bytes - i] != b[b_bytes - i]) {
                return a[a_bytes - i] > b[b_bytes - i] ? 1 : -1;
            }
        }
    } // a_bytes == b_bytes
    return 0;
}

bool long_number_left_shift(uint8_t *a, size_t a_bytes, size_t shift_bits) {
    size_t shift_bytes = shift_bits >> 3; // throws away bytes.
    assert((shift_bits + 0x07) >> 3 <= a_bytes);
    bool ret_ = a[shift_bytes] >> (8 - (shift_bits & 0x07));
    for (size_t i = 0; i < a_bytes - shift_bytes - 1; i++) {
        a[i] = a[shift_bytes + i] << (shift_bits & 0x07);
        a[i] |= a[shift_bytes + i + 1] >> (8 - (shift_bits & 0x07));
    }
    a[a_bytes - shift_bytes - 1] = a[a_bytes - 1] << (shift_bits & 0x07);
    memset(&a[a_bytes - shift_bytes], 0, shift_bytes);
    return ret_;
}

void long_number_right_shift(uint8_t *a, size_t a_bytes, size_t shift_bits) {
    size_t shift_bytes = shift_bits >> 3;
    assert((shift_bits + 0x07) >> 3 <= a_bytes);
    a[a_bytes - 1] = a[a_bytes - 1 - shift_bytes] >> (shift_bits & 0x07);
    for (size_t i = 1; i < a_bytes - shift_bytes; i++) {
        a[a_bytes - 1 - i] = a[a_bytes - 1 - shift_bytes - i] >> (shift_bits & 0x07);
        a[a_bytes - i] |= a[a_bytes - 1 - shift_bytes - i] << (8 - (shift_bits & 0x07));
    }
    memset(a, 0, shift_bytes);
}

bool long_number_plus(uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes) {
    assert(a_bytes >= b_bytes);
    size_t i = 0, carry_ = 0;
    for (; i < b_bytes; i++, carry_ >>= 8) {
        carry_ += a[a_bytes - 1 - i] + b[b_bytes - 1 - i];
        a[a_bytes - 1 - i] = (carry_ & 0xFF); // carry_ eq 1 or 0.
    }
    for (; carry_ && i < a_bytes; i++, a[a_bytes - 1 - i]++) {
        if (a[a_bytes - 1 - i] != 0xFF) {
            return false;
        }
    }
    return carry_;
}

static inline void swap_u64(void *a, void *b) {
    uint64_t tmp_ = ((uint64_t *)a)[0];
    ((uint64_t *)a)[0] = ((uint64_t *)b)[0];
    ((uint64_t *)b)[0] = tmp_;
}

bool long_number_mul(
    const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes,
    uint8_t *res, size_t res_max_bytes) {
    ;
    // assert(res_max_bytes >= a_bytes + b_bytes);
    size_t a_total = a_bytes > res_max_bytes ? res_max_bytes : a_bytes;
    size_t b_total = b_bytes > res_max_bytes ? res_max_bytes : b_bytes;
    if (a_bytes < b_bytes) {
        swap_u64(&a_bytes, &b_bytes), swap_u64(&a, &b);
        swap_u64(&a_total, &b_total);
    }
    bool ret_ = false; // overflow flag.
    for (size_t i = 0; i < a_total; i++) {
        uint16_t carry_ = 0;
        size_t j = 0;
        for (; j < b_total
               && res_max_bytes - i - j != 0;
             j++, carry_ >>= 8) {
            carry_ += a[a_bytes - 1 - i] * b[b_bytes - 1 - j];
            carry_ += res[res_max_bytes - 1 - i - j];
            res[res_max_bytes - 1 - i - j] = carry_ & 0xFF;
        }
        if (carry_ && res_max_bytes - i - j != 0) {
            ret_ = long_number_plus(res, res_max_bytes - i - j, (uint8_t *)&carry_, 1);
        } else if (carry_) {
            ret_ = true;
        }
    }
    return ret_;
}

static inline void long_number_negiv_(uint8_t *a, size_t a_bytes) {
    uint16_t carry_ = 0;
    for (size_t i = 0; i < a_bytes; a++, carry_ >>= 8) {
        carry_ += a[a_bytes - 1 - i] + 0xFF;
        a[a_bytes - 1 - i] = ~(carry_ & 0x07);
    }
}
void long_number_negiv(uint8_t *a, size_t a_bytes) {
    if (a[0] & 0x80 != 0) {
        long_number_negiv_(a, a_bytes);
    } else {
        for (size_t i = 0; i < a_bytes; i++) {
            a[i] = ~a[i];
        }
        uint8_t one_ = 1;
        long_number_plus(a, a_bytes, &one_, 1);
    }
}

bool long_number_dec(uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes) {
    size_t res_= 0, i = 0;
    for (; i < a_bytes && i < b_bytes; i++) {
        size_t a_ = a[a_bytes - 1 - i], b_ = b[b_bytes - 1 - i];
        size_t res__ = res_;
        res_ = 0;
        if (a_ < b_ + res__) {
            a_ += (size_t)0x0100;
            res_ = (size_t)0x0001;
        }
        a_ -= (b_ + res__);
        a[a_bytes - 1 - i] = (a_ & 0xFF);
    }
    if (res_) {
        for (; a[a_bytes - 1 - i] == 0 && i < a_bytes; i++) {
            a[a_bytes - 1 - i] = 0xFF;
        }
        if (a[a_bytes - 1 - i] != 0 && i < a_bytes) {
            a[a_bytes - 1 - i] -= 0x01;
            res_ = 0;
        }
    }
    return res_ != 0;
}

uint8_t long_number_divu8(uint8_t *a, size_t a_bytes, uint8_t div) {
    uint16_t remainder_ = 0;
    for (size_t i = 0; i < a_bytes; i++, remainder_ <<= 8) {
        remainder_ += a[i];
        a[i] = remainder_ / div, remainder_ %= div;
    }
    return (remainder_ >> 8) & 0xFF;
}

static inline bool read_bit(const uint8_t *a, size_t a_bytes, size_t bits) {
    assert(((bits + 0x07) >> 3) <= a_bytes);
    return a[a_bytes - 1 - (bits >> 3)] & ((0x01) << (bits & 0x07));
}
static inline void write_bit(uint8_t *a, size_t a_bytes, size_t bits, bool bit) {
    assert(((bits + 0x07) >> 3) <= a_bytes);
    if (bit) {
        a[a_bytes - 1 - (bits >> 3)] |= ((0x01) << (bits & 0x07));
    } else {
        a[a_bytes - 1 - (bits >> 3)] &= ~((0x01) << (bits & 0x07));
    }
}
// res saves deminate number. returns deminate number bytes
void long_number_div(
    uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes,
    uint8_t *res, size_t res_max_bytes, MEMORY_POOL *pool) {
    ;
    assert(res_max_bytes >= b_bytes && res_max_bytes >= a_bytes);
    // assert(buff_bytes == a_bytes)
    uint8_t *buff = (uint8_t *)mem_pool_alloc(pool, a_bytes);
    // uint8_t* buff = (uint8_t *)calloc(a_bytes, 1);
    if (-1 == long_number_compare(a, a_bytes, b, b_bytes)) {
        memcpy(&res[res_max_bytes - a_bytes], a, a_bytes);
        memset(a, 0, a_bytes);
        return;
    }
    size_t a_bits = long_number_bitwidth(a, a_bytes);
    for (size_t i = 0; i < a_bits; i++) {
        long_number_left_shift(buff, a_bytes, 1);
        if (read_bit(a, a_bytes, a_bits - 1 - i)) {
            buff[a_bytes - 1] |= 0x01;
        }
        if (-1 != long_number_compare(buff, a_bytes, b, b_bytes)) {
            assert(!long_number_dec(buff, a_bytes, b, b_bytes));
            write_bit(res, res_max_bytes, a_bits - 1 - i, true);
        }
    }
    memcpy(a, &res[res_max_bytes - a_bytes], a_bytes);
    memset(res, 0, res_max_bytes);
    memcpy(&res[res_max_bytes - a_bytes], buff, a_bytes);
    mem_pool_free(pool, a_bytes);
    // free(buff);
}

// bits is low bits to save.
void long_number_mod_2pow(uint8_t *a, size_t a_bytes, size_t bits) {
    size_t bytes = (bits + 0x07) >> 3;
    if ((bits & 0x07) != 0) {
        assert(a_bytes >= bytes + 1);
        memset(a, 0, a_bytes - bytes - 1);
    } else {
        assert(a_bytes >= bytes);
        memset(a, 0, a_bytes - bytes);
        return;
    }
    uint8_t bitmask = 0;
    for (size_t i = 0; i < (bits & 0x07); i++) {
        bitmask |= (0x01 << i);
    }
    a[a_bytes - bytes] &= bitmask;
}

size_t long_number_gcd(
    const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes,
    uint8_t *res, size_t res_max_bytes) {
    ;
    // unused function.
    // dependce long_number_div
    return size_t();
}

// returns 2^{power} mod 'mod', buff_bytes atleast is double bigger than mod_bytes
void long_number_exp_mod(
    size_t power, const uint8_t *mod, size_t mod_bytes,
    uint8_t *res, size_t res_max_bytes, MEMORY_POOL *pool) {
    ;
    memset(res, 0, res_max_bytes);
    size_t mod_bits = long_number_bitwidth(mod, mod_bytes);
    assert(res_max_bytes >= mod_bytes && mod_bits != 0);
    res[res_max_bytes - 1 - (power >> 3)] = 0x01 << (power & 0x07);
    if (mod_bits > power + 1) {
        return;
    } else if (mod_bits == power + 1) {
        size_t mod_byte_ = (mod_bits >> 3);
        if (mod[mod_bytes - 1 - mod_byte_] == ((0x01) << (mod_bits & 0x07))) {
            for (size_t i = 0; i < mod_byte_; i++) {
                if (mod[mod_bytes - 1 - i] != 0) {
                    return;
                }
            }
        } else {
            return;
        }
    } // else mod_bits <= power.
    res[res_max_bytes - 1 - (mod_bits >> 3)] = 0x01 << (mod_bits & 0x07);
    do {
        long_number_dec(res, res_max_bytes, mod, mod_bytes);
    } while (long_number_compare(res, res_max_bytes, mod, mod_bytes) != -1);
    if (long_number_is_zero(res, res_max_bytes - 1)
        && (res[res_max_bytes - 1] == 0x01
            || res[res_max_bytes - 1] == 0x00)) {
        return;
    }
    if (mod_bits != power) {
        // assert(buff_bytes >= 2 * ((power + 1 + 0x07) >> 3) && buff_bytes >= res_max_bytes);
        size_t buff_bytes = ((power + 1 + 0x07) >> 3) + res_max_bytes;
        uint8_t *buff = (uint8_t *)mem_pool_alloc(pool, 2 * buff_bytes);
        memset(buff, 0, buff_bytes);
        memcpy(&buff[buff_bytes - res_max_bytes], res, res_max_bytes);
        long_number_left_shift(buff, buff_bytes, power - mod_bits - 1);
        long_number_div(buff, buff_bytes, mod, mod_bytes, &buff[buff_bytes], buff_bytes, pool);
        memset(res, 0, res_max_bytes); // logic is compliex, might error here.
        memcpy(res, &buff[2 * buff_bytes - res_max_bytes], res_max_bytes);
        mem_pool_free(pool, 2 * buff_bytes);
    }
}

void long_number_debug_print(const uint8_t *a, size_t a_bytes) {
    size_t buff_size = 2 * a_bytes;
    uint8_t *buff = (uint8_t *)calloc(buff_size, 1);
    memcpy(buff, a, a_bytes);
    size_t j = 0;
    while (true) {
        if (buff_size - a_bytes == j) {
            buff = (uint8_t *)realloc(buff, buff_size + a_bytes);
            buff_size += a_bytes;
        }
        buff[a_bytes + j] = long_number_divu8(buff, a_bytes, 10);
        if (long_number_is_zero(buff, a_bytes)) {
            break;
        }
        j++;
    }
    for (size_t i = 0; i <= j; i++) {
        printf("%c", '0' + buff[a_bytes + j - i]);
    }
    printf("\n");
    free(buff);
}
void long_number_debug_print_hex(const uint8_t *a, size_t a_bytes) {
    size_t i = 0;
    for (; a[i] == 0 && i < a_bytes; i++) {
        ;
    }
    for (; i < a_bytes; i++) {
        printf("%02x", a[i]);
    }
    printf("\n");
}
size_t long_number_debug_input(uint8_t **res, const char *str) {
    size_t str_len = strlen(str);
    size_t buff_size = str_len, res_size = str_len;
    uint8_t *buff = (uint8_t *)calloc(str_len, 1), *buff1 = (uint8_t *)calloc(str_len, 1);
    uint8_t *res_ = (uint8_t *)calloc(str_len, 1), mul_base = 10;
    buff[buff_size - 1] = 0x01;
    for (size_t i = 0; i < str_len; i++) {
        uint8_t num_val = str[str_len - 1 - i] - '0'; // number_val
        assert(!long_number_mul(buff, buff_size, &num_val, 1, buff1, buff_size));
        if (buff1[0] != 0) {
            long_number_extend(&buff, buff_size, buff_size + str_len);
            long_number_extend(&buff1, buff_size, buff_size + str_len);
            buff_size += str_len;
        }
        assert(long_number_plus(res_, res_size, buff1, buff_size));
        if (res_[0] != 0) {
            long_number_extend(&res_, res_size, res_size + str_len);
            res_size += str_len;
        }

        memset(buff1, 0, buff_size);
        assert(!long_number_mul(buff, buff_size, &mul_base, 1, buff1, buff_size));
        if (buff1[0] != 0) {
            long_number_extend(&buff, buff_size, buff_size + str_len);
            long_number_extend(&buff1, buff_size, buff_size + str_len);
            buff_size += str_len;
        }
        memset(buff, 0, buff_size);
        swap_u64(&buff, &buff1);
    }
    free(buff), free(buff1);
    res[0] = res_;
    return res_size;
}
static inline uint8_t read_u8_from_str2(const char *str) {
    char tmp_str[3] = {str[0], str[1], '\0'};
    char *end = NULL;
    long value = strtol(tmp_str, &end, 16);
    assert(end[0] == '\0');
    return (uint8_t)value;
}
size_t long_number_debug_input_hex(uint8_t **res, const char *str) {
    size_t res_length = strlen(str);
    uint8_t *res_buff = (uint8_t *)calloc((res_length + 1) / 2, 1);
    if (res_length & 0x01 != 0) {
        char tmp_str[2] = {'0', str[0]};
        res_buff[0] = read_u8_from_str2(tmp_str);
        for (size_t i = 1; i < (res_length + 1) / 2; i++) {
            res_buff[i] = read_u8_from_str2(&str[(i - 1) * 2 + 1]);
        }
    } else {
        for (size_t i = 0; i < res_length / 2; i++) {
            res_buff[i] = read_u8_from_str2(&str[i * 2]);
        }
    }
    res[0] = res_buff;
    return (res_length + 1) / 2;
}

MG_CONTEXT *MG_ctx_init(const uint8_t *N, size_t N_bytes) {
    MG_CONTEXT *ret = (MG_CONTEXT *)calloc(sizeof(MG_CONTEXT), 1);
    ret->N = N;
    ret->N_prime = (uint8_t *)calloc(N_bytes, 1);
    ret->mg_const = (uint8_t *)calloc(N_bytes, 1);
    ret->N_bytes = N_bytes;
    ret->R_bits = long_number_bitwidth(N, N_bytes);

    ret->pool = (MEMORY_POOL*)calloc(sizeof(MEMORY_POOL), 1);
    ret->pool->max_size = N_bytes + 1;
    if (N_bytes >= ((ret->R_bits + 0x07) >> 3)) {
        ret->pool->max_size += N_bytes;
    } else {
        ret->pool->max_size += ((ret->R_bits + 0x07) >> 3);
    }
    // ret->pool->max_size *= 4; // if use pool in rsa_init. it must larger.
    ret->pool->max_size *= 8;
    create_mem_pool(ret->pool);

    // do it on RSA_init,
    // RSA_get_prime_N(N, N_bytes, ret->R_bits, ret->N_prime, N_bytes);
    return ret;
}

void MG_ctx_delete(MG_CONTEXT *ctx) {
    free(ctx->N_prime);
    free(ctx->mg_const);
    del_mem_pool(ctx->pool);
    free(ctx->pool);
    free(ctx);
}

// if x is true, means long_number_xx overflows.
#define CHECH_RET(x) \
    if ((x)) { return false; }

bool MG_mul(
    MG_CONTEXT *ctx, const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes,
    uint8_t *res, size_t res_max_bytes) {
    ;
    const uint8_t *N = ctx->N;
    size_t buff_bytes = ctx->N_bytes + 1, N_bytes = ctx->N_bytes;
    assert(res_max_bytes == N_bytes);
    assert(a_bytes <= N_bytes && b_bytes <= N_bytes);
    // assert(buff_size >= a_bytes + b_bytes
    //        && buff_size >= N_bytes + ((ctx->R_bits + 0x07) >> 3));
    if (N_bytes < ((ctx->R_bits + 0x07) >> 3)) {
        buff_bytes += ((ctx->R_bits + 0x07) >> 3);
    } else {
        buff_bytes += N_bytes;
    }
    uint8_t *buff = (uint8_t *)mem_pool_alloc(ctx->pool, buff_bytes);
    uint8_t *buff1 = (uint8_t *)mem_pool_alloc(ctx->pool, buff_bytes);
    uint8_t *buff2 = (uint8_t *)mem_pool_alloc(ctx->pool, buff_bytes);

    // buff2 is T = a * b
    // buff1 is m = ((T mod R) N_prime) mod R
    CHECH_RET(long_number_mul(a, a_bytes, b, b_bytes, buff, buff_bytes));                   // T
    memcpy(buff2, buff, buff_bytes);                                                        // save T, use it after.
    long_number_mod_2pow(buff, buff_bytes, ctx->R_bits);                                    // T mod R
    CHECH_RET(long_number_mul(buff, buff_bytes, ctx->N_prime, N_bytes, buff1, buff_bytes)); // (T mod R) N_prime
    long_number_mod_2pow(buff1, buff_bytes, ctx->R_bits);                                   // ((T mod R) N_prime) mod R

    // buff is t = (T + m * N) / R
    memset(buff, 0, buff_bytes);
    CHECH_RET(long_number_mul(buff1, buff_bytes, N, N_bytes, buff, buff_bytes)); // m * N
    CHECH_RET(long_number_plus(buff, buff_bytes, buff2, buff_bytes));            // T + m * N
    long_number_right_shift(buff, buff_bytes, ctx->R_bits);                      // (T + m * N) / R

    // if !(t < N)
    if (-1 != long_number_compare(buff, buff_bytes, N, N_bytes)) {
        memset(buff1, 0, buff_bytes);
        long_number_dec(buff, buff_bytes, N, N_bytes);
    }
    memcpy(res, &buff[buff_bytes - N_bytes], N_bytes);
    mem_pool_free(ctx->pool, buff_bytes);
    mem_pool_free(ctx->pool, buff_bytes);
    mem_pool_free(ctx->pool, buff_bytes);
    return true;
}