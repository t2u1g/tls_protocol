#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "tls_algorithm.h"

int long_number_compare(
    const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes) {
    ;
    size_t ne_bytes = 0;
    for (; ne_bytes < a_bytes && ne_bytes < b_bytes; ne_bytes++) {
        uint8_t a_ = a[a_bytes - 1 - ne_bytes];
        uint8_t b_ = b[b_bytes - 1 - ne_bytes];
        if (a_ != b_) {
            return a_ > b_ ? 1 : -1;
        }
    }
    if (ne_bytes == a_bytes) {
        for (; ne_bytes < b_bytes; ne_bytes++) {
            if (b[b_bytes - 1 - ne_bytes] != 0) {
                return -1;
            }
        }
    } else {
        for (; ne_bytes < a_bytes; ne_bytes++) {
            if (a[a_bytes - 1 - ne_bytes] != 0) {
                return 1;
            }
        }
    }
    return 0;
}

bool long_number_left_shift(uint8_t *a, size_t a_bytes, size_t shift_bits) {
    size_t shift_bytes = shift_bits >> 3; // throws away bytes.
    assert((shift_bits + 0x07) >> 3 <= a_bytes);
    a[0] = a[shift_bytes] << (shift_bits & 0x07);
    bool ret_ = a[shift_bytes] >> (8 - (shift_bits & 0x07));
    for (size_t i = 1; i < a_bytes - shift_bytes; i++) {
        a[i] = a[shift_bytes + i] << (shift_bits & 0x07);
        a[i - 1] |= a[shift_bytes + i] >> (8 - (shift_bytes & 0x07));
    }
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
    return true;
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
               && res_max_bytes - i - j == 0;
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
        a[a_bytes - 1 - i] = carry_ & 0x07;
    }
}
void long_number_negiv(uint8_t *a, size_t a_bytes) {
    if (a[0] & 0x80 != 0) {
        long_number_negiv_(a, a_bytes);
        for (size_t i = 0; i < a_bytes; i++) {
            a[i] = ~a[i];
        }
    } else {
        for (size_t i = 0; i < a_bytes; i++) {
            a[i] = ~a[i];
        }
        uint8_t one_ = 1;
        long_number_plus(a, a_bytes, &one_, 1);
    }
}

bool long_number_dec(uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes, uint8_t *buff) {
    // uint8_t *buff = (uint8_t *)calloc(b_bytes, 1);
    // assert(buff_size == b_bytes)
    memcpy(buff, b, b_bytes);
    long_number_negiv(buff, b_bytes);
    return long_number_plus(a, a_bytes, buff, b_bytes);
}

size_t long_number_divu8(uint8_t *a, size_t a_bytes, uint8_t div, uint8_t *rem_res) {
    uint16_t remainder_ = 0;
    size_t j = 0;
    for (size_t i = 0; i < a_bytes; i++, remainder_ <<= 8) {
        remainder_ += a[i];
        a[i] = remainder_ / div, remainder_ %= div;
        rem_res && (rem_res[j++] = (remainder_ & 0xFF));
    }
    return rem_res ? j : (remainder_ >> 8);
}

// bits is low bits to save.
void long_number_mod_2pow(uint8_t *a, size_t a_bytes, size_t bits) {
    size_t bytes = (bits + 0x07) >> 3;
    memset(a, 0, a_bytes - bytes);
    uint8_t bitmask = 0;
    for (size_t i = 0; i < (bits & 0x07); i++) {
        bitmask |= (0x01 << i);
    }
    a[a_bytes - bytes] &= ~bitmask;
}

size_t long_number_gcd(
    const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes,
    uint8_t *res, size_t res_max_bytes) {
    ;
    // unused function.
    // dependce long_number_div
    return size_t();
}

struct MG_ctx {
    const uint8_t *N;
    uint8_t *N_prime;
    size_t N_bytes, R_bits;

    uint8_t *buff, *buff1, *buff2;
    size_t buff_size;
};

MG_ctx* MG_ctx_init(const uint8_t *N, size_t N_bytes, size_t reserved) {
    MG_ctx *ret = (MG_ctx*)calloc(sizeof(MG_ctx), 1);
    ret->buff = (uint8_t*)calloc(N_bytes + 1, 1);
    ret->buff1 = (uint8_t*)calloc(N_bytes + 1, 1);
    ret->buff2 = (uint8_t*)calloc(N_bytes + 1, 1);
    ret->N_prime = (uint8_t*)calloc(N_bytes, 1);
    ret->buff_size = N_bytes + 1;

    ret->R_bits = RSA_get_R(N, N_bytes);
    ret->N_bytes = N_bytes;
    assert(ret->R_bits != 0);
    ret->N = N;
    RSA_get_prime_N(N, N_bytes, ret->R_bits, ret->N_prime, N_bytes);
    return ret;
}

void MG_ctx_delete(MG_ctx *ctx) {
    free(ctx->buff), free(ctx->buff1), free(ctx->buff2);
    free(ctx->N_prime);
    free(ctx);
}

// if x is true, means long_number_xx overflows.
#define CHECH_RET(x) \
    if ((x)) { return false; }

bool MG_plus(
    MG_ctx *p_ctx, const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes,
    uint8_t *res, size_t res_max_bytes) {
    ;
    uint8_t *buff = p_ctx->buff, *buff1 = p_ctx->buff1, *buff2 = p_ctx->buff2;
    const uint8_t *N = p_ctx->N;
    size_t buff_size = p_ctx->buff_size, N_bytes = p_ctx->N_bytes;
    // assert(buff_size >= a_bytes + b_bytes // do it on ctx's constructor func.
    //        && buff_size >= N_bytes + ((p_ctx->R_bits + 0x07) >> 3));
    assert(res_max_bytes >= N_bytes);
    assert(a_bytes <= N_bytes && b_bytes <= N_bytes);
    memset(buff, 0, buff_size), memset(buff1, 0, buff_size);
    memset(buff2, 0, buff_size);

    // buff2 is T = a * b
    // buff1 is m = ((T mod R) N_prime) mod R
    CHECH_RET(long_number_mul(a, a_bytes, b, b_bytes, buff, buff_size));                    // T
    memcpy(buff2, buff, buff_size);                                                         // save T, use it after.
    long_number_mod_2pow(buff, buff_size, p_ctx->R_bits);                                   // T mod R
    CHECH_RET(long_number_mul(buff, buff_size, p_ctx->N_prime, N_bytes, buff1, buff_size)); // (T mod R) N_prime
    long_number_mod_2pow(buff1, buff_size, p_ctx->R_bits);                                  // ((T mod R) N_prime) mod R

    // buff is t = (T + m * N) / R
    memset(buff, 0, buff_size);
    CHECH_RET(long_number_mul(buff1, buff_size, N, N_bytes, buff, buff_size)); // m * N
    CHECH_RET(long_number_plus(buff, buff_size, buff2, buff_size));            // T + m * N
    long_number_right_shift(buff, buff_size, p_ctx->R_bits);                   // (T + m * N) / R

    // if !(t < N)
    if (-1 != long_number_compare(buff, buff_size, N, N_bytes)) {
        assert(buff_size >= N_bytes);
        memset(buff1, 0, buff_size);
        long_number_dec(buff, buff_size, N, N_bytes, buff1);
    }
    memcpy(res, &buff[buff_size - N_bytes], N_bytes);
    return true;
}

// returns R's bits of left_shift
size_t RSA_get_R(const uint8_t *N, size_t N_bytes) {
    for (size_t i = 0; i < N_bytes; i++) {
        if (N[i] != 0) {
            // N_bytes - i - 1; // bytes total
            if (N[i] & 0x80 != 0) {
                return (N_bytes - i) * 8;
            }
            for (size_t j = 1; j < 8; j++) {
                if ((N[i] & 0x80) >> j != 0) {
                    return (N_bytes - i - 1) * 8 + (8 - j);
                }
            }
        }
    }
    return 0;
}

// returns N_prime N === -1 mod R., R_bits is left_shift bits for R.
void RSA_get_prime_N(
    const uint8_t *N, size_t N_bytes, size_t R_bits,
    uint8_t *res, size_t res_max_bytes) {
    ;
    size_t R_bytes = (R_bits + 0x07) >> 3;
    assert(R_bytes <= res_max_bytes && N_bytes <= R_bytes);
    uint8_t *buff = (uint8_t *)calloc(N_bytes, 1);
    buff[N_bytes - 1] = 0x01;
    for (size_t i = 1; i < R_bits; i++) {
        size_t cur_byte = i + 0x07 >> 3;
        long_number_mul(&N[N_bytes - cur_byte], cur_byte, &buff[N_bytes - cur_byte],
                        cur_byte, res, res_max_bytes);
        if (res[res_max_bytes - cur_byte] & (0x01 << (i & 0x07))) {
            continue;
        }
        buff[N_bytes - cur_byte] |= (0x01 << (i & 0x07));
    }
    memcpy(&res[res_max_bytes - N_bytes], buff, N_bytes);
}

// N in ctx, e is power in algorithm.
bool RSA_exp_mod(
    const uint8_t *msg, size_t msg_bytes, MG_ctx *ctx, size_t e, 
    uint8_t *res, size_t res_max_bytes) {
    ;
    assert(res_max_bytes >= ctx->N_bytes && msg_bytes <= ctx->N_bytes);
    uint8_t *buff = (uint8_t *)calloc(ctx->N_bytes, 1);

}