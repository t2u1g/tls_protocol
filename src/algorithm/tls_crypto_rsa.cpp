#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "tls_algorithm.h"

// alloc N_bytes mem from pool.
void RSA_get_prime_N(
    const uint8_t *N, size_t N_bytes, size_t N_bits,
    uint8_t *res, size_t res_max_bytes, MEMORY_POOL *pool) {
    ;
    assert(N_bytes <= res_max_bytes);
    uint8_t *buff = (uint8_t *)mem_pool_alloc(pool, N_bytes);
    buff[N_bytes - 1] = 0x01;
    for (size_t i = 1; i < N_bits; i++) {
        size_t cur_byte = (i + 1 + 0x07) >> 3;
        long_number_mul(&N[N_bytes - cur_byte], cur_byte, &buff[N_bytes - cur_byte],
                        cur_byte, res, res_max_bytes);
        uint8_t val = res[res_max_bytes - cur_byte];
        memset(res, 0, res_max_bytes);
        if (val & (0x01 << (i & 0x07))) {
            continue;
        }
        buff[N_bytes - cur_byte] |= (0x01 << (i & 0x07));
    }
    memcpy(&res[res_max_bytes - N_bytes], buff, N_bytes);
    mem_pool_free(pool, N_bytes);
}

static inline void safe_copy_lowbytes(
    uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes, size_t bytes) {
    ;
    if (bytes == 0 || bytes & ((size_t)0x01 << 63)) {
        return;
    } // if bytes is too large, then ensure is an error arg.
    size_t bytes_ = a_bytes > b_bytes ? b_bytes : a_bytes;
    bytes_ = bytes_ > bytes ? bytes : bytes_;
    memcpy(&a[a_bytes - bytes_], &b[b_bytes - bytes_], bytes_);
}

// get an converstion factor "R^{2} mod N."
// alloc 3 * ((2 * N_bits + 1 + 0x07) >> 3) + N_bytes mem from pool.
void RSA_get_MG_conv_const(
    const uint8_t *N, size_t N_bytes, size_t N_bits,
    uint8_t *res, size_t res_max_size, MEMORY_POOL *pool) {
    ;
    assert(res_max_size >= N_bytes);
    size_t R_bytes = ((2 * N_bits + 1 + 0x07) >> 3);
    uint8_t *buff = (uint8_t *)mem_pool_alloc(pool, R_bytes);
    uint8_t *buff1 = (uint8_t *)mem_pool_alloc(pool, R_bytes);
    buff[R_bytes - 1] = 0x01;
    long_number_left_shift(buff, R_bytes, 2 * N_bits);
    long_number_div(buff, R_bytes, N, N_bytes, buff1, R_bytes, pool);
    assert(
        long_number_is_zero(buff1, R_bytes - N_bytes));
    safe_copy_lowbytes(res, res_max_size, buff1, R_bytes, R_bytes);
    mem_pool_free(pool, R_bytes);
    mem_pool_free(pool, R_bytes);
}

MG_CONTEXT *RSA_MG_ctx_init(const uint8_t *N, size_t N_bytes) {
    MG_CONTEXT *ret = MG_ctx_init(N, N_bytes);
    RSA_get_prime_N(ret->N, ret->N_bytes, ret->R_bits, ret->N_prime,
                    ret->N_bytes, ret->pool);
    RSA_get_MG_conv_const(ret->N, ret->N_bytes, ret->R_bits, ret->mg_const,
                          ret->N_bytes, ret->pool);
    return ret;
}

void RSA_MG_ctx_delete(MG_CONTEXT *ctx) {
    MG_ctx_delete(ctx);
}

static inline void swap_u64(void *a, void *b) {
    uint64_t tmp_ = ((uint64_t *)a)[0];
    ((uint64_t *)a)[0] = ((uint64_t *)b)[0];
    ((uint64_t *)b)[0] = tmp_;
}

#include <stdio.h>
static inline void RSA_exp_mod_debug_check(
    MG_CONTEXT *ctx, const uint8_t *msg, size_t msg_bytes,
    const uint8_t *mg_mul_res, size_t res_max_bytes) {
    ;
    MEMORY_POOL pool;
    pool.max_size = (msg_bytes + ctx->N_bytes + 1) * 4;
    create_mem_pool(&pool);
    uint8_t *buff = (uint8_t *)mem_pool_alloc(&pool, ctx->N_bytes + 1);
    buff[ctx->N_bytes] = 0x01;
    long_number_left_shift(buff, ctx->N_bytes + 1, ctx->R_bits);
    uint8_t *buff1 = (uint8_t *)mem_pool_alloc(&pool, msg_bytes + ctx->N_bytes + 1);
    long_number_mul(buff, ctx->N_bytes + 1, msg, msg_bytes, buff1, msg_bytes + ctx->N_bytes + 1);
    uint8_t *buff2 = (uint8_t *)mem_pool_alloc(&pool, msg_bytes + ctx->N_bytes + 1);
    long_number_div(buff1, msg_bytes + ctx->N_bytes + 1, ctx->N, ctx->N_bytes, buff2,
                    msg_bytes + ctx->N_bytes + 1, &pool);
    int cmp_ = long_number_compare(buff2, msg_bytes + ctx->N_bytes + 1,
                                   mg_mul_res, res_max_bytes); // msg * R mod N result
    printf("cmp_ success: %s\n", (cmp_ == 0 ? "success" : "failed"));
    del_mem_pool(&pool);
}

// N in ctx, e is power in algorithm.
void RSA_exp_mod(
    const uint8_t *msg, size_t msg_bytes, size_t e,
    uint8_t *res, size_t res_max_bytes, MG_CONTEXT *ctx) {
    ;
    size_t N_bytes = ctx->N_bytes;
    assert(e != 0 && (e & 0x01) != 0); // if e == 0, make sure it is error param.
    assert(res_max_bytes == N_bytes && msg_bytes <= N_bytes);
    uint8_t *buff_ = (uint8_t *)mem_pool_alloc(ctx->pool, 2 * N_bytes);
    uint8_t *buff = buff_, *buff1 = &buff_[N_bytes], *buff2 = res;

    assert(MG_mul(ctx, msg, msg_bytes, ctx->mg_const, N_bytes, buff, N_bytes));
    RSA_exp_mod_debug_check(ctx, msg, msg_bytes, buff, N_bytes);
    memcpy(buff2, buff, N_bytes);
    memset(buff1, 0, N_bytes);

    size_t e_bits = 63;
    for (size_t i = 0; (e & ((size_t)0x01 << e_bits)) == 0
                       && i < 63;
         e_bits--, i++) {
        ; // get bitwidth.
    }
    for (size_t i = 1; i < e_bits + 1; i++) {
        assert(MG_mul(ctx, buff, N_bytes, buff, N_bytes, buff1, N_bytes));
        memset(buff, 0, N_bytes);
        swap_u64(&buff, &buff1);
        if ((e & ((size_t)0x01 << i)) == 0) {
            continue;
        }
        assert(MG_mul(ctx, buff, N_bytes, buff2, N_bytes, buff1, N_bytes));
        memset(buff2, 0, N_bytes);
        swap_u64(&buff1, &buff2);
    }
    uint8_t one_ = 1;
    assert(MG_mul(ctx, buff2, N_bytes, &one_, 1, buff1, N_bytes));
    swap_u64(&buff1, &buff2);
    if (buff2 != res) {
        memcpy(res, buff2, N_bytes);
    }
    mem_pool_free(ctx->pool, 2 * N_bytes); // free buff_.
}