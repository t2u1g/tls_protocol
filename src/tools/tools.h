#ifndef __TOOLS_H__
#define __TOOLS_H__
#include <stdint.h>


struct MEMORY_POOL
{
    uint8_t *mem;
    size_t max_size, usage;
};

void create_mem_pool(MEMORY_POOL *mp);
void del_mem_pool(MEMORY_POOL *mp);
void* mem_pool_alloc(MEMORY_POOL *mp, size_t size);
void mem_pool_free(MEMORY_POOL *mp, size_t size);

void long_number_extend(uint8_t **a, size_t a_bytes, size_t new_bytes, bool free_tag);
bool long_number_is_zero(const uint8_t *a, size_t a_bytes);
size_t long_number_bitwidth(const uint8_t *a, size_t a_bytes);
int long_number_compare(const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes);
bool long_number_left_shift(uint8_t *a, size_t a_bytes, size_t shift_bits);
void long_number_right_shift(uint8_t *a, size_t a_bytes, size_t shift_bits);
bool long_number_plus(uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes);
bool long_number_mul(const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes, uint8_t *res, size_t res_max_bytes);
void long_number_negiv(uint8_t *a, size_t a_bytes);

bool long_number_dec(uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes);
uint8_t long_number_divu8(uint8_t *a, size_t a_bytes, uint8_t div);
void long_number_div(uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes, uint8_t *res, size_t res_max_bytes, MEMORY_POOL *pool);
void long_number_mod_2pow(uint8_t *a, size_t a_bytes, size_t bits);

// do not use it, it is an bad function. thus it not be test and check fully.
void long_number_exp_mod(size_t power, const uint8_t *mod, size_t mod_bytes, uint8_t *res, size_t res_max_bytes, MEMORY_POOL *pool);

void long_number_debug_print(const uint8_t *a, size_t a_bytes);
void long_number_debug_print_hex(const uint8_t *a, size_t a_bytes);
size_t long_number_debug_input(uint8_t **res, const char *str);
size_t long_number_debug_input_hex(uint8_t **res, const char *str);

struct MG_CONTEXT {
    const uint8_t *N;
    uint8_t *N_prime;
    uint8_t *mg_const;
    size_t N_bytes, R_bits;

    MEMORY_POOL *pool;
};

MG_CONTEXT *MG_ctx_init(const uint8_t *N, size_t N_bytes);
void MG_ctx_delete(MG_CONTEXT *ctx);
bool MG_mul(MG_CONTEXT *p_ctx, const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes, uint8_t *res, size_t res_max_bytes);

#endif