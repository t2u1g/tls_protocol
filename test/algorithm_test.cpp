#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "./../src/algorithm/tls_algorithm.h"
#include "./../src/tools/tools.h"

void test_print_res(const void *p_arr, size_t length) {
    const uint8_t *tp_arr = (const uint8_t *)p_arr;
    for (size_t i = 0; i < length; i++) {
        printf("%02X", tp_arr[i]);
    }
    putc('\n', stdout);
}

void sha_test(const char *str) {
    uint8_t sha1_arr[20] = {0};
    size_t ret = sha1_calculate(str, strlen(str), sha1_arr);
    printf("sha1: ");
    test_print_res(sha1_arr, ret);

    uint8_t sha256_arr[32] = {0};
    ret = sha256_calculate(str, strlen(str), sha256_arr);
    printf("sha256: ");
    test_print_res(sha256_arr, ret);
}

void aes_test(const char *str1, const char *str2) {
    // AES-128 algorithm test.
    uint8_t aes_128_arr[16] = {0};
    // aes_128_encrypto((const uint8_t*)str1, (const uint8_t*)str2, aes_128_arr);
    printf("aes_128 encrypto: ");
    test_print_res(aes_128_arr, 16);
    
    uint8_t aes_128_decrypto_arr[16] = {0};
    // aes_128_decrypto(aes_128_arr, (const uint8_t *)str2, aes_128_decrypto_arr);
    printf("aes_128 decrypto: ");
    test_print_res(aes_128_decrypto_arr, 16);
}

void ghash_test(void) {
    // ghash test
    uint8_t a[] = {
        0xac, 0xbe, 0xf2, 0x05, 
        0x79, 0xb4, 0xb8, 0xeb, 
        0xce, 0x88, 0x9b, 0xac, 
        0x87, 0x32, 0xda, 0xd7};
    uint8_t b[] = {
        0xed, 0x95, 0xf8, 0xe1, 
        0x64, 0xbf, 0x32, 0x13, 
        0xfe, 0xbc, 0x74, 0x0f, 
        0x0b, 0xd9, 0xc4, 0xaf};
    uint8_t res[16] = {0};
    
    // ghash_multiplication(a, b, res);
    test_print_res(res, 16);
}

void long_number_io_test(const char* str) {
    uint8_t *buff = NULL;
    size_t res = long_number_debug_input_hex(&buff, str);
    long_number_debug_print(buff, res);
    long_number_debug_print_hex(buff, res);
}
void long_number_io_test1(const char *str) {
    uint8_t *buff = NULL;
    size_t res = long_number_debug_input(&buff, str);
    long_number_debug_print_hex(buff, res);
}
void long_number_test(const char* str1, const char *str2) {
    uint8_t *buff1 = NULL, *buff2 = NULL;
    size_t res1 = long_number_debug_input_hex(&buff1, str1);
    size_t res2 = long_number_debug_input_hex(&buff2, str2);
    size_t res3 = res1 + res2;
    uint8_t *buff3 = (uint8_t*)calloc(res3, 1);
    memcpy(&buff3[res3 - res1], buff1, res1);
    long_number_plus(buff3, res3, buff2, res2);
    // long_number_debug_print_hex(buff3, res3);
    printf("val1 + val2: ");
    long_number_debug_print(buff3, res3);

    memset(buff3, 0, res3);
    long_number_mul(buff1, res1, buff2, res2, buff3, res3);
    // long_number_debug_print_hex(buff3, res3);
    printf("val1 * val2: ");
    long_number_debug_print(buff3, res3);
    
    uint8_t *buff4 = (uint8_t*)calloc(res1, 1);
    uint8_t *buff5 = (uint8_t*)calloc(res1, 1);
    memset(buff3, 0, res3);
    MEMORY_POOL pool;
    pool.max_size = 2 * res1;
    create_mem_pool(&pool);
    long_number_div(buff1, res1, buff2, res2, buff3, res3, &pool);
    printf("val1 / val2: ");
    long_number_debug_print(buff1, res1);
    printf("val1 %% val2: ");
    long_number_debug_print(buff3, res3);

    free(buff1), free(buff2);
    free(buff3), free(buff4);
    free(buff5);
}

void RSA_prime_test(const char* str1) {
    uint8_t *buff = NULL;
    size_t res1 = long_number_debug_input_hex(&buff, str1);
    printf("input long_number: ");
    long_number_debug_print(buff, res1);
    printf("long_number_bitwdth: %llu\n", long_number_bitwidth(buff, res1));
    uint8_t *prime = (uint8_t*)calloc(res1, 1);
    // RSA_get_prime_N(buff, res1, long_number_bitwidth(buff, res1), prime, res1);
    printf("prime result: ");
    long_number_debug_print(prime, res1);
    uint8_t *prime_mul = (uint8_t*)calloc(res1, 1);
    long_number_mul(prime, res1, buff, res1, prime_mul, res1);
    printf("prime check: ");
    long_number_debug_print_hex(prime_mul, res1);

    free(buff), free(prime), free(prime_mul);
}

void RSA_exp_mod_test(const char *str1, const char *str2, const char *str3) {
    uint8_t *buff = NULL, *buff1 = NULL;
    size_t res = long_number_debug_input_hex(&buff, str1);
    printf("input long_number: ");
    long_number_debug_print(buff, res);
    MG_CONTEXT* ctx = RSA_MG_ctx_init(buff, res);
    char *endp = NULL;
    size_t e = strtoull(str2, &endp, 16);
    printf("input e: %llu\n", e);
    size_t res1 = long_number_debug_input_hex(&buff1, str3);
    printf("input msg: ");
    long_number_debug_print(buff1, res1);
    
    uint8_t *buff2 = (uint8_t*)calloc(ctx->N_bytes, 1);
    RSA_exp_mod(buff1, res1, e, buff2, ctx->N_bytes, ctx);
    printf("RSA_exp_mod result: ");
    long_number_debug_print_hex(buff2, ctx->N_bytes);

    RSA_MG_ctx_delete(ctx);
}

int main(int argc, char **argv) {
    if (argc == 1) {
        return 0;
    }
    // long_number_io_test(argv[1]);
    // long_number_io_test1(argv[1]);
    // long_number_test(argv[1], argv[2]);

    // RSA_prime_test(argv[1]);
    RSA_exp_mod_test(argv[1], argv[2], argv[3]);
    return 0;
}