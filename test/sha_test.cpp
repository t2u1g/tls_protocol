#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "./../src/algorithm/tls_algorithm.h"

void hash_test_print_res(const void *p_arr, size_t length) {
    const uint8_t *tp_arr = (const uint8_t*)p_arr;
    for (size_t i = 0; i < length; i++) {
        printf("%02X", tp_arr[i]);
    }
    putc('\n', stdout);
}

int main(int argc, char **argv) {
    if (argc == 1) {
        return 0;
    } else if (argc == 2) {
        uint8_t sha1_arr[20] = {0};
        size_t ret = sha1_calculate(argv[1], strlen(argv[1]), sha1_arr);
        printf("sha1: ");
        hash_test_print_res(sha1_arr, ret);
        
        uint8_t sha256_arr[32] = {0};
        ret = sha256_calculate(argv[1], strlen(argv[1]), sha256_arr);
        printf("sha256: ");
        hash_test_print_res(sha256_arr, ret);
    } else if (argc == 3) {
        uint8_t aes_128_arr[16] = {0};
        aes_128_encrypto((const uint8_t*)argv[1], (const uint8_t*)argv[2], aes_128_arr);
        printf("aes_128 encrypto: ");
        hash_test_print_res(aes_128_arr, 16);

        uint8_t aes_128_decrypto_arr[16] = {0};
        aes_128_decrypto(aes_128_arr, (const uint8_t *)argv[2], aes_128_decrypto_arr);
        printf("aes_128 decrypto: ");
        hash_test_print_res(aes_128_decrypto_arr, 16);
    }
    return 0;
}