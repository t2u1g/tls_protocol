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
        // AES-128 algorithm test.
        // uint8_t aes_128_arr[16] = {0};
        // aes_128_encrypto((const uint8_t*)argv[1], (const uint8_t*)argv[2], aes_128_arr);
        // printf("aes_128 encrypto: ");
        // hash_test_print_res(aes_128_arr, 16);

        // uint8_t aes_128_decrypto_arr[16] = {0};
        // aes_128_decrypto(aes_128_arr, (const uint8_t *)argv[2], aes_128_decrypto_arr);
        // printf("aes_128 decrypto: ");
        // hash_test_print_res(aes_128_decrypto_arr, 16);
    }

    // ghash test
    // uint8_t a[] = {0xac, 0xbe, 0xf2, 0x05, 0x79, 0xb4, 0xb8, 0xeb, 0xce, 0x88, 0x9b, 0xac, 0x87, 0x32, 0xda, 0xd7};
    // uint8_t b[] = {0xed, 0x95, 0xf8, 0xe1, 0x64, 0xbf, 0x32, 0x13, 0xfe, 0xbc, 0x74, 0x0f, 0x0b, 0xd9, 0xc4, 0xaf};
    // uint8_t res[16] = {0};

    // ghash_multiplication(a, b, res);
    // hash_test_print_res(res, 16);
    return 0;
}