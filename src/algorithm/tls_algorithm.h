#ifndef __TLS_ALGORITHM_H__
#define __TLS_ALGORITHM_H__

#include <stdint.h>

size_t hash_null_func(
    const void *p_data, size_t length, 
    void *p_ret);
size_t sha1_calculate(
    const void *p_data, size_t length, 
    void *p_ret);
size_t sha256_calculate(
    const void *p_data, size_t length, 
    void *p_ret);

// hash algorithm arguments.
typedef size_t (*pf_hash)(const void *, size_t, void *);

enum HashAlgorithm {
    Hash_null,
    Hash_md5,
    Hash_sha1,
    Hash_sha224,
    Hash_sha256,
    Hash_sha384,
    Hash_sha512
}; // hash algorithm header implemention.
const size_t HashBlockSizeTable[7] = {
    0, 64, 64, 64, 64, 128, 128};
const size_t HashResultSizeTable[7] = {
    0, 16, 20, 28, 32, 48, 64};
const pf_hash HashFnucTable[7] = {
    hash_null_func,
    hash_null_func, // md5
    sha1_calculate,
    hash_null_func, // sha 224
    sha256_calculate,
    hash_null_func, // sha 384
    hash_null_func  // sha 256
};

uint8_t *str_cat_(
    const void *str1, size_t l1, 
    const void *str2, size_t l2, 
    void *buffer);
size_t tls_hmac(
    HashAlgorithm type, 
    const void *key, size_t key_length,
    const void *p_data, size_t data_length, 
    void *p_ret);
void tls_prf(
    HashAlgorithm type, 
    const void *secret, size_t secret_length,
    const void *label, size_t label_length, 
    const void *seed, size_t seed_length,
    void *p_res, size_t res_length);


void tls_aes_128_CBC_encrypto(
    const void *key, const void *iv, 
    void *p_data, size_t data_length);
void tls_aes_128_CBC_decrypto(
    const void *key, const void *iv, 
    void *p_data, size_t data_length);

void tls_aes_128_GCM_encrypto(
    const void *key, const void *nonce,
    const void *auth, size_t auth_length,
    void *p_data, size_t data_length, 
    void *auth_tag);
size_t tls_aes_128_GCM_decrypto(
    const void *key, const void *nonce,
    const void *auth, size_t auth_length,
    void *p_data, size_t data_length, 
    const void *auth_tag);

// certification defines and consts.


#endif