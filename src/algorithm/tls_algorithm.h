#ifndef __TLS_ALGORITHM_H__
#define __TLS_ALGORITHM_H__

#include <stdint.h>

size_t hash_null_func(const void *p_data, size_t length, void *p_ret);
size_t sha1_calculate(const void *p_data, size_t length, void *p_ret);
size_t sha256_calculate(const void *p_data, size_t length, void *p_ret);

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

uint8_t *str_cat_(const void *str1, size_t l1, const void *str2, size_t l2, void *buffer);

size_t tls_hmac(HashAlgorithm type, const void *key, size_t key_length,
                const void *p_data, size_t data_length, void *p_ret);

void tls_prf(HashAlgorithm type, const void *secret, size_t secret_length,
             const void *label, size_t label_length, const void *seed, size_t seed_length,
             void *p_res, size_t res_length);

void tls_aes_128_CBC_encrypto(const void *key, const void *iv, void *p_data, size_t data_length);
void tls_aes_128_CBC_decrypto(const void *key, const void *iv, void *p_data, size_t data_length);

void tls_aes_128_GCM_encrypto(const void *key, const void *nonce,
                              const void *auth, size_t auth_length, void *p_data, size_t data_length,
                              void *auth_tag);
                              
size_t tls_aes_128_GCM_decrypto(const void *key, const void *nonce,
                                const void *auth, size_t auth_length, void *p_data, size_t data_length,
                                const void *auth_tag);

// certification defines and consts.
// cert ASN.1 language support:
enum ASN_FRAG_TYPE : uint8_t {
    ASN_RESERVE = 0x00,
    ASN_INTEGER = 0x02,
    ASN_BITSTRING = 0x03,
    ASN_OBJECT_IDENTIFIER = 0x06,
    ASN_SEQUENCE = 0x10,
};
enum ASN_FRAG_TAG_TYPE : uint8_t {
    ASN_Universal = 0x00,
    ASN_Application = 0x40,
    ASN_Context = 0x80,
    ASN_Private = 0xC0
};

struct ASN_FRAG_TAG {
    ASN_FRAG_TAG_TYPE tag_type;
    uint8_t tag_number;
    bool is_constru;
};
struct ASN_FRAG {
    ASN_FRAG_TAG tag;
    ASN_FRAG_TYPE type;
    size_t length;
    const uint8_t *p_frag_data;
};

// cert support
struct CERT_UNPACK {
    ASN_FRAG tbs_sign_alg;
    ASN_FRAG issuer;
    ASN_FRAG valid;
    ASN_FRAG subject;
    ASN_FRAG pub_key_info;
    ASN_FRAG extens;
    ASN_FRAG sign_val;
};

struct ASN_OID {
    uint32_t oid_val[16];
    size_t oid_num;
};
const ASN_OID sha1WithRSAEncryption{
    {1, 2, 840, 113549, 1, 1, 5},
    7};
const ASN_OID sha256WithRSAEncryption{
    {1, 2, 840, 113549, 1, 1, 11},
    7};
const ASN_OID rsaEncryption{
    {1, 2, 840, 113549, 1, 1, 1},
    7};

size_t long_number_bitwidth(const uint8_t *N, size_t N_bytes);
bool long_number_is_zero(const uint8_t *a, size_t a_bytes);
int long_number_compare(
    const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes);
bool long_number_left_shift(uint8_t *a, size_t a_bytes, size_t shift_bits);
void long_number_right_shift(uint8_t *a, size_t a_bytes, size_t shift_bits);
bool long_number_plus(uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes);
bool long_number_mul(
    const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes,
    uint8_t *res, size_t res_max_bytes);
void long_number_negiv(uint8_t *a, size_t a_bytes);
bool long_number_dec(uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes, uint8_t *buff);
uint8_t long_number_divu8(uint8_t *a, size_t a_bytes, uint8_t div);

void long_number_debug_print(const uint8_t *a, size_t a_bytes);
void long_number_debug_print_hex(const uint8_t *a, size_t a_bytes);
size_t long_number_debug_input(uint8_t **res, const char *str);
size_t long_number_debug_input_hex(uint8_t **res, const char* str);

void RSA_get_prime_N(const uint8_t *N, size_t N_bytes, size_t R_bits,
                     uint8_t *res, size_t res_max_bytes);

#endif