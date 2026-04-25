#include "tls_algorithm.h"

void long_number_plus(
    const uint8_t *a, size_t a_bytes,
    const uint8_t *b, size_t b_bytes,
    uint8_t *res, size_t res_max_bytes) {
    ;
    uint8_t p_buff = NULL;
    size_t buff_size = 0;
    if (a_bytes + 1 > res_max_bytes
        || b_bytes + 1 > res_max_bytes) {
        return;
    }
    
}

// returns (m^e) mod n
void long_number_mod_exp(
    const uint8_t *m, size_t m_bytes,
    size_t e,
    size_t n, size_t n_bytes) {
    ;
}