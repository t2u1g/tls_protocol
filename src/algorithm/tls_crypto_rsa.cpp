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

bool long_number_right_shift(uint8_t *a, size_t a_bytes, size_t shift_bits) {
    size_t shift_bytes = shift_bits >> 3;
    assert((shift_bits + 0x07) >> 3 <= a_bytes);
    a[a_bytes - 1] = a[a_bytes - 1 - shift_bytes] >> (shift_bits & 0x07);
    bool ret_ = false; // already returns false.
    for (size_t i = 1; i < a_bytes - shift_bytes; i++) {
        a[a_bytes - 1 - i] = a[a_bytes - 1 - shift_bytes - i] >> (shift_bits & 0x07);
        a[a_bytes - i] |= a[a_bytes - 1 - shift_bytes - i] << (8 - (shift_bits & 0x07));
    }
    return ret_;
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

bool long_number_mul(
    const uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes, 
    uint8_t *res, size_t res_max_bytes) {
    ;
    assert(res_max_bytes >= a_bytes + b_bytes);
    if (a_bytes < b_bytes) {
        size_t tmp_ = a_bytes;
        a_bytes = b_bytes, b_bytes = tmp_;
        const uint8_t* tmp__ = a;
        a = b, b = tmp__; // swap a, b
    }
    for (size_t i = 0; i < a_bytes; i++) {
        uint16_t carry_ = 0;
        for (size_t j = 0; j < b_bytes; j++, carry_ >>= 8) {
            carry_ += a[a_bytes - 1 - i] * b[b_bytes - 1 - i];
            carry_ += res[res_max_bytes - 1 - i - j];
            res[res_max_bytes - 1 - i - j] = carry_ & 0x07;
        } // res[res_max - 1 - i - b_bytes] += carry_
        if (carry_) {
            long_number_plus(res, res_max_bytes - i - b_bytes, (uint8_t*)&carry_, 1);
        } // in here, carry is already shift by last loop.
    }
    return false;
}

static inline void long_number_negiv_(uint8_t *a, size_t a_bytes) {
    uint16_t carry_ = 0;
    for (size_t i = 0; i < a_bytes; a++, carry_ >>= 8) {
        carry_ += a[a_bytes - 1 - i] + 0xFF;
        a[a_bytes - 1 - i] = carry_ & 0x07;
    }
}
bool long_number_negiv(uint8_t *a, size_t a_bytes) {
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
    return false;
}

bool long_number_dec(uint8_t *a, size_t a_bytes, const uint8_t *b, size_t b_bytes) {
    uint8_t *buff = (uint8_t*)calloc(b_bytes, 1);
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