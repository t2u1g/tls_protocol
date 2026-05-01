#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "tls_algorithm.h"

static inline size_t read_rvs_num(const uint8_t *p, size_t length) {
    assert(length <= sizeof(uint64_t));
    const uint8_t *p_ = &p[length];
    uint64_t ret = 0;
    uint8_t *p_ret = (uint8_t *)&ret;
    p_--;
    for (size_t i = 0; i < length; i++) {
        p_ret[0] = p_[0];
        p_ret++, p_--;
    }
    return ret;
}

/**
 * This is a simplified ASN parsing implementation.
 * It does not support variable-length parsing with
 * a length longer than UINT64_MAX, and does not
 * support variable-label-length parsing, which means
 * that all label numbers are less than or equal to 30.
 * If you need to extend it, change ASN_FRAG_TAG.tag_number
 * and ASN_FRAG.length to larger integer types or customize
 * long integer structure implementations, and then
 * modify ASN_length_parser and ASN_tag_parser
 */

size_t ASN_length_parser(const uint8_t *p_len, size_t max_length, size_t *result) {
    if (0 == max_length) {
        return (size_t)-1;
    }
    if ((0x80 & p_len[0]) == 0) {
        result[0] = p_len[0];
        return 1;
    } else {
        uint8_t l_len = (~0x80) & p_len[0];
        if (l_len > sizeof(uint64_t) || l_len > max_length - 1) {
            abort(); // too long data_length.
        }
        result[0] = read_rvs_num(&p_len[1], l_len);
        return l_len + 1;
    }
}

size_t ASN_tag_parser(const uint8_t *asn_str, size_t max_length, ASN_FRAG_TAG *tag) {
    if (max_length < 2) {
        return (size_t)-1; // an valid asn_fragments at least have 2 bytes.
    }
    tag->tag_type = (ASN_FRAG_TAG_TYPE)(asn_str[0] & 0xC0);
    tag->tag_number = asn_str[0] & (~0xE0);
    tag->is_constru = asn_str[0] & 0x02;
    if (ASN_Universal != tag->tag_type
        && 0x1F == tag->tag_number) {
        return (size_t)-1; // not support variable tag number.
    }
    return 1;
};

size_t ASN_frag_parser(const uint8_t *asn_str, size_t max_length, ASN_FRAG *frag) {
    size_t offset = 0;
    size_t ret =
        ASN_length_parser(asn_str, max_length, &frag->length);
    offset += ret;
    if ((size_t)-1 == ret) {
        return -1;
    }
    ret = ASN_tag_parser(&asn_str[offset],
                         max_length - offset, &frag->tag);
    offset += ret;
    if ((size_t)-1 == ret || offset > max_length
        || offset + frag->length > max_length) {
        return -1;
    }

    if (ASN_Universal == frag->tag.tag_type) {
        frag->type = (ASN_FRAG_TYPE)frag->tag.tag_number;
    } else {
        frag->type = ASN_RESERVE;
    }
    frag->p_frag_data = &asn_str[offset];
    return offset;
}

#define EXPR_CHECK(x)      \
    if (!(x)) {            \
        return (size_t)-1; \
    }

#define RET_CHECK(x) EXPR_CHECK((size_t)-1 == (x))

size_t x509v3_cert_unpack(void *cert, size_t cert_length, CERT_UNPACK *unpack) {
    const uint8_t *cert_ = (const uint8_t *)cert;
    ASN_FRAG *frag_arr[5] = {
        &unpack->tbs_sign_alg,
        &unpack->issuer,
        &unpack->valid,
        &unpack->subject,
        &unpack->pub_key_info,
    };
    size_t offset = 0, ret = 0;

    ASN_FRAG t_frag;
    for (size_t i = 0; i < 3; i++) {
        RET_CHECK(ret = ASN_frag_parser(&cert_[offset], cert_length - offset, &t_frag));
        offset += ret;
    }
    RET_CHECK(ret = ASN_frag_parser(&cert_[offset], cert_length - offset, &t_frag))
    offset += ret + t_frag.length;
    EXPR_CHECK(ASN_INTEGER == t_frag.type && 0x02 == t_frag.p_frag_data[0]); // check version == v3(2).
    RET_CHECK(ret = ASN_frag_parser(&cert_[offset], cert_length - offset, &t_frag))
    offset += ret + t_frag.length; // jump .serialNumber

    for (size_t i = 0; i < 5; i++) {
        RET_CHECK(ret = ASN_frag_parser(&cert_[offset], cert_length - offset, &t_frag));
        offset += ret + t_frag.length;
        memcpy(frag_arr[i], &t_frag, sizeof(ASN_FRAG));
    }

    do {
        RET_CHECK(ret = ASN_frag_parser(&cert_[offset], cert_length - offset, &t_frag));
        offset += ret + t_frag.length;
        if (ASN_Context == t_frag.tag.tag_type
            && 0x03 == t_frag.tag.tag_number) {
            memcpy(&unpack->extens, &t_frag, sizeof(ASN_FRAG));
            break;
        }
    } while (ASN_Universal != t_frag.tag.tag_type);

    if (ASN_Universal != t_frag.tag.tag_type) {
        RET_CHECK(ret = ASN_frag_parser(&cert_[offset], cert_length - offset, &t_frag));
        offset += ret + t_frag.length;
    }
    for (size_t i = 0; i < t_frag.length; i++) {
        if (t_frag.p_frag_data[i] != unpack->tbs_sign_alg.p_frag_data[i]) {
            return (size_t)-1;
        }
    }
    RET_CHECK(ret = ASN_frag_parser(&cert_[offset], cert_length - offset, &t_frag));
    memcpy(&unpack->sign_val, &t_frag, sizeof(ASN_FRAG)); // save signature value.
    return 0;
}

static inline void write_shift_bit_str(
    uint8_t *dst, const uint8_t *src,
    size_t length, uint8_t val) {
    ;
    size_t shift_bytes = val / 8, shift_bits = val & 0x07;
    uint8_t *dst_ = dst + shift_bytes, shift_ = 0;
    while (dst_ < &dst[length]) {
        dst_[0] = (src[0] >> shift_bits);
        dst_[0] |= shift_;
        shift_ = (src[0] << (8 - shift_bits));
        dst_++, src++;
    }
}

size_t ASN_read_bitstr(ASN_FRAG *frag, uint8_t *val_buff, size_t max_length) {
    size_t total_length = frag->length - 1;
    EXPR_CHECK(ASN_Universal == frag->tag.tag_type
               && ASN_BITSTRING == frag->type);
    if (max_length < total_length) {
        return 0;
    }
    write_shift_bit_str(val_buff, &frag->p_frag_data[1],
                        total_length, frag->p_frag_data[0]);
    return total_length - frag->p_frag_data[0] / 8;
}

// this function not safe. uint32_t might overflow.
static inline size_t read_base128_str(const uint8_t *str, size_t max_length, uint32_t *ret_val) {
    uint32_t ret = 0, read_bytes = 0;
    while (str[read_bytes] & 0x80 != 0
           && read_bytes <= max_length) {
        ret *= 128;
        ret += str[0] & (~0x80);
        read_bytes++;
    }
    if (read_bytes + 1 > max_length) {
        return (uint32_t)-1;
    }
    ret *= 128;
    ret += str[0] & (~0x80);
    ret_val[0] = ret;
    return read_bytes + 1;
}

size_t ASN_read_oid(ASN_FRAG *frag, ASN_OID *oid) {
    EXPR_CHECK(ASN_Universal == frag->tag.tag_type
               && ASN_OBJECT_IDENTIFIER == frag->type
               && frag->length > 1);
    size_t offset = 1;
    oid->oid_val[0] = frag->p_frag_data[0] >> 6;
    oid->oid_val[1] = frag->p_frag_data[0] & 0x3F;
    oid->oid_num = 2;
    while (offset < frag->length) {
        EXPR_CHECK(oid->oid_num < 16);
        size_t ret_ = read_base128_str(&frag->p_frag_data[offset],
                                       frag->length - offset, 
                                       &oid->oid_val[oid->oid_num]);
        RET_CHECK(ret_);
        offset += ret_;
        oid->oid_num++;
    }
    return offset;
}

size_t x509v3_read_name(ASN_FRAG *frag) {
    // unused;
    return size_t();
}

size_t x509v3_read_date(ASN_FRAG *frag) {
    // unused.
    return size_t();
}

// this function signed data with cert.
size_t x509v3_signed_with_cert(
    CERT_UNPACK *cert, 
    const uint8_t *data, size_t data_length, 
    const uint8_t **res) {
    ;
    return size_t();
}

// this function check cert with another cert
size_t x509v3_check_cert_sign(CERT_UNPACK *cert, CERT_UNPACK *ca) {
    return size_t();
}

#undef RET_CHECK