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

enum ASN_FRAG_TYPE : uint8_t {
    ASN_RESERVE = 0x00,
    ASN_INTEGER = 0x02,
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

struct ASN_FRAG {
    ASN_FRAG_TAG tag;
    ASN_FRAG_TYPE type;
    size_t length;
    const uint8_t *p_frag_data;
};

size_t ASN_length_parser(const uint8_t *p_len, size_t max_length, size_t *result) {
    if (0 == max_length) {
        return (size_t)-1;
    }
    if (0x80 & p_len[0] == 0) {
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

struct CERT_UNPACK {
    ASN_FRAG tbs_sign_alg;
    ASN_FRAG issuer;
    ASN_FRAG valid;
    ASN_FRAG subject;
    ASN_FRAG pub_key_info;
    ASN_FRAG extens;
    ASN_FRAG sign_val;
};

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

    for (size_t i = 0; i < 2; i++) {
        RET_CHECK(ret = ASN_frag_parser(&cert_[offset], cert_length - offset, &t_frag));
        if (ASN_Context == t_frag.type
            && 0x03 == t_frag.tag.tag_number) {
            break;
        }
        offset += ret + t_frag.length;
    }
    memcpy(&unpack->extens, &t_frag, sizeof(ASN_FRAG)); // save extends.
    offset += ret + t_frag.length;

    RET_CHECK(ret = ASN_frag_parser(&cert_[offset], cert_length - offset, &t_frag));
    for (size_t i = 0; i < t_frag.length; i++) {
        if (t_frag.p_frag_data[i] != unpack->tbs_sign_alg.p_frag_data[i]) {
            return (size_t)-1;
        }
    }
    offset += ret + t_frag.length;
    RET_CHECK(ret = ASN_frag_parser(&cert_[offset], cert_length - offset, &t_frag));
    memcpy(&unpack->sign_val, &t_frag, sizeof(ASN_FRAG)); // save signature value.
    return 0;
}

static inline void write_shift_bit_str(
    uint8_t* dst, const uint8_t* src, 
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

size_t x509v3_cert_get_sign(CERT_UNPACK *pack, uint8_t *val_buff, size_t max_length) {
    size_t total_length = pack->valid.length - 1;
    if (max_length < total_length) {
        return 0;
    }
    write_shift_bit_str(val_buff, &pack->sign_val.p_frag_data[1],
                        total_length, pack->sign_val.p_frag_data[0]);
    return total_length - pack->sign_val.p_frag_data[0] / 8;
}

#undef RET_CHECK