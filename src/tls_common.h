#ifndef __TLS_COMMON_H__
#define __TLS_COMMON_H__
#include <stdint.h>

#include "tls_record.h"

// All high-level protocol-related constructs and derived functions

enum HandshakeType : uint8_t {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
};

struct HADSHAKE_MESSAGE {
    HandshakeType msg_type;
    uint8_t length[3];
    uint8_t body[];
};

enum KeyExchangeAlgorithmType{
    RSA, ECDHE
};
enum CertificateType{
    Cert_rsa
};

const size_t TlsCipherSuiteNumbers = 2;
enum TlsCipherSuiteType : uint16_t {
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
};
const uint16_t TlsCipherSuiteValues[TlsCipherSuiteNumbers] = {
    0x2F00, 0x2FC0
};

struct CipherSuiteParams{
    HashAlgorithm hash_algorithm;
    CiperType ciper_type;
    KeyExchangeAlgorithmType key_exchange_type;
    CertificateType cert_type;
};
const CipherSuiteParams TlsCipherSuiteParams[TlsCipherSuiteNumbers] = {
    {Hash_sha1, Ciper_block, RSA, Cert_rsa},
    {Hash_sha256, Ciper_aead, ECDHE, Cert_rsa}
};


enum HandShakeType : uint8_t{
    hello_request = 0, 
    client_hello = 1, 
    server_hello = 2,           
    certificate = 11, 
    server_key_exchange = 12,           
    certificate_request = 13, 
    server_hello_done = 14,           
    certificate_verify = 15, 
    client_key_exchange = 16,           
    finished = 20
};

/*
#pragma pack(1)
struct Hadshake{
    HandShakeType type;
    uint32_t length:24;
    uint8_t body[];
};

#pragma pack(1)
struct HelloRequestBody {};
#pragma pack(1)
struct Random{
    uint32_t gmt_unix_time;
    uint8_t random_byte[28];
};
#pragma pack(1)
struct SessionID {
    uint8_t id_length;
    uint8_t id[];
};
#pragma pack(1)
struct CiperSuite {
    uint16_t suite_length;
    uint16_t suites[];
};
#pragma pack(1)
struct ClientHello {
    ProtocolVersion clinet_version;
    Random random;
    SessionID session_id;
    CiperSuite ciper_suite;
};

enum ExtensionType : uint16_t{
    signature_algorithms = 13
};
#pragma pack(1)
struct Extension {
    ExtensionType extension_type;
    uint16_t extension_data_length;
    uint8_t extension_datas[];
};*/ // such as structs. but c/cpp not support defines.

#endif
