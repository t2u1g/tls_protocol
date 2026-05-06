#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#include <iostream>
#include <cstring>
#include <cassert>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/applink.c>

#include "net_funcs.h"
#include "bio_funcs.h"

#define FILENAME "./ssl_recive.html"
#define HOST "www.baidu.com"
#define PORT "443"

static int create_socket(const char* hostname, const char* port) {
    std::vector<IPv4AddressInfo> ip_list;
    assert(GetIPv4Addresses(HOST, PORT, ip_list));

    for (auto &i : ip_list) {
        std::cout << "[*] metchs ip address \"" << i.ip_address.c_str();
        std::cout << "\":\"" << i.port <<"\"" << std::endl;
    }
    SOCKET sock = win32sockets_open(ip_list[0].ip_address.c_str(), (size_t)ip_list[0].port);
    
    return sock;
}

/* ===== 自定义扩展（教学用） ===== */
int custom_ext_add_cb_(SSL *s, unsigned int ext_type,
                      const unsigned char **out, size_t *outlen,
                      int *al, void *add_arg) {
    static const unsigned char dummy_data[] = {0x01, 0x02, 0x03, 0x04};

    *out = dummy_data;
    *outlen = sizeof(dummy_data);

    std::cout << "[*] Custom extension added (type=" << ext_type << ")\n";
    return 1;
}

void custom_ext_free_cb_(SSL *s, unsigned int ext_type,
                        const unsigned char *out, void *add_arg) {
    // nothing to free
}

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* ===== 强制 TLS1.2 ===== */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    /* ===== 指定 Cipher ===== */
    if (!SSL_CTX_set_cipher_list(ctx, "AES128-SHA")) {
        std::cerr << "Cipher set failed\n";
        return -1;
    }

    /* ===== 禁用 session ticket（减少扩展）===== */
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

    /* ===== 禁用压缩（避免 CRIME）===== */
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    /* ===== 注册自定义扩展（关键）===== */
    // 0x1234 是随便选的私有扩展 ID（RFC 8446 允许）
    SSL_CTX_add_client_custom_ext(
        ctx,
        0x1234,
        custom_ext_add_cb_,
        custom_ext_free_cb_,
        nullptr,
        nullptr,
        nullptr
    );

    int sock = create_socket(HOST, PORT);
    if (sock < 0) return -1;

    BIO *socket_bio = BIO_new_socket(sock, BIO_NOCLOSE);
    BIO *hook_bio = bio_hook_create("hook_bio");
    BIO_set_next(hook_bio, socket_bio);

    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl, hook_bio, hook_bio);

    /* ===== 控制 SNI（可以开/关）===== */
    SSL_set_tlsext_host_name(ssl, HOST);

    /* ===== 禁用 ALPN（减少扩展）===== */
    SSL_set_alpn_protos(ssl, nullptr, 0);

    /* ===== 开始握手 ===== */
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    std::cout << "[+] TLS Handshake completed\n";
    std::cout << "[+] Cipher: " << SSL_get_cipher(ssl) << "\n";

    /* ===== 发送 HTTP 请求 ===== */
    std::string request =
        "GET / HTTP/1.1\r\n"
        "Host: " HOST "\r\n"
        "Connection: close\r\n\r\n";

    int ret_ = SSL_write(ssl, request.c_str(), request.size());
    if (ret_ <= 0) {
        std::cout << "Failed to send data" << "\n";
    } else {
        std::cout << "[+] SSL_write success" << "\n";
    }

    /* ===== 接收响应 ===== */
    char buffer[8192];
    int bytes;
    
    std::ofstream file(FILENAME, std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << FILENAME << std::endl;
        return false;
    }

    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        file.write(buffer, bytes);
    }
    file.close();
    if (!file.good()) {
        std::cerr << "Filed to close file" << std::endl;
    }

    std::cout << "[+] SSL clean start" << std::endl;
    /* ===== 清理 ===== */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    std::cout << "[+] programing finish" << std::endl;

    return 0;
}
