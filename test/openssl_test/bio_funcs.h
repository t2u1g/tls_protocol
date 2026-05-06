#include <iostream>
#include <cstring>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>

size_t freqs = 0;

bool SaveBytesToFile(const char* data, size_t data_size, const char* filename) {
    if (!data || data_size == 0 || !filename) {
        std::cerr << "Invalid parameters" << std::endl;
        return false;
    }
    
    std::ofstream file(filename, std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return false;
    }
    
    file.write(data, data_size);
    file.close();
    
    return file.good();
}

int bio_hook_read_cbk(BIO *b, char *buf, int len) {
    BIO *next = BIO_next(b);
    int ret = BIO_read(next, buf, len);

    if (ret > 0) {
        std::string filename = "./hook/ssl_hook_recv_" + std::to_string(freqs) + ".bin";
        SaveBytesToFile(buf, ret, filename.c_str());
        freqs++;
    }
    return ret;
}

int bio_hook_write_cbk(BIO *b, const char *buf, int len) {
    BIO *next = BIO_next(b);

    if (len > 0) {
        std::string filename = "./hook/ssl_hook_send_" + std::to_string(freqs) + ".bin";
        SaveBytesToFile(buf, len, filename.c_str());
        freqs++;
    }
    return BIO_write(next, buf, len);
}

long bio_hook_ctrl_cbk(BIO *b, int cmd, long num, void *ptr) {
    BIO *next = BIO_next(b);
    return BIO_ctrl(next, cmd, num, ptr);
} // do nothing.

BIO_METHOD *bio_hook_create_(const char *bio_name) {
    BIO_METHOD *ret = BIO_meth_new(BIO_TYPE_FILTER, bio_name);

    BIO_meth_set_read(ret, bio_hook_read_cbk);
    BIO_meth_set_write(ret, bio_hook_write_cbk);
    BIO_meth_set_ctrl(ret, bio_hook_ctrl_cbk);
    return ret;
}

BIO *bio_hook_create(const char *bio_name) {
    BIO *ret = BIO_new(bio_hook_create_(bio_name));

    // BIO_set_data(ret, next);
    BIO_set_init(ret, 1);
    return ret;
}