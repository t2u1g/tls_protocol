#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "win32_sockets.h"


// get length-bytes random to fill p_rand buff.
void win32get_random(void* p_rand, size_t length) {
    BCRYPT_SUCCESS(BCryptGenRandom(
        NULL, (PUCHAR)p_rand, length,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    ));
}

static size_t sockets_count = 0;
SOCKET win32sockets_open(const char *ip, size_t port) {
    WSADATA wsaData;                      
    WORD wVersion = MAKEWORD(2, 2);
    SOCKET ret = INVALID_SOCKET;
    if (WSAStartup(wVersion, &wsaData)) { 
        printf("initial failed \n");
        return ret;
    }

    ret = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (ret == INVALID_SOCKET) {
        printf("socket create failed \n");
        WSACleanup();
        return ret;
    }

    sockaddr_in addrServer;
    addrServer.sin_family = AF_INET;
    addrServer.sin_port = htons(port);
    addrServer.sin_addr.s_addr = inet_addr(ip); 
    
    int nRet = connect(ret, (sockaddr *)&addrServer, sizeof(addrServer));
    if (nRet == SOCKET_ERROR) {
        printf("connect failed \n");
        closesocket(ret);
        WSACleanup();
        return 0;
    }
    sockets_count++;
    return ret;
}

static const timeval win32socket_timeout_val = { 10, 0 };
size_t win32sockets_send(SOCKET sock, const void *p_send, size_t length) {
    fd_set set_;
    FD_ZERO(&set_);
    FD_SET(sock, &set_);
    const char *p_send_ = (const char*)p_send;
    size_t send_bytes = 0;
    do {
        int select_ret = select(0, NULL, &set_, NULL, &win32socket_timeout_val);
        if (select_ret <= 0) {
            return (size_t)-1; // if equal 0, timeout; if equal -1, SOCKET_ERROR.
        }
        int send_ret = send(sock, &p_send_[send_bytes], length - send_bytes, 0);
        if (SOCKET_ERROR == send_ret) {
            return (size_t)-1;
        }
        send_bytes += (size_t)send_ret;
    } while (send_bytes < length);
    return send_bytes;
} 

size_t win32sockets_recv(SOCKET sock, void *p_recv, size_t length) {
    fd_set set_;
    FD_ZERO(&set_);
    FD_SET(sock, &set_);
    char *p_recv_ = (char*)p_recv;
    size_t recv_bytes = 0;
    do {
        int select_ret = select(0, &set_, NULL, NULL, &win32socket_timeout_val);
        if (select_ret <= 0) {
            return (size_t)-1; // if equal 0, timeout; if equal -1, SOCKET_ERROR.
        }
        int recv_ret = recv(sock, &p_recv_[recv_bytes], length - recv_bytes, 0);
        if (SOCKET_ERROR == recv_ret) {
            return (size_t)-1;
        }
        recv_bytes += (size_t)recv_ret;
    } while (recv_bytes < length);
    return recv_bytes;
}

void win32sockets_close(SOCKET sock) {
    if (INVALID_SOCKET != sock) {
        closesocket(sock);
    }
    sockets_count--;
    if (0 == sockets_count) {
        WSACleanup();
    }
}
