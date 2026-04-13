#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <WinSock2.h>

#pragma comment(lib, "ws2_32.lib")

#include "win32_sockets.h"

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
        printf("socket failed \n");
        WSACleanup();
        return ret;
    }

    sockaddr_in addrServer;
    addrServer.sin_family = AF_INET;
    addrServer.sin_port = htons(port);
    addrServer.sin_addr.s_addr = inet_addr(ip); 
    
    int nRet = connect(ret, (sockaddr *)&addrServer, sizeof(addrServer));
    if (nRet == SOCKET_ERROR) {
        printf("connect error \n");
        closesocket(ret);
        WSACleanup();
        return 0;
    }
    return ret;
}

size_t win32sockets_send(SOCKET sock, const void *p_send, size_t length) {
    size_t send_bytes = send(sock, (const char*)p_send, length, 0);
    while(send_bytes < length) {
        size_t inner_send = send(sock, &((const char*)p_send)[send_bytes], length - send_bytes, 0);
        if ((size_t)-1 == inner_send) {
            return (size_t)-1;
        }
        send_bytes += inner_send;
    }
    return send_bytes;
}

size_t win32sockets_recv(SOCKET sock, void *p_recv, size_t max_length) {
    size_t recv_bytes = recv(sock, (char*)p_recv, max_length, 0);
    while (recv_bytes < max_length) {
        size_t inner_recv = recv(sock, &((char*)p_recv)[recv_bytes], max_length - recv_bytes, 0);
        if ((size_t)-1 == inner_recv) {
            return (size_t)-1;
        }
        recv_bytes += inner_recv;
    }
    return recv_bytes;
}

void win32sockets_close(SOCKET sock) {
    if (INVALID_SOCKET != sock) {
        closesocket(sock);
    }
    WSACleanup();
}
