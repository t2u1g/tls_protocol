#ifndef __WIN32_SOCKETS_H__
#define __WIN32_SOCKETS_H__

// #define WIN32_LEAN_AND_MEAN
// #define _WINSOCKAPI_
#include <WinSock2.h>
#include <Windows.h>

#include <stdlib.h>
#include <bcrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

void win32get_random(void* p_rand, size_t length);

SOCKET win32sockets_open(const char* ip, size_t port);
size_t win32sockets_send(SOCKET sock, const void* p_send, size_t length);
size_t win32sockets_recv(SOCKET sock, void* p_recv, size_t max_length);
void win32sockets_close(SOCKET sock);

// AF_IPX;

#endif