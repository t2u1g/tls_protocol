#ifndef __WIN32_SOCKETS_H__
#define __WIN32_SOCKETS_H__
#include <stdlib.h>
#include <WinSock2.h>

void win32get_random(void* p_rand, size_t length);

SOCKET win32sockets_open(const char* ip, size_t port);
size_t win32sockets_send(SOCKET sock, const void* p_send, size_t length);
size_t win32sockets_recv(SOCKET sock, void* p_recv, size_t max_length);
void win32sockets_close(SOCKET sock);

#endif