#include <iostream>
#include <fstream>
#include <vector>

#include "./../../src/win32/win32_sockets.h"
#include <WS2tcpip.h>

struct IPv4AddressInfo {
    std::string ip_address;
    uint16_t port;
};

bool GetIPv4Addresses(const char* hostname, const char* port, std::vector<IPv4AddressInfo>& ipv4_addresses) {
    
    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return false;
    }

    struct addrinfo hints, *result = nullptr, *ptr = nullptr;
    
    // 设置地址查询提示
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;        // 只查询 IPv4 地址
    hints.ai_socktype = SOCK_STREAM;  // TCP 套接字类型
    hints.ai_protocol = IPPROTO_TCP;  // TCP 协议
    
    // 执行地址解析
    int dwRetval = getaddrinfo(hostname, port, &hints, &result);
    if (dwRetval != 0) {
        std::cerr << "getaddrinfo failed with error: " << dwRetval << std::endl;
        WSACleanup();
        return false;
    }
    
    // 遍历结果链表
    for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        // 确保是 IPv4 地址
        if (ptr->ai_family == AF_INET) {
            struct sockaddr_in* ipv4_addr = (struct sockaddr_in*)ptr->ai_addr;
            char ip_str[INET_ADDRSTRLEN];
            
            // 将 IPv4 地址转换为字符串
            inet_ntop(AF_INET, &(ipv4_addr->sin_addr), ip_str, INET_ADDRSTRLEN);
            
            IPv4AddressInfo addr_info;
            addr_info.ip_address = ip_str;
            addr_info.port = ntohs(ipv4_addr->sin_port);
            ipv4_addresses.push_back(addr_info);
        }
    }
    
    // 释放地址信息
    freeaddrinfo(result);
    WSACleanup();
    
    return !ipv4_addresses.empty();
}
