// SPDX-License-Identifier: GPL-3.0-or-later
// Disposable Windows CI resolver pair. No external network access; exits after 90 seconds.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

int main() {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 1;
    SOCKET sockets[2]{INVALID_SOCKET, INVALID_SOCKET};
    for (unsigned i = 0; i < 2; ++i) {
        sockets[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = htons(53);
        InetPtonA(AF_INET, i ? "127.0.0.3" : "127.0.0.2", &local.sin_addr);
        BOOL exclusive = TRUE;
        setsockopt(sockets[i], SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
        if (bind(sockets[i], reinterpret_cast<sockaddr*>(&local), sizeof(local))) return 2;
    }
    std::cout << "READY" << std::endl;
    const ULONGLONG deadline = GetTickCount64() + 90000;
    while (GetTickCount64() < deadline) {
        fd_set readers;
        FD_ZERO(&readers);
        for (SOCKET value : sockets) FD_SET(value, &readers);
        timeval wait{0, 100000};
        if (select(0, &readers, nullptr, nullptr, &wait) <= 0) continue;
        for (unsigned i = 0; i < 2; ++i) {
            if (!FD_ISSET(sockets[i], &readers)) continue;
            std::vector<unsigned char> packet(65535);
            sockaddr_in peer{};
            int peerSize = sizeof(peer);
            const int received = recvfrom(sockets[i], reinterpret_cast<char*>(packet.data()), static_cast<int>(packet.size()), 0,
                                          reinterpret_cast<sockaddr*>(&peer), &peerSize);
            if (received < 17) continue;
            packet.resize(received);
            size_t offset = 12;
            std::string name;
            while (offset < packet.size()) {
                const unsigned length = packet[offset++];
                if (!length) break;
                if (length > 63 || offset + length > packet.size()) break;
                if (!name.empty()) name += '.';
                name.append(reinterpret_cast<const char*>(packet.data() + offset), length);
                offset += length;
            }
            if (offset + 4 > packet.size()) continue;
            packet.resize(offset + 4);
            packet[2] = 0x81; packet[3] = 0x80;
            packet[4] = 0; packet[5] = 1; packet[6] = 0; packet[7] = 1;
            packet[8] = packet[9] = packet[10] = packet[11] = 0;
            packet.insert(packet.end(), {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1});
            sendto(sockets[i], reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0,
                   reinterpret_cast<sockaddr*>(&peer), peerSize);
            std::cout << (i ? "TUNNEL " : "DIRECT ") << name << std::endl;
        }
    }
    for (SOCKET value : sockets) closesocket(value);
    WSACleanup();
}
