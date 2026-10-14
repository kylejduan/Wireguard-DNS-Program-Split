// SPDX-License-Identifier: GPL-3.0-or-later
// Disposable Windows CI resolver pair. No external network access; exits after 90 seconds, or after the
// number of seconds given after --fixture. 127.0.0.2 is the direct lane and 127.0.0.3 the tunnel lane, each
// on UDP and TCP. A UDP query for a name starting with "tc-" or "tcbig-" gets a truncated answer; over TCP
// a "tcbig-" name gets 300 records, more than any client accepts over UDP.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

// The answer for a query on lane i, or nothing for a packet that is not a query. Each lane answers with
// its own address, so a client can tell which resolver answered it.
std::vector<unsigned char> answer(std::vector<unsigned char> packet, unsigned i, bool truncate, std::string& name,
                                  bool large = false) {
    if (packet.size() < 17) return {};
    size_t offset = 12;
    name.clear();
    while (offset < packet.size()) {
        const unsigned length = packet[offset++];
        if (!length) break;
        if (length > 63 || offset + length > packet.size()) return {};
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(packet.data() + offset), length);
        offset += length;
    }
    if (offset + 4 > packet.size()) return {};
    packet.resize(offset + 4);
    packet[2] = truncate ? 0x83 : 0x81;
    packet[3] = 0x80;
    const unsigned records = truncate ? 0 : large ? 300 : 1;
    packet[4] = 0; packet[5] = 1; packet[6] = static_cast<unsigned char>(records >> 8); packet[7] = records & 0xff;
    packet[8] = packet[9] = packet[10] = packet[11] = 0;
    for (unsigned record = 0; record < records; ++record) {
        // The first record carries the lane's address; the rest only make the answer large.
        packet.insert(packet.end(), {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4});
        if (!record) packet.insert(packet.end(), {192, 0, 2, static_cast<unsigned char>(i ? 1 : 2)});
        else packet.insert(packet.end(), {198, static_cast<unsigned char>(51 + i), static_cast<unsigned char>(record >> 8),
                                          static_cast<unsigned char>(record & 0xff)});
    }
    return packet;
}

bool receiveAll(SOCKET socket, char* data, int size) {
    for (int done = 0; done < size;) {
        const int received = recv(socket, data + done, size - done, 0);
        if (received <= 0) return false;
        done += received;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    const unsigned long lifetime = argc > 2 ? std::strtoul(argv[2], nullptr, 10) : 90;
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 1;
    SOCKET udp[2]{INVALID_SOCKET, INVALID_SOCKET};
    SOCKET tcp[2]{INVALID_SOCKET, INVALID_SOCKET};
    for (unsigned i = 0; i < 2; ++i) {
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = htons(53);
        InetPtonA(AF_INET, i ? "127.0.0.3" : "127.0.0.2", &local.sin_addr);
        BOOL exclusive = TRUE;
        udp[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        tcp[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        for (SOCKET value : {udp[i], tcp[i]}) {
            setsockopt(value, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
            if (bind(value, reinterpret_cast<sockaddr*>(&local), sizeof(local))) return 2;
        }
        if (listen(tcp[i], 16)) return 3;
    }
    std::cout << "READY" << std::endl;
    const ULONGLONG deadline = GetTickCount64() + lifetime * 1000;
    while (GetTickCount64() < deadline) {
        fd_set readers;
        FD_ZERO(&readers);
        for (unsigned i = 0; i < 2; ++i) {
            FD_SET(udp[i], &readers);
            FD_SET(tcp[i], &readers);
        }
        timeval wait{0, 100000};
        if (select(0, &readers, nullptr, nullptr, &wait) <= 0) continue;
        for (unsigned i = 0; i < 2; ++i) {
            const char* lane = i ? "TUNNEL " : "DIRECT ";
            std::string name;
            if (FD_ISSET(udp[i], &readers)) {
                std::vector<unsigned char> packet(65535);
                sockaddr_in peer{};
                int peerSize = sizeof(peer);
                const int received = recvfrom(udp[i], reinterpret_cast<char*>(packet.data()), static_cast<int>(packet.size()), 0,
                                              reinterpret_cast<sockaddr*>(&peer), &peerSize);
                if (received > 0) {
                    packet.resize(received);
                    std::string probe;
                    answer(packet, i, false, probe);
                    const bool truncate = probe.rfind("tc-", 0) == 0 || probe.rfind("tcbig-", 0) == 0;
                    const auto reply = answer(packet, i, truncate, name);
                    if (!reply.empty()) {
                        sendto(udp[i], reinterpret_cast<const char*>(reply.data()), static_cast<int>(reply.size()), 0,
                               reinterpret_cast<sockaddr*>(&peer), peerSize);
                        std::cout << lane << name << (truncate ? " (truncated)" : "") << std::endl;
                    }
                }
            }
            if (FD_ISSET(tcp[i], &readers)) {
                SOCKET client = accept(tcp[i], nullptr, nullptr);
                if (client == INVALID_SOCKET) continue;
                DWORD timeout = 2000;
                setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
                unsigned char prefix[2]{};
                if (receiveAll(client, reinterpret_cast<char*>(prefix), 2)) {
                    std::vector<unsigned char> packet((prefix[0] << 8) | prefix[1]);
                    if (!packet.empty() && receiveAll(client, reinterpret_cast<char*>(packet.data()), static_cast<int>(packet.size()))) {
                        std::string probe;
                        answer(packet, i, false, probe);
                        auto reply = answer(packet, i, false, name, probe.rfind("tcbig-", 0) == 0);
                        if (!reply.empty()) {
                            const unsigned char size[2]{static_cast<unsigned char>(reply.size() >> 8),
                                                        static_cast<unsigned char>(reply.size() & 0xff)};
                            reply.insert(reply.begin(), size, size + 2);
                            send(client, reinterpret_cast<const char*>(reply.data()), static_cast<int>(reply.size()), 0);
                            std::cout << lane << name << " (TCP)" << std::endl;
                        }
                    }
                }
                closesocket(client);
            }
        }
    }
    for (unsigned i = 0; i < 2; ++i) {
        closesocket(udp[i]);
        closesocket(tcp[i]);
    }
    WSACleanup();
}
