#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> makeQuery(const std::string& name, uint16_t id) {
    std::vector<uint8_t> query{
        static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id),
        0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    size_t start = 0;
    while (start < name.size()) {
        const size_t end = name.find('.', start);
        const size_t length = (end == std::string::npos ? name.size() : end) - start;
        if (length == 0 || length > 63) throw std::runtime_error("Invalid DNS name");
        query.push_back(static_cast<uint8_t>(length));
        query.insert(query.end(), name.begin() + start, name.begin() + start + length);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    query.insert(query.end(), {0x00, 0x00, 0x01, 0x00, 0x01});
    return query;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--self-test") {
            const auto query = makeQuery("example.com", 0x1234);
            if (query.size() != 29 || query[0] != 0x12 || query[1] != 0x34 || query[12] != 7) return 2;
            std::cout << "PASS: deterministic DNS query encoding.\n";
            return 0;
        }
        if (argc < 2 || argc > 3) {
            std::cerr << "Usage: dns-probe.exe <dns-ip> [name]\n";
            return 2;
        }
        const std::string name = argc == 3 ? argv[2] : "example.com";
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) throw std::runtime_error("WSAStartup failed");

        SOCKET socketHandle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socketHandle == INVALID_SOCKET) throw std::runtime_error("socket failed");
        DWORD timeout = 5000;
        setsockopt(socketHandle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&timeout), sizeof(timeout));

        sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_port = htons(53);
        if (InetPtonA(AF_INET, argv[1], &target.sin_addr) != 1) throw std::runtime_error("Invalid DNS IPv4 address");

        const uint16_t id = static_cast<uint16_t>(GetTickCount64());
        const auto query = makeQuery(name, id);
        if (sendto(socketHandle, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0,
                   reinterpret_cast<sockaddr*>(&target), sizeof(target)) == SOCKET_ERROR) {
            throw std::runtime_error("sendto failed: " + std::to_string(WSAGetLastError()));
        }

        uint8_t response[4096]{};
        sockaddr_in peer{};
        int peerLength = sizeof(peer);
        const int received = recvfrom(socketHandle, reinterpret_cast<char*>(response), sizeof(response), 0,
                                      reinterpret_cast<sockaddr*>(&peer), &peerLength);
        if (received < 12) throw std::runtime_error("DNS response failed: " + std::to_string(WSAGetLastError()));
        if (response[0] != static_cast<uint8_t>(id >> 8) || response[1] != static_cast<uint8_t>(id) || !(response[2] & 0x80)) {
            throw std::runtime_error("Invalid DNS response");
        }

        char peerText[INET_ADDRSTRLEN]{};
        InetNtopA(AF_INET, &peer.sin_addr, peerText, sizeof(peerText));
        std::cout << "PASS: " << name << " answered with " << received << " bytes from " << peerText << ".\n";
        closesocket(socketHandle);
        WSACleanup();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << "\n";
        return 1;
    }
}
