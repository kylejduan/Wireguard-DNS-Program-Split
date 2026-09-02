#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>

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

DWORD parseTimeout(const char* text) {
    size_t consumed{};
    const unsigned long value = std::stoul(text, &consumed);
    if (consumed != std::string(text).size() || value < 100 || value > 30000) {
        throw std::runtime_error("Invalid timeout");
    }
    return static_cast<DWORD>(value);
}

void querySystemDns(const char* name) {
    DNS_RECORD* records{};
    const DNS_STATUS status = DnsQuery_A(name, DNS_TYPE_A,
        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE, nullptr, &records, nullptr);
    if (records) DnsRecordListFree(records, DnsFreeRecordList);
    if (status != ERROR_SUCCESS) {
        throw std::runtime_error("System DNS query failed: " + std::to_string(status));
    }
    std::cout << "PASS: " << name << " resolved through the Windows DNS Client.\n";
}

bool validDnsResponse(const std::vector<uint8_t>& query, const uint8_t* response, int received,
                      const sockaddr_in& target, const sockaddr_in& peer) {
    return query.size() >= 2 && received >= 12 && peer.sin_addr.s_addr == target.sin_addr.s_addr &&
           peer.sin_port == target.sin_port && response[0] == query[0] && response[1] == query[1] &&
           (response[2] & 0x80) && (response[3] & 0x0f) == 0 && (response[6] != 0 || response[7] != 0);
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--self-test") {
            const auto query = makeQuery("example.com", 0x1234);
            if (query.size() != 29 || query[0] != 0x12 || query[1] != 0x34 || query[12] != 7) return 2;
            if (parseTimeout("750") != 750) return 3;
            std::vector<uint8_t> response(12);
            response[0] = query[0];
            response[1] = query[1];
            response[2] = 0x80;
            response[7] = 1;
            sockaddr_in target{};
            target.sin_addr.s_addr = 1;
            target.sin_port = 53;
            auto peer = target;
            if (!validDnsResponse(query, response.data(), static_cast<int>(response.size()), target, peer)) return 4;
            response[3] = 2;
            if (validDnsResponse(query, response.data(), static_cast<int>(response.size()), target, peer)) return 5;
            response[3] = 0;
            peer.sin_addr.s_addr = 2;
            if (validDnsResponse(query, response.data(), static_cast<int>(response.size()), target, peer)) return 6;
            peer = target;
            response[7] = 0;
            if (validDnsResponse(query, response.data(), static_cast<int>(response.size()), target, peer)) return 7;
            std::cout << "PASS: DNS query encoding, timeout, and response validation.\n";
            return 0;
        }
        if (argc == 3 && std::string(argv[1]) == "--system") {
            querySystemDns(argv[2]);
            return 0;
        }
        if (argc < 2 || argc > 4) {
            std::cerr << "Usage: dns-probe.exe <dns-ip> [name] [timeout-ms] | --system <name>\n";
            return 2;
        }
        const std::string name = argc >= 3 ? argv[2] : "example.com";
        const DWORD timeout = argc == 4 ? parseTimeout(argv[3]) : 5000;
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) throw std::runtime_error("WSAStartup failed");

        SOCKET socketHandle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socketHandle == INVALID_SOCKET) throw std::runtime_error("socket failed");
        setsockopt(socketHandle, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&timeout), sizeof(timeout));

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
        if (!validDnsResponse(query, response, received, target, peer)) {
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
