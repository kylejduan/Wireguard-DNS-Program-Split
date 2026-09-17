// SPDX-License-Identifier: GPL-3.0-or-later
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>

#include <cstdint>
#include <functional>
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

enum class Outcome { Valid, NoResponse, Rejected };

struct Attempt {
    Outcome outcome;
    std::string detail;
};

struct ProbeResult {
    bool passed;
    unsigned attemptsMade;
    std::string error;
};

// One lost datagram or one transient refusal is not a failed probe: retry within the check, as the
// Linux controller does. `keepGoing` lets the caller stop early once its own time budget is spent.
ProbeResult probe(unsigned attempts, const std::function<Attempt()>& exchange,
                  const std::function<bool()>& keepGoing) {
    Attempt last{Outcome::NoResponse, {}};
    unsigned made = 0;
    while (made < attempts) {
        last = exchange();
        ++made;
        if (last.outcome == Outcome::Valid) return {true, made, {}};
        if (made < attempts && !keepGoing()) break;
    }
    const std::string count = std::to_string(made) + (made == 1 ? " attempt" : " attempts");
    if (last.outcome == Outcome::NoResponse) return {false, made, "No DNS response after " + count};
    return {false, made, "DNS response rejected after " + count + ": " + last.detail};
}

unsigned parseAttempts(const char* text) {
    size_t consumed{};
    const unsigned long value = std::stoul(text, &consumed);
    if (consumed != std::string(text).size() || value < 1 || value > 10) {
        throw std::runtime_error("Invalid attempt count");
    }
    return static_cast<unsigned>(value);
}

DWORD parseTimeout(const char* text) {
    size_t consumed{};
    const unsigned long value = std::stoul(text, &consumed);
    if (consumed != std::string(text).size() || value < 100 || value > 30000) {
        throw std::runtime_error("Invalid timeout");
    }
    return static_cast<DWORD>(value);
}

Attempt querySystemDns(const char* name) {
    DNS_RECORD* records{};
    const DNS_STATUS status = DnsQuery_A(name, DNS_TYPE_A,
        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE, nullptr, &records, nullptr);
    if (records) DnsRecordListFree(records, DnsFreeRecordList);
    if (status != ERROR_SUCCESS) return {Outcome::Rejected, "System DNS query failed: " + std::to_string(status)};
    return {Outcome::Valid, {}};
}

// A reply to this query from the queried server, whatever it says.
bool matchesQuery(const std::vector<uint8_t>& query, const uint8_t* response, int received,
                  const sockaddr_in& target, const sockaddr_in& peer) {
    return query.size() >= 2 && received >= 12 && peer.sin_addr.s_addr == target.sin_addr.s_addr &&
           peer.sin_port == target.sin_port && response[0] == query[0] && response[1] == query[1] &&
           (response[2] & 0x80);
}

bool validDnsResponse(const std::vector<uint8_t>& query, const uint8_t* response, int received,
                      const sockaddr_in& target, const sockaddr_in& peer) {
    return matchesQuery(query, response, received, target, peer) &&
           (response[3] & 0x0f) == 0 && (response[6] != 0 || response[7] != 0);
}

// Sends the query once and waits up to `timeout` for the server's reply. Datagrams that are not a
// reply to this query are ignored rather than ending the attempt.
Attempt exchangeOnce(SOCKET socketHandle, const std::vector<uint8_t>& query, const sockaddr_in& target,
                     DWORD timeout, int& receivedBytes) {
    if (sendto(socketHandle, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0,
               reinterpret_cast<const sockaddr*>(&target), sizeof(target)) == SOCKET_ERROR) {
        return {Outcome::Rejected, "sendto failed: " + std::to_string(WSAGetLastError())};
    }
    const ULONGLONG deadline = GetTickCount64() + timeout;
    while (true) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) return {Outcome::NoResponse, {}};
        const DWORD remaining = static_cast<DWORD>(deadline - now);
        setsockopt(socketHandle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&remaining),
                   sizeof(remaining));
        uint8_t response[4096]{};
        sockaddr_in peer{};
        int peerLength = sizeof(peer);
        const int received = recvfrom(socketHandle, reinterpret_cast<char*>(response), sizeof(response), 0,
                                      reinterpret_cast<sockaddr*>(&peer), &peerLength);
        if (received == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            if (error == WSAETIMEDOUT) return {Outcome::NoResponse, {}};
            return {Outcome::Rejected, "recvfrom failed: " + std::to_string(error)};
        }
        if (!matchesQuery(query, response, received, target, peer)) continue;
        if (!validDnsResponse(query, response, received, target, peer)) {
            return {Outcome::Rejected, "rcode " + std::to_string(response[3] & 0x0f) + ", answers " +
                                           std::to_string((response[6] << 8) | response[7])};
        }
        receivedBytes = received;
        return {Outcome::Valid, {}};
    }
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
            const auto always = [] { return true; };
            const auto scripted = [](std::vector<Attempt> script, unsigned& calls) {
                return [script, &calls]() {
                    const Attempt next = script.at(calls);
                    ++calls;
                    return next;
                };
            };
            unsigned calls = 0;
            ProbeResult result = probe(3, scripted({{Outcome::NoResponse, {}}, {Outcome::NoResponse, {}},
                                                    {Outcome::Valid, {}}}, calls), always);
            if (!result.passed || calls != 3 || result.attemptsMade != 3) return 8;
            calls = 0;
            result = probe(3, scripted({{Outcome::NoResponse, {}}, {Outcome::NoResponse, {}},
                                        {Outcome::NoResponse, {}}}, calls), always);
            if (result.passed || calls != 3 ||
                result.error.find("No DNS response after 3 attempts") == std::string::npos) return 9;
            calls = 0;
            result = probe(1, scripted({{Outcome::NoResponse, {}}}, calls), always);
            if (result.passed || calls != 1 ||
                result.error.find("No DNS response after 1 attempt") == std::string::npos) return 10;
            calls = 0;
            result = probe(3, scripted({{Outcome::Rejected, "rcode 2"}, {Outcome::Valid, {}}}, calls), always);
            if (!result.passed || calls != 2) return 11;
            calls = 0;
            result = probe(3, scripted({{Outcome::Rejected, "rcode 2"}, {Outcome::Rejected, "rcode 2"},
                                        {Outcome::Rejected, "rcode 2"}}, calls), always);
            if (result.passed || result.error.find("rejected after 3 attempts: rcode 2") == std::string::npos) return 12;
            calls = 0;
            result = probe(3, scripted({{Outcome::Valid, {}}}, calls), always);
            if (!result.passed || calls != 1) return 13;
            calls = 0;
            result = probe(3, scripted({{Outcome::NoResponse, {}}, {Outcome::Valid, {}}}, calls),
                           [] { return false; });
            if (result.passed || calls != 1) return 14;
            if (parseAttempts("3") != 3) return 15;
            for (const char* invalid : {"0", "11", "2x"}) {
                bool rejected = false;
                try { parseAttempts(invalid); } catch (const std::exception&) { rejected = true; }
                if (!rejected) return 16;
            }
            std::cout << "PASS: DNS query encoding, timeout, response validation, and probe retries.\n";
            return 0;
        }
        if ((argc == 3 || argc == 4) && std::string(argv[1]) == "--system") {
            const unsigned attempts = argc == 4 ? parseAttempts(argv[3]) : 1;
            // Callers bound this process at eight seconds, so stop retrying once five have passed.
            const ULONGLONG started = GetTickCount64();
            const ProbeResult result = probe(attempts, [&] { return querySystemDns(argv[2]); }, [&] {
                if (GetTickCount64() - started >= 5000) return false;
                Sleep(300);
                return true;
            });
            if (!result.passed) throw std::runtime_error(result.error);
            std::cout << "PASS: " << argv[2] << " resolved through the Windows DNS Client (attempt "
                      << result.attemptsMade << " of " << attempts << ").\n";
            return 0;
        }
        if (argc < 2 || argc > 5) {
            std::cerr << "Usage: dns-probe.exe <dns-ip> [name] [timeout-ms] [attempts] | --system <name> [attempts]\n";
            return 2;
        }
        const std::string name = argc >= 3 ? argv[2] : "example.com";
        const DWORD timeout = argc >= 4 ? parseTimeout(argv[3]) : 5000;
        const unsigned attempts = argc == 5 ? parseAttempts(argv[4]) : 1;
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) throw std::runtime_error("WSAStartup failed");

        SOCKET socketHandle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socketHandle == INVALID_SOCKET) throw std::runtime_error("socket failed");

        sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_port = htons(53);
        if (InetPtonA(AF_INET, argv[1], &target.sin_addr) != 1) throw std::runtime_error("Invalid DNS IPv4 address");

        // Every attempt retransmits the same query, so a late reply to an earlier datagram still counts.
        const uint16_t id = static_cast<uint16_t>(GetTickCount64());
        const auto query = makeQuery(name, id);
        int received = 0;
        const ProbeResult result = probe(attempts,
            [&] { return exchangeOnce(socketHandle, query, target, timeout, received); }, [] { return true; });
        closesocket(socketHandle);
        WSACleanup();
        if (!result.passed) {
            throw std::runtime_error(result.error + " (" + std::to_string(timeout) + " ms each) from " + argv[1]);
        }
        std::cout << "PASS: " << name << " answered with " << received << " bytes from " << argv[1]
                  << " (attempt " << result.attemptsMade << " of " << attempts << ").\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << "\n";
        return 1;
    }
}
