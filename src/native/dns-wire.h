// SPDX-License-Identifier: GPL-3.0-or-later
// Private implementation fragment of dns-dispatcher.cpp.
struct Question {
    std::wstring name;
    uint16_t type;
};

std::optional<Question> parseQuestion(const std::vector<char>& packet) {
    if (packet.size() < 17 || static_cast<unsigned char>(packet[4]) != 0 ||
        static_cast<unsigned char>(packet[5]) != 1) return std::nullopt;
    size_t offset = 12;
    std::wstring name;
    while (offset < packet.size()) {
        const unsigned length = static_cast<unsigned char>(packet[offset++]);
        if (!length) break;
        if ((length & 0xc0) || offset + length > packet.size()) return std::nullopt;
        if (!name.empty()) name.push_back(L'.');
        for (unsigned i = 0; i < length; ++i) name.push_back(static_cast<unsigned char>(packet[offset++]));
    }
    if (name.empty() || name.size() > 253 || offset + 4 > packet.size()) return std::nullopt;
    const uint16_t type = (static_cast<unsigned char>(packet[offset]) << 8) |
                          static_cast<unsigned char>(packet[offset + 1]);
    return Question{normalizeName(name), type};
}

std::vector<char> makeServfail(const std::vector<char>& query) {
    if (query.size() < 12) return {};
    auto response = query;
    response[2] = static_cast<char>(static_cast<unsigned char>(response[2]) | 0x80);
    response[3] = static_cast<char>((static_cast<unsigned char>(response[3]) & 0xf0) | 0x02);
    std::fill(response.begin() + 6, response.begin() + 12, 0);
    return response;
}

bool matchingResponse(const std::vector<char>& query, const std::vector<char>& response) {
    return query.size() >= 2 && response.size() >= 12 && response[0] == query[0] &&
           response[1] == query[1] && (static_cast<unsigned char>(response[2]) & 0x80);
}

uint16_t read16(const std::vector<char>& packet, size_t offset) {
    return (static_cast<unsigned char>(packet[offset]) << 8) |
           static_cast<unsigned char>(packet[offset + 1]);
}

bool skipDnsName(const std::vector<char>& packet, size_t& offset) {
    while (offset < packet.size()) {
        const unsigned length = static_cast<unsigned char>(packet[offset++]);
        if (!length) return true;
        if ((length & 0xc0) == 0xc0) {
            if (offset >= packet.size()) return false;
            ++offset;
            return true;
        }
        if ((length & 0xc0) || offset + length > packet.size()) return false;
        offset += length;
    }
    return false;
}

bool zeroResponseTtls(std::vector<char>& packet) {
    if (packet.size() < 12) return false;
    size_t offset = 12;
    const uint16_t questions = read16(packet, 4);
    const uint32_t records = static_cast<uint32_t>(read16(packet, 6)) + read16(packet, 8) + read16(packet, 10);
    for (uint16_t i = 0; i < questions; ++i) {
        if (!skipDnsName(packet, offset) || offset + 4 > packet.size()) return false;
        offset += 4;
    }
    for (uint32_t i = 0; i < records; ++i) {
        if (!skipDnsName(packet, offset) || offset + 10 > packet.size()) return false;
        const uint16_t type = read16(packet, offset);
        if (type != 41) std::fill(packet.begin() + offset + 4, packet.begin() + offset + 8, 0);
        const uint16_t dataLength = read16(packet, offset + 8);
        offset += 10;
        if (offset + dataLength > packet.size()) return false;
        offset += dataLength;
    }
    return true;
}

sockaddr_in address(const wchar_t* ip, uint16_t port) {
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_port = htons(port);
    if (InetPtonW(AF_INET, ip, &result.sin_addr) != 1) throw std::runtime_error("Invalid IPv4 address");
    return result;
}

#include "dns-sockets.h"

std::optional<std::vector<char>> udpExchange(const std::vector<char>& packet, sockaddr_in source,
                                             sockaddr_in resolver) {
    SOCKET upstream = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (upstream == INVALID_SOCKET) return std::nullopt;
    SocketOwner owned(upstream);
    if (!nonblocking(upstream)) return std::nullopt;
    const auto deadline = afterMilliseconds(4000);
    source.sin_port = 0;
    std::optional<std::vector<char>> result;
    if (bind(upstream, reinterpret_cast<sockaddr*>(&source), sizeof(source)) == 0 &&
        connectBefore(upstream, resolver, deadline) &&
        socketReady(upstream, true, deadline) &&
        send(upstream, packet.data(), static_cast<int>(packet.size()), 0) == static_cast<int>(packet.size()) &&
        socketReady(upstream, false, deadline)) {
        std::vector<char> response(65535);
        const int received = recv(upstream, response.data(), static_cast<int>(response.size()), 0);
        if (received > 0) {
            response.resize(received);
            if (matchingResponse(packet, response) && zeroResponseTtls(response)) result = std::move(response);
        }
    }
    return result;
}

std::optional<std::vector<char>> tcpExchange(const std::vector<char>& packet, sockaddr_in source,
                                             sockaddr_in resolver) {
    SOCKET upstream = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (upstream == INVALID_SOCKET) return std::nullopt;
    SocketOwner owned(upstream);
    if (!nonblocking(upstream)) return std::nullopt;
    const auto deadline = afterMilliseconds(4000);
    source.sin_port = 0;
    std::optional<std::vector<char>> result;
    const uint16_t length = htons(static_cast<uint16_t>(packet.size()));
    if (bind(upstream, reinterpret_cast<sockaddr*>(&source), sizeof(source)) == 0 &&
        connectBefore(upstream, resolver, deadline) &&
        sendAll(upstream, reinterpret_cast<const char*>(&length), sizeof(length), deadline) &&
        sendAll(upstream, packet.data(), static_cast<int>(packet.size()), deadline)) {
        uint16_t responseLength{};
        if (receiveAll(upstream, reinterpret_cast<char*>(&responseLength), sizeof(responseLength), deadline)) {
            const int size = ntohs(responseLength);
            std::vector<char> response(size);
            if (size && receiveAll(upstream, response.data(), size, deadline) && matchingResponse(packet, response) &&
                zeroResponseTtls(response)) {
                result = std::move(response);
            }
        }
    }
    return result;
}

