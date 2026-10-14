// SPDX-License-Identifier: GPL-3.0-or-later
// Disposable Windows CI client for WFP filter traffic proofs. Copies of it are listed or unlisted.
//   tcp <ip> <port> <timeout-ms>   connect, IPv4 or IPv6 (a link-local address takes a %scope)
//   udp-dns <ip> <timeout-ms>      one DNS query to port 53 and its reply
//   loopback <ip>                  TCP connect to a listener this process opens on a loopback address
//   udp-listen <ip> <port> <ms>    hold a UDP port, as a stand-in for a ready dispatcher; prints READY
//   system-dns <name> [count]      A lookups through the Windows DNS Client, bypassing its cache; prints
//                                  the first address of the first, which tells the resolver lanes apart
// Prints PASS or FAIL with the Winsock error and exits 0 or 1.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

struct Address {
    sockaddr_storage storage{};
    int size{};
    int family{};
};

// Numeric IPv4 or IPv6, including a scoped link-local address such as fe80::1%12.
bool parseAddress(const char* text, unsigned short port, Address& address) {
    addrinfo hints{};
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
    addrinfo* result{};
    if (getaddrinfo(text, std::to_string(port).c_str(), &hints, &result) || !result) return false;
    std::memcpy(&address.storage, result->ai_addr, result->ai_addrlen);
    address.size = static_cast<int>(result->ai_addrlen);
    address.family = result->ai_family;
    freeaddrinfo(result);
    return true;
}

int fail(const std::string& step, int error) {
    std::cout << "FAIL: " << step << " error " << error << std::endl;
    return 1;
}

// Returns 0 when connected, otherwise the Winsock error.
int connectWithin(SOCKET socketHandle, const Address& target, DWORD timeoutMilliseconds) {
    u_long nonBlocking = 1;
    if (ioctlsocket(socketHandle, FIONBIO, &nonBlocking)) return WSAGetLastError();
    if (!connect(socketHandle, reinterpret_cast<const sockaddr*>(&target.storage), target.size)) return 0;
    const int error = WSAGetLastError();
    if (error != WSAEWOULDBLOCK) return error;
    fd_set writers;
    fd_set failures;
    FD_ZERO(&writers);
    FD_ZERO(&failures);
    FD_SET(socketHandle, &writers);
    FD_SET(socketHandle, &failures);
    timeval wait{static_cast<long>(timeoutMilliseconds / 1000), static_cast<long>((timeoutMilliseconds % 1000) * 1000)};
    const int ready = select(0, nullptr, &writers, &failures, &wait);
    if (ready == 0) return WSAETIMEDOUT;
    if (ready < 0) return WSAGetLastError();
    int socketError = 0;
    int length = sizeof(socketError);
    getsockopt(socketHandle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socketError), &length);
    return FD_ISSET(socketHandle, &writers) && !socketError ? 0 : (socketError ? socketError : WSAECONNREFUSED);
}

int tcpProbe(const char* ip, const char* port, const char* timeout) {
    Address target;
    if (!parseAddress(ip, static_cast<unsigned short>(std::atoi(port)), target)) return fail("address", 0);
    SOCKET socketHandle = socket(target.family, SOCK_STREAM, IPPROTO_TCP);
    if (socketHandle == INVALID_SOCKET) return fail("socket", WSAGetLastError());
    const int error = connectWithin(socketHandle, target, static_cast<DWORD>(std::atoi(timeout)));
    closesocket(socketHandle);
    if (error) return fail("connect", error);
    std::cout << "PASS: connected to " << ip << ":" << port << std::endl;
    return 0;
}

int udpDnsProbe(const char* ip, const char* timeout) {
    Address target;
    if (!parseAddress(ip, 53, target)) return fail("address", 0);
    SOCKET socketHandle = socket(target.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socketHandle == INVALID_SOCKET) return fail("socket", WSAGetLastError());
    const unsigned char query[] = {0x5a, 0x17, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                                   7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
    if (sendto(socketHandle, reinterpret_cast<const char*>(query), sizeof(query), 0,
               reinterpret_cast<const sockaddr*>(&target.storage), target.size) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        closesocket(socketHandle);
        return fail("sendto", error);
    }
    fd_set readers;
    FD_ZERO(&readers);
    FD_SET(socketHandle, &readers);
    const DWORD milliseconds = static_cast<DWORD>(std::atoi(timeout));
    timeval wait{static_cast<long>(milliseconds / 1000), static_cast<long>((milliseconds % 1000) * 1000)};
    const int ready = select(0, &readers, nullptr, nullptr, &wait);
    if (ready <= 0) {
        const int error = ready ? WSAGetLastError() : WSAETIMEDOUT;
        closesocket(socketHandle);
        return fail("receive", error);
    }
    std::vector<char> reply(1500);
    const int received = recv(socketHandle, reply.data(), static_cast<int>(reply.size()), 0);
    const int error = received == SOCKET_ERROR ? WSAGetLastError() : 0;
    closesocket(socketHandle);
    if (received < 12 || reply[0] != 0x5a || reply[1] != 0x17) return fail("receive", error);
    std::cout << "PASS: DNS reply from " << ip << std::endl;
    return 0;
}

int udpListen(const char* ip, const char* port, const char* milliseconds) {
    Address local;
    if (!parseAddress(ip, static_cast<unsigned short>(std::atoi(port)), local)) return fail("address", 0);
    SOCKET socketHandle = socket(local.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socketHandle == INVALID_SOCKET) return fail("socket", WSAGetLastError());
    BOOL exclusive = TRUE;
    setsockopt(socketHandle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
    if (bind(socketHandle, reinterpret_cast<const sockaddr*>(&local.storage), local.size)) {
        const int error = WSAGetLastError();
        closesocket(socketHandle);
        return fail("bind", error);
    }
    std::cout << "READY" << std::endl;
    Sleep(static_cast<DWORD>(std::atoi(milliseconds)));
    closesocket(socketHandle);
    return 0;
}

int loopbackProbe(const char* ip) {
    Address listenAddress;
    if (!parseAddress(ip, 0, listenAddress)) return fail("address", 0);
    SOCKET listener = socket(listenAddress.family, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return fail("socket", WSAGetLastError());
    if (bind(listener, reinterpret_cast<const sockaddr*>(&listenAddress.storage), listenAddress.size) ||
        listen(listener, 1)) {
        const int error = WSAGetLastError();
        closesocket(listener);
        return fail("listen", error);
    }
    Address bound;
    bound.size = sizeof(bound.storage);
    bound.family = listenAddress.family;
    getsockname(listener, reinterpret_cast<sockaddr*>(&bound.storage), &bound.size);
    SOCKET client = socket(listenAddress.family, SOCK_STREAM, IPPROTO_TCP);
    const int error = client == INVALID_SOCKET ? WSAGetLastError() : connectWithin(client, bound, 3000);
    if (client != INVALID_SOCKET) closesocket(client);
    closesocket(listener);
    if (error) return fail("loopback connect", error);
    std::cout << "PASS: loopback connection on " << ip << std::endl;
    return 0;
}

int systemDns(const char* name, int count) {
    // Further lookups only raise more query events for the name; their answers are not reported.
    for (int extra = 1; extra < count; ++extra) {
        PDNS_RECORD records{};
        if (DnsQuery_A(name, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE, nullptr, &records, nullptr) == ERROR_SUCCESS) {
            DnsRecordListFree(records, DnsFreeRecordList);
        }
    }
    PDNS_RECORD records{};
    const DNS_STATUS status = DnsQuery_A(name, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE, nullptr,
                                         &records, nullptr);
    if (status != ERROR_SUCCESS) return fail("system DNS query", static_cast<int>(status));
    for (PDNS_RECORD record = records; record; record = record->pNext) {
        if (record->wType != DNS_TYPE_A) continue;
        in_addr value{};
        value.S_un.S_addr = record->Data.A.IpAddress;
        char text[INET_ADDRSTRLEN]{};
        InetNtopA(AF_INET, &value, text, sizeof(text));
        DnsRecordListFree(records, DnsFreeRecordList);
        std::cout << "PASS: ANSWER " << text << std::endl;
        return 0;
    }
    DnsRecordListFree(records, DnsFreeRecordList);
    return fail("system DNS answer", 0);
}

}  // namespace

int main(int argc, char** argv) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 2;
    int result = 2;
    if (argc == 5 && std::strcmp(argv[1], "tcp") == 0) result = tcpProbe(argv[2], argv[3], argv[4]);
    else if (argc == 4 && std::strcmp(argv[1], "udp-dns") == 0) result = udpDnsProbe(argv[2], argv[3]);
    else if (argc == 3 && std::strcmp(argv[1], "loopback") == 0) result = loopbackProbe(argv[2]);
    else if (argc == 5 && std::strcmp(argv[1], "udp-listen") == 0) result = udpListen(argv[2], argv[3], argv[4]);
    else if ((argc == 3 || argc == 4) && std::strcmp(argv[1], "system-dns") == 0) {
        result = systemDns(argv[2], argc == 4 ? std::clamp(std::atoi(argv[3]), 1, 50) : 1);
    }
    else std::cerr << "Usage: net-probe.exe tcp <ip> <port> <timeout-ms> | udp-dns <ip> <timeout-ms> | loopback <ip> | system-dns <name> [count]\n";
    WSACleanup();
    return result;
}
