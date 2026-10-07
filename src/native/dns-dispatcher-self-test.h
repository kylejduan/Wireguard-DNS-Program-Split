// SPDX-License-Identifier: GPL-3.0-or-later
// Private implementation fragment of dns-dispatcher.cpp.
bool socketDeadlineTest() {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return false;
    struct Cleanup { ~Cleanup() { WSACleanup(); } } cleanup;
    SocketOwner listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    auto endpoint = address(L"127.0.0.1", 0);
    if (bind(listener.value, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) || listen(listener.value, 1)) return false;
    int size = sizeof(endpoint);
    if (getsockname(listener.value, reinterpret_cast<sockaddr*>(&endpoint), &size)) return false;
    SocketOwner sender(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (!nonblocking(sender.value) || !connectBefore(sender.value, endpoint, afterMilliseconds(1000))) return false;
    SocketOwner receiver(accept(listener.value, nullptr, nullptr));
    if (receiver.value == INVALID_SOCKET || !nonblocking(receiver.value)) return false;
    // A peer making steady partial progress cannot extend the total transfer deadline.
    std::atomic_bool done{};
    std::thread trickle([&] {
        while (!done) {
            if (send(sender.value, "x", 1, 0) != 1) break;
            Sleep(20);
        }
    });
    char data[100]{};
    const auto start = std::chrono::steady_clock::now();
    const bool completed = receiveAll(receiver.value, data, sizeof(data), afterMilliseconds(120));
    const auto elapsed = std::chrono::steady_clock::now() - start;
    done = true;
    trickle.join();
    if (completed || elapsed > std::chrono::seconds(1)) return false;
    // Shutdown interrupts an otherwise long I/O deadline.
    gRunning = false;
    const bool stopped = !receiveAll(receiver.value, data, sizeof(data), afterMilliseconds(5000));
    gRunning = true;
    return stopped;
}

bool exchangeTest(const std::vector<char>& query, bool tcp) {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return false;
    struct Cleanup { ~Cleanup() { WSACleanup(); } } cleanup;
    SocketOwner listener(socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, tcp ? IPPROTO_TCP : IPPROTO_UDP));
    auto endpoint = address(L"127.0.0.1", 0);
    if (!nonblocking(listener.value) || bind(listener.value, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint))) return false;
    int length = sizeof(endpoint);
    if (getsockname(listener.value, reinterpret_cast<sockaddr*>(&endpoint), &length) || (tcp && listen(listener.value, 1))) return false;
    auto reply = query;
    reply[2] = static_cast<char>(0x80);
    std::thread server([&] {
        const auto deadline = afterMilliseconds(1500);
        if (!socketReady(listener.value, false, deadline)) return;
        if (tcp) {
            SocketOwner client(accept(listener.value, nullptr, nullptr));
            if (!nonblocking(client.value)) return;
            uint16_t size{};
            if (!receiveAll(client.value, reinterpret_cast<char*>(&size), sizeof(size), deadline)) return;
            std::vector<char> request(ntohs(size));
            if (!receiveAll(client.value, request.data(), static_cast<int>(request.size()), deadline) || request != query) return;
            size = htons(static_cast<uint16_t>(reply.size()));
            sendAll(client.value, reinterpret_cast<const char*>(&size), sizeof(size), deadline);
            sendAll(client.value, reply.data(), static_cast<int>(reply.size()), deadline);
        } else {
            sockaddr_in peer{};
            int peerSize = sizeof(peer);
            std::vector<char> request(65535);
            const int received = recvfrom(listener.value, request.data(), static_cast<int>(request.size()), 0,
                                          reinterpret_cast<sockaddr*>(&peer), &peerSize);
            if (received != static_cast<int>(query.size())) return;
            sendto(listener.value, reply.data(), static_cast<int>(reply.size()), 0,
                   reinterpret_cast<sockaddr*>(&peer), peerSize);
        }
    });
    const auto answer = tcp ? tcpExchange(query, address(L"127.0.0.1", 0), endpoint)
                            : udpExchange(query, address(L"127.0.0.1", 0), endpoint);
    server.join();
    return answer && *answer == reply;
}

int selfTest() {
    std::vector<char> query(12, 0);
    query[5] = 1;
    for (const std::string& label : {std::string("example"), std::string("com")}) {
        query.push_back(static_cast<char>(label.size()));
        query.insert(query.end(), label.begin(), label.end());
    }
    query.insert(query.end(), {0, 0, 1, 0, 1});
    auto parsed = parseQuestion(query);
    if (!parsed || parsed->name != L"example.com" || parsed->type != 1) return 1;
    if (normalizeName(L"Example.COM.") != L"example.com") return 2;
    const auto included = parseIncludedText(L"  C:\\Apps\\One.exe\r\n# comment\nC:\\Apps\\Two.exe\n");
    if (included.size() != 2 || !included.contains(L"c:\\apps\\one.exe") ||
        !included.contains(L"c:\\apps\\two.exe")) return 3;
    const auto failure = makeServfail(query);
    if (failure.size() != query.size() || !(static_cast<unsigned char>(failure[2]) & 0x80) ||
        (static_cast<unsigned char>(failure[3]) & 0x0f) != 2) return 4;
    auto matching = query;
    matching[2] = static_cast<char>(0x80);
    if (!matchingResponse(query, matching)) return 5;
    matching[1] ^= 1;
    if (matchingResponse(query, matching)) return 6;
    auto answer = matching;
    answer[1] ^= 1;
    answer[6] = 0;
    answer[7] = 1;
    answer.insert(answer.end(), {static_cast<char>(0xc0), 0x0c, 0, 1, 0, 1,
                                 0, 0, 1, 44, 0, 4, 1, 2, 3, 4});
    if (!zeroResponseTtls(answer) || answer[answer.size() - 10] || answer[answer.size() - 9] ||
        answer[answer.size() - 8] || answer[answer.size() - 7]) return 7;
    const auto firstPath = processPath(GetCurrentProcessId());
    const auto cachedPath = processPath(GetCurrentProcessId());
    if (firstPath.empty() || firstPath != cachedPath) return 8;
    Hints precedence({L"c:\\apps\\selected.exe"});
    precedence.addResolved(L"precedence.example", 1, L"");
    if (precedence.take(L"precedence.example", 1).has_value()) return 9;
    precedence.addResolved(L"precedence.example", 1, L"c:\\apps\\direct.exe");
    const auto direct = precedence.take(L"precedence.example", 1);
    if (!direct || *direct) return 10;
    precedence.addResolved(L"precedence.example", 1, L"c:\\apps\\selected.exe");
    const auto tunnel = precedence.take(L"precedence.example", 1);
    if (!tunnel || !*tunnel) return 11;
    // A repeat without a new event reuses the answered route inside the window ...
    precedence.complete(L"precedence.example", 1);
    bool reused = false;
    const auto repeat = precedence.take(L"precedence.example", 1, &reused);
    if (!repeat || !*repeat || !reused) return 19;
    // ... and a newer direct event after the answer replaces it.
    precedence.addResolved(L"precedence.example", 1, L"c:\\apps\\direct.exe");
    const auto replaced = precedence.take(L"precedence.example", 1, &reused);
    if (!replaced || *replaced || reused) return 20;
    // Outside the window an answered repeat is still blocked.
    Hints noReuse({L"c:\\apps\\selected.exe"}, std::chrono::milliseconds(0));
    noReuse.addResolved(L"blocked.example", 1, L"c:\\apps\\direct.exe");
    if (!noReuse.take(L"blocked.example", 1).has_value()) return 21;
    noReuse.complete(L"blocked.example", 1);
    if (noReuse.take(L"blocked.example", 1, &reused).has_value() || reused) return 22;
    for (unsigned i = 0; i < kMaxWorkers; ++i) {
        if (!acquireWorker()) return 12;
    }
    if (acquireWorker()) return 13;
    for (unsigned i = 0; i < kMaxWorkers; ++i) gActiveWorkers.fetch_sub(1);
    if (gActiveWorkers.load()) return 14;
    if (qpcElapsedMilliseconds(1500, 1000, 1000) != 500) return 15;
    if (qpcElapsedMilliseconds(999, 1000, 1000) != -1) return 16;
    if (qpcElapsedMilliseconds(1500, 1000, 0) != -1) return 17;
    if (qpcElapsedMilliseconds(0, 0, 1000) != -1) return 18;
    Hints bounded({L"selected.exe"});
    for (size_t i = 0; i < Hints::kMaxHints; ++i) {
        if (!bounded.addResolved(L"host" + std::to_wstring(i), 1, L"direct.exe")) return 23;
    }
    if (bounded.addResolved(L"overflow", 1, L"selected.exe")) return 24;
    // Neither a cached direct route nor a later direct hint may bypass overload quarantine.
    bounded.addResolved(L"host0", 1, L"direct.exe");
    if (bounded.take(L"host0", 1).has_value()) return 25;
    Sleep(10100);
    if (!bounded.addResolved(L"recovered", 1, L"selected.exe")) return 26;
    const auto recovered = bounded.take(L"recovered", 1);
    if (!recovered || !*recovered) return 27;
    if (!socketDeadlineTest()) return 28;
    if (!exchangeTest(query, false) || !exchangeTest(query, true)) return 29;
    std::wcout << L"PASS: DNS parsing, attribution capacity/recovery, and real socket deadlines.\n";
    return 0;
}

