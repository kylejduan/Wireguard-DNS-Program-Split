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

bool exchangeTest(const std::vector<char>& query, bool tcp, bool decoy = false) {
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
            sendDnsFrame(client.value, reply, deadline);
        } else {
            sockaddr_in peer{};
            int peerSize = sizeof(peer);
            std::vector<char> request(65535);
            const int received = recvfrom(listener.value, request.data(), static_cast<int>(request.size()), 0,
                                          reinterpret_cast<sockaddr*>(&peer), &peerSize);
            if (received != static_cast<int>(query.size())) return;
            if (decoy) {
                // A datagram with another transaction ID must not end the exchange.
                auto other = reply;
                other[1] ^= 1;
                sendto(listener.value, other.data(), static_cast<int>(other.size()), 0,
                       reinterpret_cast<sockaddr*>(&peer), peerSize);
            }
            sendto(listener.value, reply.data(), static_cast<int>(reply.size()), 0,
                   reinterpret_cast<sockaddr*>(&peer), peerSize);
        }
    });
    const auto answer = tcp ? tcpExchange(query, address(L"127.0.0.1", 0), endpoint)
                            : udpExchange(query, address(L"127.0.0.1", 0), endpoint);
    server.join();
    return answer && *answer == reply;
}

// A barrier that completes at once, as if every earlier event had been processed and checked for loss.
void immediateBarrier(Hints& hints) {
    hints.setSentinelWriter([&hints](unsigned long long sequence) {
        hints.sentinelProcessed(sequence);
        hints.flushChecked(sequence);
        return true;
    });
}

// A barrier whose sentinel is delivered after the selected application's query event for name.
void lateSelectedBarrier(Hints& hints, std::thread& late, const wchar_t* name) {
    hints.setSentinelWriter([&hints, &late, name](unsigned long long sequence) {
        late = std::thread([&hints, name, sequence] {
            Sleep(30);
            hints.addResolved(name, 1, L"c:\\apps\\selected.exe");
            hints.sentinelProcessed(sequence);
            hints.flushChecked(sequence);
        });
        return true;
    });
}

int barrierTest() {
    // The selected query's event is delivered after its packet, behind an earlier unlisted hint: TUNNEL.
    std::thread late;
    Hints ordered({L"c:\\apps\\selected.exe"});
    lateSelectedBarrier(ordered, late, L"order.example");
    ordered.addResolved(L"order.example", 1, L"c:\\apps\\direct.exe");
    const auto orderedRoute = ordered.take(L"order.example", 1);
    late.join();
    if (orderedRoute != std::optional<bool>(true)) return 41;
    // The same for a packet that would otherwise reuse an answered direct route.
    Hints reuse({L"c:\\apps\\selected.exe"});
    immediateBarrier(reuse);
    reuse.addResolved(L"reuse.example", 1, L"c:\\apps\\direct.exe");
    if (reuse.take(L"reuse.example", 1) != std::optional<bool>(false)) return 42;
    reuse.complete(L"reuse.example", 1);
    lateSelectedBarrier(reuse, late, L"reuse.example");
    bool reused = true;
    const auto reuseRoute = reuse.take(L"reuse.example", 1, &reused);
    late.join();
    if (reuseRoute != std::optional<bool>(true) || reused) return 43;
    // A barrier that does not complete in time refuses, even with direct evidence; so does one whose
    // sentinel arrived but whose loss check did not, and one whose sentinel could not be written.
    Hints stalled({L"c:\\apps\\selected.exe"}, std::chrono::milliseconds(3000), std::chrono::milliseconds(100));
    stalled.setSentinelWriter([](unsigned long long) { return true; });
    stalled.addResolved(L"stalled.example", 1, L"c:\\apps\\direct.exe");
    const auto stalledStart = std::chrono::steady_clock::now();
    if (stalled.take(L"stalled.example", 1).has_value()) return 44;
    const auto stalledFor = std::chrono::steady_clock::now() - stalledStart;
    if (stalledFor < std::chrono::milliseconds(90) || stalledFor > std::chrono::seconds(1)) return 45;
    stalled.setSentinelWriter([&stalled](unsigned long long sequence) {
        stalled.sentinelProcessed(sequence);
        return true;
    });
    if (stalled.take(L"stalled.example", 1).has_value()) return 46;
    stalled.setSentinelWriter([](unsigned long long) { return false; });
    if (stalled.take(L"stalled.example", 1).has_value()) return 47;
    // Tunnel evidence needs no barrier.
    stalled.addResolved(L"selected.example", 1, L"c:\\apps\\selected.exe");
    if (stalled.take(L"selected.example", 1) != std::optional<bool>(true)) return 48;
    // A selected query answered through the tunnel, then an unlisted event for the same name, then the
    // selected application's TCP fallback, which raises no event: still the tunnel.
    Hints fallback({L"c:\\apps\\selected.exe"});
    immediateBarrier(fallback);
    unsigned long long generation{};
    fallback.addResolved(L"fallback.example", 1, L"c:\\apps\\selected.exe");
    if (fallback.take(L"fallback.example", 1, nullptr, &generation) != std::optional<bool>(true)) return 56;
    fallback.complete(L"fallback.example", 1, generation);
    fallback.addResolved(L"fallback.example", 1, L"c:\\apps\\direct.exe");
    if (fallback.take(L"fallback.example", 1) != std::optional<bool>(true)) return 57;
    // A second selected hint merged during a tunnel exchange is not finalized by that exchange's answer,
    // so an unlisted event afterwards cannot turn its packet direct.
    Hints merged({L"c:\\apps\\selected.exe"}, std::chrono::milliseconds(0));
    immediateBarrier(merged);
    merged.addResolved(L"merged.example", 1, L"c:\\apps\\selected.exe");
    if (merged.take(L"merged.example", 1, nullptr, &generation) != std::optional<bool>(true)) return 58;
    merged.addResolved(L"merged.example", 1, L"c:\\apps\\selected.exe");
    merged.complete(L"merged.example", 1, generation);
    merged.addResolved(L"merged.example", 1, L"c:\\apps\\direct.exe");
    if (merged.take(L"merged.example", 1) != std::optional<bool>(true)) return 59;
    // A selected lookup merged into an in-flight direct one has its event seen before the answer is
    // delivered, which is then withheld; so is any answer whose barrier does not complete.
    Hints inFlightDirect({L"c:\\apps\\selected.exe"});
    immediateBarrier(inFlightDirect);
    inFlightDirect.addResolved(L"merge.example", 1, L"c:\\apps\\direct.exe");
    if (inFlightDirect.take(L"merge.example", 1) != std::optional<bool>(false) ||
        inFlightDirect.directAnswerUnsafe(L"merge.example", 1)) return 64;
    lateSelectedBarrier(inFlightDirect, late, L"merge.example");
    const bool mergedUnsafe = inFlightDirect.directAnswerUnsafe(L"merge.example", 1);
    late.join();
    if (!mergedUnsafe || inFlightDirect.take(L"merge.example", 1) != std::optional<bool>(true)) return 65;
    stalled.setSentinelWriter([](unsigned long long) { return false; });
    if (!stalled.directAnswerUnsafe(L"stalled.example", 1)) return 66;
    // ETW loss, or an overflow, while a direct exchange is outstanding: its answer is withheld.
    Hints lossDuring({L"c:\\apps\\selected.exe"});
    immediateBarrier(lossDuring);
    lossDuring.addResolved(L"loss.example", 1, L"c:\\apps\\direct.exe");
    if (lossDuring.take(L"loss.example", 1) != std::optional<bool>(false)) return 67;
    lossDuring.lostEvents();
    if (!lossDuring.directAnswerUnsafe(L"loss.example", 1)) return 68;
    Hints overflowDuring({L"c:\\apps\\selected.exe"});
    immediateBarrier(overflowDuring);
    overflowDuring.addResolved(L"overflow.example", 1, L"c:\\apps\\direct.exe");
    if (overflowDuring.take(L"overflow.example", 1) != std::optional<bool>(false)) return 69;
    overflowDuring.addResolved(std::wstring(300, L'x'), 1, L"c:\\apps\\selected.exe");
    if (!overflowDuring.directAnswerUnsafe(L"overflow.example", 1)) return 70;
    // With no hint once the barrier completes, the query is refused at once rather than after the timeout.
    Hints none({L"c:\\apps\\selected.exe"});
    immediateBarrier(none);
    const auto noneStart = std::chrono::steady_clock::now();
    if (none.take(L"none.example", 1).has_value()) return 49;
    if (std::chrono::steady_clock::now() - noneStart > std::chrono::milliseconds(100)) return 50;
    return 0;
}

// A UDP endpoint on 127.0.0.1 answering every query while answering is set: as a plain answer, or with
// the truncation bit. Unset, it takes datagrams and never answers.
struct TestResolver {
    SocketOwner udp{socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)};
    sockaddr_in endpoint{};
    std::atomic_bool answering;
    std::atomic_bool truncate{};
    std::atomic_bool done{};
    std::thread server;
    explicit TestResolver(bool answers) : answering(answers) {
        endpoint = address(L"127.0.0.1", 0);
        if (bind(udp.value, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint))) return;
        int size = sizeof(endpoint);
        getsockname(udp.value, reinterpret_cast<sockaddr*>(&endpoint), &size);
        nonblocking(udp.value);
        server = std::thread([this] {
            while (!done) {
                if (!answering || !socketReady(udp.value, false, afterMilliseconds(50))) {
                    if (!answering) Sleep(20);
                    continue;
                }
                std::vector<char> request(512);
                sockaddr_in peer{};
                int peerSize = sizeof(peer);
                const int received = recvfrom(udp.value, request.data(), static_cast<int>(request.size()), 0,
                                              reinterpret_cast<sockaddr*>(&peer), &peerSize);
                if (received <= 0) continue;
                request.resize(received);
                request[2] = static_cast<char>(static_cast<unsigned char>(request[2]) | 0x80 | (truncate ? 0x02 : 0));
                sendto(udp.value, request.data(), received, 0, reinterpret_cast<sockaddr*>(&peer), peerSize);
            }
        });
    }
    ~TestResolver() {
        done = true;
        if (server.joinable()) server.join();
    }
};

// A TCP listener that takes connections into its backlog and never accepts or answers them.
struct SilentTcp {
    SocketOwner listener{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
    explicit SilentTcp(sockaddr_in endpoint) {
        bind(listener.value, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint));
        listen(listener.value, 16);
    }
};

long long millisecondsSince(std::chrono::steady_clock::time_point started) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
}

// The direct route passes over a physical resolver that takes datagrams and never answers, prefers the one
// that answered, and under continuous traffic still re-probes the first-listed one within the window. Every
// upstream attempt for a query, over every resolver and transport, stays within one deadline.
int failoverTest(const std::vector<char>& query) {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return 80;
    struct Cleanup { ~Cleanup() { WSACleanup(); } } cleanup;
    TestResolver primary(false);
    TestResolver secondary(true);
    if (!primary.endpoint.sin_port || !secondary.endpoint.sin_port) return 81;
    DirectResolvers state(std::chrono::milliseconds(600));
    const std::vector<sockaddr_in> resolvers{primary.endpoint, secondary.endpoint};
    const auto exchange = [&](size_t& answeredBy) {
        const auto started = std::chrono::steady_clock::now();
        const auto response = directExchange(query, address(L"127.0.0.1", 0), resolvers, state,
                                             [](auto&&... arguments) { return udpExchange(arguments...); }, upstreamDeadline(),
                                             &answeredBy);
        return response ? millisecondsSince(started) : -1LL;
    };
    size_t answeredBy = 9;
    const long long first = exchange(answeredBy);
    if (first < 1000 || first > 2500 || answeredBy != 1) return 82;
    const long long preferred = exchange(answeredBy);
    if (preferred < 0 || preferred > 500 || answeredBy != 1) return 83;
    // The primary recovers while queries keep arriving faster than the window: it is used again within it.
    primary.answering = true;
    const auto recovering = std::chrono::steady_clock::now();
    while (millisecondsSince(recovering) < 3000) {
        if (exchange(answeredBy) < 0) return 84;
        if (answeredBy == 0) break;
        Sleep(100);
    }
    if (answeredBy != 0 || millisecondsSince(recovering) > 1500) return 85;

    // Two silent resolvers and a third that answers truncated and never over TCP: the TCP completion gets
    // only what is left of the query's four seconds, not four more.
    TestResolver silentA(false), silentB(false), truncating(true);
    truncating.truncate = true;
    SilentTcp truncatingTcp(truncating.endpoint);
    Routes routes{};
    routes.directSource = address(L"127.0.0.1", 0);
    routes.directDns = {silentA.endpoint, silentB.endpoint, truncating.endpoint};
    DirectResolvers fresh;
    bool completed = false;
    size_t resolverIndex = 0;
    auto started = std::chrono::steady_clock::now();
    const auto truncated = exchangeUdpRoute(query, false, routes, fresh, completed, resolverIndex);
    const long long udpRoute = millisecondsSince(started);
    if (!truncated || completed || resolverIndex != 2 || udpRoute > kDirectBudgetMilliseconds + 400) return 86;
    // A TCP query to resolvers that never answer over TCP or UDP: one deadline for both transports.
    SilentTcp tcpA(silentA.endpoint), tcpB(silentB.endpoint);
    routes.directDns = {silentA.endpoint, silentB.endpoint};
    started = std::chrono::steady_clock::now();
    const auto none = exchangeTcpRoute(query, false, routes, fresh);
    const long long tcpRoute = millisecondsSince(started);
    if (none || tcpRoute > kDirectBudgetMilliseconds + 400 || tcpRoute < kDirectBudgetMilliseconds - 400) return 87;
    // TCP silent on both resolvers, UDP silent on the first and answering on the second: the UDP fallback
    // shares what is left between them, so the second still answers within the deadline.
    TestResolver udpOnly(true);
    SilentTcp udpOnlyTcp(udpOnly.endpoint);
    routes.directDns = {silentA.endpoint, udpOnly.endpoint};
    DirectResolvers fallbackState;
    started = std::chrono::steady_clock::now();
    const auto fallback = exchangeTcpRoute(query, false, routes, fallbackState);
    if (!fallback || millisecondsSince(started) > kDirectBudgetMilliseconds + 400) return 89;
    return 0;
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
    // A whole answer replaces a truncated one only within the size the client advertised.
    if (advertisedUdpSize(query) != 512) return 60;
    auto withEdns = query;
    withEdns[11] = 1;
    withEdns.insert(withEdns.end(), {0, 0, 41, 0x04, static_cast<char>(0xd0), 0, 0, 0, 0, 0, 0});
    if (advertisedUdpSize(withEdns) != 1232) return 61;
    withEdns[withEdns.size() - 8] = 0;
    withEdns[withEdns.size() - 7] = 100;
    if (advertisedUdpSize(withEdns) != 512) return 62;
    withEdns.resize(withEdns.size() - 3);
    if (advertisedUdpSize(withEdns) != 512) return 63;
    if (!parsed || parsed->name != L"example.com" || parsed->type != 1) return 1;
    if (normalizeName(L"Example.COM.") != L"example.com") return 2;
    const auto included = parseIncludedText(L"  C:\\Apps\\One.exe\r\n# comment\nC:\\Apps\\Two.exe\n");
    if (included.size() != 2 || !included.contains(L"c:\\apps\\one.exe") ||
        !included.contains(L"c:\\apps\\two.exe")) return 3;
    // An identity record is accepted only whole: every row has an entry, a path and hexadecimal identifiers.
    const auto record = parseIncludedText(L"# wgps-identities 1\nC:\\A\\One.exe\tC:\\A\\One.exe\t0a0b,0C0d\n");
    if (record.size() != 1 || !record.contains(L"c:\\a\\one.exe")) return 51;
    if (!parseIncludedText(L"# wgps-identities 1\n").empty()) return 52;
    for (const wchar_t* damaged : {L"# wgps-identities 1\nC:\\A\\One.exe\tC:\\A\\One.exe\t0a0b",
                                   L"# wgps-identities 1\nC:\\A\\One.exe\t\t0a0b\n",
                                   L"# wgps-identities 1\n\tC:\\A\\One.exe\t0a0b\n",
                                   L"# wgps-identities 1\nC:\\A\\One.exe\tC:\\A\\One.exe\n",
                                   L"# wgps-identities 1\nC:\\A\\One.exe\tC:\\A\\One.exe\t0a0\n",
                                   L"# wgps-identities 1\nC:\\A\\One.exe\tC:\\A\\One.exe\t0a,,0b\n",
                                   L"# wgps-identities 1\nC:\\A\\One.exe\tC:\\A\\One.exe\tzz\n",
                                   L"# wgps-identities 1\n\n"}) {
        try {
            parseIncludedText(damaged);
            return 53;
        } catch (const std::runtime_error&) {
        }
    }
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
    immediateBarrier(precedence);
    // An event whose process could not be identified (it may have exited before the event was read) makes
    // the name unsafe for direct routing in either order with an unlisted event; tunnel evidence still routes.
    precedence.addResolved(L"precedence.example", 1, L"");
    if (precedence.take(L"precedence.example", 1).has_value()) return 9;
    precedence.addResolved(L"precedence.example", 1, L"c:\\apps\\direct.exe");
    if (precedence.take(L"precedence.example", 1).has_value()) return 10;
    Hints unknownLater({L"c:\\apps\\selected.exe"});
    immediateBarrier(unknownLater);
    unknownLater.addResolved(L"later.example", 1, L"c:\\apps\\direct.exe");
    unknownLater.addResolved(L"later.example", 1, L"");
    if (unknownLater.take(L"later.example", 1).has_value()) return 71;
    // The uncertainty outlasts a completed exchange and a newer unlisted event.
    Hints unknownKept({L"c:\\apps\\selected.exe"}, std::chrono::milliseconds(0));
    immediateBarrier(unknownKept);
    unknownKept.addResolved(L"kept.example", 1, L"");
    unknownKept.addResolved(L"kept.example", 1, L"c:\\apps\\selected.exe");
    if (unknownKept.take(L"kept.example", 1) != std::optional<bool>(true)) return 72;
    unknownKept.complete(L"kept.example", 1);
    unknownKept.addResolved(L"kept.example", 1, L"c:\\apps\\direct.exe");
    if (unknownKept.take(L"kept.example", 1).has_value()) return 73;
    // The reusable route expires before the quarantine does, and taking the expired route keeps it:
    // a later unlisted event still cannot route or answer directly.
    Hints unknownReuse({L"c:\\apps\\selected.exe"}, std::chrono::milliseconds(50));
    immediateBarrier(unknownReuse);
    unsigned long long reuseGeneration{};
    unknownReuse.addResolved(L"reuse.example", 1, L"");
    unknownReuse.addResolved(L"reuse.example", 1, L"c:\\apps\\selected.exe");
    if (unknownReuse.take(L"reuse.example", 1, nullptr, &reuseGeneration) != std::optional<bool>(true)) return 76;
    unknownReuse.complete(L"reuse.example", 1, reuseGeneration);
    Sleep(80);
    if (unknownReuse.take(L"reuse.example", 1).has_value()) return 77;
    unknownReuse.addResolved(L"reuse.example", 1, L"c:\\apps\\direct.exe");
    if (unknownReuse.take(L"reuse.example", 1).has_value() || !unknownReuse.directAnswerUnsafe(L"reuse.example", 1)) return 78;
    // Lost events keep an entry under quarantine as well.
    unknownReuse.lostEvents();
    unknownReuse.addResolved(L"reuse.example", 1, L"c:\\apps\\direct.exe");
    if (!unknownReuse.directAnswerUnsafe(L"reuse.example", 1)) return 79;
    // An unidentified event during an outstanding direct exchange withholds its answer.
    Hints unknownDuring({L"c:\\apps\\selected.exe"});
    immediateBarrier(unknownDuring);
    unknownDuring.addResolved(L"during.example", 1, L"c:\\apps\\direct.exe");
    if (unknownDuring.take(L"during.example", 1) != std::optional<bool>(false)) return 74;
    unknownDuring.addResolved(L"during.example", 1, L"");
    if (!unknownDuring.directAnswerUnsafe(L"during.example", 1)) return 75;
    precedence.addResolved(L"precedence.example", 1, L"c:\\apps\\selected.exe");
    const auto tunnel = precedence.take(L"precedence.example", 1);
    if (!tunnel || !*tunnel) return 11;
    // A repeat without a new event reuses the answered route inside the window ...
    precedence.complete(L"precedence.example", 1);
    bool reused = false;
    const auto repeat = precedence.take(L"precedence.example", 1, &reused);
    if (!repeat || !*repeat || !reused) return 19;
    // ... and a newer direct event within the reuse window of an answered selected exchange keeps the
    // tunnel: that application may still retransmit or fall back to TCP without a new event.
    precedence.addResolved(L"precedence.example", 1, L"c:\\apps\\direct.exe");
    const auto replaced = precedence.take(L"precedence.example", 1, &reused);
    if (!replaced || !*replaced || reused) return 20;
    // A selected hint that arrives while a direct query is in flight is not overridden by
    // that query's completion, nor discarded by a newer unlisted event after it.
    Hints inFlight({L"c:\\apps\\selected.exe"});
    immediateBarrier(inFlight);
    inFlight.addResolved(L"race.example", 1, L"c:\\apps\\direct.exe");
    const auto first = inFlight.take(L"race.example", 1);
    if (!first || *first) return 33;
    inFlight.addResolved(L"race.example", 1, L"c:\\apps\\selected.exe");
    inFlight.complete(L"race.example", 1);
    const auto selectedAfter = inFlight.take(L"race.example", 1, &reused);
    if (!selectedAfter || !*selectedAfter || reused) return 34;
    inFlight.complete(L"race.example", 1);
    inFlight.addResolved(L"race.example", 1, L"c:\\apps\\direct.exe");
    const auto second = inFlight.take(L"race.example", 1);
    if (!second || !*second) return 35;
    inFlight.addResolved(L"race.example", 1, L"c:\\apps\\selected.exe");
    inFlight.complete(L"race.example", 1);
    inFlight.addResolved(L"race.example", 1, L"c:\\apps\\direct.exe");
    const auto carried = inFlight.take(L"race.example", 1);
    if (!carried || !*carried) return 36;
    // Outside the window an answered repeat is still blocked, and a newer direct event goes direct.
    Hints noReuse({L"c:\\apps\\selected.exe"}, std::chrono::milliseconds(0));
    immediateBarrier(noReuse);
    noReuse.addResolved(L"window.example", 1, L"c:\\apps\\selected.exe");
    if (noReuse.take(L"window.example", 1) != std::optional<bool>(true)) return 54;
    noReuse.complete(L"window.example", 1);
    noReuse.addResolved(L"window.example", 1, L"c:\\apps\\direct.exe");
    if (noReuse.take(L"window.example", 1) != std::optional<bool>(false)) return 55;
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
    immediateBarrier(bounded);
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
    // Lost ETW events discard direct evidence and refuse even later direct hints, but keep
    // tunnel hints and tunnel routing.
    Hints lost({L"selected.exe"});
    immediateBarrier(lost);
    lost.addResolved(L"direct.example", 1, L"direct.exe");
    if (lost.take(L"direct.example", 1) != std::optional<bool>(false)) return 32;
    lost.complete(L"direct.example", 1);
    lost.addResolved(L"tunnel.example", 1, L"selected.exe");
    lost.lostEvents();
    if (lost.take(L"tunnel.example", 1) != std::optional<bool>(true)) return 37;
    if (lost.take(L"direct.example", 1).has_value()) return 38;
    lost.addResolved(L"later.example", 1, L"direct.exe");
    if (lost.take(L"later.example", 1).has_value()) return 39;
    lost.addResolved(L"later.example", 1, L"selected.exe");
    if (lost.take(L"later.example", 1) != std::optional<bool>(true)) return 40;
    {
        // The refusals these cases provoke are logged; keep them out of the test's output.
        wchar_t directory[MAX_PATH + 1]{};
        GetTempPathW(MAX_PATH + 1, directory);
        gLog = std::make_unique<wgps::BoundedLog>(std::filesystem::path(directory) / L"wgps-dispatcher-self-test.log");
        const int barrier = barrierTest();
        gLog.reset();
        if (barrier) return barrier;
    }
    if (const int failover = failoverTest(query)) return failover;
    // A resolver list is one to three distinct IPv4 addresses, or the input is rejected whole.
    if (resolverList(L"192.0.2.1,198.51.100.2").size() != 2 || resolverList(L"192.0.2.1").size() != 1) return 86;
    for (const wchar_t* malformed : {L"", L"192.0.2.1,", L",192.0.2.1", L"192.0.2.1,192.0.2.1", L"192.0.2.1;192.0.2.2",
                                     L"192.0.2.1,192.0.2.2,192.0.2.3,192.0.2.4", L"999.0.2.1", L"192.0.2.1, 192.0.2.2"}) {
        try {
            resolverList(malformed);
            return 88;
        } catch (const std::runtime_error&) {
        }
    }
    if (!socketDeadlineTest()) return 28;
    if (!exchangeTest(query, false) || !exchangeTest(query, true) || !exchangeTest(query, false, true)) return 29;
    auto largeQuery = query;
    largeQuery.resize(65507, 0); // Maximum IPv4 UDP payload, also a large TCP frame.
    if (!exchangeTest(largeQuery, false) || !exchangeTest(largeQuery, true)) return 30;
    largeQuery.resize(65535, 0);
    if (!exchangeTest(largeQuery, true)) return 31;
    if (gHintWaiters.load()) return 30;
    std::wcout << L"PASS: DNS parsing, attribution capacity/recovery, the ordering barrier, physical resolver failover, and real socket deadlines.\n";
    return 0;
}

