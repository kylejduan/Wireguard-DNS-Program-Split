// SPDX-License-Identifier: GPL-3.0-or-later
// Private implementation fragment of dns-dispatcher.cpp.
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
    std::wcout << L"PASS: DNS question parser.\n";
    return 0;
}

