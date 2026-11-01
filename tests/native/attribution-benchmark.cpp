// SPDX-License-Identifier: GPL-3.0-or-later
// In-memory contention benchmark of the production Hints implementation.
// No DNS sockets, ETW sessions, adapters or installed service are touched.
// Override BENCH_SOURCE to compare another checkout using the same harness.
#ifndef BENCH_SOURCE
#define BENCH_SOURCE "../../src/native/dns-dispatcher.cpp"
#endif
#define wmain productionEntryForAttributionBenchmark
#include BENCH_SOURCE
#undef wmain

static double cpuMilliseconds() {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) throw std::runtime_error("GetProcessTimes");
    const auto ticks = [](FILETIME value) { return (static_cast<unsigned long long>(value.dwHighDateTime) << 32) | value.dwLowDateTime; };
    return static_cast<double>(ticks(kernel) + ticks(user)) / 10000.0;
}
int wmain(int argc, wchar_t** argv) {
    const int events = argc > 1 ? _wtoi(argv[1]) : 10000;
    const int count = argc > 2 ? _wtoi(argv[2]) : 8;
    if (events < 1 || events > 1000000 || count < 1 || count > 64) return 1;
    Hints hints({L"c:\\apps\\selected.exe"}, std::chrono::milliseconds(3000), std::chrono::seconds(10));
    hints.setSentinelWriter([](unsigned long long) { return true; });
    std::vector<std::thread> workers;
    std::vector<int> answers(count);
    for (int i = 0; i < count; ++i) workers.emplace_back([&, i] {
        answers[i] = hints.take(L"absent-" + std::to_wstring(i) + L".invalid", 1).has_value() ? 2 : 1;
    });
    const auto waitDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (gHintWaiters < static_cast<unsigned>(count) && std::chrono::steady_clock::now() < waitDeadline) Sleep(1);
    if (gHintWaiters != static_cast<unsigned>(count)) {
        // Release even a late-starting worker before returning a fixture error.
        hints.sentinelProcessed(~0ULL);
        hints.flushChecked(~0ULL);
        for (auto& worker : workers) worker.join();
        return 2;
    }
    const auto started = std::chrono::steady_clock::now();
    const double cpu = cpuMilliseconds();
    for (int i = 0; i < events; ++i) {
        hints.addResolved(L"noise-" + std::to_wstring(i % 128) + L".invalid", 1, L"c:\\apps\\direct.exe");
        if (i % 257 == 0) hints.lostEvents();
    }
    const auto sequence = hints.lastSequence();
    hints.sentinelProcessed(sequence);
    hints.flushChecked(sequence);
    for (auto& worker : workers) worker.join();
    const auto elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    const double used = cpuMilliseconds() - cpu;
    for (int value : answers) if (value != 1) return 3;
    if (elapsed >= 5000) return 4;
    std::wcout << L"{\"events\":" << events << L",\"waiters\":" << count << L",\"cpu_ms\":" << used << L",\"wall_ms\":" << elapsed << L"}\n";
    return 0;
}
