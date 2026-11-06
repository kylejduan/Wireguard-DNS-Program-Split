// SPDX-License-Identifier: GPL-3.0-or-later
// Disposable Windows CI only: open-loop DNS Client traffic, not one process per
// lookup. Uses unique names below the fixture's NRPT namespace and no server override.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {
// Windows SDK v1 layouts, named locally because older MinGW headers omit the
// request and cancellation types. DNS_QUERY_RESULT is supplied by windns.h.
struct Request {
    ULONG version;
    PCWSTR name;
    WORD type;
    ULONG64 options;
    void* servers;
    ULONG interfaceIndex;
    PDNS_QUERY_COMPLETION_ROUTINE callback;
    void* context;
};
struct Cancel { char reserved[32]{}; };
static_assert(sizeof(Request) == 64 && sizeof(Cancel) == 32);
using QueryEx = DNS_STATUS(WINAPI*)(Request*, DNS_QUERY_RESULT*, Cancel*);
using CancelQuery = DNS_STATUS(WINAPI*)(Cancel*);
using Clock = std::chrono::steady_clock;
struct Query {
    std::wstring name;
    DNS_QUERY_RESULT result{};
    Cancel cancel;
    Clock::time_point started;
    std::atomic_flag finishing{};
    std::atomic_bool done{};
    DNS_STATUS status{};
    DWORD address{};
    double milliseconds{};
};

void WINAPI completed(void* context, DNS_QUERY_RESULT* result) {
    auto& query = *static_cast<Query*>(context);
    if (query.finishing.test_and_set()) return;
    query.status = result->QueryStatus;
    for (PDNS_RECORD record = result->pQueryRecords; record; record = record->pNext) {
        if (record->wType == DNS_TYPE_A) { query.address = ntohl(record->Data.A.IpAddress); break; }
    }
    if (result->pQueryRecords) DnsRecordListFree(result->pQueryRecords, DnsFreeRecordList);
    query.milliseconds = std::chrono::duration<double, std::milli>(Clock::now() - query.started).count();
    query.done.store(true, std::memory_order_release);
}

int load(const std::wstring& prefix, const std::wstring& zone, unsigned rate, unsigned seconds) {
    HMODULE dns = GetModuleHandleW(L"dnsapi.dll");
    const auto queryEx = reinterpret_cast<QueryEx>(reinterpret_cast<void*>(GetProcAddress(dns, "DnsQueryEx")));
    const auto cancelQuery = reinterpret_cast<CancelQuery>(reinterpret_cast<void*>(GetProcAddress(dns, "DnsCancelQuery")));
    if (!queryEx || !cancelQuery) return 2;
    std::vector<std::unique_ptr<Query>> queries;
    queries.reserve(rate * seconds);
    const auto start = Clock::now();
    for (unsigned i = 0; i < rate * seconds; ++i) {
        const auto due = start + std::chrono::microseconds(1000000ULL * i / rate);
        while (Clock::now() < due) Sleep(1);
        auto query = std::make_unique<Query>();
        query->name = prefix + L"-" + std::to_wstring(i) + L"." + zone;
        query->result.Version = DNS_QUERY_RESULTS_VERSION1;
        query->started = Clock::now();
        Request request{DNS_QUERY_REQUEST_VERSION1, query->name.c_str(), DNS_TYPE_A,
                        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE, nullptr, 0, completed, query.get()};
        const auto status = queryEx(&request, &query->result, &query->cancel);
        if (status != DNS_REQUEST_PENDING) {
            query->result.QueryStatus = status;
            completed(query.get(), &query->result);
        }
        queries.push_back(std::move(query));
    }
    const double launchSeconds = std::chrono::duration<double>(Clock::now() - start).count();
    const auto deadline = Clock::now() + std::chrono::seconds(20);
    auto allDone = [&] {
        return std::all_of(queries.begin(), queries.end(), [](const auto& q) { return q->done.load(std::memory_order_acquire); });
    };
    while (!allDone() && Clock::now() < deadline) Sleep(10);
    for (auto& query : queries) if (!query->done.load(std::memory_order_acquire)) cancelQuery(&query->cancel);
    const auto cancelDeadline = Clock::now() + std::chrono::seconds(5);
    while (!allDone() && Clock::now() < cancelDeadline) Sleep(10);
    // Pending callbacks still own their request/result memory. Exit without
    // unwinding that memory if the DNS API does not honor its cancellation.
    if (!allDone()) { std::cerr << "DNS callbacks did not drain\n"; ExitProcess(3); }
    unsigned successes{}, directAnswers{}, tunnelAnswers{};
    std::vector<double> times;
    for (const auto& query : queries) {
        if (query->status != ERROR_SUCCESS || !query->address) continue;
        ++successes;
        directAnswers += query->address == 0xc0000202;
        tunnelAnswers += query->address == 0xc0000201;
        times.push_back(query->milliseconds);
    }
    std::sort(times.begin(), times.end());
    const double p99 = times.empty() ? 0 : times[(times.size() * 99 + 99) / 100 - 1];
    std::cout << "{\"started\":" << queries.size() << ",\"successes\":" << successes
              << ",\"directAnswers\":" << directAnswers << ",\"tunnelAnswers\":" << tunnelAnswers
              << ",\"launch_seconds\":" << launchSeconds << ",\"p99_ms\":" << p99 << "}\n";
    return 0;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 5 && argc != 6) return 2;
    const unsigned rate = static_cast<unsigned>(_wtoi(argv[3]));
    const unsigned seconds = static_cast<unsigned>(_wtoi(argv[4]));
    if (!rate || rate > 200 || !seconds || seconds > 20) return 2;
    if (argc == 6) {
        if (std::wstring(argv[5]) != L"--warm") return 2;
        const std::wstring name = L"warm-" + std::wstring(argv[1]) + L"." + argv[2];
        PDNS_RECORDW records{};
        const auto status = DnsQuery_W(name.c_str(), DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
                                      nullptr, &records, nullptr);
        if (records) DnsRecordListFree(reinterpret_cast<PDNS_RECORD>(records), DnsFreeRecordList);
        if (status != ERROR_SUCCESS) return 4;
        std::cerr << "READY pid=" << GetCurrentProcessId() << std::endl;
    }
    return load(argv[1], argv[2], rate, seconds);
}
