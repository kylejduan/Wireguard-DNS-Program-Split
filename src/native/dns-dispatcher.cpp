// SPDX-License-Identifier: GPL-3.0-or-later
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cwctype>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <memory>
#include "bounded-log.h"

namespace {

constexpr GUID kDnsClientProvider{0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};
constexpr USHORT kQueryEvent = 3006;
constexpr unsigned kMaxWorkers = 256;
constexpr ULONG kProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD |
                                    PROCESS_TRACE_MODE_RAW_TIMESTAMP;
static_assert(kProcessTraceMode & PROCESS_TRACE_MODE_RAW_TIMESTAMP);
std::atomic_bool gRunning{true};
std::atomic<HANDLE> gTraceFlushRequested{nullptr};
std::atomic_uint gActiveWorkers{};
SOCKET gUdpListener{INVALID_SOCKET};
SOCKET gTcpListener{INVALID_SOCKET};
std::mutex gLogMutex;
std::unique_ptr<wgps::BoundedLog> gLog;
std::mutex gProcessCacheMutex;

struct CachedProcess {
    ULONGLONG creationTime{};
    std::wstring path;
};

std::unordered_map<DWORD, CachedProcess> gProcessCache;

bool acquireWorker() {
    if (gActiveWorkers.fetch_add(1) < kMaxWorkers) return true;
    gActiveWorkers.fetch_sub(1);
    return false;
}

struct WorkerLease {
    ~WorkerLease() { gActiveWorkers.fetch_sub(1); }
};

void check(DWORD status, const char* operation) {
    if (status != ERROR_SUCCESS) throw std::runtime_error(std::string(operation) + " failed: " + std::to_string(status));
}

std::wstring lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return std::towlower(c); });
    return value;
}

std::wstring trim(std::wstring value) {
    const auto first = value.find_first_not_of(L" \t\r");
    if (first == std::wstring::npos) return {};
    const auto last = value.find_last_not_of(L" \t\r");
    return value.substr(first, last - first + 1);
}

std::wstring normalizeName(std::wstring value) {
    value = lower(trim(std::move(value)));
    while (!value.empty() && value.back() == L'.') value.pop_back();
    return value;
}

std::wstring canonicalPath(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return path;
    std::vector<wchar_t> buffer(32768);
    DWORD size = GetFinalPathNameByHandleW(file, buffer.data(), static_cast<DWORD>(buffer.size()),
                                           FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    CloseHandle(file);
    if (!size || size >= buffer.size()) return path;
    std::wstring result(buffer.data(), size);
    if (result.rfind(L"\\\\?\\", 0) == 0) result.erase(0, 4);
    return result;
}

std::wstring processPath(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return {};
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) {
        CloseHandle(process);
        return {};
    }
    ULARGE_INTEGER createdValue{};
    createdValue.LowPart = created.dwLowDateTime;
    createdValue.HighPart = created.dwHighDateTime;
    {
        std::lock_guard lock(gProcessCacheMutex);
        const auto found = gProcessCache.find(pid);
        if (found != gProcessCache.end() && found->second.creationTime == createdValue.QuadPart) {
            CloseHandle(process);
            return found->second.path;
        }
    }
    std::vector<wchar_t> buffer(32768);
    DWORD size = static_cast<DWORD>(buffer.size());
    bool ok = QueryFullProcessImageNameW(process, 0, buffer.data(), &size);
    CloseHandle(process);
    if (!ok) return {};
    std::wstring path = canonicalPath(std::wstring(buffer.data(), size));
    {
        std::lock_guard lock(gProcessCacheMutex);
        // a bounded reset is enough; use lifecycle notifications only if this host
        // ever sustains thousands of distinct processes between dispatcher restarts.
        if (gProcessCache.size() >= 2048) gProcessCache.clear();
        gProcessCache[pid] = CachedProcess{createdValue.QuadPart, path};
    }
    return path;
}

std::unordered_set<std::wstring> parseIncludedText(const std::wstring& text) {
    std::unordered_set<std::wstring> result;
    size_t start{};
    while (start <= text.size()) {
        const size_t end = text.find(L'\n', start);
        std::wstring line = trim(text.substr(start, end == std::wstring::npos ? end : end - start));
        if (!line.empty() && line.front() != L'#') result.insert(lower(canonicalPath(line)));
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    return result;
}

std::unordered_set<std::wstring> loadIncludedPaths(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot open included-app list");
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file, &length) || length.QuadPart > 1024 * 1024) {
        CloseHandle(file);
        throw std::runtime_error("Invalid included-app list size");
    }
    std::string bytes(static_cast<size_t>(length.QuadPart), '\0');
    DWORD read{};
    const bool ok = bytes.empty() || ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok || read != bytes.size()) throw std::runtime_error("Cannot read included-app list");
    if (bytes.rfind("\xef\xbb\xbf", 0) == 0) bytes.erase(0, 3);
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
                                          static_cast<int>(bytes.size()), nullptr, 0);
    if (count <= 0 && !bytes.empty()) throw std::runtime_error("Included-app list must be UTF-8");
    std::wstring text(static_cast<size_t>(count), L'\0');
    if (count) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
                                   static_cast<int>(bytes.size()), text.data(), count);
    auto result = parseIncludedText(text);
    if (result.empty()) throw std::runtime_error("Included-app list is empty");
    return result;
}

void logLine(const std::wstring& line, bool flush = false) {
    std::lock_guard lock(gLogMutex);
    if (gLog) {
        gLog->write(wgps::utf8(line + L"\r\n"));
        // stdout is only a readiness channel when a bounded log owns diagnostics.
        if (line.rfind(L"READY:", 0) == 0) std::wcout << line << std::endl;
    } else {
        // Interactive diagnostic usage retains the original stdout contract.
        std::wcout << line << L'\n';
        if (flush) std::wcout.flush();
    }
}

long long qpcNow() {
    LARGE_INTEGER value{};
    return QueryPerformanceCounter(&value) ? value.QuadPart : 0;
}

long long qpcElapsedMilliseconds(long long now, long long then, long long frequency) {
    if (frequency <= 0 || now <= 0 || then <= 0 || now < then) return -1;
    const long double milliseconds =
        (static_cast<long double>(now) - static_cast<long double>(then)) * 1000 / frequency;
    if (milliseconds > std::numeric_limits<long long>::max()) {
        return std::numeric_limits<long long>::max();
    }
    return static_cast<long long>(milliseconds);
}

std::vector<BYTE> eventProperty(EVENT_RECORD* event, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
    descriptor.ArrayIndex = ULONG_MAX;
    ULONG size{};
    if (TdhGetPropertySize(event, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS || size > 4096) return {};
    std::vector<BYTE> value(size);
    if (TdhGetProperty(event, 0, nullptr, 1, &descriptor, size, value.data()) != ERROR_SUCCESS) return {};
    return value;
}

#include "dns-attribution.h"

class DnsTrace {
public:
    DnsTrace(Hints& hints, std::wstring traceName)
        : hints_(hints), traceName_(std::move(traceName)) {
        if (traceName_.empty()) throw std::runtime_error("ETW trace name is empty");
        if (!QueryPerformanceFrequency(&frequency_) || frequency_.QuadPart <= 0) {
            throw std::runtime_error("QueryPerformanceFrequency failed");
        }
        const size_t traceNameBytes = (traceName_.size() + 1) * sizeof(wchar_t);
        const size_t bytes = sizeof(EVENT_TRACE_PROPERTIES) + traceNameBytes;
        properties_.resize(bytes);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data());
        properties->Wnode.BufferSize = static_cast<ULONG>(bytes);
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties->Wnode.ClientContext = 1;
        properties->BufferSize = 4;
        properties->MinimumBuffers = 2;
        properties->MaximumBuffers = 8;
        properties->FlushTimer = 1;
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        memcpy(properties_.data() + properties->LoggerNameOffset, traceName_.c_str(), traceNameBytes);

        try {
            check(StartTraceW(&session_, traceName_.c_str(), properties), "StartTraceW");
            check(EnableTraceEx2(session_, &kDnsClientProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                 TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr), "EnableTraceEx2");

            log_.LoggerName = traceName_.data();
            // ClientContext=1 selects QPC; RAW_TIMESTAMP prevents ProcessTrace from converting it to FILETIME.
            log_.ProcessTraceMode = kProcessTraceMode;
            log_.EventRecordCallback = onEvent;
            log_.Context = this;
            trace_ = OpenTraceW(&log_);
            if (trace_ == INVALID_PROCESSTRACE_HANDLE) throw std::runtime_error("OpenTraceW failed");
            flushRequested_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
            if (!flushRequested_) throw std::runtime_error("CreateEventW failed");
            gTraceFlushRequested.store(flushRequested_);
            consumer_ = std::thread([this] {
                ProcessTrace(&trace_, 1, nullptr, nullptr);
                if (!stopping_) gRunning = false;
            });
            flusher_ = std::thread([this] {
                auto* current = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data());
                while (!stopping_) {
                    WaitForSingleObject(flushRequested_, 10);
                    if (stopping_) break;
                    FlushTraceW(session_, traceName_.c_str(), current);
                }
            });
        } catch (...) {
            stop();
            throw;
        }
    }

    long long frequency() const { return frequency_.QuadPart; }

    ~DnsTrace() { stop(); }

private:
    void stop() noexcept {
        stopping_ = true;
        gTraceFlushRequested.store(nullptr);
        if (flushRequested_) SetEvent(flushRequested_);
        if (flusher_.joinable()) flusher_.join();
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data());
        if (session_) {
            EnableTraceEx2(session_, &kDnsClientProvider, EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, nullptr);
            ControlTraceW(session_, traceName_.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
        }
        if (trace_ != INVALID_PROCESSTRACE_HANDLE) CloseTrace(trace_);
        if (consumer_.joinable()) consumer_.join();
        if (flushRequested_) CloseHandle(flushRequested_);
    }

private:
    static void WINAPI onEvent(EVENT_RECORD* event) noexcept {
        try { processEvent(event); }
        catch (...) { gRunning = false; } // Fail the component; never unwind through the ETW C callback.
    }

    static void processEvent(EVENT_RECORD* event) {
        if (!IsEqualGUID(event->EventHeader.ProviderId, kDnsClientProvider) ||
            event->EventHeader.EventDescriptor.Id != kQueryEvent) return;
        auto* self = static_cast<DnsTrace*>(event->UserContext);
        const auto nameData = eventProperty(event, L"QueryName");
        const auto typeData = eventProperty(event, L"QueryType");
        if (nameData.size() < sizeof(wchar_t) || typeData.empty()) return;
        if (nameData.size() % sizeof(wchar_t)) return;
        std::wstring name(nameData.size() / sizeof(wchar_t), L'\0');
        memcpy(name.data(), nameData.data(), nameData.size());
        const auto terminator = name.find(L'\0');
        if (terminator == std::wstring::npos || terminator > 253) return;
        name.resize(terminator);
        uint16_t type{};
        memcpy(&type, typeData.data(), std::min(typeData.size(), sizeof(type)));
        const long long eventQpc = event->EventHeader.TimeStamp.QuadPart;
        const long long deliveryMilliseconds =
            qpcElapsedMilliseconds(qpcNow(), eventQpc, self->frequency_.QuadPart);
        self->hints_.add(name, type, event->EventHeader.ProcessId, eventQpc,
                         deliveryMilliseconds, event->EventHeader.EventDescriptor.Id);
    }

    Hints& hints_;
    std::wstring traceName_;
    std::vector<BYTE> properties_;
    TRACEHANDLE session_{};
    TRACEHANDLE trace_{INVALID_PROCESSTRACE_HANDLE};
    EVENT_TRACE_LOGFILEW log_{};
    std::atomic_bool stopping_{};
    HANDLE flushRequested_{};
    std::thread consumer_;
    std::thread flusher_;
    LARGE_INTEGER frequency_{};
};

#include "dns-wire.h"

std::optional<bool> selectRoute(Hints& hints, const Question& question, const wchar_t* transport,
                                long long queryQpc, long long& waitMilliseconds, bool& reused) {
    const auto started = std::chrono::steady_clock::now();
    const auto route = hints.take(question.name, question.type, &reused);
    waitMilliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - started)
                           .count();
    if (!route) {
        logLine(L"DNS " + question.name + L" type=" + std::to_wstring(question.type) +
                L" -> BLOCKED (no process hint, " + transport + L", wait=" +
                std::to_wstring(waitMilliseconds) + L"ms, query-qpc=" +
                std::to_wstring(queryQpc) + L")", true);
    }
    return route;
}

void handleUdpQuery(Hints& hints, std::vector<char> packet, sockaddr_in client, int clientSize,
                    sockaddr_in directSource, sockaddr_in directDns, sockaddr_in tunnelSource,
                    sockaddr_in tunnelDns, long long queryQpc) {
    const auto question = parseQuestion(packet);
    if (!question) {
        const auto failure = makeServfail(packet);
        if (!failure.empty()) sendto(gUdpListener, failure.data(), static_cast<int>(failure.size()), 0,
                                     reinterpret_cast<sockaddr*>(&client), clientSize);
        return;
    }
    long long classifyMilliseconds{};
    bool reused = false;
    const auto tunnel = selectRoute(hints, *question, L"UDP", queryQpc, classifyMilliseconds, reused);
    std::optional<std::vector<char>> response;
    if (tunnel) {
        response = udpExchange(packet, *tunnel ? tunnelSource : directSource,
                               *tunnel ? tunnelDns : directDns);
    }
    const bool answered = response.has_value();
    if (!response) response = makeServfail(packet);
    if (!response->empty()) sendto(gUdpListener, response->data(), static_cast<int>(response->size()), 0,
                                   reinterpret_cast<sockaddr*>(&client), clientSize);
    if (tunnel) {
        hints.complete(question->name, question->type);
        logLine(L"DNS " + question->name + L" type=" + std::to_wstring(question->type) + L" -> " +
                (*tunnel ? L"TUNNEL" : L"DIRECT") + (reused ? L" (reused)" : L"") + (answered ? L"" : L" FAILED") +
                L" classify=" + std::to_wstring(classifyMilliseconds) + L"ms query-qpc=" +
                std::to_wstring(queryQpc), !answered);
    }
}

void handleTcpClient(SOCKET client, Hints& hints, sockaddr_in directSource, sockaddr_in directDns,
                     sockaddr_in tunnelSource, sockaddr_in tunnelDns) {
    SocketOwner owned(client);
    if (!nonblocking(client)) return;
    for (unsigned requests = 0; gRunning && requests < 64; ++requests) {
        const auto requestDeadline = afterMilliseconds(5000);
        uint16_t wireLength{};
        if (!receiveAll(client, reinterpret_cast<char*>(&wireLength), sizeof(wireLength), requestDeadline)) break;
        const int size = ntohs(wireLength);
        if (size < 12) break;
        std::vector<char> packet(size);
        if (!receiveAll(client, packet.data(), size, requestDeadline)) break;
        const long long queryQpc = qpcNow();
        const auto question = parseQuestion(packet);
        std::optional<bool> tunnel;
        long long classifyMilliseconds{};
        bool reused = false;
        if (question) tunnel = selectRoute(hints, *question, L"TCP", queryQpc, classifyMilliseconds, reused);
        std::optional<std::vector<char>> response;
        if (question && tunnel) {
            response = tcpExchange(packet, *tunnel ? tunnelSource : directSource,
                                   *tunnel ? tunnelDns : directDns);
            // Some consumer routers refuse upstream TCP/53. Preserve the client's TCP contract
            // while using the same configured router resolver over UDP when that happens.
            if (!*tunnel && (!response || (response->size() >= 4 &&
                                            (static_cast<unsigned char>((*response)[3]) & 0x0f) == 5))) {
                response = udpExchange(packet, directSource, directDns);
            }
        }
        const bool answered = response.has_value();
        if (!response) response = makeServfail(packet);
        const auto responseDeadline = afterMilliseconds(5000);
        const uint16_t responseLength = htons(static_cast<uint16_t>(response->size()));
        if (!sendAll(client, reinterpret_cast<const char*>(&responseLength), sizeof(responseLength), responseDeadline) ||
            !sendAll(client, response->data(), static_cast<int>(response->size()), responseDeadline)) break;
        if (question && tunnel) {
            hints.complete(question->name, question->type);
            logLine(L"DNS " + question->name + L" type=" + std::to_wstring(question->type) + L" -> " +
                    (*tunnel ? L"TUNNEL" : L"DIRECT") + L" (TCP)" + (reused ? L" (reused)" : L"") + (answered ? L"" : L" FAILED") +
                    L" classify=" + std::to_wstring(classifyMilliseconds) + L"ms query-qpc=" +
                    std::to_wstring(queryQpc), !answered);
        }
    }
}

BOOL WINAPI consoleControl(DWORD) {
    gRunning = false;
    return TRUE;
}

#include "dns-dispatcher-self-test.h"

}  // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wstring(argv[1]) == L"--self-test") return selfTest();
        if (argc != 7 && argc != 8) {
            std::wcerr << L"Usage: dns-dispatcher.exe <included-apps.txt> <direct-source> <direct-dns> <tunnel-source> <tunnel-dns> <etw-session> [log-file]\n";
            return 2;
        }
        if (argc == 8) gLog = std::make_unique<wgps::BoundedLog>(argv[7]);
        WSADATA winsock{};
        if (WSAStartup(MAKEWORD(2, 2), &winsock)) throw std::runtime_error("WSAStartup failed");
        SetConsoleCtrlHandler(consoleControl, TRUE);

        auto included = loadIncludedPaths(argv[1]);
        const size_t includedCount = included.size();
        Hints hints(std::move(included));
        DnsTrace trace(hints, argv[6]);
        const auto directSource = address(argv[2], 0);
        const auto directDns = address(argv[3], 53);
        const auto tunnelSource = address(argv[4], 0);
        const auto tunnelDns = address(argv[5], 53);

        gUdpListener = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        gTcpListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (gUdpListener == INVALID_SOCKET || gTcpListener == INVALID_SOCKET ||
            !nonblocking(gUdpListener) || !nonblocking(gTcpListener)) {
            throw std::runtime_error("Cannot create local DNS sockets");
        }
        BOOL exclusive = TRUE;
        setsockopt(gUdpListener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
        setsockopt(gTcpListener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
        auto listenAddress = address(L"127.0.0.1", 53);
        if (bind(gUdpListener, reinterpret_cast<sockaddr*>(&listenAddress), sizeof(listenAddress)) == SOCKET_ERROR ||
            bind(gTcpListener, reinterpret_cast<sockaddr*>(&listenAddress), sizeof(listenAddress)) == SOCKET_ERROR ||
            listen(gTcpListener, SOMAXCONN) == SOCKET_ERROR) {
            throw std::runtime_error("Cannot bind local DNS port 53");
        }
        logLine(L"READY: ETW split-DNS dispatcher on 127.0.0.1:53 (UDP/TCP), apps=" +
                    std::to_wstring(includedCount) + L", qpc-frequency=" +
                    std::to_wstring(trace.frequency()), true);

        std::thread tcpAcceptor([&] {
            while (gRunning) {
                if (!socketReady(gTcpListener, false, afterMilliseconds(1000))) continue;
                SOCKET client = accept(gTcpListener, nullptr, nullptr);
                if (client == INVALID_SOCKET) {
                    if (!gRunning) break;
                    continue;
                }
                if (!acquireWorker()) {
                    closesocket(client);
                    continue;
                }
                try {
                    std::thread([&, client] {
                        WorkerLease lease;
                        try {
                            handleTcpClient(client, hints, directSource, directDns, tunnelSource,
                                            tunnelDns);
                        } catch (...) {
                            // handleTcpClient owns the socket even on an exception.
                        }
                    }).detach();
                } catch (...) {
                    gActiveWorkers.fetch_sub(1);
                    closesocket(client);
                }
            }
        });

        while (gRunning) {
            std::vector<char> packet(65535);
            sockaddr_in client{};
            int clientSize = sizeof(client);
            if (!socketReady(gUdpListener, false, afterMilliseconds(1000))) continue;
            const int received = recvfrom(gUdpListener, packet.data(), static_cast<int>(packet.size()), 0,
                                          reinterpret_cast<sockaddr*>(&client), &clientSize);
            if (received <= 0) continue;
            const long long queryQpc = qpcNow();
            packet.resize(received);
            if (!acquireWorker()) {
                const auto failure = makeServfail(packet);
                sendto(gUdpListener, failure.data(), static_cast<int>(failure.size()), 0,
                       reinterpret_cast<sockaddr*>(&client), clientSize);
                continue;
            }
            try {
                std::thread([&, packet = std::move(packet), client, clientSize, queryQpc]() mutable {
                    WorkerLease lease;
                    try {
                        handleUdpQuery(hints, std::move(packet), client, clientSize, directSource,
                                       directDns, tunnelSource, tunnelDns, queryQpc);
                    } catch (...) {
                    }
                }).detach();
            } catch (...) {
                gActiveWorkers.fetch_sub(1);
                const auto failure = makeServfail(packet);
                sendto(gUdpListener, failure.data(), static_cast<int>(failure.size()), 0,
                       reinterpret_cast<sockaddr*>(&client), clientSize);
            }
        }
        if (tcpAcceptor.joinable()) tcpAcceptor.join();
        // Detached workers borrow hints and network inputs. Drain them before stack destruction.
        // Every socket operation checks gRunning at least every 200 ms.
        while (gActiveWorkers.load()) std::this_thread::sleep_for(std::chrono::milliseconds(10));
        closesocket(gUdpListener);
        closesocket(gTcpListener);
        WSACleanup();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << "\n";
        return 1;
    }
}
