// SPDX-License-Identifier: GPL-3.0-or-later
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <evntprov.h>
#include <tdh.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cwctype>
#include <functional>
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
#include "path-identity.h"
#include "bounded-log.h"

namespace {

constexpr GUID kDnsClientProvider{0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};
constexpr USHORT kQueryEvent = 3006;
// The dispatcher's own provider, enabled on the same session, carries the ordering-barrier sentinels.
constexpr GUID kSentinelProvider{0x677ab7ee, 0x429f, 0x4181, {0xa4, 0x7b, 0xd4, 0x7b, 0xc7, 0x29, 0x26, 0xb0}};
constexpr EVENT_DESCRIPTOR kSentinelEvent{1, 0, 0, TRACE_LEVEL_INFORMATION, 0, 0, 0};
// EVENT_FILTER_TYPE_EVENT_ID and EVENT_FILTER_EVENT_ID (Windows 8.1+) are absent from MinGW headers.
constexpr ULONG kEventFilterTypeEventId = 0x80000200;
struct EventIdFilter {
    BOOLEAN filterIn;
    UCHAR reserved;
    USHORT count;
    USHORT events[1];
};
constexpr unsigned kMaxWorkers = 256;
constexpr ULONG kProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD |
                                    PROCESS_TRACE_MODE_RAW_TIMESTAMP;
static_assert(kProcessTraceMode & PROCESS_TRACE_MODE_RAW_TIMESTAMP);
std::atomic_bool gRunning{true};
std::atomic<HANDLE> gTraceFlushRequested{nullptr};
std::atomic_uint gActiveWorkers{};
std::atomic_uint gHintWaiters{};
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

// The final path, as wfp-probe.exe resolves it: through junctions, symbolic links and substituted drives,
// and for an absent executable through its nearest existing ancestor, so a listed alias matches the
// running image. A path that does not resolve at all is kept as listed.
std::wstring canonicalPath(const std::wstring& path) {
    std::wstring resolved = wgps::resolvePath(path, VOLUME_NAME_DOS);
    return resolved.empty() ? path : resolved;
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
    // wfp-probe.exe's identity record: each line's second field is the final path its filters identify. The
    // dispatcher attributes by that path and does not resolve the list again, so it cannot disagree with
    // the filters, including for an entry whose path does not resolve at the moment.
    // Every row is validated, and one malformed or truncated row rejects the whole record, so a damaged
    // record cannot silently deselect an application. A record with no rows is valid and selects nothing.
    constexpr wchar_t kIdentityHeader[] = L"# wgps-identities 1\n";
    if (text.rfind(kIdentityHeader, 0) == 0) {
        if (text.back() != L'\n') throw std::runtime_error("The identity record is truncated");
        size_t line = std::size(kIdentityHeader) - 1;
        while (line < text.size()) {
            const size_t end = text.find(L'\n', line);
            const std::wstring row = text.substr(line, end - line);
            line = end + 1;
            const size_t first = row.find(L'\t');
            const size_t second = first == std::wstring::npos ? first : row.find(L'\t', first + 1);
            if (first == 0 || second == std::wstring::npos || second == first + 1 ||
                row.find(L'\t', second + 1) != std::wstring::npos ||
                std::any_of(row.begin(), row.end(), [](wchar_t c) { return c < L' ' && c != L'\t'; })) {
                throw std::runtime_error("The identity record has a malformed row");
            }
            const std::wstring ids = row.substr(second + 1);
            size_t start = 0;
            do {
                const size_t comma = std::min(ids.find(L',', start), ids.size());
                const size_t length = comma - start;
                if (!length || length % 2 ||
                    !std::all_of(ids.begin() + start, ids.begin() + comma, [](wchar_t c) { return std::iswxdigit(c); })) {
                    throw std::runtime_error("The identity record has a malformed identifier");
                }
                start = comma + 1;
            } while (start <= ids.size());
            result.insert(lower(row.substr(first + 1, second - first - 1)));
        }
        return result;
    }
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
    // An identity record may hold no entry that resolved yet; a plain list must name one.
    if (result.empty() && text.rfind(L"# wgps-identities", 0) != 0) throw std::runtime_error("Included-app list is empty");
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
        // Buffers are allocated on demand; the ceiling only absorbs lookup bursts.
        properties->MaximumBuffers = 64;
        properties->FlushTimer = 1;
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        memcpy(properties_.data() + properties->LoggerNameOffset, traceName_.c_str(), traceNameBytes);

        try {
            check(StartTraceW(&session_, traceName_.c_str(), properties), "StartTraceW");
            // The provider emits roughly ten events per lookup; only the query event carries
            // attribution. Filtering at the provider keeps the others out of the buffers.
            EventIdFilter ids{TRUE, 0, 1, {kQueryEvent}};
            EVENT_FILTER_DESCRIPTOR filter{reinterpret_cast<ULONGLONG>(&ids), sizeof(ids),
                                           kEventFilterTypeEventId};
            ENABLE_TRACE_PARAMETERS parameters{};
            parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            parameters.EnableFilterDesc = &filter;
            parameters.FilterDescCount = 1;
            if (EnableTraceEx2(session_, &kDnsClientProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                               TRACE_LEVEL_INFORMATION, 0, 0, 0, &parameters) != ERROR_SUCCESS) {
                eventFilter_ = false;
                check(EnableTraceEx2(session_, &kDnsClientProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                     TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr), "EnableTraceEx2");
            }
            // Filters are per provider: the sentinels are not subject to the query-event filter.
            check(EventRegister(&kSentinelProvider, nullptr, nullptr, &sentinelProvider_), "EventRegister");
            check(EnableTraceEx2(session_, &kSentinelProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                 TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr), "EnableTraceEx2 (sentinel)");
            hints_.setSentinelWriter([this](unsigned long long sequence) {
                EVENT_DATA_DESCRIPTOR data{};
                EventDataDescCreate(&data, &sequence, sizeof(sequence));
                return EventWrite(sentinelProvider_, &kSentinelEvent, 1, &data) == ERROR_SUCCESS;
            });

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
            // An exception must not escape a thread; a failed flusher ends the dispatcher, which is restarted.
            flusher_ = std::thread([this] { try {
                // Room for the logger and log file names the call returns; with less, it fails with
                // ERROR_MORE_DATA and the loss counters cannot be trusted.
                constexpr size_t kNameBytes = 1024 * sizeof(wchar_t);
                std::vector<BYTE> query(sizeof(EVENT_TRACE_PROPERTIES) + 2 * kNameBytes);
                auto* current = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(query.data());
                ULONG lostEvents{}, lostBuffers{}, flushFailure{};
                while (!stopping_) {
                    // Queries request an immediate flush. Keep the low-latency retry cadence
                    // only while attribution is pending; idle DNS does not need 100 flushes/s.
                    WaitForSingleObject(flushRequested_, gHintWaiters.load() ? 10 : 1000);
                    if (stopping_) break;
                    // Every barrier sequence assigned before this flush began is covered by its loss check.
                    const unsigned long long covered = hints_.lastSequence();
                    std::fill(query.begin(), query.end(), BYTE{});
                    current->Wnode.BufferSize = static_cast<ULONG>(query.size());
                    current->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
                    current->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + kNameBytes;
                    const ULONG flushed = FlushTraceW(session_, traceName_.c_str(), current);
                    if (flushed != ERROR_SUCCESS) {
                        if (flushed != flushFailure) logLine(L"ETW FLUSH FAILED " + std::to_wstring(flushed), true);
                        flushFailure = flushed;
                        continue;
                    }
                    if (current->EventsLost != lostEvents || current->RealTimeBuffersLost != lostBuffers) {
                        lostEvents = current->EventsLost;
                        lostBuffers = current->RealTimeBuffersLost;
                        hints_.lostEvents();
                        logLine(L"ETW LOST events=" + std::to_wstring(lostEvents) + L" buffers=" +
                                std::to_wstring(lostBuffers) + L"; refusing direct routes for 10s", true);
                    }
                    hints_.flushChecked(covered);
                }
            } catch (...) { gRunning = false; } });
        } catch (...) {
            stop();
            throw;
        }
    }

    long long frequency() const { return frequency_.QuadPart; }
    bool eventFilter() const { return eventFilter_; }

    ~DnsTrace() { stop(); }

private:
    void stop() noexcept {
        stopping_ = true;
        hints_.setSentinelWriter(nullptr);
        gTraceFlushRequested.store(nullptr);
        if (flushRequested_) SetEvent(flushRequested_);
        if (flusher_.joinable()) flusher_.join();
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(properties_.data());
        if (session_) {
            EnableTraceEx2(session_, &kDnsClientProvider, EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, nullptr);
            EnableTraceEx2(session_, &kSentinelProvider, EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0, nullptr);
            ControlTraceW(session_, traceName_.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
        }
        if (trace_ != INVALID_PROCESSTRACE_HANDLE) CloseTrace(trace_);
        if (consumer_.joinable()) consumer_.join();
        if (sentinelProvider_) EventUnregister(sentinelProvider_);
        if (flushRequested_) CloseHandle(flushRequested_);
    }

private:
    static void WINAPI onEvent(EVENT_RECORD* event) noexcept {
        try { processEvent(event); }
        catch (...) { gRunning = false; } // Fail the component; never unwind through the ETW C callback.
    }

    static void processEvent(EVENT_RECORD* event) {
        auto* self = static_cast<DnsTrace*>(event->UserContext);
        if (IsEqualGUID(event->EventHeader.ProviderId, kSentinelProvider)) {
            unsigned long long sequence{};
            if (event->UserDataLength != sizeof(sequence)) return;
            memcpy(&sequence, event->UserData, sizeof(sequence));
            self->hints_.sentinelProcessed(sequence);
            return;
        }
        if (!IsEqualGUID(event->EventHeader.ProviderId, kDnsClientProvider) ||
            event->EventHeader.EventDescriptor.Id != kQueryEvent) return;
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
    REGHANDLE sentinelProvider_{};
    std::thread consumer_;
    std::thread flusher_;
    LARGE_INTEGER frequency_{};
    bool eventFilter_{true};
};

#include "dns-wire.h"
#include "dns-dispatcher-state.h"

// The supervisor's liveness probe, answered by the receive loop itself without attribution or an upstream,
// so an answer shows the listener serving queries rather than only that the process exists. It reveals
// nothing: the reply is NOERROR with no records.
constexpr wchar_t kLivenessName[] = L"liveness.wireguard-program-split.invalid";

bool answerLiveness(const char* data, int size, const sockaddr_in& client, int clientSize) {
    if (size < 17) return false;
    const std::vector<char> packet(data, data + size);
    const auto question = parseQuestion(packet);
    if (!question || normalizeName(question->name) != kLivenessName) return false;
    auto reply = makeServfail(packet);
    reply[3] = static_cast<char>(static_cast<unsigned char>(reply[3]) & 0xf0);
    sendto(gUdpListener, reply.data(), static_cast<int>(reply.size()), 0, reinterpret_cast<const sockaddr*>(&client), clientSize);
    return true;
}

// The UDP payload size the client advertised in an EDNS OPT record, or 512 without one.
size_t advertisedUdpSize(const std::vector<char>& query) {
    if (query.size() < 12) return 512;
    size_t offset = 12;
    for (unsigned i = 0, count = read16(query, 4); i < count; ++i) {
        if (!skipDnsName(query, offset) || offset + 4 > query.size()) return 512;
        offset += 4;
    }
    for (unsigned i = 0, count = read16(query, 6) + read16(query, 8) + read16(query, 10); i < count; ++i) {
        if (!skipDnsName(query, offset) || offset + 10 > query.size()) return 512;
        if (read16(query, offset) == 41) return std::max<size_t>(512, read16(query, offset + 2));
        offset += 10 + read16(query, offset + 8);
    }
    return 512;
}

std::optional<bool> selectRoute(Hints& hints, const Question& question, const wchar_t* transport,
                                long long queryQpc, long long& waitMicroseconds, bool& reused,
                                unsigned long long& generation) {
    const auto started = std::chrono::steady_clock::now();
    const auto route = hints.take(question.name, question.type, &reused, &generation);
    waitMicroseconds = std::chrono::duration_cast<std::chrono::microseconds>(
                           std::chrono::steady_clock::now() - started)
                           .count();
    if (!route) {
        logLine(L"DNS " + question.name + L" type=" + std::to_wstring(question.type) +
                L" -> BLOCKED (no process hint, " + transport + L", wait=" +
                std::to_wstring(waitMicroseconds) + L"us, query-qpc=" +
                std::to_wstring(queryQpc) + L")", true);
    }
    return route;
}

void handleUdpQuery(Hints& hints, std::vector<char> packet, sockaddr_in client, int clientSize,
                    const Routes& routes, long long queryQpc) {
    const auto question = parseQuestion(packet);
    if (!question) {
        const auto failure = makeServfail(packet);
        if (!failure.empty()) sendto(gUdpListener, failure.data(), static_cast<int>(failure.size()), 0,
                                     reinterpret_cast<sockaddr*>(&client), clientSize);
        return;
    }
    long long classifyMicroseconds{};
    bool reused = false;
    unsigned long long generation{};
    const auto tunnel = selectRoute(hints, *question, L"UDP", queryQpc, classifyMicroseconds, reused, generation);
    std::optional<std::vector<char>> response;
    bool completed = false;
    if (tunnel) {
        const sockaddr_in source = *tunnel ? routes.tunnelSource : routes.directSource;
        const sockaddr_in resolver = *tunnel ? routes.tunnelDns : routes.directDns;
        response = udpExchange(packet, source, resolver);
        // A truncated answer sends the client to TCP, where the Windows DNS Client can hand it another
        // process's answer for the same name. Fetch the whole answer over TCP on the same route, with no
        // new classification, and return it over UDP when it fits what the client accepts.
        if (response && response->size() >= 12 && (static_cast<unsigned char>((*response)[2]) & 0x02)) {
            auto whole = tcpExchange(packet, source, resolver);
            if (whole && whole->size() <= advertisedUdpSize(packet)) {
                response = std::move(whole);
                completed = true;
            }
        }
    }
    const bool withheld = response && tunnel && !*tunnel && hints.directAnswerUnsafe(question->name, question->type);
    if (withheld) response.reset();
    const bool answered = response.has_value();
    if (!response) response = makeServfail(packet);
    if (!response->empty()) sendto(gUdpListener, response->data(), static_cast<int>(response->size()), 0,
                                   reinterpret_cast<sockaddr*>(&client), clientSize);
    if (tunnel) {
        // A withheld answer is not reused; the entry's tunnel evidence decides the retries.
        if (!withheld) hints.complete(question->name, question->type, generation);
        logLine(L"DNS " + question->name + L" type=" + std::to_wstring(question->type) + L" -> " +
                (*tunnel ? L"TUNNEL" : L"DIRECT") + (reused ? L" (reused)" : L"") + (completed ? L" (completed over TCP)" : L"") +
                (withheld ? L" WITHHELD (selected lookup of the same name)" : answered ? L"" : L" FAILED") + L" classify=" + std::to_wstring(classifyMicroseconds) + L"us query-qpc=" +
                std::to_wstring(queryQpc), !answered);
    }
}

void handleTcpClient(SOCKET client, Hints& hints) {
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
        long long classifyMicroseconds{};
        bool reused = false;
        unsigned long long generation{};
        if (question) tunnel = selectRoute(hints, *question, L"TCP", queryQpc, classifyMicroseconds, reused, generation);
        std::optional<std::vector<char>> response;
        if (question && tunnel) {
            // Each request uses the routes current when it arrives, so a reload takes effect between requests.
            const auto routes = currentRoutes();
            const auto directSource = routes->directSource;
            const auto directDns = routes->directDns;
            response = tcpExchange(packet, *tunnel ? routes->tunnelSource : directSource,
                                   *tunnel ? routes->tunnelDns : directDns);
            // Some consumer routers refuse upstream TCP/53. Preserve the client's TCP contract
            // while using the same configured router resolver over UDP when that happens.
            if (!*tunnel && (!response || (response->size() >= 4 &&
                                            (static_cast<unsigned char>((*response)[3]) & 0x0f) == 5))) {
                response = udpExchange(packet, directSource, directDns);
            }
        }
        const bool withheld = response && question && tunnel && !*tunnel && hints.directAnswerUnsafe(question->name, question->type);
        if (withheld) response.reset();
        const bool answered = response.has_value();
        if (!response) response = makeServfail(packet);
        const auto responseDeadline = afterMilliseconds(5000);
        if (!sendDnsFrame(client, *response, responseDeadline)) break;
        if (question && tunnel) {
            if (!withheld) hints.complete(question->name, question->type, generation);
            logLine(L"DNS " + question->name + L" type=" + std::to_wstring(question->type) + L" -> " +
                    (*tunnel ? L"TUNNEL" : L"DIRECT") + L" (TCP)" + (reused ? L" (reused)" : L"") +
                    (withheld ? L" WITHHELD (selected lookup of the same name)" : answered ? L"" : L" FAILED") +
                    L" classify=" + std::to_wstring(classifyMicroseconds) + L"us query-qpc=" +
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
        // --state <installation root>: inputs come from the state directory and reload in place.
        const bool stateMode = argc == 3 && std::wstring(argv[1]) == L"--state";
        if (!stateMode && argc != 7 && argc != 8) {
            std::wcerr << L"Usage: dns-dispatcher.exe --state <root> | <included-apps.txt> <direct-source> <direct-dns> <tunnel-source> <tunnel-dns> <etw-session> [log-file]\n";
            return 2;
        }
        const std::wstring root = stateMode ? argv[2] : L"";
        if (stateMode) gLog = std::make_unique<wgps::BoundedLog>(root + L"\\logs\\dns-dispatcher.log");
        else if (argc == 8) gLog = std::make_unique<wgps::BoundedLog>(argv[7]);
        WSADATA winsock{};
        if (WSAStartup(MAKEWORD(2, 2), &winsock)) throw std::runtime_error("WSAStartup failed");
        SetConsoleCtrlHandler(consoleControl, TRUE);

        std::optional<StateInputs> stateInputs;
        std::unordered_set<std::wstring> included;
        std::wstring traceName;
        if (stateMode) {
            stateInputs = readStateInputs(root);
            included = stateInputs->included;
            setRoutes(stateInputs->routes);
            traceName = replaceTraceSession(root);
        } else {
            included = loadIncludedPaths(argv[1]);
            setRoutes({address(argv[2], 0), address(argv[3], 53), address(argv[4], 0), address(argv[5], 53)});
            traceName = argv[6];
        }
        const size_t includedCount = included.size();
        Hints hints(std::move(included));
        DnsTrace trace(hints, traceName);

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
        unsigned generation = 1;
        if (stateMode) {
            writeAtomically(root + L"\\state\\dns-dispatcher.pid", std::to_string(GetCurrentProcessId()));
            publishLoaded(root, *stateInputs, generation);
        }
        // A reload validates the new inputs before swapping them in, and keeps the loaded ones otherwise.
        HANDLE reloadRequested = stateMode ? CreateEventW(nullptr, FALSE, FALSE, L"Global\\WireGuardProgramSplitDispatcherReload") : nullptr;
        if (stateMode && !reloadRequested) throw std::runtime_error("Cannot create the reload event");
        std::thread reloader;
        if (reloadRequested) {
            reloader = std::thread([&] {
                while (gRunning) try {
                    if (WaitForSingleObject(reloadRequested, 500) != WAIT_OBJECT_0) continue;
                    StateInputs next;
                    try {
                        next = readStateInputs(root);
                    } catch (const std::exception& error) {
                        const std::string what = error.what();
                        logLine(L"RELOAD REJECTED; keeping the loaded inputs: " + std::wstring(what.begin(), what.end()), true);
                        continue;
                    }
                    const size_t count = next.included.size();
                    setRoutes(next.routes);
                    hints.setIncluded(next.included);
                    ++generation;
                    // Unpublished, the reload is requested again by Invoke-DnsDispatcher.ps1, which waits for it.
                    try {
                        publishLoaded(root, next, generation);
                        logLine(L"RELOADED generation=" + std::to_wstring(generation) + L" apps=" + std::to_wstring(count), true);
                    } catch (const std::exception&) {
                        logLine(L"RELOADED generation=" + std::to_wstring(generation) + L" but could not publish it", true);
                    }
                } catch (...) {
                    // A reload that fails unexpectedly keeps whatever was loaded; Start requests it again.
                }
            });
        }
        logLine(L"READY: ETW split-DNS dispatcher on 127.0.0.1:53 (UDP/TCP), apps=" +
                    std::to_wstring(includedCount) + L", qpc-frequency=" +
                    std::to_wstring(trace.frequency()) + L", etw-filter=" +
                    (trace.eventFilter() ? L"query-event" : L"none"), true);

        std::thread tcpAcceptor([&] { try {
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
                            handleTcpClient(client, hints);
                        } catch (...) {
                            // handleTcpClient owns the socket even on an exception.
                        }
                    }).detach();
                } catch (...) {
                    gActiveWorkers.fetch_sub(1);
                    closesocket(client);
                }
            }
        } catch (...) { gRunning = false; } });

        // One ingress buffer; workers retain only the received bytes, rather
        // than a 64 KiB vector capacity while waiting for attribution/upstream.
        std::array<char, 65535> receiveBuffer;
        while (gRunning) {
            sockaddr_in client{};
            int clientSize = sizeof(client);
            if (!socketReady(gUdpListener, false, afterMilliseconds(1000))) continue;
            const int received = recvfrom(gUdpListener, receiveBuffer.data(), static_cast<int>(receiveBuffer.size()), 0,
                                          reinterpret_cast<sockaddr*>(&client), &clientSize);
            if (received <= 0) continue;
            const long long queryQpc = qpcNow();
            if (answerLiveness(receiveBuffer.data(), received, client, clientSize)) continue;
            std::vector<char> packet(receiveBuffer.data(), receiveBuffer.data() + received);
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
                        const auto routes = currentRoutes();
                        handleUdpQuery(hints, std::move(packet), client, clientSize, *routes, queryQpc);
                    } catch (...) {
                    }
                }).detach();
            } catch (...) {
                gActiveWorkers.fetch_sub(1);
                const auto failure = makeServfail(std::vector<char>(receiveBuffer.data(), receiveBuffer.data() + received));
                sendto(gUdpListener, failure.data(), static_cast<int>(failure.size()), 0,
                       reinterpret_cast<sockaddr*>(&client), clientSize);
            }
        }
        if (tcpAcceptor.joinable()) tcpAcceptor.join();
        if (reloader.joinable()) reloader.join();
        if (reloadRequested) CloseHandle(reloadRequested);
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
