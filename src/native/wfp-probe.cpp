#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <rpcdce.h>

#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

constexpr UINT32 kDynamicSession = 1;
constexpr UINT32 kHasProviderContext = 4;
constexpr UINT32 kUsesProviderContext = 0x00020000;
constexpr UINT32 kCalloutRegistered = 0x00040000;

constexpr GUID kLayerBindV4{0x66978cad, 0xc704, 0x42ac, {0x86, 0xac, 0x7c, 0x1a, 0x23, 0x1b, 0xd2, 0x53}};
constexpr GUID kLayerConnectV4{0xc6e63c8c, 0xb784, 0x4562, {0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3}};
constexpr GUID kConditionAppId{0xd78e1e87, 0x8644, 0x4ea5, {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}};
// PIA WFP callout ABI identifiers and context layout. See NOTICE.md for source and license.
constexpr GUID kCalloutBind{0xb16b0a6e, 0x2b2a, 0x41a3, {0x8b, 0x39, 0xbd, 0x3f, 0xfc, 0x85, 0x5f, 0xf8}};
constexpr GUID kCalloutConnect{0xb80ca14a, 0xa807, 0x4ef2, {0x87, 0x2d, 0x4b, 0x1a, 0x51, 0x82, 0x54, 0x02}};

struct ContextData {
    UINT32 bindIp;
    UINT32 rewriteDnsServer;
    UINT32 dnsSourceIp;
};
static_assert(sizeof(ContextData) == 12, "PIA provider context must be 12 bytes");

HANDLE gStopEvent{};

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

void check(DWORD status, const char* operation) {
    if (status != ERROR_SUCCESS) {
        throw std::runtime_error(std::string(operation) + " failed with 0x" + [&] {
            char value[16]{};
            snprintf(value, sizeof(value), "%08lx", static_cast<unsigned long>(status));
            return std::string(value);
        }());
    }
}

BOOL WINAPI onConsoleSignal(DWORD) {
    if (gStopEvent) SetEvent(gStopEvent);
    return TRUE;
}

UINT32 parseIpv4(const wchar_t* text) {
    IN_ADDR address{};
    if (InetPtonW(AF_INET, text, &address) != 1) throw std::runtime_error("Invalid IPv4 address");
    return ntohl(address.S_un.S_addr);
}

GUID newGuid() {
    GUID value{};
    check(CoCreateGuid(&value), "CoCreateGuid");
    return value;
}

FWPM_DISPLAY_DATA0 display(const wchar_t* name, const wchar_t* description = L"") {
    return {const_cast<wchar_t*>(name), const_cast<wchar_t*>(description)};
}

void addCallout(HANDLE engine, const GUID& provider, const GUID& key, const GUID& layer, const wchar_t* name) {
    FWPM_CALLOUT0 callout{};
    callout.calloutKey = key;
    callout.displayData = display(name);
    callout.providerKey = const_cast<GUID*>(&provider);
    callout.applicableLayer = layer;
    callout.flags = kUsesProviderContext;
    check(FwpmCalloutAdd0(engine, &callout, nullptr, nullptr), "FwpmCalloutAdd0");

    FWPM_CALLOUT0* installed{};
    check(FwpmCalloutGetByKey0(engine, &key, &installed), "FwpmCalloutGetByKey0");
    const bool registered = (installed->flags & kCalloutRegistered) != 0;
    FwpmFreeMemory0(reinterpret_cast<void**>(&installed));
    if (!registered) throw std::runtime_error("PIA kernel callout is not registered");
}

void addFilter(HANDLE engine, const GUID& provider, const GUID& sublayer, const GUID& layer,
               const GUID& callout, FWP_ACTION_TYPE action, UINT8 weight,
               const GUID* context, FWPM_FILTER_CONDITION0* conditions, UINT32 conditionCount,
               const wchar_t* name) {
    FWPM_FILTER0 filter{};
    filter.filterKey = newGuid();
    filter.displayData = display(name);
    filter.providerKey = const_cast<GUID*>(&provider);
    filter.layerKey = layer;
    filter.subLayerKey = sublayer;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.action.type = action;
    if (action & FWP_ACTION_FLAG_CALLOUT) filter.action.calloutKey = callout;
    if (context) {
        filter.flags |= kHasProviderContext;
        filter.providerContextKey = *context;
    }
    if (conditions) {
        filter.numFilterConditions = conditionCount;
        filter.filterCondition = conditions;
    }
    check(FwpmFilterAdd0(engine, &filter, nullptr, nullptr), "FwpmFilterAdd0");
}

FWPM_FILTER_CONDITION0 appCondition(FWP_BYTE_BLOB* appId) {
    FWPM_FILTER_CONDITION0 condition{};
    condition.fieldKey = kConditionAppId;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.byteBlob = appId;
    return condition;
}

class SplitSession {
public:
    SplitSession(const std::unordered_set<std::wstring>& apps, UINT32 tunnelIp) {
        FWPM_SESSION0 session{};
        session.sessionKey = newGuid();
        session.displayData = display(L"WireGuard Program Split dynamic session");
        session.flags = kDynamicSession;
        check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &engine_), "FwpmEngineOpen0");

        provider_ = newGuid();
        FWPM_PROVIDER0 provider{};
        provider.providerKey = provider_;
        provider.displayData = display(L"WireGuard Program Split provider");
        check(FwpmProviderAdd0(engine_, &provider, nullptr), "FwpmProviderAdd0");

        sublayer_ = newGuid();
        FWPM_SUBLAYER0 sublayer{};
        sublayer.subLayerKey = sublayer_;
        sublayer.displayData = display(L"WireGuard Program Split filters");
        sublayer.providerKey = &provider_;
        sublayer.weight = 0x8000;
        check(FwpmSubLayerAdd0(engine_, &sublayer, nullptr), "FwpmSubLayerAdd0");

        check(FwpmTransactionBegin0(engine_, 0), "FwpmTransactionBegin0");
        bool committed = false;
        try {
            install(apps, tunnelIp);
            check(FwpmTransactionCommit0(engine_), "FwpmTransactionCommit0");
            committed = true;
        } catch (...) {
            if (!committed) FwpmTransactionAbort0(engine_);
            throw;
        }
    }

    ~SplitSession() {
        if (engine_) FwpmEngineClose0(engine_);
    }

private:
    void install(const std::unordered_set<std::wstring>& apps, UINT32 tunnelIp) {
        ContextData contextData{tunnelIp, 0, 0};
        FWP_BYTE_BLOB contextBlob{sizeof(contextData), reinterpret_cast<UINT8*>(&contextData)};
        GUID contextKey = newGuid();
        FWPM_PROVIDER_CONTEXT0 context{};
        context.providerContextKey = contextKey;
        context.displayData = display(L"WireGuard Program Split PIA context");
        context.providerKey = &provider_;
        context.type = FWPM_GENERAL_CONTEXT;
        context.dataBuffer = &contextBlob;
        check(FwpmProviderContextAdd0(engine_, &context, nullptr, nullptr), "FwpmProviderContextAdd0");

        addCallout(engine_, provider_, kCalloutBind, kLayerBindV4, L"PIA bind redirect");
        addCallout(engine_, provider_, kCalloutConnect, kLayerConnectV4, L"PIA connect redirect");

        for (const auto& app : apps) {
            FWP_BYTE_BLOB* appId{};
            check(FwpmGetAppIdFromFileName0(app.c_str(), &appId), "FwpmGetAppIdFromFileName0");
            try {
                auto appMatch = appCondition(appId);
                addFilter(engine_, provider_, sublayer_, kLayerBindV4, kCalloutBind,
                          FWP_ACTION_CALLOUT_TERMINATING, 15, &contextKey, &appMatch, 1,
                          L"Included app UDP bind");
                addFilter(engine_, provider_, sublayer_, kLayerConnectV4, kCalloutConnect,
                          FWP_ACTION_CALLOUT_TERMINATING, 15, &contextKey, &appMatch, 1,
                          L"Included app TCP connect");
            } catch (...) {
                FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
                throw;
            }
            FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
        }
    }

    HANDLE engine_{};
    GUID provider_{};
    GUID sublayer_{};
};

}  // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wcscmp(argv[1], L"--self-test") == 0) {
            if (parseIpv4(L"192.0.2.2") != 0xc0000202) return 2;
            const auto included = parseIncludedText(L"C:\\Apps\\One.exe\r\n# comment\nC:\\Apps\\Two.exe\n");
            if (included.size() != 2 || !included.count(L"c:\\apps\\one.exe") ||
                !included.count(L"c:\\apps\\two.exe")) return 3;
            std::wcout << L"PASS: WFP context layout and IPv4 conversion.\n";
            return 0;
        }
        if (argc != 3) {
            std::wcerr << L"Usage: wfp-probe.exe <included-apps.txt> <tunnel-ip>\n";
            return 2;
        }
        const auto apps = loadIncludedPaths(argv[1]);
        for (const auto& app : apps) {
            if (GetFileAttributesW(app.c_str()) == INVALID_FILE_ATTRIBUTES) {
                throw std::runtime_error("Included executable does not exist");
            }
        }

        gStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!gStopEvent) throw std::runtime_error("CreateEventW failed");
        SetConsoleCtrlHandler(onConsoleSignal, TRUE);

        SplitSession session(apps, parseIpv4(argv[2]));
        std::wcout << L"READY: dynamic payload filters active for " << apps.size()
                   << L" included application(s)\n";
        std::wcout.flush();
        WaitForSingleObject(gStopEvent, INFINITE);
        CloseHandle(gStopEvent);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << "\n";
        return 1;
    }
}
