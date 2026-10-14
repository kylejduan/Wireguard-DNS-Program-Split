// SPDX-License-Identifier: GPL-3.0-or-later
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <rpcdce.h>
#include <winternl.h>

#include <map>
#include <set>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include "parse-number.h"
#include "path-identity.h"

namespace {

// fwpmtypes.h flag values that MinGW does not define.
constexpr UINT32 kProviderPersistent = 0x00000001;
constexpr UINT16 kSublayerPersistent = 0x0001;
constexpr UINT32 kCalloutPersistent = 0x00010000;
constexpr UINT32 kUsesProviderContext = 0x00020000;
constexpr UINT32 kCalloutRegistered = 0x00040000;
constexpr UINT32 kContextPersistent = 0x00000001;
constexpr UINT32 kFilterPersistent = 0x00000001;
constexpr UINT32 kFilterBootTime = 0x00000002;
constexpr UINT32 kHasProviderContext = 0x00000004;
constexpr UINT32 kClearActionRight = 0x00000008;
constexpr UINT32 kReadOnlyTransaction = 0x00000001;
// Sublayers are arbitrated from the highest weight down. At the maximum, another provider's filters,
// hard permits included, come after these hard blocks unless they share the weight.
constexpr UINT16 kSublayerWeight = 0xffff;

// Exit codes Invoke-WfpFilters.ps1 tells apart.
constexpr int kExitFailed = 1;
constexpr int kExitUsage = 2;
constexpr int kExitCalloutInUse = 3;
constexpr int kExitUnregistered = 4;

// Project-owned persistent identities. Every object this program adds names kProvider, so install and
// remove find whatever an earlier run left behind, including a run that was killed or a previous list.
constexpr GUID kProvider{0xaf8ce9d2, 0x71b6, 0x4050, {0x84, 0x47, 0x0e, 0xbb, 0xc4, 0x25, 0x58, 0xde}};
constexpr GUID kSublayer{0xf79561bc, 0x0027, 0x4152, {0x9a, 0x46, 0xc8, 0xc7, 0x30, 0x91, 0x1a, 0xbb}};

constexpr GUID kLayerBindV4{0x66978cad, 0xc704, 0x42ac, {0x86, 0xac, 0x7c, 0x1a, 0x23, 0x1b, 0xd2, 0x53}};
constexpr GUID kLayerConnectV4{0xc6e63c8c, 0xb784, 0x4562, {0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3}};
constexpr GUID kLayerAuthConnectV4{0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
constexpr GUID kLayerRecvAcceptV4{0xe1cd9fe7, 0xf4b5, 0x4273, {0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}};
constexpr GUID kLayerConnectV6{0x4a72393b, 0x319f, 0x44bc, {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}};
constexpr GUID kLayerRecvAcceptV6{0xa3b42c97, 0x9f04, 0x4672, {0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}};
constexpr GUID kConditionAppId{0xd78e1e87, 0x8644, 0x4ea5, {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}};
constexpr GUID kConditionFlags{0x632ce23b, 0x5167, 0x435c, {0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}};
constexpr GUID kConditionLocalAddress{0xd9ee00de, 0xc1ef, 0x4617, {0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57}};
// PIA WFP callout ABI identifiers and context layout. See NOTICE.md for source and license.
constexpr GUID kCalloutBind{0xb16b0a6e, 0x2b2a, 0x41a3, {0x8b, 0x39, 0xbd, 0x3f, 0xfc, 0x85, 0x5f, 0xf8}};
constexpr GUID kCalloutConnect{0xb80ca14a, 0xa807, 0x4ef2, {0x87, 0x2d, 0x4b, 0x1a, 0x51, 0x82, 0x54, 0x02}};

struct ContextData {
    UINT32 bindIp;
    UINT32 rewriteDnsServer;
    UINT32 dnsSourceIp;
};
static_assert(sizeof(ContextData) == 12, "PIA provider context must be 12 bytes");

struct CalloutRule {
    const GUID* key;
    const GUID* layer;
    const wchar_t* name;
};
constexpr CalloutRule kCallouts[] = {
    {&kCalloutBind, &kLayerBindV4, L"PIA bind redirect"},
    {&kCalloutConnect, &kLayerConnectV4, L"PIA connect redirect"},
};

// Each included application gets every rule. The PIA callouts bind its IPv4 sockets to the tunnel
// address. The blocks need no driver: authorization refuses IPv4 whose local address is not the tunnel
// address, which is what an unredirected socket has, and all IPv6, so it falls back to IPv4. Loopback,
// which never leaves the host, is exempt.
struct FilterRule {
    const GUID* layer;
    FWP_ACTION_TYPE action;
    const GUID* callout;
    bool exceptLoopback;
    bool exceptTunnel;
    const wchar_t* name;
};
constexpr FilterRule kRules[] = {
    {&kLayerBindV4, FWP_ACTION_CALLOUT_TERMINATING, &kCalloutBind, false, false, L"Included app UDP bind"},
    {&kLayerConnectV4, FWP_ACTION_CALLOUT_TERMINATING, &kCalloutConnect, false, false, L"Included app TCP connect"},
    {&kLayerAuthConnectV4, FWP_ACTION_BLOCK, nullptr, true, true, L"Included app IPv4 connect outside the tunnel"},
    {&kLayerRecvAcceptV4, FWP_ACTION_BLOCK, nullptr, true, true, L"Included app IPv4 accept outside the tunnel"},
    {&kLayerConnectV6, FWP_ACTION_BLOCK, nullptr, true, false, L"Included app IPv6 connect block"},
    {&kLayerRecvAcceptV6, FWP_ACTION_BLOCK, nullptr, true, false, L"Included app IPv6 accept block"},
};

class ProbeError : public std::runtime_error {
public:
    ProbeError(const std::string& message, int code) : std::runtime_error(message), code_(code) {}
    int code() const { return code_; }

private:
    int code_;
};

// ASCII only, as WFP lowercases application identifiers; other letters keep their case.
std::wstring lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](wchar_t c) { return c >= L'A' && c <= L'Z' ? static_cast<wchar_t>(c + (L'a' - L'A')) : c; });
    return value;
}

std::wstring trim(std::wstring value) {
    const auto first = value.find_first_not_of(L" \t\r");
    if (first == std::wstring::npos) return {};
    const auto last = value.find_last_not_of(L" \t\r");
    return value.substr(first, last - first + 1);
}

std::unordered_set<std::wstring> parseIncludedText(const std::wstring& text) {
    std::unordered_set<std::wstring> result;
    size_t start{};
    while (start <= text.size()) {
        const size_t end = text.find(L'\n', start);
        std::wstring line = trim(text.substr(start, end == std::wstring::npos ? end : end - start));
        // Entries keep the listed spelling; resolution happens per entry, so the entry also names a path's
        // installed filters while the path cannot be resolved.
        if (!line.empty() && line.front() != L'#') result.insert(lower(line));
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

std::string utf8(const std::wstring& text) {
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size > 0 ? static_cast<size_t>(size) : 0, '\0');
    if (size > 0) WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr);
    return result;
}

bool insideDirectory(const std::wstring& path, const std::wstring& directory) {
    return !directory.empty() && path.size() > directory.size() && path.compare(0, directory.size(), directory) == 0;
}

// The dispatcher, tunnel host and controller host are installed beside this program. Listing one of them
// would put the stack's own traffic behind these filters, so it is refused.
std::wstring componentDirectory() {
    std::vector<wchar_t> buffer(32768);
    const DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (!size || size >= buffer.size()) throw std::runtime_error("Cannot locate wfp-probe.exe");
    const std::wstring path = lower(wgps::finalPath(std::wstring(buffer.data(), size), VOLUME_NAME_DOS));
    const size_t separator = path.find_last_of(L'\\');
    if (separator == std::wstring::npos) throw std::runtime_error("Cannot locate wfp-probe.exe");
    return path.substr(0, separator + 1);
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

bool isStatus(DWORD status, HRESULT expected) { return status == static_cast<DWORD>(expected); }

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

bool sameGuid(const GUID& left, const GUID& right) { return std::memcmp(&left, &right, sizeof(GUID)) == 0; }

bool ownedBy(const GUID* provider) { return provider && sameGuid(*provider, kProvider); }

std::string guidText(const GUID& value) {
    char text[40]{};
    snprintf(text, sizeof(text), "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             static_cast<unsigned long>(value.Data1), value.Data2, value.Data3, value.Data4[0], value.Data4[1],
             value.Data4[2], value.Data4[3], value.Data4[4], value.Data4[5], value.Data4[6], value.Data4[7]);
    return text;
}

std::string hexBytes(const UINT8* data, size_t size) {
    static const char digits[] = "0123456789abcdef";
    std::string text;
    text.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        text.push_back(digits[data[i] >> 4]);
        text.push_back(digits[data[i] & 15]);
    }
    return text;
}

FWPM_DISPLAY_DATA0 display(const wchar_t* name, const wchar_t* description = L"") {
    return {const_cast<wchar_t*>(name), const_cast<wchar_t*>(description)};
}

ContextData contextFor(UINT32 tunnelIp) { return {tunnelIp, 0, 0}; }

bool contextMatches(const std::vector<UINT8>& data, UINT32 tunnelIp) {
    const ContextData expected = contextFor(tunnelIp);
    return data.size() == sizeof(expected) && std::memcmp(data.data(), &expected, sizeof(expected)) == 0;
}

std::string conditionText(const FWPM_FILTER_CONDITION0& condition) {
    const FWP_CONDITION_VALUE0& value = condition.conditionValue;
    std::string text;
    switch (value.type) {
    case FWP_UINT8: text = "u8:" + std::to_string(value.uint8); break;
    case FWP_UINT16: text = "u16:" + std::to_string(value.uint16); break;
    case FWP_UINT32: text = "u32:" + std::to_string(value.uint32); break;
    case FWP_BYTE_BLOB_TYPE:
        text = value.byteBlob ? "blob:" + hexBytes(value.byteBlob->data, value.byteBlob->size) : "blob:null";
        break;
    default: text = "type:" + std::to_string(value.type);
    }
    return guidText(condition.fieldKey) + "/" + std::to_string(condition.matchType) + "/" + text;
}

// Everything that decides what a filter does. The key, display name and weight are not compared.
std::string filterSignature(const FWPM_FILTER0& filter) {
    std::vector<std::string> conditions;
    for (UINT32 i = 0; i < filter.numFilterConditions; ++i) conditions.push_back(conditionText(filter.filterCondition[i]));
    std::sort(conditions.begin(), conditions.end());
    // A boot-time filter is added to the default sublayer, which BFE reports under its own key.
    const bool bootTime = (filter.flags & kFilterBootTime) != 0;
    std::string text = guidText(filter.layerKey) + " sublayer:" + (bootTime ? "default" : guidText(filter.subLayerKey)) +
                       " action:" + std::to_string(filter.action.type);
    if (filter.action.type & FWP_ACTION_FLAG_CALLOUT) text += " callout:" + guidText(filter.action.calloutKey);
    text += (filter.flags & kFilterPersistent) ? " persistent" : bootTime ? " boottime" : " dynamic";
    if (filter.flags & kClearActionRight) text += " hard";
    if (filter.flags & kHasProviderContext) text += " context:" + guidText(filter.providerContextKey);
    text += " tag:" + (filter.providerData.data ? hexBytes(filter.providerData.data, filter.providerData.size) : std::string());
    for (const auto& condition : conditions) text += " " + condition;
    return text;
}

struct FilterDraft {
    FWPM_FILTER0 filter{};
    FWPM_FILTER_CONDITION0 conditions[3]{};
};

// One identifier of a listed entry. The tag, the entry as listed, is stored as each filter's provider data,
// so the filters of an entry that cannot be resolved later are found and kept rather than replaced.
struct AppEntry {
    FWP_BYTE_BLOB* appId;
    FWP_BYTE_BLOB* tag;
};

// Fills the draft in place: the filter points at the draft's own condition array.
void draftFilter(FilterDraft& draft, const FilterRule& rule, const AppEntry& app, const GUID& context, UINT32 tunnelIp,
                 bool bootTime = false) {
    draft = FilterDraft{};
    draft.conditions[0].fieldKey = kConditionAppId;
    draft.conditions[0].matchType = FWP_MATCH_EQUAL;
    draft.conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    draft.conditions[0].conditionValue.byteBlob = app.appId;
    UINT32 conditionCount = 1;
    if (rule.exceptLoopback) {
        draft.conditions[conditionCount].fieldKey = kConditionFlags;
        draft.conditions[conditionCount].matchType = FWP_MATCH_FLAGS_NONE_SET;
        draft.conditions[conditionCount].conditionValue.type = FWP_UINT32;
        draft.conditions[conditionCount].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        ++conditionCount;
    }
    if (rule.exceptTunnel) {
        draft.conditions[conditionCount].fieldKey = kConditionLocalAddress;
        draft.conditions[conditionCount].matchType = FWP_MATCH_NOT_EQUAL;
        draft.conditions[conditionCount].conditionValue.type = FWP_UINT32;
        draft.conditions[conditionCount].conditionValue.uint32 = tunnelIp;
        ++conditionCount;
    }
    FWPM_FILTER0& filter = draft.filter;
    filter.displayData = display(rule.name);
    filter.flags = kFilterPersistent;
    filter.providerKey = const_cast<GUID*>(&kProvider);
    filter.providerData = *app.tag;
    filter.layerKey = *rule.layer;
    filter.subLayerKey = kSublayer;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 15;
    filter.action.type = rule.action;
    if (rule.callout) {
        filter.action.calloutKey = *rule.callout;
        filter.flags |= kHasProviderContext;
        filter.providerContextKey = context;
    } else {
        // A hard block: no filter or callout in a later sublayer can turn it into a permit.
        filter.flags |= kClearActionRight;
    }
    if (bootTime) {
        // TCP/IP enforces boot-time filters from its start until BFE has loaded the persistent set. They
        // cannot also be persistent and take the default sublayer, which exists before BFE does.
        filter.flags = (filter.flags & ~kFilterPersistent) | kFilterBootTime;
        filter.subLayerKey = GUID{};
    }
    filter.numFilterConditions = conditionCount;
    filter.filterCondition = draft.conditions;
}

// Visits every filter of the set: each rule per application, and a boot-time copy of each block. The
// redirect filters are left out while another provider holds the PIA callout keys.
template <typename Visit>
void forEachFilter(const std::vector<AppEntry>& apps, const GUID& context, UINT32 tunnelIp,
                   bool withRedirects, Visit visit) {
    FilterDraft draft;
    for (const AppEntry& app : apps) {
        for (const auto& rule : kRules) {
            if (rule.callout && !withRedirects) continue;
            draftFilter(draft, rule, app, context, tunnelIp);
            visit(draft.filter);
            if (rule.callout) continue;
            draftFilter(draft, rule, app, context, tunnelIp, true);
            visit(draft.filter);
        }
    }
}

std::vector<std::string> expectedSignatures(const std::vector<AppEntry>& apps, const GUID& context,
                                            UINT32 tunnelIp) {
    std::vector<std::string> result;
    forEachFilter(apps, context, tunnelIp, true, [&](const FWPM_FILTER0& filter) {
        result.push_back(filterSignature(filter));
    });
    std::sort(result.begin(), result.end());
    return result;
}

struct OwnedFilter {
    UINT64 id;
    std::string signature;
    std::wstring tag;
    std::wstring path;
    std::vector<UINT8> appId;
};

OwnedFilter ownedFilter(const FWPM_FILTER0& filter) {
    OwnedFilter owned{filter.filterId, filterSignature(filter), {}, {}, {}};
    if (filter.providerData.data && filter.providerData.size % sizeof(wchar_t) == 0) {
        // The listed entry, a tab and its attribution path: the whole shared identity, committed with the filter.
        const std::wstring data(reinterpret_cast<const wchar_t*>(filter.providerData.data), filter.providerData.size / sizeof(wchar_t));
        const size_t tab = data.find(L'\t');
        owned.tag = data.substr(0, tab);
        if (tab != std::wstring::npos) owned.path = data.substr(tab + 1);
    }
    for (UINT32 i = 0; i < filter.numFilterConditions; ++i) {
        const FWPM_FILTER_CONDITION0& condition = filter.filterCondition[i];
        if (sameGuid(condition.fieldKey, kConditionAppId) && condition.conditionValue.type == FWP_BYTE_BLOB_TYPE &&
            condition.conditionValue.byteBlob) {
            const FWP_BYTE_BLOB& blob = *condition.conditionValue.byteBlob;
            owned.appId.assign(blob.data, blob.data + blob.size);
        }
    }
    return owned;
}
struct OwnedCallout {
    GUID key;
    UINT32 flags;
    GUID layer;
};
struct OwnedContext {
    GUID key;
    UINT64 id;
    UINT32 flags;
    FWPM_PROVIDER_CONTEXT_TYPE type;
    std::vector<UINT8> data;
};
struct OwnedSublayer {
    GUID key;
    UINT16 flags;
    UINT16 weight;
};
struct Owned {
    bool provider{};
    UINT32 providerFlags{};
    std::vector<OwnedFilter> filters;
    std::vector<OwnedCallout> callouts;
    std::vector<OwnedContext> contexts;
    std::vector<OwnedSublayer> sublayers;
    bool empty() const {
        return !provider && filters.empty() && callouts.empty() && contexts.empty() && sublayers.empty();
    }
};

const CalloutRule* calloutRule(const GUID& key) {
    for (const auto& rule : kCallouts) {
        if (sameGuid(*rule.key, key)) return &rule;
    }
    return nullptr;
}

bool calloutCurrent(const OwnedCallout& callout) {
    const CalloutRule* rule = calloutRule(callout.key);
    return rule && sameGuid(*rule->layer, callout.layer) && (callout.flags & kCalloutPersistent) &&
           (callout.flags & kUsesProviderContext);
}

bool sublayerCurrent(const OwnedSublayer& sublayer) {
    return sameGuid(sublayer.key, kSublayer) && (sublayer.flags & kSublayerPersistent) &&
           sublayer.weight == kSublayerWeight;
}

// Returns an empty string when the owned objects are exactly the set install creates for these inputs.
std::string describeMismatch(const Owned& owned, const std::vector<AppEntry>& apps, UINT32 tunnelIp) {
    if (!owned.provider) return "the provider is missing";
    if (!(owned.providerFlags & kProviderPersistent)) return "the provider is not persistent";
    if (owned.sublayers.size() != 1 || !sublayerCurrent(owned.sublayers.front())) {
        return "expected the persistent sublayer alone, found " + std::to_string(owned.sublayers.size()) + " sublayer(s)";
    }
    size_t currentCallouts{};
    for (const auto& callout : owned.callouts) currentCallouts += calloutCurrent(callout) ? 1 : 0;
    if (owned.callouts.size() != std::size(kCallouts) || currentCallouts != std::size(kCallouts)) {
        return "expected both persistent PIA callouts, found " + std::to_string(currentCallouts) + " of " +
               std::to_string(owned.callouts.size());
    }
    if (owned.contexts.size() != 1) {
        return "expected one provider context, found " + std::to_string(owned.contexts.size());
    }
    const OwnedContext& context = owned.contexts.front();
    if (!(context.flags & kContextPersistent) || context.type != FWPM_GENERAL_CONTEXT ||
        !contextMatches(context.data, tunnelIp)) {
        return "the provider context does not carry this tunnel address";
    }
    std::vector<std::string> actual;
    for (const auto& filter : owned.filters) actual.push_back(filter.signature);
    std::sort(actual.begin(), actual.end());
    const std::vector<std::string> expected = expectedSignatures(apps, context.key, tunnelIp);
    if (actual != expected) {
        std::vector<std::string> missing;
        std::set_difference(expected.begin(), expected.end(), actual.begin(), actual.end(), std::back_inserter(missing));
        return "expected " + std::to_string(expected.size()) + " filter(s), found " + std::to_string(actual.size()) +
               " with " + std::to_string(missing.size()) + " missing";
    }
    return {};
}

class Engine {
public:
    Engine() {
        FWPM_SESSION0 session{};
        session.displayData = display(L"WireGuard Program Split");
        // Wait for another writer's transaction, but not indefinitely.
        session.txnWaitTimeoutInMSec = 15000;
        check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &handle_), "FwpmEngineOpen0");
    }
    ~Engine() {
        if (handle_) FwpmEngineClose0(handle_);
    }
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    HANDLE get() const { return handle_; }

private:
    HANDLE handle_{};
};

// Closing the engine or exiting before commit aborts, so a killed run changes nothing.
class Transaction {
public:
    Transaction(HANDLE engine, UINT32 flags) : engine_(engine) {
        check(FwpmTransactionBegin0(engine, flags), "FwpmTransactionBegin0");
    }
    ~Transaction() {
        if (!finished_) FwpmTransactionAbort0(engine_);
    }
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    void commit() {
        check(FwpmTransactionCommit0(engine_), "FwpmTransactionCommit0");
        finished_ = true;
    }

private:
    HANDLE engine_;
    bool finished_{};
};

#include "wfp-probe-identity.h"

class AppIds {
public:
    explicit AppIds(const Identities& identified) {
        for (const auto& [entry, found] : identified) {
            // Each attribution path tags its own identifiers, so recovery restores each pairing.
            std::vector<AttributionGroup> groups{{found.path, found.ids}};
            groups.insert(groups.end(), found.others.begin(), found.others.end());
            for (const auto& group : groups) {
                const std::wstring tag = entry + L"\t" + group.path;
                tags_.push_back(std::vector<UINT8>(reinterpret_cast<const UINT8*>(tag.data()),
                                                   reinterpret_cast<const UINT8*>(tag.data() + tag.size())));
                for (const auto& id : group.ids) {
                    data_.push_back(id);
                    owners_.push_back(tags_.size() - 1);
                }
            }
        }
        tagBlobs_.reserve(tags_.size());
        for (auto& tag : tags_) tagBlobs_.push_back({static_cast<UINT32>(tag.size()), tag.data()});
        idBlobs_.reserve(data_.size());
        for (auto& bytes : data_) idBlobs_.push_back({static_cast<UINT32>(bytes.size()), bytes.data()});
        for (size_t i = 0; i < idBlobs_.size(); ++i) entries_.push_back({&idBlobs_[i], &tagBlobs_[owners_[i]]});
    }
    AppIds(const AppIds&) = delete;
    AppIds& operator=(const AppIds&) = delete;
    const std::vector<AppEntry>& get() const { return entries_; }

private:
    std::vector<std::vector<UINT8>> tags_;
    std::vector<std::vector<UINT8>> data_;
    std::vector<size_t> owners_;
    std::vector<FWP_BYTE_BLOB> tagBlobs_;
    std::vector<FWP_BYTE_BLOB> idBlobs_;
    std::vector<AppEntry> entries_;
};

template <typename Item, typename Template, typename Create, typename Next, typename Destroy, typename Visit>
void enumerate(HANDLE engine, const Template* match, Create create, Next next, Destroy destroy, Visit visit,
               const char* operation) {
    constexpr UINT32 kBatch = 256;
    HANDLE handle{};
    check(create(engine, match, &handle), operation);
    try {
        for (;;) {
            Item** entries{};
            UINT32 count{};
            check(next(engine, handle, kBatch, &entries, &count), operation);
            try {
                for (UINT32 i = 0; i < count; ++i) visit(*entries[i]);
            } catch (...) {
                FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                throw;
            }
            FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
            if (count < kBatch) break;
        }
    } catch (...) {
        destroy(engine, handle);
        throw;
    }
    destroy(engine, handle);
}

std::vector<GUID> distinctLayers(bool callouts) {
    std::vector<GUID> layers;
    auto add = [&](const GUID& layer) {
        if (std::none_of(layers.begin(), layers.end(), [&](const GUID& known) { return sameGuid(known, layer); })) {
            layers.push_back(layer);
        }
    };
    if (callouts) for (const auto& rule : kCallouts) add(*rule.layer);
    else for (const auto& rule : kRules) add(*rule.layer);
    return layers;
}

// Everything owned by kProvider. The filter engine filters by provider, and for filters and callouts by
// layer, so only the project's own objects are marshaled. Removal also enumerates every layer, so an
// object a different release added elsewhere cannot outlive it.
Owned snapshot(HANDLE engine, bool everyLayer = false) {
    Owned owned;
    FWPM_PROVIDER0* provider{};
    const DWORD status = FwpmProviderGetByKey0(engine, &kProvider, &provider);
    if (status == ERROR_SUCCESS) {
        owned.provider = true;
        owned.providerFlags = provider->flags;
        FwpmFreeMemory0(reinterpret_cast<void**>(&provider));
    } else if (!isStatus(status, FWP_E_PROVIDER_NOT_FOUND)) {
        check(status, "FwpmProviderGetByKey0");
    }
    const auto visitFilter = [&](const FWPM_FILTER0& filter) {
        if (ownedBy(filter.providerKey)) owned.filters.push_back(ownedFilter(filter));
    };
    const auto visitCallout = [&](const FWPM_CALLOUT0& callout) {
        if (ownedBy(callout.providerKey)) owned.callouts.push_back({callout.calloutKey, callout.flags, callout.applicableLayer});
    };
    if (everyLayer) {
        enumerate<FWPM_FILTER0>(engine, static_cast<const FWPM_FILTER_ENUM_TEMPLATE0*>(nullptr), FwpmFilterCreateEnumHandle0,
                                FwpmFilterEnum0, FwpmFilterDestroyEnumHandle0, visitFilter, "FwpmFilterEnum0");
        enumerate<FWPM_CALLOUT0>(engine, static_cast<const FWPM_CALLOUT_ENUM_TEMPLATE0*>(nullptr), FwpmCalloutCreateEnumHandle0,
                                 FwpmCalloutEnum0, FwpmCalloutDestroyEnumHandle0, visitCallout, "FwpmCalloutEnum0");
    } else {
        for (const GUID& layer : distinctLayers(false)) {
            FWPM_FILTER_ENUM_TEMPLATE0 match{};
            match.providerKey = const_cast<GUID*>(&kProvider);
            match.layerKey = layer;
            match.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
            // A template that names a layer leaves boot-time filters out unless asked for them.
            match.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME;
            match.actionMask = 0xffffffff;
            enumerate<FWPM_FILTER0>(engine, &match, FwpmFilterCreateEnumHandle0, FwpmFilterEnum0,
                                    FwpmFilterDestroyEnumHandle0, visitFilter, "FwpmFilterEnum0");
        }
        for (const GUID& layer : distinctLayers(true)) {
            FWPM_CALLOUT_ENUM_TEMPLATE0 match{};
            match.providerKey = const_cast<GUID*>(&kProvider);
            match.layerKey = layer;
            enumerate<FWPM_CALLOUT0>(engine, &match, FwpmCalloutCreateEnumHandle0, FwpmCalloutEnum0,
                                     FwpmCalloutDestroyEnumHandle0, visitCallout, "FwpmCalloutEnum0");
        }
    }
    FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0 contextMatch{};
    contextMatch.providerKey = const_cast<GUID*>(&kProvider);
    contextMatch.providerContextType = FWPM_GENERAL_CONTEXT;
    enumerate<FWPM_PROVIDER_CONTEXT0>(engine, everyLayer ? nullptr : &contextMatch, FwpmProviderContextCreateEnumHandle0,
        FwpmProviderContextEnum0, FwpmProviderContextDestroyEnumHandle0, [&](const FWPM_PROVIDER_CONTEXT0& context) {
            if (!ownedBy(context.providerKey)) return;
            std::vector<UINT8> data;
            if (context.type == FWPM_GENERAL_CONTEXT && context.dataBuffer && context.dataBuffer->data) {
                data.assign(context.dataBuffer->data, context.dataBuffer->data + context.dataBuffer->size);
            }
            owned.contexts.push_back({context.providerContextKey, context.providerContextId, context.flags,
                                      context.type, std::move(data)});
        }, "FwpmProviderContextEnum0");
    FWPM_SUBLAYER_ENUM_TEMPLATE0 sublayerMatch{};
    sublayerMatch.providerKey = const_cast<GUID*>(&kProvider);
    enumerate<FWPM_SUBLAYER0>(engine, everyLayer ? nullptr : &sublayerMatch, FwpmSubLayerCreateEnumHandle0,
        FwpmSubLayerEnum0, FwpmSubLayerDestroyEnumHandle0, [&](const FWPM_SUBLAYER0& sublayer) {
            if (ownedBy(sublayer.providerKey)) owned.sublayers.push_back({sublayer.subLayerKey, sublayer.flags, sublayer.weight});
        }, "FwpmSubLayerEnum0");
    return owned;
}

Owned readSnapshot(HANDLE engine, bool everyLayer = false) {
    Transaction transaction(engine, kReadOnlyTransaction);
    Owned owned = snapshot(engine, everyLayer);
    transaction.commit();
    return owned;
}

std::string describeCounts(const Owned& owned) {
    const auto bootTime = std::count_if(owned.filters.begin(), owned.filters.end(), [](const OwnedFilter& filter) {
        return filter.signature.find(" boottime") != std::string::npos;
    });
    return std::to_string(owned.filters.size()) + " filter(s) including " + std::to_string(bootTime) + " boot-time, " +
           std::to_string(owned.contexts.size()) +
           " provider context(s), " + std::to_string(owned.callouts.size()) + " callout(s), " +
           std::to_string(owned.sublayers.size()) + " sublayer(s)" + (owned.provider ? ", provider" : "");
}

void deleteFiltersAndContexts(HANDLE engine, const Owned& owned) {
    // Filters first: they reference the provider context, callouts and sublayer.
    for (const auto& filter : owned.filters) check(FwpmFilterDeleteById0(engine, filter.id), "FwpmFilterDeleteById0");
    for (const auto& context : owned.contexts) {
        check(FwpmProviderContextDeleteById0(engine, context.id), "FwpmProviderContextDeleteById0");
    }
}

// True when a PIA callout key belongs to another provider: the dynamic session of an earlier release's
// filter host, or the PIA client. A persistent filter cannot reference that callout.
bool calloutsForeign(HANDLE engine) {
    bool foreign = false;
    for (const auto& rule : kCallouts) {
        FWPM_CALLOUT0* existing{};
        const DWORD status = FwpmCalloutGetByKey0(engine, rule.key, &existing);
        if (status == ERROR_SUCCESS) {
            foreign = foreign || !ownedBy(existing->providerKey);
            FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
        } else if (!isStatus(status, FWP_E_CALLOUT_NOT_FOUND)) {
            check(status, "FwpmCalloutGetByKey0");
        }
    }
    return foreign;
}

void addCallout(HANDLE engine, const CalloutRule& rule) {
    FWPM_CALLOUT0 callout{};
    callout.calloutKey = *rule.key;
    callout.displayData = display(rule.name);
    callout.flags = kCalloutPersistent | kUsesProviderContext;
    callout.providerKey = const_cast<GUID*>(&kProvider);
    callout.applicableLayer = *rule.layer;
    check(FwpmCalloutAdd0(engine, &callout, nullptr, nullptr), "FwpmCalloutAdd0");
}

// Replaces every object owned by kProvider with the set for these inputs in one transaction, so a list or
// tunnel-address change never passes through a state without filters. The PIA driver need not be loaded.
// While another provider holds the PIA callout keys, the blocks are committed without the redirect and
// the caller is told, so an earlier release's filter host is stopped only after its successor blocks.
void install(HANDLE engine, const std::vector<AppEntry>& apps, UINT32 tunnelIp) {
    Transaction transaction(engine, 0);
    const bool foreign = calloutsForeign(engine);
    const Owned existing = snapshot(engine);
    if (existing.provider && !(existing.providerFlags & kProviderPersistent)) {
        throw std::runtime_error("The WireGuard Program Split WFP provider exists but is not persistent");
    }
    if (!existing.provider) {
        FWPM_PROVIDER0 provider{};
        provider.providerKey = kProvider;
        provider.displayData = display(L"WireGuard Program Split provider");
        provider.flags = kProviderPersistent;
        check(FwpmProviderAdd0(engine, &provider, nullptr), "FwpmProviderAdd0");
    }
    deleteFiltersAndContexts(engine, existing);
    std::vector<const CalloutRule*> calloutsToAdd;
    for (const auto& rule : kCallouts) calloutsToAdd.push_back(&rule);
    for (const auto& callout : existing.callouts) {
        if (calloutCurrent(callout)) {
            calloutsToAdd.erase(std::remove(calloutsToAdd.begin(), calloutsToAdd.end(), calloutRule(callout.key)),
                                calloutsToAdd.end());
        } else {
            check(FwpmCalloutDeleteByKey0(engine, &callout.key), "FwpmCalloutDeleteByKey0");
        }
    }
    bool sublayerPresent = false;
    for (const auto& sublayer : existing.sublayers) {
        if (sublayerCurrent(sublayer)) sublayerPresent = true;
        else check(FwpmSubLayerDeleteByKey0(engine, &sublayer.key), "FwpmSubLayerDeleteByKey0");
    }
    if (!sublayerPresent) {
        FWPM_SUBLAYER0 sublayer{};
        sublayer.subLayerKey = kSublayer;
        sublayer.displayData = display(L"WireGuard Program Split filters");
        sublayer.flags = kSublayerPersistent;
        sublayer.providerKey = const_cast<GUID*>(&kProvider);
        sublayer.weight = kSublayerWeight;
        check(FwpmSubLayerAdd0(engine, &sublayer, nullptr), "FwpmSubLayerAdd0");
    }
    if (!foreign) for (const CalloutRule* rule : calloutsToAdd) addCallout(engine, *rule);

    ContextData contextData = contextFor(tunnelIp);
    FWP_BYTE_BLOB contextBlob{sizeof(contextData), reinterpret_cast<UINT8*>(&contextData)};
    FWPM_PROVIDER_CONTEXT0 context{};
    context.providerContextKey = newGuid();
    context.displayData = display(L"WireGuard Program Split PIA context");
    context.flags = kContextPersistent;
    context.providerKey = const_cast<GUID*>(&kProvider);
    context.type = FWPM_GENERAL_CONTEXT;
    context.dataBuffer = &contextBlob;
    check(FwpmProviderContextAdd0(engine, &context, nullptr, nullptr), "FwpmProviderContextAdd0");

    forEachFilter(apps, context.providerContextKey, tunnelIp, !foreign, [&](FWPM_FILTER0& filter) {
        filter.filterKey = newGuid();
        check(FwpmFilterAdd0(engine, &filter, nullptr, nullptr), "FwpmFilterAdd0");
    });
    transaction.commit();
    if (foreign) {
        throw ProbeError("The PIA callouts belong to another WFP provider, the PIA client or an earlier release's "
                         "filter host; the blocking filters are installed without the redirect", kExitCalloutInUse);
    }
}

Owned removeAll(HANDLE engine) {
    Transaction transaction(engine, 0);
    const Owned existing = snapshot(engine, true);
    deleteFiltersAndContexts(engine, existing);
    for (const auto& callout : existing.callouts) check(FwpmCalloutDeleteByKey0(engine, &callout.key), "FwpmCalloutDeleteByKey0");
    for (const auto& sublayer : existing.sublayers) {
        check(FwpmSubLayerDeleteByKey0(engine, &sublayer.key), "FwpmSubLayerDeleteByKey0");
    }
    if (existing.provider) check(FwpmProviderDeleteByKey0(engine, &kProvider), "FwpmProviderDeleteByKey0");
    transaction.commit();
    return existing;
}

bool calloutsRegistered(HANDLE engine) {
    for (const auto& rule : kCallouts) {
        FWPM_CALLOUT0* callout{};
        check(FwpmCalloutGetByKey0(engine, rule.key, &callout), "FwpmCalloutGetByKey0");
        const bool registered = (callout->flags & kCalloutRegistered) != 0;
        FwpmFreeMemory0(reinterpret_cast<void**>(&callout));
        if (!registered) return false;
    }
    return true;
}

enum class Mode { Invalid, Install, Remove, Verify, Status };

Mode parseMode(int argc, const wchar_t* const* argv) {
    if (argc == 2 && std::wcscmp(argv[1], L"remove") == 0) return Mode::Remove;
    if (argc == 2 && std::wcscmp(argv[1], L"status") == 0) return Mode::Status;
    if (argc == 4 && std::wcscmp(argv[1], L"install") == 0) return Mode::Install;
    if (argc == 4 && std::wcscmp(argv[1], L"verify") == 0) return Mode::Verify;
    return Mode::Invalid;
}

#include "wfp-probe-self-test.h"

}  // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wcscmp(argv[1], L"--self-test") == 0) return selfTest();
        const Mode mode = parseMode(argc, argv);
        if (mode == Mode::Invalid) {
            std::wcerr << L"Usage: wfp-probe.exe install|verify <included-apps.txt> <tunnel-ip> | remove | status\n";
            return kExitUsage;
        }
        if (mode == Mode::Remove) {
            Engine engine;
            const Owned removed = removeAll(engine.get());
            const Owned remaining = readSnapshot(engine.get(), true);
            if (!remaining.empty()) throw std::runtime_error("WFP objects remain after removal: " + describeCounts(remaining));
            std::cout << "REMOVED: " << describeCounts(removed) << "; no WireGuard Program Split WFP objects remain.\n";
            return 0;
        }
        if (mode == Mode::Status) {
            Engine engine;
            const Owned owned = readSnapshot(engine.get());
            if (owned.empty()) std::cout << "ABSENT: no WireGuard Program Split WFP objects are installed.\n";
            else std::cout << "PRESENT: " << describeCounts(owned) << ".\n";
            return 0;
        }
        const auto listed = loadIncludedPaths(argv[2]);
        const std::wstring components = componentDirectory();
        for (const auto& entry : listed) {
            const std::wstring resolved = lower(wgps::resolvePath(entry, VOLUME_NAME_DOS));
            if (insideDirectory(entry, components) || insideDirectory(resolved, components)) {
                throw std::runtime_error("Included executable is a WireGuard Program Split component");
            }
        }
        const UINT32 tunnelIp = parseIpv4(argv[3]);
        Engine engine;
        const std::wstring identitiesPath = identitiesPathFor(argv[2]);
        const std::string recorded = readText(identitiesPath);
        const Identities identified = identifyApps(listed, parseIdentities(recorded), readSnapshot(engine.get()),
            [](const std::wstring& entry) {
                return std::pair{wgps::resolvePath(entry, VOLUME_NAME_DOS), wgps::resolvePath(entry, VOLUME_NAME_NT)};
            },
            [](const std::wstring& resolved) {
                // The filter engine's own identifier for a present executable, from its final name.
                const DWORD attributes = GetFileAttributesW(resolved.c_str());
                if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) return std::vector<UINT8>{};
                try { return fileAppId(resolved); } catch (const std::exception&) { return std::vector<UINT8>{}; }
            });
        for (const auto& [entry, found] : identified) {
            // Filters without a path to attribute DNS by would protect payload while DNS for the same
            // executable went direct; that is refused instead.
            if (!found.ids.empty() && found.path.empty()) {
                throw std::runtime_error("Listed entry has payload identifiers but no attribution identity: " + utf8(entry));
            }
        }
        const std::string serialized = serializeIdentities(identified);
        const AppIds appIds(identified);
        for (const auto& [entry, found] : identified) {
            if (found.source == Identity::Derived) {
                std::cout << "WARNING: listed executable is absent; its filters stay in place for its return: " << utf8(entry) << "\n";
            } else if (found.source == Identity::Retained) {
                std::cout << "WARNING: listed executable's path cannot be resolved; its recorded identity is kept: " << utf8(entry) << "\n";
            } else if (found.source == Identity::None) {
                std::cout << "WARNING: listed executable's path cannot be resolved and it has no filters: " << utf8(entry) << "\n";
            }
        }
        if (mode == Mode::Install) {
            install(engine.get(), appIds.get(), tunnelIp);
            // Recorded after the filters commit; a run ended in between leaves a record verification rejects.
            writeTextAtomically(identitiesPath, serialized);
        } else if (serialized != recorded) {
            throw std::runtime_error("Persistent payload filters do not match: the resolved identities changed or were not recorded");
        }
        const std::string mismatch = describeMismatch(readSnapshot(engine.get()), appIds.get(), tunnelIp);
        if (!mismatch.empty()) throw std::runtime_error("Persistent payload filters do not match: " + mismatch);
        const bool registered = calloutsRegistered(engine.get());
        if (mode == Mode::Install) {
            std::cout << "READY: persistent payload filters installed for " << identified.size() << " listed application(s); "
                      << (registered ? "PIA callouts registered.\n" : "PIA callouts are not registered until the PIA driver loads.\n");
            return 0;
        }
        if (!registered) {
            throw ProbeError("Persistent payload filters match, but the PIA driver has not registered its callouts",
                             kExitUnregistered);
        }
        std::cout << "PASS: persistent payload filters match " << identified.size()
                  << " included application(s) and the tunnel address; PIA callouts registered.\n";
        return 0;
    } catch (const ProbeError& error) {
        std::cerr << "ERROR: " << error.what() << "\n";
        return error.code();
    } catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << "\n";
        return kExitFailed;
    }
}
