// SPDX-License-Identifier: GPL-3.0-or-later
// Private implementation fragment of wfp-probe.cpp.
// The identifier WFP derives from an image path: the NT device path of its final name, with ASCII
// lowercased, NUL included. Built without the file, from the resolved NT path, so a listed path keeps its
// filters while its executable is absent, as when an updater replaces it; FwpmGetAppIdFromFileName0
// requires the file.
std::vector<UINT8> appIdFromNtPath(const std::wstring& ntPath) {
    const std::wstring text = lower(ntPath);
    std::vector<UINT8> bytes((text.size() + 1) * sizeof(wchar_t), 0);
    std::memcpy(bytes.data(), text.c_str(), text.size() * sizeof(wchar_t));
    return bytes;
}

std::vector<UINT8> derivedAppId(const std::wstring& path) {
    const std::wstring resolved = wgps::resolvePath(path, VOLUME_NAME_NT);
    return resolved.empty() ? std::vector<UINT8>{} : appIdFromNtPath(resolved);
}

std::vector<UINT8> fileAppId(const std::wstring& path) {
    FWP_BYTE_BLOB* appId{};
    check(FwpmGetAppIdFromFileName0(path.c_str(), &appId), "FwpmGetAppIdFromFileName0");
    std::vector<UINT8> bytes(appId->data, appId->data + appId->size);
    FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
    return bytes;
}

// The same identifier with every letter lowercased the way the kernel compares names. The management API
// lowercases ASCII only, so for a path with uppercase non-ASCII letters it differs; both are installed.
std::vector<UINT8> fullyLowered(const std::vector<UINT8>& appId) {
    using Downcase = LONG(WINAPI*)(UNICODE_STRING*, const UNICODE_STRING*, BOOLEAN);
    static const auto downcase = reinterpret_cast<Downcase>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlDowncaseUnicodeString")));
    if (!downcase || appId.size() < sizeof(wchar_t) || appId.size() > 0xfffe) return appId;
    std::vector<UINT8> result = appId;
    const USHORT length = static_cast<USHORT>(appId.size() - sizeof(wchar_t));
    UNICODE_STRING source{length, length, reinterpret_cast<PWSTR>(const_cast<UINT8*>(appId.data()))};
    UNICODE_STRING target{0, length, reinterpret_cast<PWSTR>(result.data())};
    if (downcase(&target, &source, FALSE) < 0 || target.Length != length) return appId;
    return result;
}

enum class Identity { Present, Derived, Retained, None };

// A further attribution path an unresolved entry still holds, with its own identifiers. An install stopped
// between committing new filters and publishing the record leaves the newer identity in the filters and
// the older one in the record; both stay protected and attributed.
struct AttributionGroup {
    std::wstring path;
    std::vector<std::vector<UINT8>> ids;
};

// One listed entry's identity: the final DOS path the dispatcher attributes by, and the WFP identifiers.
struct ResolvedIdentity {
    Identity source{Identity::None};
    std::wstring path;
    std::vector<std::vector<UINT8>> ids;
    std::vector<AttributionGroup> others;
};
using Identities = std::map<std::wstring, ResolvedIdentity>;

// state\resolved-identities.tsv, the one record of every entry's identity: written by install after the
// filters commit, loaded by the dispatcher, and compared by verification. A line holds the entry, its
// final path and its identifiers in hexadecimal, and an entry with further attribution paths has a line for
// each; the source is not recorded, so an executable that comes and goes keeps the same record.
constexpr char kIdentityHeader[] = "# wgps-identities 1\n";

std::wstring wide(const std::string& text) {
    const int count = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(count > 0 ? static_cast<size_t>(count) : 0, L'\0');
    if (count > 0) MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), count);
    return result;
}

std::string serializeIdentities(const Identities& identities) {
    std::string text = kIdentityHeader;
    for (const auto& [entry, identity] : identities) {
        if (identity.ids.empty()) continue;
        std::vector<AttributionGroup> groups{{identity.path, identity.ids}};
        groups.insert(groups.end(), identity.others.begin(), identity.others.end());
        for (const auto& group : groups) {
            text += utf8(entry) + "\t" + utf8(group.path) + "\t";
            for (size_t i = 0; i < group.ids.size(); ++i) {
                if (i) text += ",";
                text += hexBytes(group.ids[i].data(), group.ids[i].size());
            }
            text += "\n";
        }
    }
    return text;
}

// A record with any malformed row is rejected whole and read as empty, so recovery falls back to the
// identities committed with the filters instead of using part of a damaged record.
Identities parseIdentities(const std::string& text) {
    Identities result;
    if (text.rfind(kIdentityHeader, 0) != 0 || text.back() != '\n') return {};
    size_t start = sizeof(kIdentityHeader) - 1;
    while (start < text.size()) {
        const size_t end = text.find('\n', start);
        const std::string line = text.substr(start, end - start);
        start = end + 1;
        const size_t first = line.find('\t');
        const size_t second = first == std::string::npos ? std::string::npos : line.find('\t', first + 1);
        if (first == 0 || second == std::string::npos || second == first + 1 || line.find('\t', second + 1) != std::string::npos) {
            return {};
        }
        ResolvedIdentity identity{Identity::Retained, wide(line.substr(first + 1, second - first - 1)), {}, {}};
        size_t position = second + 1;
        do {
            const size_t comma = std::min(line.find(',', position), line.size());
            if (comma == position || (comma - position) % 2) return {};
            std::vector<UINT8> bytes;
            for (size_t i = position; i < comma; i += 2) {
                const int high = wgps::hexDigit(line[i]);
                const int low = wgps::hexDigit(line[i + 1]);
                if (high < 0 || low < 0) return {};
                bytes.push_back(static_cast<UINT8>(high * 16 + low));
            }
            identity.ids.push_back(std::move(bytes));
            position = comma + 1;
        } while (position <= line.size());
        const std::wstring entry = wide(line.substr(0, first));
        const auto existing = result.find(entry);
        if (existing == result.end()) result[entry] = std::move(identity);
        else existing->second.others.push_back({std::move(identity.path), std::move(identity.ids)});
    }
    return result;
}

// How each listed entry is identified: a present executable by the filter engine itself, an absent one by
// its resolved path, and one whose path does not resolve by every identity it already had, from the filters
// tagged with it and the identity record together. Protection is never replaced by an omitted or guessed identity.
// resolve(entry) returns the final DOS and NT paths, both empty when the entry does not resolve.
template <typename Resolve, typename PresentId>
Identities identifyApps(const std::unordered_set<std::wstring>& listed, const Identities& previous, const Owned& current,
                        Resolve resolve, PresentId presentId) {
    Identities result;
    for (const auto& entry : listed) {
        ResolvedIdentity& identity = result[entry];
        const auto [dosPath, ntPath] = resolve(entry);
        if (!dosPath.empty() && !ntPath.empty()) {
            std::vector<UINT8> id = presentId(dosPath);
            identity.source = id.empty() ? Identity::Derived : Identity::Present;
            if (id.empty()) id = appIdFromNtPath(ntPath);
            // Case of the not-yet-existing components follows the listed spelling; the record compares ASCII
            // case-insensitively, as attribution and WFP do, so an executable's coming and going changes nothing.
            identity.path = lower(dosPath);
            auto lowered = fullyLowered(id);
            if (lowered != id) identity.ids.push_back(std::move(lowered));
            identity.ids.push_back(std::move(id));
            continue;
        }
        // An entry that does not resolve keeps every identifier it had, each with the path it was attributed
        // by: the committed filters' (an install can stop between committing them and publishing the record,
        // so they may be newer) and the record's together, so a disagreement keeps the protection and the
        // attribution of both. Paths and identifiers are ordered, so the result does not depend on the order
        // the filter engine enumerates in.
        std::map<std::wstring, std::vector<std::vector<UINT8>>> groups;
        std::vector<std::vector<UINT8>> pathless;
        std::set<std::vector<UINT8>> seen;
        const auto add = [&](const std::wstring& path, const std::vector<UINT8>& id) {
            if (id.empty() || !seen.insert(id).second) return;
            (path.empty() ? pathless : groups[path]).push_back(id);
        };
        for (const auto& filter : current.filters) {
            if (filter.tag == entry) add(filter.path, filter.appId);
        }
        const auto recorded = previous.find(entry);
        if (recorded != previous.end()) {
            for (const auto& id : recorded->second.ids) add(recorded->second.path, id);
            for (const auto& other : recorded->second.others) {
                for (const auto& id : other.ids) add(other.path, id);
            }
        }
        if (groups.empty() && pathless.empty()) continue;
        identity.source = Identity::Retained;
        for (auto& [path, ids] : groups) {
            std::sort(ids.begin(), ids.end());
            if (identity.path.empty()) {
                identity.path = path;
                identity.ids = std::move(ids);
            } else {
                identity.others.push_back({path, std::move(ids)});
            }
        }
        // Identifiers without a path join the first group; with no path at all, install refuses the entry.
        identity.ids.insert(identity.ids.end(), pathless.begin(), pathless.end());
        std::sort(identity.ids.begin(), identity.ids.end());
    }
    return result;
}

std::string readText(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER length{};
    std::string bytes;
    if (GetFileSizeEx(file, &length) && length.QuadPart <= 4 * 1024 * 1024) {
        bytes.resize(static_cast<size_t>(length.QuadPart));
        DWORD read{};
        if (!bytes.empty() && (!ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) ||
                               read != bytes.size())) bytes.clear();
    }
    CloseHandle(file);
    return bytes;
}

// Replaces the file in one rename, so a reader sees the previous record or the new one.
void writeTextAtomically(const std::wstring& path, const std::string& text) {
    const std::wstring temporary = path + L"." + std::to_wstring(GetCurrentProcessId()) + L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot write the resolved identities");
    DWORD written{};
    const bool ok = WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) &&
                    written == text.size() && FlushFileBuffers(file);
    CloseHandle(file);
    if (!ok || !MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        throw std::runtime_error("Cannot replace the resolved identities");
    }
}

// The identity record lives beside the included-app list: state\resolved-identities.tsv in an installation.
std::wstring identitiesPathFor(const std::wstring& listPath) {
    const size_t separator = listPath.find_last_of(L"\\/");
    return (separator == std::wstring::npos ? std::wstring() : listPath.substr(0, separator + 1)) + L"resolved-identities.tsv";
}
