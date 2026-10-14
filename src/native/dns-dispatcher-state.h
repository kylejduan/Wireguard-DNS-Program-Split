// SPDX-License-Identifier: GPL-3.0-or-later
// Private implementation fragment of dns-dispatcher.cpp: inputs read from an installation's state
// directory and reloaded in place, so repairs and included-app reloads never stop the dispatcher.
struct Routes {
    sockaddr_in directSource{};
    sockaddr_in directDns{};
    sockaddr_in tunnelSource{};
    sockaddr_in tunnelDns{};
};

std::mutex gRoutesMutex;
std::shared_ptr<const Routes> gRoutes;

// A query keeps the routes it started with; a reload replaces them for later queries.
std::shared_ptr<const Routes> currentRoutes() {
    std::lock_guard lock(gRoutesMutex);
    return gRoutes;
}

void setRoutes(Routes routes) {
    auto replacement = std::make_shared<const Routes>(routes);
    std::lock_guard lock(gRoutesMutex);
    gRoutes = std::move(replacement);
}

std::string readBytes(const std::wstring& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot open dispatcher input");
    LARGE_INTEGER length{};
    std::string bytes;
    const bool sized = GetFileSizeEx(file, &length) && length.QuadPart <= 4 * 1024 * 1024;
    if (sized) bytes.resize(static_cast<size_t>(length.QuadPart));
    DWORD read{};
    const bool ok = sized && (bytes.empty() || (ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) &&
                                                read == bytes.size()));
    CloseHandle(file);
    if (!ok) throw std::runtime_error("Cannot read dispatcher input");
    return bytes;
}

std::wstring wideText(const std::string& bytes) {
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (count <= 0 && !bytes.empty()) throw std::runtime_error("Dispatcher input must be UTF-8");
    std::wstring text(static_cast<size_t>(count), L'\0');
    if (count) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), text.data(), count);
    return text;
}

// Replaces the file in one rename, so a reader sees the previous content or the new one. A reader that
// opened the file without delete sharing blocks the rename for a moment, so it is retried for a second.
void writeAtomically(const std::wstring& path, const std::string& bytes) {
    const std::wstring temporary = path + L"." + std::to_wstring(GetCurrentProcessId()) + L".tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot write dispatcher state");
    DWORD written{};
    bool ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) && written == bytes.size();
    CloseHandle(file);
    bool replaced = false;
    for (int attempt = 0; ok && !replaced && attempt < 20; ++attempt) {
        if (attempt) Sleep(50);
        replaced = MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING);
    }
    if (!replaced) {
        DeleteFileW(temporary.c_str());
        throw std::runtime_error("Cannot replace dispatcher state");
    }
}

struct StateInputs {
    std::string inputsBytes;
    std::string identitiesBytes;
    Routes routes;
    std::unordered_set<std::wstring> included;
};

// state\dns-dispatcher-inputs.txt: the direct and tunnel sources and resolvers, written by the controller.
// state\resolved-identities.tsv: wfp-probe.exe's identity record. Both are validated before any is used.
StateInputs readStateInputs(const std::wstring& root) {
    StateInputs inputs;
    inputs.inputsBytes = readBytes(root + L"\\state\\dns-dispatcher-inputs.txt");
    inputs.identitiesBytes = readBytes(root + L"\\state\\resolved-identities.tsv");
    const std::wstring text = wideText(inputs.inputsBytes);
    if (text.rfind(L"# wgps-dispatcher-inputs 1", 0) != 0) throw std::runtime_error("Dispatcher inputs have no header");
    std::unordered_map<std::wstring, std::wstring> values;
    size_t start{};
    while (start < text.size()) {
        const size_t end = std::min(text.find(L'\n', start), text.size());
        const std::wstring line = trim(text.substr(start, end - start));
        start = end + 1;
        const size_t equals = line.find(L'=');
        if (!line.empty() && line.front() != L'#' && equals != std::wstring::npos) values[line.substr(0, equals)] = line.substr(equals + 1);
    }
    const auto field = [&](const wchar_t* name) {
        const auto found = values.find(name);
        if (found == values.end()) throw std::runtime_error("Dispatcher inputs lack a field");
        return found->second;
    };
    inputs.routes.directSource = address(field(L"direct-source").c_str(), 0);
    inputs.routes.directDns = address(field(L"direct-dns").c_str(), 53);
    inputs.routes.tunnelSource = address(field(L"tunnel-source").c_str(), 0);
    inputs.routes.tunnelDns = address(field(L"tunnel-dns").c_str(), 53);
    const std::wstring identities = wideText(inputs.identitiesBytes);
    if (identities.rfind(L"# wgps-identities 1\n", 0) != 0) throw std::runtime_error("The identity record has no header");
    inputs.included = parseIncludedText(identities);
    return inputs;
}

// The inputs this process attributes and forwards by, published with a generation after each load, so
// validation can confirm that a reload took effect. The status is written last.
void publishLoaded(const std::wstring& root, const StateInputs& inputs, unsigned generation) {
    writeAtomically(root + L"\\state\\dns-dispatcher-loaded-inputs.txt", inputs.inputsBytes);
    writeAtomically(root + L"\\state\\dns-dispatcher-loaded-identities.tsv", inputs.identitiesBytes);
    writeAtomically(root + L"\\state\\dns-dispatcher-status.txt",
                    "pid=" + std::to_string(GetCurrentProcessId()) + "\r\ngeneration=" + std::to_string(generation) + "\r\n");
}

// A per-launch ETW session name. A session outlives a dispatcher that crashed, so the one named in the
// state file by the previous launch is stopped first.
std::wstring replaceTraceSession(const std::wstring& root) {
    const std::wstring stateFile = root + L"\\state\\dns-etw-session.txt";
    constexpr wchar_t kPrefix[] = L"WireGuardProgramSplitDnsEtw-";
    try {
        const std::wstring previous = trim(wideText(readBytes(stateFile)));
        if (previous.rfind(kPrefix, 0) == 0 && previous.size() == std::size(kPrefix) - 1 + 32) {
            std::vector<BYTE> buffer(sizeof(EVENT_TRACE_PROPERTIES) + (previous.size() + 1) * sizeof(wchar_t));
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
            properties->Wnode.BufferSize = static_cast<ULONG>(buffer.size());
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            ControlTraceW(0, previous.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
        }
    } catch (const std::exception&) {
    }
    LARGE_INTEGER counter{};
    QueryPerformanceCounter(&counter);
    wchar_t suffix[40]{};
    swprintf(suffix, 40, L"%08lx%016llx%08lx", static_cast<unsigned long>(GetCurrentProcessId()),
             static_cast<unsigned long long>(counter.QuadPart), static_cast<unsigned long>(GetTickCount64() & 0xffffffff));
    const std::wstring name = std::wstring(kPrefix) + suffix;
    std::string narrow(name.begin(), name.end());
    writeAtomically(stateFile, narrow);
    return name;
}
