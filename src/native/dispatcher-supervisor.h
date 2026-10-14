// SPDX-License-Identifier: GPL-3.0-or-later
// Private implementation fragment of controller-service.cpp: supervision of dns-dispatcher.exe.
//
// The PowerShell controller blocks on network work (tunnel readiness, health probes), so it cannot react
// in time when the dispatcher ends. This loop never blocks on the network: while the stack is enabled
// (state\dns-dispatcher.supervised exists) it starts the dispatcher, or adopts the running one, and
// restarts it about a second after it exits. If no ready dispatcher answers for 15 seconds it suspends
// the owned NRPT rule, so the rest of the host keeps working DNS, and restores it once one is ready
// again; the rule's actual state is compared with readiness on every pass. Invariant: while the stack
// is enabled the owned rule names a ready owned dispatcher except for at most about 15 seconds, and
// nothing but disable, service stop or uninstall removes it otherwise.

constexpr ULONGLONG kSuspendAfterMilliseconds = 15000;
constexpr ULONGLONG kRestartSpacingMilliseconds = 1000;
constexpr ULONGLONG kHelperRetryMilliseconds = 2000;
constexpr ULONGLONG kHelperTimeoutMilliseconds = 60000;
constexpr ULONGLONG kLivenessIntervalMilliseconds = 1000;
constexpr DWORD kLivenessTimeoutMilliseconds = 300;
constexpr unsigned kLivenessFailures = 3;
// A started or adopted dispatcher that has not published its inputs by then is hung and is replaced.
constexpr ULONGLONG kStartupDeadlineMilliseconds = 10000;

bool pathExists(const std::filesystem::path& path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::string readSmallFile(const std::filesystem::path& path) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return {};
    char buffer[256]{};
    DWORD read{};
    const bool ok = ReadFile(file, buffer, sizeof(buffer) - 1, &read, nullptr);
    CloseHandle(file);
    return ok ? std::string(buffer, read) : std::string();
}

// The process ID a dispatcher published with its loaded inputs, or 0 for anything but a valid record:
// "pid=" and digits within the DWORD range, ending the text or the line.
DWORD statusProcessId(const std::string& status) {
    if (status.rfind("pid=", 0) != 0) return 0;
    const size_t end = std::min(status.find_first_of("\r\n"), status.size());
    const auto value = wgps::parseDecimal(std::string_view(status).substr(4, end - 4), 0xffffffffULL);
    return value ? static_cast<DWORD>(*value) : 0;
}

bool imageMatches(HANDLE process, const std::filesystem::path& expected) {
    std::vector<wchar_t> buffer(32768);
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) return false;
    return CompareStringOrdinal(buffer.data(), static_cast<int>(size), expected.c_str(), -1, TRUE) == CSTR_EQUAL;
}

// The dispatcher named by its pid file, if it still runs with its exact image.
HANDLE adoptDispatcher(const std::filesystem::path& root, DWORD& processId) {
    const DWORD candidate = statusProcessId("pid=" + readSmallFile(root / L"state" / L"dns-dispatcher.pid"));
    if (!candidate) return nullptr;
    // PROCESS_TERMINATE: an adopted dispatcher that hangs is replaced like a started one.
    HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, candidate);
    if (!process) return nullptr;
    if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT || !imageMatches(process, root / L"bin" / L"dns-dispatcher.exe")) {
        CloseHandle(process);
        return nullptr;
    }
    processId = candidate;
    return process;
}

HANDLE startDispatcher(const std::filesystem::path& root, DWORD& processId) {
    const std::filesystem::path exe = root / L"bin" / L"dns-dispatcher.exe";
    std::wstring commandLine = quoteArgument(exe.wstring()) + L" --state " + quoteArgument(root.wstring());
    SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
    HANDLE output = CreateFileW((root / L"logs" / L"dns-dispatcher-ready.log").c_str(), GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_DELETE, &inherit, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    if (output != INVALID_HANDLE_VALUE) {
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdOutput = output;
        startup.hStdError = output;
    }
    PROCESS_INFORMATION process{};
    // Not in this host's job: a dispatcher outlives a host restart and is adopted, so DNS keeps working.
    const BOOL created = CreateProcessW(exe.c_str(), commandLine.data(), nullptr, nullptr, output != INVALID_HANDLE_VALUE,
                                        CREATE_NO_WINDOW, nullptr, root.c_str(), &startup, &process);
    if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
    if (!created) return nullptr;
    CloseHandle(process.hThread);
    processId = process.dwProcessId;
    return process.hProcess;
}

// The owned NRPT rule as Get-ProgramSplitLocalNrptRules and Test-ProgramSplitNrptRuleOwnership see it,
// read from the policy keys, so every pass can compare the actual rule with the dispatcher's readiness.
bool ownedRulePresent() {
    HKEY policies{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig", 0,
                      KEY_READ, &policies) != ERROR_SUCCESS) return false;
    const auto text = [](HKEY rule, const wchar_t* name, DWORD flags) {
        std::vector<wchar_t> buffer(1024);
        DWORD size = static_cast<DWORD>(buffer.size() * sizeof(wchar_t));
        if (RegGetValueW(rule, nullptr, name, flags, nullptr, buffer.data(), &size) != ERROR_SUCCESS) return std::wstring();
        return std::wstring(buffer.data(), size / sizeof(wchar_t));
    };
    bool found = false;
    wchar_t name[256];
    for (DWORD index = 0; !found; ++index) {
        DWORD length = static_cast<DWORD>(std::size(name));
        if (RegEnumKeyExW(policies, index, name, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        HKEY rule{};
        if (RegOpenKeyExW(policies, name, 0, KEY_READ, &rule) != ERROR_SUCCESS) continue;
        // REG_MULTI_SZ "." is ".", NUL, NUL; REG_SZ values end in one NUL.
        found = text(rule, L"DisplayName", RRF_RT_REG_SZ) == std::wstring(L"WireGuard Program Split local dispatcher") + L'\0' &&
                text(rule, L"Comment", RRF_RT_REG_SZ) ==
                    std::wstring(L"Owned by WireGuardProgramSplit; safe to remove on recovery.") + L'\0' &&
                text(rule, L"Name", RRF_RT_REG_MULTI_SZ) == std::wstring(L".\0\0", 3) &&
                text(rule, L"GenericDNSServers", RRF_RT_REG_SZ) == std::wstring(L"127.0.0.1") + L'\0';
        RegCloseKey(rule);
    }
    RegCloseKey(policies);
    return found;
}

// Suspend or Resume through Invoke-LocalNrpt.ps1, which holds the NRPT lock and checks readiness itself.
// It runs beside the loop, so exit detection and restarts continue while PowerShell starts.
HANDLE startNrptHelper(const std::filesystem::path& root, const wchar_t* action) {
    const std::wstring powerShell = powerShellPath();
    if (powerShell.empty()) return nullptr;
    std::wstring commandLine = quoteArgument(powerShell) + L" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " +
                               quoteArgument((root / L"src" / L"Invoke-LocalNrpt.ps1").wstring()) + L" -Action " + action;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(powerShell.c_str(), commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                        nullptr, &startup, &process)) return nullptr;
    CloseHandle(process.hThread);
    return process.hProcess;
}

// The supervisor holds the verified process; a lost pid record would hide it from readiness checks.
void republishProcessId(const std::filesystem::path& root, DWORD processId) {
    const auto path = root / L"state" / L"dns-dispatcher.pid";
    const std::string text = std::to_string(processId);
    if (readSmallFile(path) == text) return;
    const auto temporary = root / L"state" / L"dns-dispatcher.pid.supervisor.tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    DWORD written{};
    const bool ok = WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) && written == text.size();
    CloseHandle(file);
    if (ok && MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        appendHostLog(L"Republished the process ID of DNS dispatcher " + std::to_wstring(processId) + L".");
    } else {
        DeleteFileW(temporary.c_str());
    }
}

// One liveness query to 127.0.0.1:53, which the dispatcher's receive loop answers itself; a process that
// exists but is hung or suspended does not.
bool dispatcherAnswers() {
    SOCKET probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (probe == INVALID_SOCKET) return false;
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(53);
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const unsigned short id = static_cast<unsigned short>(GetTickCount64() ^ GetCurrentThreadId());
    std::vector<char> query{static_cast<char>(id >> 8), static_cast<char>(id & 0xff), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    for (const std::string label : {"liveness", "wireguard-program-split", "invalid"}) {
        query.push_back(static_cast<char>(label.size()));
        query.insert(query.end(), label.begin(), label.end());
    }
    query.insert(query.end(), {0, 0, 1, 0, 1});
    bool answered = false;
    if (!connect(probe, reinterpret_cast<const sockaddr*>(&target), sizeof(target)) &&
        send(probe, query.data(), static_cast<int>(query.size()), 0) == static_cast<int>(query.size())) {
        const ULONGLONG deadline = GetTickCount64() + kLivenessTimeoutMilliseconds;
        char reply[512];
        for (ULONGLONG now = GetTickCount64(); !answered && now < deadline; now = GetTickCount64()) {
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(probe, &readable);
            const timeval wait{0, static_cast<long>((deadline - now) * 1000)};
            if (select(0, &readable, nullptr, nullptr, &wait) <= 0) break;
            const int received = recv(probe, reply, sizeof(reply), 0);
            if (received == SOCKET_ERROR) break;
            answered = received >= 12 && static_cast<unsigned char>(reply[0]) == (id >> 8) &&
                       static_cast<unsigned char>(reply[1]) == (id & 0xff) && (static_cast<unsigned char>(reply[2]) & 0x80);
        }
    }
    closesocket(probe);
    return answered;
}

void superviseLoop(const std::filesystem::path& root, HANDLE stop);

// Never ends the service host: an unexpected failure is logged and supervision continues.
void superviseDispatcher(const std::filesystem::path& root, HANDLE stop) {
    WSADATA winsock{};
    const bool network = !WSAStartup(MAKEWORD(2, 2), &winsock);
    while (WaitForSingleObject(stop, 0) == WAIT_TIMEOUT) {
        try {
            superviseLoop(root, stop);
        } catch (...) {
            try { appendHostLog(L"Dispatcher supervision failed unexpectedly; continuing."); } catch (...) {}
            WaitForSingleObject(stop, 1000);
        }
    }
    if (network) WSACleanup();
}

void superviseLoop(const std::filesystem::path& root, HANDLE stop) {
    HANDLE child{};
    DWORD childId{};
    ULONGLONG lastStart{};
    ULONGLONG unreadySince{};
    HANDLE helper{};
    std::wstring helperAction;
    ULONGLONG helperStarted{};
    ULONGLONG helperEnded{};
    ULONGLONG lastProbe{};
    ULONGLONG childSince{};
    unsigned failures{};
    bool answered = false;
    struct Handles {
        HANDLE& child;
        HANDLE& helper;
        ~Handles() {
            if (child) CloseHandle(child);
            if (helper) CloseHandle(helper);
        }
    } handles{child, helper};
    while (WaitForSingleObject(stop, 250) == WAIT_TIMEOUT) {
        const ULONGLONG now = GetTickCount64();
        if (helper && WaitForSingleObject(helper, 0) == WAIT_TIMEOUT && now - helperStarted >= kHelperTimeoutMilliseconds) {
            TerminateProcess(helper, 1);
        }
        if (helper && WaitForSingleObject(helper, 0) != WAIT_TIMEOUT) {
            DWORD exitCode{};
            GetExitCodeProcess(helper, &exitCode);
            if (exitCode) appendHostLog(L"NRPT " + helperAction + L" failed with exit code " + std::to_wstring(exitCode) + L"; retrying.");
            CloseHandle(helper);
            helper = nullptr;
            helperEnded = now;
        }
        if (!pathExists(root / L"state" / L"dns-dispatcher.supervised")) {
            if (child) CloseHandle(child);
            child = nullptr;
            unreadySince = 0;
            continue;
        }
        // Invoke-DnsDispatcher.ps1 stops the dispatcher under the same lock, after clearing the flag.
        HANDLE lock = CreateMutexW(nullptr, FALSE, L"Global\\WireGuardProgramSplitDnsDispatcherComponent");
        if (lock) {
            const DWORD acquired = WaitForSingleObject(lock, 0);
            if (acquired == WAIT_OBJECT_0 || acquired == WAIT_ABANDONED) {
                if (pathExists(root / L"state" / L"dns-dispatcher.supervised")) {
                    if (child && WaitForSingleObject(child, 0) != WAIT_TIMEOUT) {
                        appendHostLog(L"DNS dispatcher " + std::to_wstring(childId) + L" ended.");
                        CloseHandle(child);
                        child = nullptr;
                        failures = 0;
                        answered = false;
                        lastProbe = 0;
                    }
                    if (!child && (child = adoptDispatcher(root, childId))) {
                        childSince = now;
                        appendHostLog(L"Supervising running DNS dispatcher " + std::to_wstring(childId) + L".");
                    }
                    if (!child && now - lastStart >= kRestartSpacingMilliseconds) {
                        lastStart = now;
                        childSince = now;
                        child = startDispatcher(root, childId);
                        appendHostLog(child ? L"Started DNS dispatcher " + std::to_wstring(childId) + L"."
                                            : L"DNS dispatcher start failed: " + std::to_wstring(GetLastError()) + L".");
                    }
                }
                ReleaseMutex(lock);
            }
            CloseHandle(lock);
        }
        const bool alive = child && WaitForSingleObject(child, 0) == WAIT_TIMEOUT;
        const bool published = alive && statusProcessId(readSmallFile(root / L"state" / L"dns-dispatcher-status.txt")) == childId;
        // A process that exists but does not answer is not ready, and after a few failed probes it is
        // replaced: ended here, it is restarted by the next pass. So is one that never publishes its inputs.
        const auto replace = [&](const wchar_t* reason) {
            if (TerminateProcess(child, 1)) {
                appendHostLog(L"DNS dispatcher " + std::to_wstring(childId) + reason + L"; replacing it.");
            } else {
                appendHostLog(L"DNS dispatcher " + std::to_wstring(childId) + reason + L" but could not be ended: " +
                              std::to_wstring(GetLastError()) + L"; retrying.");
            }
            answered = false;
        };
        if (published && now - lastProbe >= kLivenessIntervalMilliseconds) {
            lastProbe = now;
            if (dispatcherAnswers()) {
                failures = 0;
                answered = true;
            } else if (++failures >= kLivenessFailures) {
                replace(L" does not answer");
            }
        } else if (alive && !published && now - childSince >= kStartupDeadlineMilliseconds &&
                   now - lastProbe >= kLivenessIntervalMilliseconds) {
            lastProbe = now;
            replace(L" did not publish its inputs in time");
        }
        const bool ready = published && answered && failures == 0;
        if (ready) republishProcessId(root, childId);
        if (ready) unreadySince = 0;
        else if (!unreadySince) unreadySince = now;
        // Reconciled on every pass, not latched: the rule must name a ready dispatcher, except for at most
        // about 15 seconds; a suspended rule returns once one is ready. A helper that failed is retried.
        const wchar_t* action = nullptr;
        if (ready && pathExists(root / L"state" / L"nrpt-suspended")) action = L"Resume";
        else if (!ready && now - unreadySince >= kSuspendAfterMilliseconds && ownedRulePresent()) action = L"Suspend";
        if (action && !helper && now - helperEnded >= kHelperRetryMilliseconds) {
            appendHostLog(ready ? L"DNS dispatcher ready; restoring the suspended NRPT rule."
                                : L"No ready DNS dispatcher for 15 seconds; suspending the NRPT rule.");
            helperAction = action;
            helperStarted = now;
            helper = startNrptHelper(root, action);
            if (!helper) {
                appendHostLog(L"NRPT " + helperAction + L" could not start; retrying.");
                helperEnded = now;
            }
        }
    }
}
