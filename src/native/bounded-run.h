// SPDX-License-Identifier: GPL-3.0-or-later
// Private implementation fragment of controller-service.exe: --run, the bounded runner the PowerShell
// components use for every program they wait on.
//
//   controller-service.exe --run <timeout-ms> <base64 of the UTF-16LE command line>
//
// The program is created suspended and already in a job without breakaway that ends everything in it when
// closed (PROC_THREAD_ATTRIBUTE_JOB_LIST), so even this runner's death right after creation ends it; it runs
// only once its containment is confirmed, and if that fails it is ended and does not run. Its deadline counts
// from this runner's start, whoever collects the result and whenever. Both pipes are drained by their own
// threads, keeping at most kRunLimitBytes each. After the program exits, descendants still holding its
// pipes get kRunDrainMilliseconds, then the job is ended and blocked reads are cancelled. The result goes
// to this runner's stdout as ASCII lines, the streams base64-encoded so the caller decodes them by producer:
//
//   WGPS-RUN 1 / exit=<code or empty> / timedout=0|1 / runtime=<ms> / stdout-truncated=0|1 /
//   stderr-truncated=0|1 / stdout=<base64> / stderr=<base64>       or       WGPS-RUN 1 / error=<reason>

constexpr size_t kRunLimitBytes = 65536;
constexpr DWORD kRunDrainMilliseconds = 2000;
constexpr DWORD kRunMaximumTimeout = 600000;

struct RunPipe {
    HANDLE read{};
    std::string kept;
    bool truncated{};
};

DWORD WINAPI drainRunPipe(void* parameter) {
    auto* pipe = static_cast<RunPipe*>(parameter);
    char buffer[8192];
    DWORD count{};
    while (ReadFile(pipe->read, buffer, sizeof(buffer), &count, nullptr) && count) {
        const size_t room = pipe->kept.size() < kRunLimitBytes ? kRunLimitBytes - pipe->kept.size() : 0;
        pipe->kept.append(buffer, std::min<size_t>(room, count));
        if (count > room) pipe->truncated = true;
    }
    return 0;
}

std::string base64Encode(const std::string& bytes) {
    static constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve((bytes.size() + 2) / 3 * 4);
    for (size_t i = 0; i < bytes.size(); i += 3) {
        const unsigned value = (static_cast<unsigned char>(bytes[i]) << 16) |
                               (i + 1 < bytes.size() ? static_cast<unsigned char>(bytes[i + 1]) << 8 : 0) |
                               (i + 2 < bytes.size() ? static_cast<unsigned char>(bytes[i + 2]) : 0);
        result += kAlphabet[(value >> 18) & 63];
        result += kAlphabet[(value >> 12) & 63];
        result += i + 1 < bytes.size() ? kAlphabet[(value >> 6) & 63] : '=';
        result += i + 2 < bytes.size() ? kAlphabet[value & 63] : '=';
    }
    return result;
}

// Strict: padding only at the end, nothing outside the alphabet. Empty on any malformed input.
std::string base64Decode(const std::wstring& text) {
    if (text.empty() || text.size() % 4) return {};
    std::string result;
    unsigned value = 0;
    int bits = 0;
    size_t padding = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        const wchar_t c = text[i];
        int digit = -1;
        if (c >= L'A' && c <= L'Z') digit = c - L'A';
        else if (c >= L'a' && c <= L'z') digit = c - L'a' + 26;
        else if (c >= L'0' && c <= L'9') digit = c - L'0' + 52;
        else if (c == L'+') digit = 62;
        else if (c == L'/') digit = 63;
        else if (c == L'=' && i + 2 >= text.size()) { ++padding; digit = 0; }
        if (digit < 0 || (padding && c != L'=')) return {};
        value = (value << 6) | static_cast<unsigned>(digit);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result += static_cast<char>((value >> bits) & 0xff);
        }
    }
    result.resize(result.size() - padding);
    return result;
}

void writeRunFrame(const std::string& text) {
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written{};
    for (size_t offset = 0; offset < text.size(); offset += written) {
        if (!WriteFile(out, text.data() + offset, static_cast<DWORD>(text.size() - offset), &written, nullptr) || !written) return;
    }
}

int runFailure(const char* reason) {
    writeRunFrame(std::string("WGPS-RUN 1\r\nerror=") + reason + " (" + std::to_string(GetLastError()) + ")\r\n");
    return 3;
}

// Reader threads that do not stop own buffers that cannot then be read or freed. The run is reported as
// failed and this runner ends at once, after the job, without unwinding anything they still use.
[[noreturn]] void abandonRun(HANDLE job, const char* reason) {
    if (job) TerminateJobObject(job, 1);
    runFailure(reason);
    TerminateProcess(GetCurrentProcess(), 4);
    for (;;) Sleep(INFINITE);
}

// Waits for the readers, ending the job and then cancelling their reads; true once both have stopped.
bool stopReaders(HANDLE job, const HANDLE* threads, DWORD count, DWORD graceMilliseconds) {
    if (WaitForMultipleObjects(count, threads, TRUE, graceMilliseconds) != WAIT_TIMEOUT) return true;
    TerminateJobObject(job, 1);
    for (int attempt = 0; attempt < 100; ++attempt) {
        if (WaitForMultipleObjects(count, threads, TRUE, 50) != WAIT_TIMEOUT) return true;
        if (attempt >= 20) {
            for (DWORD i = 0; i < count; ++i) CancelSynchronousIo(threads[i]);
        }
    }
    return false;
}

struct OwnedHandle {
    HANDLE value{};
    OwnedHandle() = default;
    explicit OwnedHandle(HANDLE handle) : value(handle == INVALID_HANDLE_VALUE ? nullptr : handle) {}
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
    ~OwnedHandle() { reset(); }
    void reset() {
        if (value) CloseHandle(value);
        value = nullptr;
    }
};

int boundedRun(const wchar_t* timeoutText, const wchar_t* encodedCommand) {
    const ULONGLONG started = GetTickCount64();
    const std::wstring wideTimeout(timeoutText);
    const auto timeout = wgps::parseDecimal(std::string(wideTimeout.begin(), wideTimeout.end()), kRunMaximumTimeout);
    const std::string commandBytes = base64Decode(encodedCommand);
    if (!timeout || commandBytes.empty() || commandBytes.size() % 2) return runFailure("invalid arguments");
    std::wstring commandLine(commandBytes.size() / 2, L'\0');
    memcpy(commandLine.data(), commandBytes.data(), commandBytes.size());

    OwnedHandle job(CreateJobObjectW(nullptr, nullptr));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job.value || !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        return runFailure("cannot create the job");
    }
    SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
    RunPipe pipes[2];
    OwnedHandle reads[2], writes[2];
    for (int i = 0; i < 2; ++i) {
        HANDLE read{}, write{};
        if (!CreatePipe(&read, &write, &inherit, 0)) return runFailure("cannot create a pipe");
        reads[i].value = read;
        writes[i].value = write;
        SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0);
        pipes[i].read = read;
    }
    OwnedHandle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr));
    if (!input.value) return runFailure("cannot open NUL");
    // Only these three handles are inherited, whatever else this runner holds, and the program is created
    // in the job.
    HANDLE inherited[3] = {input.value, writes[0].value, writes[1].value};
    HANDLE jobs[1] = {job.value};
    SIZE_T attributeBytes{};
    InitializeProcThreadAttributeList(nullptr, 2, 0, &attributeBytes);
    std::vector<char> attributeBuffer(attributeBytes);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeBuffer.data());
    if (!InitializeProcThreadAttributeList(attributes, 2, 0, &attributeBytes)) return runFailure("cannot limit inheritance");
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr) ||
        !UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs, sizeof(jobs), nullptr, nullptr)) {
        DeleteProcThreadAttributeList(attributes);
        return runFailure("cannot limit inheritance or set the job");
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.value;
    startup.StartupInfo.hStdOutput = writes[0].value;
    startup.StartupInfo.hStdError = writes[1].value;
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION created{};
    const BOOL launched = CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, TRUE,
                                         CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                                         &startup.StartupInfo, &created);
    DeleteProcThreadAttributeList(attributes);
    if (!launched) return runFailure("cannot start the program");
    OwnedHandle process(created.hProcess), thread(created.hThread);
    // Contained before it runs a single instruction, or not run at all.
    BOOL contained = FALSE;
    if (!IsProcessInJob(process.value, job.value, &contained) || !contained) {
        const DWORD error = GetLastError();
        TerminateProcess(process.value, 1);
        WaitForSingleObject(process.value, 5000);
        SetLastError(error);
        return runFailure("cannot contain the program");
    }
    input.reset();
    writes[0].reset();
    writes[1].reset();
    OwnedHandle readers[2];
    for (int i = 0; i < 2; ++i) readers[i].value = CreateThread(nullptr, 0, drainRunPipe, &pipes[i], 0, nullptr);
    if (!readers[0].value || !readers[1].value) {
        // The program never ran; ending it closes its pipe ends, so a reader that did start stops.
        const DWORD error = GetLastError();
        TerminateJobObject(job.value, 1);
        HANDLE started[1] = {readers[0].value ? readers[0].value : readers[1].value};
        if (started[0] && !stopReaders(job.value, started, 1, 5000)) abandonRun(job.value, "a reader did not stop");
        SetLastError(error);
        return runFailure("cannot start a reader");
    }
    ResumeThread(thread.value);

    const ULONGLONG spent = GetTickCount64() - started;
    const DWORD left = spent >= *timeout ? 0 : static_cast<DWORD>(*timeout - spent);
    const bool timedOut = WaitForSingleObject(process.value, left) == WAIT_TIMEOUT;
    if (timedOut) {
        TerminateJobObject(job.value, 1);
        WaitForSingleObject(process.value, 5000);
    }
    DWORD exitCode{};
    const bool exited = !timedOut && GetExitCodeProcess(process.value, &exitCode);
    // Descendants holding the pipes get a short drain; then everything in the job ends, and any read still
    // blocked (on a holder outside the job, which suspended assignment should rule out) is cancelled.
    HANDLE threads[2] = {readers[0].value, readers[1].value};
    if (!stopReaders(job.value, threads, 2, kRunDrainMilliseconds)) abandonRun(job.value, "a reader did not stop");
    FILETIME creation{}, exit{}, kernel{}, user{};
    long long runtime = static_cast<long long>(GetTickCount64() - started);
    if (GetProcessTimes(process.value, &creation, &exit, &kernel, &user) && exited) {
        const auto ticks = [](FILETIME time) { return (static_cast<long long>(time.dwHighDateTime) << 32) | time.dwLowDateTime; };
        runtime = (ticks(exit) - ticks(creation)) / 10000;
    }
    std::string frame = "WGPS-RUN 1\r\nexit=" + (exited ? std::to_string(exitCode) : std::string()) +
                        "\r\ntimedout=" + (timedOut ? "1" : "0") + "\r\nruntime=" + std::to_string(runtime) +
                        "\r\nstdout-truncated=" + (pipes[0].truncated ? "1" : "0") +
                        "\r\nstderr-truncated=" + (pipes[1].truncated ? "1" : "0") +
                        "\r\nstdout=" + base64Encode(pipes[0].kept) + "\r\nstderr=" + base64Encode(pipes[1].kept) + "\r\n";
    writeRunFrame(frame);
    // Closing the job ends anything still in it; exiting ends any reader still blocked.
    job.reset();
    return 0;
}
