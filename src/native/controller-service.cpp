#define _WIN32_WINNT 0x0A00
#include <windows.h>

#include <cwchar>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr wchar_t kServiceName[] = L"WireGuardProgramSplitController";
constexpr DWORD kStopTimeoutMilliseconds = 240000;

SERVICE_STATUS_HANDLE gStatusHandle{};
SERVICE_STATUS gStatus{};
HANDLE gStopEvent{};
std::wstring gControllerScript;

void reportStatus(DWORD state, DWORD win32ExitCode = NO_ERROR, DWORD serviceExitCode = 0,
                  DWORD waitHint = 0) {
    gStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gStatus.dwCurrentState = state;
    gStatus.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0;
    gStatus.dwWin32ExitCode = win32ExitCode;
    gStatus.dwServiceSpecificExitCode = serviceExitCode;
    gStatus.dwWaitHint = waitHint;
    gStatus.dwCheckPoint = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
                            ? gStatus.dwCheckPoint + 1 : 0;
    SetServiceStatus(gStatusHandle, &gStatus);
}

std::wstring quoteArgument(const std::wstring& value) {
    std::wstring result = L"\"";
    size_t backslashes{};
    for (wchar_t character : value) {
        if (character == L'\\') {
            ++backslashes;
        } else if (character == L'\"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(character);
            backslashes = 0;
        } else {
            result.append(backslashes, L'\\');
            result.push_back(character);
            backslashes = 0;
        }
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

std::wstring powerShellPath() {
    std::vector<wchar_t> directory(32768);
    const UINT length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
    if (!length || length >= directory.size()) return {};
    return (std::filesystem::path(directory.data()) / L"WindowsPowerShell" / L"v1.0" /
            L"powershell.exe").wstring();
}

bool launchController(HANDLE job, HANDLE& child) {
    const std::filesystem::path script(gControllerScript);
    const std::filesystem::path logDirectory = script.parent_path().parent_path() / L"logs";
    std::error_code error;
    std::filesystem::create_directories(logDirectory, error);
    if (error) return false;

    HANDLE log = CreateFileW((logDirectory / L"controller-service.log").c_str(), GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log == INVALID_HANDLE_VALUE) return false;
    SetFilePointer(log, 0, nullptr, FILE_END);
    if (!SetHandleInformation(log, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        CloseHandle(log);
        return false;
    }
    HANDLE nullInput = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (nullInput == INVALID_HANDLE_VALUE ||
        !SetHandleInformation(nullInput, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        if (nullInput != INVALID_HANDLE_VALUE) CloseHandle(nullInput);
        CloseHandle(log);
        return false;
    }

    const std::wstring powerShell = powerShellPath();
    if (powerShell.empty()) {
        CloseHandle(nullInput);
        CloseHandle(log);
        return false;
    }
    std::wstring commandLine = quoteArgument(powerShell) +
        L" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File " +
        quoteArgument(gControllerScript) + L" -StopEventHandle " +
        std::to_wstring(reinterpret_cast<ULONG_PTR>(gStopEvent));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = nullInput;
    startup.hStdOutput = log;
    startup.hStdError = log;
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(powerShell.c_str(), commandLine.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &startup,
                                        &process);
    CloseHandle(nullInput);
    CloseHandle(log);
    if (!created) return false;
    if (!AssignProcessToJobObject(job, process.hProcess) || ResumeThread(process.hThread) == DWORD(-1)) {
        TerminateProcess(process.hProcess, ERROR_PROCESS_ABORTED);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        return false;
    }
    CloseHandle(process.hThread);
    child = process.hProcess;
    return true;
}

DWORD WINAPI controlHandler(DWORD control, DWORD, void*, void*) {
    if (control != SERVICE_CONTROL_STOP) return ERROR_CALL_NOT_IMPLEMENTED;
    if (gStopEvent) SetEvent(gStopEvent);
    return NO_ERROR;
}

void WINAPI serviceMain(DWORD, wchar_t**) {
    gStatusHandle = RegisterServiceCtrlHandlerExW(kServiceName, controlHandler, nullptr);
    if (!gStatusHandle) return;
    reportStatus(SERVICE_START_PENDING, NO_ERROR, 0, 30000);

    SECURITY_ATTRIBUTES eventAttributes{};
    eventAttributes.nLength = sizeof(eventAttributes);
    eventAttributes.bInheritHandle = TRUE;
    gStopEvent = CreateEventW(&eventAttributes, TRUE, FALSE, nullptr);
    if (!gStopEvent) {
        reportStatus(SERVICE_STOPPED, GetLastError());
        return;
    }
    ResetEvent(gStopEvent);

    SECURITY_ATTRIBUTES jobAttributes{};
    jobAttributes.nLength = sizeof(jobAttributes);
    jobAttributes.bInheritHandle = FALSE;
    HANDLE job = CreateJobObjectW(&jobAttributes, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                              JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    HANDLE child{};
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
        !launchController(job, child)) {
        const DWORD error = GetLastError();
        if (child) CloseHandle(child);
        if (job) CloseHandle(job);
        CloseHandle(gStopEvent);
        gStopEvent = nullptr;
        reportStatus(SERVICE_STOPPED, error ? error : ERROR_SERVICE_SPECIFIC_ERROR, 1);
        return;
    }

    reportStatus(SERVICE_RUNNING);
    HANDLE waits[] = {gStopEvent, child};
    const DWORD result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
    if (result == WAIT_OBJECT_0) {
        reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, kStopTimeoutMilliseconds);
        const ULONGLONG deadline = GetTickCount64() + kStopTimeoutMilliseconds;
        while (WaitForSingleObject(child, 1000) == WAIT_TIMEOUT && GetTickCount64() < deadline) {
            const ULONGLONG now = GetTickCount64();
            const DWORD remaining = now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
            reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, remaining);
        }
        bool forced = false;
        DWORD stopFailure = NO_ERROR;
        if (WaitForSingleObject(child, 0) == WAIT_TIMEOUT) {
            forced = true;
            if (!TerminateJobObject(job, ERROR_PROCESS_ABORTED)) stopFailure = GetLastError();
        }
        if (WaitForSingleObject(child, 5000) != WAIT_OBJECT_0 && stopFailure == NO_ERROR) {
            stopFailure = ERROR_TIMEOUT;
        }
        DWORD childExitCode = STILL_ACTIVE;
        if (!GetExitCodeProcess(child, &childExitCode) && stopFailure == NO_ERROR) {
            stopFailure = GetLastError();
        } else if (!forced && childExitCode != NO_ERROR && stopFailure == NO_ERROR) {
            stopFailure = childExitCode;
        }
        if (forced && stopFailure == NO_ERROR) stopFailure = ERROR_PROCESS_ABORTED;
        if (stopFailure == NO_ERROR) reportStatus(SERVICE_STOPPED);
        else reportStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, stopFailure);
    } else {
        DWORD childExitCode = 1;
        GetExitCodeProcess(child, &childExitCode);
        reportStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, childExitCode ? childExitCode : 1);
    }
    CloseHandle(child);
    CloseHandle(job);
    CloseHandle(gStopEvent);
    gStopEvent = nullptr;
}

int selfTest() {
    if (std::wstring(kServiceName) != L"WireGuardProgramSplitController") return 1;
    if (quoteArgument(L"C:\\Program Files\\WireGuard\\Controller.ps1") !=
        L"\"C:\\Program Files\\WireGuard\\Controller.ps1\"") return 2;
    if (quoteArgument(L"C:\\ends-with-slash\\") != L"\"C:\\ends-with-slash\\\\\"") return 3;
    std::wcout << L"PASS: controller service command-line setup.\n";
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wcscmp(argv[1], L"--self-test") == 0) return selfTest();
    if (argc != 3 || std::wcscmp(argv[1], L"/service") != 0) {
        std::wcerr << L"Usage: controller-service.exe /service <Controller.ps1>\n";
        return 2;
    }
    gControllerScript = argv[2];
    SERVICE_TABLE_ENTRYW services[] = {{const_cast<wchar_t*>(kServiceName), serviceMain}, {nullptr, nullptr}};
    return StartServiceCtrlDispatcherW(services) ? 0 : 3;
}
