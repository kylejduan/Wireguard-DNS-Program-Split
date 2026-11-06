// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../src/native/tray-support.h"
#include <iostream>

namespace {
BOOL CALLBACK cancel(HWND window, LPARAM found) {
    wchar_t name[64]{};
    GetClassNameW(window, name, 64);
    if (std::wcscmp(name, L"#32770") == 0) {
        *reinterpret_cast<bool*>(found) = true;
        PostMessageW(window, WM_COMMAND, IDCANCEL, 0);
    }
    return TRUE;
}
void check(const std::wstring& executable, const std::wstring& arguments, HDESK desktop,
           std::wstring& desktopName, const std::string& expected = "CANCEL") {
    using wgps::tray::Handle;
    SECURITY_ATTRIBUTES inherit{sizeof(inherit), nullptr, TRUE};
    HANDLE read{}, write{};
    if (!CreatePipe(&read, &write, &inherit, 0)) throw std::runtime_error("picker pipe");
    Handle input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr));
    Handle error(CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, 0, nullptr));
    Handle output(read), writer(write);
    if (!input.value || !error.value || !SetHandleInformation(output.value, HANDLE_FLAG_INHERIT, 0)) throw std::runtime_error("picker streams");
    SIZE_T bytes{};
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<char> storage(bytes);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) throw std::runtime_error("picker attributes");
    HANDLE allowed[] = {input.value, writer.value, error.value};
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup); startup.StartupInfo.lpDesktop = desktopName.data();
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.value; startup.StartupInfo.hStdOutput = writer.value; startup.StartupInfo.hStdError = error.value;
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION created{};
    std::wstring command = wgps::tray::quote(executable) + L" " + arguments;
    BOOL started = FALSE;
    if (UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, allowed, sizeof(allowed), nullptr, nullptr))
        started = CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &created);
    const DWORD launchError = GetLastError();
    DeleteProcThreadAttributeList(attributes);
    if (!started) throw std::runtime_error("picker launch: " + std::to_string(launchError));
    Handle process(created.hProcess), thread(created.hThread);
    CloseHandle(writer.value); writer.value = nullptr;
    bool found{};
    const auto deadline = GetTickCount64() + 15000;
    while (WaitForSingleObject(process.value, 50) == WAIT_TIMEOUT && GetTickCount64() < deadline)
        EnumDesktopWindows(desktop, cancel, reinterpret_cast<LPARAM>(&found));
    if (WaitForSingleObject(process.value, 0) != WAIT_OBJECT_0) {
        TerminateProcess(process.value, 1); WaitForSingleObject(process.value, 5000);
        throw std::runtime_error("picker deadline");
    }
    DWORD code{}; GetExitCodeProcess(process.value, &code);
    char result[64]{}; DWORD count{};
    ReadFile(output.value, result, sizeof(result), &count, nullptr);
    if (code || !found || std::string(result, count) != expected) throw std::runtime_error("picker cancellation contract");
}
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2 && argc != 4) return 2;
    std::wstring name = L"WgpsTrayTest-" + std::to_wstring(GetCurrentProcessId());
    HDESK desktop = CreateDesktopW(name.c_str(), nullptr, nullptr, 0, GENERIC_ALL, nullptr);
    if (!desktop) { std::cerr << "Cannot create isolated test desktop\n"; return 1; }
    int code{};
    try {
        // The desktop is never made visible. The real pickers run and cancel
        // there, without opening or closing any interactive user's window.
        check(std::filesystem::absolute(argv[1]).wstring(), L"--pick-app", desktop, name);
        check(std::filesystem::absolute(argv[1]).wstring(), L"--pick-profile", desktop, name);
        if (argc == 4) {
            const auto root = wgps::tray::quote(argv[3]);
            check(std::filesystem::absolute(argv[2]).wstring(), root + L" PickAdd", desktop, name, "");
            check(std::filesystem::absolute(argv[2]).wstring(), root + L" PickImport", desktop, name, "");
        }
        std::cout << "PASS: both native pickers launch and cancel on an isolated desktop.\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; code = 1; }
    CloseDesktop(desktop);
    return code;
}
