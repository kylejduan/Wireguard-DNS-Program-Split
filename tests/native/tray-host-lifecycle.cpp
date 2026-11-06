// SPDX-License-Identifier: GPL-3.0-or-later
#include "../../src/native/tray-support.h"
#include <tlhelp32.h>
#include <cwchar>
#include <iostream>
namespace {
BOOL CALLBACK closeUi(HWND window, LPARAM root) {
    wchar_t name[64]{}; GetClassNameW(window, name, 64);
    if (std::wcscmp(name, L"WireGuardProgramSplitTray") == 0 &&
        wgps::tray::exists(*reinterpret_cast<const std::wstring*>(root) + L"\\status-completed"))
        PostMessageW(window, WM_CLOSE, 0, 0);
    return TRUE;
}
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    using namespace wgps::tray;
    std::wstring desktopName = L"WgpsHostLifecycle-" + std::to_wstring(GetCurrentProcessId());
    HDESK desktop = CreateDesktopW(desktopName.c_str(), nullptr, nullptr, 0, GENERIC_ALL, nullptr);
    if (!desktop) return 1;
    int result{};
    try {
        const std::wstring root = argv[1], executable = root + L"\\bin\\tray.exe";
        Handle job(CreateJobObjectW(nullptr, nullptr));
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!job.value || !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
            throw std::runtime_error("lifecycle job");
        STARTUPINFOW startup{}; startup.cb = sizeof(startup); startup.lpDesktop = desktopName.data();
        PROCESS_INFORMATION created{}; auto command = quote(executable);
        if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE,
                            CREATE_SUSPENDED, nullptr, root.c_str(), &startup, &created))
            throw std::runtime_error("lifecycle host launch");
        Handle process(created.hProcess), thread(created.hThread);
        if (!AssignProcessToJobObject(job.value, process.value)) {
            TerminateProcess(process.value, 1); throw std::runtime_error("lifecycle containment");
        }
        if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) throw std::runtime_error("lifecycle resume");
        const auto deadline = GetTickCount64() + 20000;
        while (WaitForSingleObject(process.value, 50) == WAIT_TIMEOUT && GetTickCount64() < deadline)
            EnumDesktopWindows(desktop, closeUi, reinterpret_cast<LPARAM>(&root));
        DWORD code{};
        if (WaitForSingleObject(process.value, 0) != WAIT_OBJECT_0 ||
            !GetExitCodeProcess(process.value, &code) || code || !exists(root + L"\\status-completed"))
            throw std::runtime_error("host did not exit cleanly after action and WM_CLOSE");
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
        if (!snapshot.value || !Process32FirstW(snapshot.value, &entry)) throw std::runtime_error("lifecycle process snapshot");
        do {
            if (_wcsicmp(entry.szExeFile, L"tray.exe") != 0) continue;
            Handle observed(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID));
            wchar_t path[32768]{}; DWORD size = 32768;
            if (observed.value && QueryFullProcessImageNameW(observed.value, 0, path, &size) &&
                _wcsicmp(path, executable.c_str()) == 0)
                throw std::runtime_error("a tray process survived the clean host exit");
        } while (Process32NextW(snapshot.value, &entry));
        std::cout << "PASS: real native host and UI finish an action and exit cleanly with no tray left.\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; result = 1; }
    CloseDesktop(desktop);
    return result;
}
