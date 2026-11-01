// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace wgps {
inline bool inheritedProcessSelfTest() {
    wchar_t executable[32768]{};
    if (!GetModuleFileNameW(nullptr, executable, 32768)) return false;
    SECURITY_ATTRIBUTES inheritable{sizeof(inheritable), nullptr, TRUE};
    HANDLE allowed = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    HANDLE excluded = CreateEventW(&inheritable, TRUE, FALSE, nullptr);
    HANDLE input = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               &inheritable, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    struct Handles {
        HANDLE a, b, c;
        ~Handles() {
            if (a) CloseHandle(a);
            if (b) CloseHandle(b);
            if (c != INVALID_HANDLE_VALUE) CloseHandle(c);
        }
    } handles{allowed, excluded, input};
    if (!allowed || !excluded || input == INVALID_HANDLE_VALUE) return false;
    std::wstring command = L"\"" + std::wstring(executable) + L"\" --check-inherited-handles " +
        std::to_wstring(reinterpret_cast<ULONG_PTR>(allowed)) + L" " +
        std::to_wstring(reinterpret_cast<ULONG_PTR>(excluded));
    PROCESS_INFORMATION child{};
    if (!createWithInheritedHandles(executable, command.data(), nullptr, CREATE_NO_WINDOW,
                                     {input, allowed}, input, input, input, child)) return false;
    CloseHandle(child.hThread);
    const DWORD wait = WaitForSingleObject(child.hProcess, 5000);
    DWORD code = 1;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(child.hProcess, &code);
    else TerminateProcess(child.hProcess, 1);
    CloseHandle(child.hProcess);
    return code == 0 && WaitForSingleObject(allowed, 0) == WAIT_OBJECT_0 &&
           WaitForSingleObject(excluded, 0) == WAIT_TIMEOUT;
}
} // namespace wgps
