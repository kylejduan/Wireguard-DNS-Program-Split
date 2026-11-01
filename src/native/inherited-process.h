// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <windows.h>
#include <initializer_list>
#include <vector>

namespace wgps {
// A long-lived child must not inherit transient pipe ends, events or handles
// belonging to a concurrently launched component. Specify the entire allowlist.
inline BOOL createWithInheritedHandles(const wchar_t* application, wchar_t* command,
                                      const wchar_t* directory, DWORD flags,
                                      std::initializer_list<HANDLE> handles,
                                      HANDLE input, HANDLE output, HANDLE error,
                                      PROCESS_INFORMATION& process) {
    SIZE_T bytes{};
    InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
    std::vector<char> storage(bytes);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &bytes)) return FALSE;
    std::vector<HANDLE> allowed(handles);
    BOOL created = FALSE;
    if (UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                  allowed.data(), allowed.size() * sizeof(HANDLE), nullptr, nullptr)) {
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = input;
        startup.StartupInfo.hStdOutput = output;
        startup.StartupInfo.hStdError = error;
        startup.lpAttributeList = attributes;
        created = CreateProcessW(application, command, nullptr, nullptr, TRUE,
                                 flags | EXTENDED_STARTUPINFO_PRESENT, nullptr, directory,
                                 &startup.StartupInfo, &process);
    }
    const DWORD savedError = GetLastError();
    DeleteProcThreadAttributeList(attributes);
    SetLastError(savedError);
    return created;
}
} // namespace wgps
