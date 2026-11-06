// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "tray-support.h"

namespace wgps::tray {
// Task Scheduler remains the logon launcher. A running action's failure does
// not reliably trigger RestartOnFailure on every supported Windows host.
// Keep its task alive while the UI recovers, with no timer or idle polling.
inline DWORD supervise(const std::wstring& image, const std::wstring& arguments,
                       const std::wstring& directory, DWORD delay = 2000) {
    for (unsigned attempt = 0; ; ++attempt) {
        DWORD code{};
        {
            std::wstring command = quote(image) + L" " + arguments;
            STARTUPINFOW startup{}; startup.cb = sizeof(startup);
            PROCESS_INFORMATION created{};
            if (!CreateProcessW(image.c_str(), command.data(), nullptr, nullptr, FALSE,
                                CREATE_NO_WINDOW, nullptr, directory.c_str(), &startup, &created))
                throw std::runtime_error("Cannot start the tray UI");
            Handle process(created.hProcess), thread(created.hThread);
            if (WaitForSingleObject(process.value, INFINITE) != WAIT_OBJECT_0 ||
                !GetExitCodeProcess(process.value, &code))
                throw std::runtime_error("Cannot observe the tray UI");
        }
        if (code == 0 || attempt == 3) return code;
        Sleep(delay << attempt); // Three bounded retries: 2, 4, then 8 seconds.
    }
}
}
