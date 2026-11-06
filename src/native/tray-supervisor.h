// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "tray-support.h"
#include <optional>

namespace wgps::tray {
// Task Scheduler remains the logon launcher. A running action's failure does
// not reliably trigger RestartOnFailure on every supported Windows host.
// Keep its task alive while the UI recovers, with no timer or idle polling.
struct TrayRestartBudget {
    unsigned retries{};
    DWORD baseDelay{2000};
    std::optional<DWORD> failed(ULONGLONG awakeLifetime) {
        if (awakeLifetime >= 600000) retries = 0;
        if (retries == 3) return {};
        return baseDelay << retries++;
    }
};
inline DWORD supervise(const std::wstring& image, const std::wstring& arguments,
                       const std::wstring& directory, DWORD delay = 2000) {
    TrayRestartBudget budget{0, delay};
    for (;;) {
        if (GetSystemMetrics(SM_SHUTTINGDOWN)) return 0;
        DWORD code{};
        ULONGLONG awakeLifetime{};
        {
            std::wstring command = quote(image) + L" " + arguments;
            STARTUPINFOW startup{}; startup.cb = sizeof(startup);
            PROCESS_INFORMATION created{};
            if (!CreateProcessW(image.c_str(), command.data(), nullptr, nullptr, FALSE,
                                CREATE_NO_WINDOW, nullptr, directory.c_str(), &startup, &created)) {
                code = GetLastError();
                if (!code) code = ERROR_GEN_FAILURE;
            } else {
                Handle process(created.hProcess), thread(created.hThread);
                const auto started = awakeMilliseconds();
                if (WaitForSingleObject(process.value, INFINITE) != WAIT_OBJECT_0 ||
                    !GetExitCodeProcess(process.value, &code))
                    throw std::runtime_error("Cannot observe the tray UI");
                awakeLifetime = awakeMilliseconds() - started;
            }
        }
        if (code == 0 || GetSystemMetrics(SM_SHUTTINGDOWN)) return 0;
        const auto wait = budget.failed(awakeLifetime);
        if (!wait) return code;
        Sleep(*wait); // Three bounded retries: 2, 4, then 8 seconds.
    }
}
}
