// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "async-log.h"

namespace wgps {
inline bool asyncLogSelfTest() {
    struct Events {
        HANDLE entered{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        HANDLE release{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        ~Events() { if (entered) CloseHandle(entered); if (release) CloseHandle(release); }
    };
    auto events = std::make_shared<Events>();
    if (!events->entered || !events->release) return false;
    struct Release { std::shared_ptr<Events> events; ~Release() { SetEvent(events->release); } } release{events};
    auto marker = std::make_shared<int>(1);
    std::weak_ptr<int> lifetime = marker;
    bool bounded{}, stopped{};
    ULONGLONG stopStarted{};
    {
        AsyncLog log([events, retained = std::move(marker)](std::string_view) {
            (void)retained;
            SetEvent(events->entered);
            WaitForSingleObject(events->release, INFINITE);
        });
        if (!log.write("start\r\n") || WaitForSingleObject(events->entered, 5000) != WAIT_OBJECT_0) return false;
        // A writer blocked in an uncancellable wait cannot block producers or
        // grow queued data beyond 256 KiB. This is failure injection, not disk load.
        const ULONGLONG start = GetTickCount64();
        unsigned accepted{};
        for (unsigned i = 0; i < 512; ++i) accepted += log.write(std::string(4096, 'x'));
        bounded = accepted <= AsyncLog::kMaxBytes / 4096 && log.dropped() && GetTickCount64() - start < 1000;
        stopStarted = GetTickCount64();
        // The sink deliberately ignores CancelSynchronousIo. Its captured state
        // must remain alive after the logger's bounded destructor returns.
    }
    stopped = !lifetime.expired() && GetTickCount64() - stopStarted < 3000;
    SetEvent(events->release);
    const ULONGLONG deadline = GetTickCount64() + 2000;
    while (!lifetime.expired() && GetTickCount64() < deadline) Sleep(1);
    return bounded && stopped && lifetime.expired();
}
} // namespace wgps
