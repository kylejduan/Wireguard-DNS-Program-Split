// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "async-log.h"
#include <thread>
#include <vector>

namespace wgps {
inline bool asyncLogContentionSelfTest() {
    struct Acks {
        std::array<HANDLE, 8> ready{};
        std::array<std::atomic_uint, 8> received{};
        std::atomic_bool failed{};
        ~Acks() { for (HANDLE event : ready) if (event) CloseHandle(event); }
    };
    auto acks = std::make_shared<Acks>();
    for (auto& event : acks->ready) {
        event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!event) return false;
    }
    AsyncLog log([acks](std::string_view line) {
        const unsigned producer = line.empty() ? 8 : static_cast<unsigned>(line[0] - '0');
        if (producer >= 8) { acks->failed = true; return; }
        ++acks->received[producer];
        SetEvent(acks->ready[producer]);
    });
    std::vector<std::thread> producers;
    for (unsigned i = 0; i < 8; ++i) producers.emplace_back([&, i] {
        for (unsigned n = 0; n < 128; ++n) {
            // One outstanding message per producer keeps the queue below eight
            // entries, so a drop demonstrates contention rather than overload.
            if (!log.write(std::to_string(i) + ":" + std::to_string(n) + "\r\n") ||
                WaitForSingleObject(acks->ready[i], 5000) != WAIT_OBJECT_0) {
                acks->failed = true;
                return;
            }
        }
    });
    for (auto& producer : producers) producer.join();
    if (acks->failed || log.dropped()) return false;
    for (auto& received : acks->received) if (received != 128) return false;
    return true;
}

inline bool asyncLogFinalDropSelfTest() {
    struct Notice {
        HANDLE reported{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        std::atomic_bool exact{};
        ~Notice() { if (reported) CloseHandle(reported); }
    };
    auto notice = std::make_shared<Notice>();
    if (!notice->reported) return false;
    AsyncLog log([notice](std::string_view line) {
        notice->exact = line == "LOG QUEUE DROPPED 1\r\n";
        SetEvent(notice->reported);
    });
    // No accepted message follows this loss: waking an empty writer must itself
    // report the final drop, rather than waiting for a later successful write.
    if (log.write(std::string(AsyncLog::kMaxMessageBytes + 1, 'x')) || log.dropped() != 1) return false;
    return WaitForSingleObject(notice->reported, 1000) == WAIT_OBJECT_0 && notice->exact;
}

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
