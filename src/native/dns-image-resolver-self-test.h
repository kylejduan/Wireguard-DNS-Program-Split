// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "dns-image-resolver.h"
#include <thread>

namespace wgps {
inline HANDLE imageTestHandle() {
    HANDLE handle{};
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &handle,
                         0, FALSE, DUPLICATE_SAME_ACCESS)) return nullptr;
    return handle;
}
struct ImageTestGate {
    HANDLE entered{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    HANDLE release{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::atomic_uint calls{};
    ~ImageTestGate() { CloseHandle(entered); CloseHandle(release); }
};
inline bool imageResolverSelfTest() {
    auto gate = std::make_shared<ImageTestGate>();
    struct Release { std::shared_ptr<ImageTestGate> gate; ~Release() { SetEvent(gate->release); } } release{gate};
    ImageResolver resolver([gate](HANDLE) {
        if (++gate->calls == 1) {
            SetEvent(gate->entered);
            WaitForSingleObject(gate->release, INFINITE);
            return std::wstring(L"c:\\apps\\old.exe");
        }
        return std::wstring(L"c:\\apps\\direct.exe");
    }, 40);
    const ImageResolver::Key old{1234, 1}, newer{1234, 2};
    if (resolver.identifyPinned(old, imageTestHandle()).status != ImageResolver::Status::Pending ||
        WaitForSingleObject(gate->entered, 1000) != WAIT_OBJECT_0) return false;
    auto current = resolver.identifyPinned(newer, imageTestHandle());
    for (unsigned i = 0; i < 10 && current.status == ImageResolver::Status::Pending; ++i) {
        Sleep(10); current = resolver.identifyPinned(newer, imageTestHandle());
    }
    if (current.path != L"c:\\apps\\direct.exe") return false;
    DWORD before{}, after{};
    GetProcessHandleCount(GetCurrentProcess(), &before);
    for (unsigned i = 0; i < 128; ++i) {
        if (resolver.identifyPinned(old, imageTestHandle()).status != ImageResolver::Status::Pending ||
            resolver.identifyPinned(newer, imageTestHandle()).path != current.path) return false;
    }
    GetProcessHandleCount(GetCurrentProcess(), &after);
    if (after > before + 2 || gate->calls != 2) return false;
    SetEvent(gate->release);
    auto late = resolver.identifyPinned(old, imageTestHandle());
    for (unsigned i = 0; i < 20 && late.status == ImageResolver::Status::Pending; ++i) {
        Sleep(10); late = resolver.identifyPinned(old, imageTestHandle());
    }
    // A delayed result from the earlier process lifetime cannot overwrite the
    // cache entry for a reused PID, and a slow process did not block another.
    return late.path == L"c:\\apps\\old.exe" &&
           resolver.identifyPinned(newer, imageTestHandle()).path == current.path;
}

inline bool imageResolverExhaustionTest() {
    auto gate = std::make_shared<ImageTestGate>();
    struct Release { std::shared_ptr<ImageTestGate> gate; ~Release() { SetEvent(gate->release); } } release{gate};
    auto marker = std::make_shared<int>(1);
    std::weak_ptr<int> lifetime = marker;
    ULONGLONG stopping{};
    {
        ImageResolver resolver([gate, held = std::move(marker)](HANDLE) {
            (void)held;
            ++gate->calls;
            WaitForSingleObject(gate->release, INFINITE);
            return std::wstring(L"c:\\apps\\direct.exe");
        }, 30);
        for (unsigned i = 0; i < ImageResolver::kWorkers; ++i) {
            if (resolver.identifyPinned({100 + i, 1}, imageTestHandle()).status != ImageResolver::Status::Pending) return false;
        }
        Sleep(60);
        const ULONGLONG start = GetTickCount64();
        for (unsigned i = 0; i < 128; ++i) {
            if (resolver.identifyPinned({1000 + i, 1}, imageTestHandle()).status != ImageResolver::Status::Pending) return false;
        }
        if (GetTickCount64() - start > 100 || gate->calls != ImageResolver::kWorkers) return false;
        stopping = GetTickCount64();
    }
    const bool bounded = GetTickCount64() - stopping < 3000 && !lifetime.expired();
    SetEvent(gate->release);
    const ULONGLONG deadline = GetTickCount64() + 2000;
    while (!lifetime.expired() && GetTickCount64() < deadline) Sleep(1);
    return bounded && lifetime.expired();
}

inline bool imageResolverCancellationTest() {
    auto gate = std::make_shared<ImageTestGate>();
    struct Release { std::shared_ptr<ImageTestGate> gate; ~Release() { SetEvent(gate->release); } } release{gate};
    ImageResolver resolver([gate](HANDLE) {
        SetEvent(gate->entered);
        WaitForSingleObject(gate->release, INFINITE);
        return std::wstring(L"c:\\apps\\direct.exe");
    }, 5000);
    ImageResolver::Result result;
    std::atomic_bool finished{};
    std::thread consumer([&] {
        result = resolver.identifyPinned({1234, 1}, imageTestHandle());
        finished = true;
    });
    const bool entered = WaitForSingleObject(gate->entered, 5000) == WAIT_OBJECT_0;
    const ULONGLONG start = GetTickCount64();
    resolver.cancel();
    while (!finished && GetTickCount64() - start < 1000) Sleep(1);
    const bool immediate = finished && GetTickCount64() - start < 300;
    SetEvent(gate->release);
    consumer.join();
    return entered && immediate && result.status == ImageResolver::Status::Unavailable &&
           resolver.identifyPinned({1234, 2}, imageTestHandle()).status == ImageResolver::Status::Unavailable;
}
} // namespace wgps
