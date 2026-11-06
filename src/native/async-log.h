// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <windows.h>
#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace wgps {
// Best-effort diagnostics must not hold DNS attribution, its mutex, or a query
// worker behind disk/pipe I/O. A single writer owns the sink. Producers never
// wait for it, and queued memory is bounded independently of the rotating file.
class AsyncLog {
public:
    using Sink = std::function<void(std::string_view)>;
    static constexpr size_t kMaxMessages = 256;
    static constexpr size_t kMaxBytes = 256 * 1024;
    static constexpr size_t kMaxMessageBytes = 65536;

    explicit AsyncLog(Sink sink) : state_(std::make_shared<State>(std::move(sink))) {
        if (!state_->ready) return;
        auto context = std::make_unique<std::shared_ptr<State>>(state_);
        thread_ = CreateThread(nullptr, 0, run, context.get(), 0, nullptr);
        if (thread_) context.release();
        else state_->accepting = false;
    }
    ~AsyncLog() {
        state_->accepting = false;
        state_->stopAt = GetTickCount64() + 500;
        state_->stopping = true;
        if (state_->ready) SetEvent(state_->ready);
        if (thread_) {
            if (WaitForSingleObject(thread_, 500) == WAIT_TIMEOUT) {
                CancelSynchronousIo(thread_);
                WaitForSingleObject(thread_, 500);
            }
            // A sink whose driver ignores cancellation may still be running.
            // It owns State (including its sink and event) independently: no
            // borrowed pointers or unbounded join. Only one writer exists per
            // dispatcher lifetime; the OS ends it when that process exits.
            CloseHandle(thread_);
        }
    }
    AsyncLog(const AsyncLog&) = delete;
    AsyncLog& operator=(const AsyncLog&) = delete;

    bool write(std::string_view bytes) noexcept {
        try {
            if (!state_->accepting || bytes.size() > kMaxMessageBytes) return drop();
            // Allocate/copy outside the queue lock. Queue slots are fixed and
            // moved by swap; the writer never holds this lock during sink I/O.
            std::string message(bytes);
            std::unique_lock lock(state_->mutex, std::try_to_lock);
            if (!lock || !state_->accepting || state_->count == kMaxMessages ||
                bytes.size() > kMaxBytes - state_->bytes) return drop();
            state_->slots[state_->tail].swap(message);
            state_->tail = (state_->tail + 1) % kMaxMessages;
            ++state_->count;
            state_->bytes += bytes.size();
            lock.unlock();
            SetEvent(state_->ready);
            return true;
        } catch (...) { return drop(); }
    }
    unsigned long long dropped() const { return state_->dropped.load(); }

private:
    struct State {
        explicit State(Sink callback) : sink(std::move(callback)), ready(CreateEventW(nullptr, FALSE, FALSE, nullptr)) {
            accepting = ready != nullptr;
        }
        ~State() { if (ready) CloseHandle(ready); }
        Sink sink;
        HANDLE ready{};
        std::mutex mutex;
        std::array<std::string, kMaxMessages> slots;
        size_t head{}, tail{}, count{}, bytes{};
        std::atomic_bool accepting{}, stopping{};
        std::atomic<ULONGLONG> stopAt{};
        std::atomic<unsigned long long> dropped{};
    };
    bool drop() noexcept { ++state_->dropped; return false; }
    static DWORD WINAPI run(void* opaque) noexcept {
        std::unique_ptr<std::shared_ptr<State>> context(static_cast<std::shared_ptr<State>*>(opaque));
        auto state = std::move(*context);
        context.reset();
        try {
            unsigned long long reported{};
            for (;;) {
                if (WaitForSingleObject(state->ready, INFINITE) != WAIT_OBJECT_0) break;
                for (;;) {
                    if (state->stopping && GetTickCount64() >= state->stopAt) return 0;
                    std::string message;
                    {
                        std::lock_guard lock(state->mutex);
                        if (!state->count) {
                            if (state->stopping) return 0;
                            break;
                        }
                        message.swap(state->slots[state->head]);
                        state->head = (state->head + 1) % kMaxMessages;
                        --state->count;
                        state->bytes -= message.size();
                    }
                    const auto lost = state->dropped.load();
                    if (lost != reported) {
                        state->sink("LOG QUEUE DROPPED " + std::to_string(lost - reported) + "\r\n");
                        reported = lost;
                    }
                    state->sink(message);
                }
            }
        } catch (...) { state->accepting = false; }
        return 0;
    }
    std::shared_ptr<State> state_;
    HANDLE thread_{};
};
} // namespace wgps
