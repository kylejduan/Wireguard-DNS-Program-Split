// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace wgps {
// Canonical image resolution can enter a filesystem or AV minifilter. Keep it
// off the ETW consumer and never wait indefinitely for it. A late result only
// populates this cache; it cannot amend a DNS hint or shorten its quarantine.
class ImageResolver {
public:
    static constexpr unsigned kWorkers = 4;
    static constexpr size_t kSlots = 16;
    static constexpr size_t kCacheEntries = 2048;
    static constexpr DWORD kWaitMilliseconds = 150;
    using Resolve = std::function<std::wstring(HANDLE)>;
    enum class Status { Known, Pending, Unavailable };
    struct Result { std::wstring path; Status status{Status::Unavailable}; };
    struct Key {
        DWORD pid{};
        ULONGLONG created{};
        bool operator==(const Key&) const = default;
    };

    explicit ImageResolver(Resolve resolve, DWORD wait = kWaitMilliseconds)
        : state_(std::make_shared<State>(std::move(resolve))), wait_(wait) {
        if (!state_->stop || !state_->work) throw std::runtime_error("Cannot create image resolver synchronization");
        for (const auto& job : state_->jobs) if (!job.done) throw std::runtime_error("Cannot create image resolver slot");
        try {
            for (unsigned i = 0; i < kWorkers; ++i) {
                auto context = std::make_unique<std::shared_ptr<State>>(state_);
                HANDLE thread = CreateThread(nullptr, 0, run, context.get(), 0, nullptr);
                if (!thread) throw std::runtime_error("Cannot start image resolver worker");
                threads_[count_++] = thread;
                context.release();
            }
        } catch (...) {
            stopWorkers();
            throw;
        }
    }
    ~ImageResolver() { stopWorkers(); }
    ImageResolver(const ImageResolver&) = delete;
    ImageResolver& operator=(const ImageResolver&) = delete;

    // Nonblocking: wake the consumer's current wait and stop accepting work
    // before an ETW trace drains its remaining records during shutdown.
    void cancel() noexcept { if (state_->stop) SetEvent(state_->stop); }

    // Single consumer. Only this thread accesses cache_/recent_. The pool mutex
    // protects slots only; a worker never holds it during resolution or CloseHandle.
    Result identify(DWORD pid) {
        if (WaitForSingleObject(state_->stop, 0) == WAIT_OBJECT_0) return {};
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) return {};
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) { CloseHandle(process); return {}; }
        ULARGE_INTEGER value{};
        value.LowPart = created.dwLowDateTime;
        value.HighPart = created.dwHighDateTime;
        return identifyPinned({pid, value.QuadPart}, process);
    }

    // Takes ownership of the exact process handle, including on cache hits and
    // refusals. Exposed for deterministic lifetime/PID-reuse failure injection.
    Result identifyPinned(Key key, HANDLE process) {
        struct Close { HANDLE value; ~Close() { if (value) CloseHandle(value); } } owned{process};
        if (!count_ || !process || WaitForSingleObject(state_->stop, 0) == WAIT_OBJECT_0) return {};
        const ULONGLONG now = GetTickCount64();
        harvest();
        if (auto hit = cached(key, now)) return *hit;
        HANDLE done{};
        ULONGLONG submitted{};
        {
            std::lock_guard lock(state_->mutex);
            Job* job{};
            for (auto& candidate : state_->jobs) {
                if (candidate.phase != Phase::Empty && candidate.key == key) { job = &candidate; break; }
            }
            if (!job) {
                unsigned running{}, overdue{};
                for (const auto& candidate : state_->jobs) if (candidate.phase == Phase::Running) {
                    ++running;
                    overdue += now >= candidate.started && now - candidate.started >= wait_;
                }
                if (running == count_ && overdue == count_) return {{}, Status::Pending};
                for (auto& candidate : state_->jobs) if (candidate.phase == Phase::Empty) { job = &candidate; break; }
                if (!job) return {{}, Status::Pending};
                ResetEvent(job->done);
                job->key = key;
                job->process = owned.value;
                owned.value = nullptr;
                job->submitted = now;
                job->phase = Phase::Queued;
                ReleaseSemaphore(state_->work, 1, nullptr);
            }
            done = job->done;
            submitted = job->submitted;
        }
        const ULONGLONG elapsed = GetTickCount64() - submitted;
        const HANDLE waits[]{state_->stop, done};
        const auto beforeWait = std::chrono::steady_clock::now();
        if (beforeWait - windowStarted_ >= std::chrono::seconds(1)) {
            windowStarted_ = beforeWait;
            waited_ = {};
        }
        // One slow process must not turn a stream of cache misses into an
        // unbounded sequence of waits ahead of every ordering sentinel. Share
        // the wait allowance across all identities, not just one process key.
        const auto available = std::chrono::milliseconds(wait_) - waited_;
        DWORD allowance{};
        if (elapsed < wait_ && available > std::chrono::steady_clock::duration::zero()) {
            allowance = std::min<DWORD>(static_cast<DWORD>(wait_ - elapsed),
                static_cast<DWORD>(std::chrono::duration_cast<std::chrono::milliseconds>(available).count()));
        }
        if (allowance) {
            WaitForMultipleObjects(2, waits, FALSE, allowance);
            waited_ += std::chrono::steady_clock::now() - beforeWait;
        }
        if (WaitForSingleObject(state_->stop, 0) == WAIT_OBJECT_0) return {};
        harvest();
        if (auto hit = cached(key, GetTickCount64())) return *hit;
        return {{}, Status::Pending};
    }

private:
    void stopWorkers() noexcept {
        cancel();
        for (unsigned i = 0; i < count_; ++i) CancelSynchronousIo(threads_[i]);
        if (count_) WaitForMultipleObjects(count_, threads_.data(), TRUE, 1000);
        // Worker-owned State survives an I/O operation ignoring cancellation.
        for (unsigned i = 0; i < count_; ++i) CloseHandle(threads_[i]);
        count_ = 0;
    }
    enum class Phase { Empty, Queued, Running, Done };
    struct Job {
        HANDLE done{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        HANDLE process{};
        Key key;
        Phase phase{Phase::Empty};
        ULONGLONG submitted{}, started{};
        std::wstring path;
        ~Job() { if (done) CloseHandle(done); if (process) CloseHandle(process); }
    };
    struct State {
        explicit State(Resolve callback) : resolve(std::move(callback)) {}
        ~State() { if (stop) CloseHandle(stop); if (work) CloseHandle(work); }
        Resolve resolve;
        HANDLE stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        HANDLE work{CreateSemaphoreW(nullptr, 0, static_cast<LONG>(kSlots), nullptr)};
        std::mutex mutex;
        std::array<Job, kSlots> jobs;
    };
    struct Hash {
        size_t operator()(const Key& key) const { return std::hash<ULONGLONG>{}(key.created) ^ std::hash<DWORD>{}(key.pid); }
    };
    struct Cached {
        Result result;
        ULONGLONG expires{};
        std::list<Key>::iterator recent;
    };
    std::optional<Result> cached(Key key, ULONGLONG now) {
        const auto found = cache_.find(key);
        if (found == cache_.end()) return std::nullopt;
        if (found->second.expires && now >= found->second.expires) {
            recent_.erase(found->second.recent);
            cache_.erase(found);
            return std::nullopt;
        }
        recent_.splice(recent_.begin(), recent_, found->second.recent);
        return found->second.result;
    }
    void harvest() {
        std::lock_guard lock(state_->mutex);
        for (auto& job : state_->jobs) {
            if (job.phase != Phase::Done) continue;
            if (cache_.size() >= kCacheEntries) { cache_.erase(recent_.back()); recent_.pop_back(); }
            const auto existing = cache_.find(job.key);
            if (existing != cache_.end()) { recent_.erase(existing->second.recent); cache_.erase(existing); }
            recent_.push_front(job.key);
            const auto status = job.path.empty() ? Status::Unavailable : Status::Known;
            const ULONGLONG expiry = job.path.empty() ? GetTickCount64() + 1000 : 0;
            cache_.emplace(job.key, Cached{{std::move(job.path), status}, expiry, recent_.begin()});
            job.phase = Phase::Empty;
        }
    }
    static DWORD WINAPI run(void* opaque) noexcept {
        std::unique_ptr<std::shared_ptr<State>> context(static_cast<std::shared_ptr<State>*>(opaque));
        auto state = std::move(*context);
        context.reset();
        const HANDLE waits[]{state->stop, state->work};
        while (WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0 + 1) {
            Job* job{};
            {
                std::lock_guard lock(state->mutex);
                for (auto& candidate : state->jobs) {
                    if (candidate.phase != Phase::Queued) continue;
                    if (!job || candidate.submitted < job->submitted) job = &candidate;
                }
                if (!job) continue;
                job->phase = Phase::Running;
                job->started = GetTickCount64();
            }
            std::wstring path;
            try { path = state->resolve(job->process); } catch (...) {}
            CloseHandle(job->process);
            {
                std::lock_guard lock(state->mutex);
                job->process = nullptr;
                job->path = std::move(path);
                job->phase = Phase::Done;
                SetEvent(job->done);
            }
        }
        return 0;
    }
    std::shared_ptr<State> state_;
    std::array<HANDLE, kWorkers> threads_{};
    unsigned count_{};
    DWORD wait_;
    std::chrono::steady_clock::time_point windowStarted_{std::chrono::steady_clock::now()};
    std::chrono::steady_clock::duration waited_{};
    std::list<Key> recent_;
    std::unordered_map<Key, Cached, Hash> cache_;
};
} // namespace wgps
