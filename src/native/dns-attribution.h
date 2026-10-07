// SPDX-License-Identifier: GPL-3.0-or-later
// Private implementation fragment of dns-dispatcher.cpp.
class Hints {
public:
    static constexpr size_t kMaxHints = 4096;
    // A repeated query for a name and type answered within reuseWindow, carrying no
    // newer attribution event, reuses that answer's route: the Windows DNS Client
    // retransmits and falls back to TCP without raising a new query event.
    explicit Hints(std::unordered_set<std::wstring> included,
                   std::chrono::milliseconds reuseWindow = std::chrono::milliseconds(3000))
        : included_(std::move(included)), reuseWindow_(reuseWindow) {}

    void add(const std::wstring& name, uint16_t type, DWORD pid, long long eventQpc,
             long long deliveryMilliseconds, USHORT eventId) {
        const std::wstring path = lower(processPath(pid));
        const bool selected = !path.empty() && included_.count(path);
        addResolved(name, type, path);
        logLine(L"HINT " + normalizeName(name) + L" type=" + std::to_wstring(type) +
                L" pid=" + std::to_wstring(pid) + L" selected=" +
                std::to_wstring(selected ? 1 : 0) + L" delivery=" +
                std::to_wstring(deliveryMilliseconds) + L"ms event=" + std::to_wstring(eventId) +
                L" event-qpc=" + std::to_wstring(eventQpc) + L" path=" + path);
    }

    bool addResolved(const std::wstring& name, uint16_t type, const std::wstring& path) {
        const bool selected = !path.empty() && included_.count(lower(path));
        const auto key = makeKey(name, type);
        {
            std::lock_guard lock(mutex_);
            const auto now = std::chrono::steady_clock::now();
            expire(now);
            // Losing even one selected hint makes subsequent same-name direct hints unsafe.
            // Refuse forwarding during a full attribution lifetime after any dropped event.
            if (name.size() > 253 || (hints_.size() >= kMaxHints && !hints_.contains(key))) {
                overloadedUntil_ = now + std::chrono::seconds(10);
                changed_.notify_all();
                return false;
            }
            auto& pending = hints_[key];
            if (pending.answered || pending.expires <= now) pending = {};
            pending.tunnel = pending.tunnel || selected;
            pending.direct = pending.direct || (!path.empty() && !selected);
            pending.unknown = pending.unknown || path.empty();
            pending.expires = now + std::chrono::seconds(10);
        }
        changed_.notify_all();
        return true;
    }

    std::optional<bool> take(const std::wstring& name, uint16_t type, bool* reused = nullptr) {
        const auto key = makeKey(name, type);
        if (reused) *reused = false;
        struct Waiting {
            Waiting() { gHintWaiters.fetch_add(1); }
            ~Waiting() { gHintWaiters.fetch_sub(1); }
        } waiting;
        if (const HANDLE flush = gTraceFlushRequested.load()) SetEvent(flush);
        std::unique_lock lock(mutex_);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (true) {
            const auto now = std::chrono::steady_clock::now();
            if (now < overloadedUntil_) return std::nullopt;
            expire(now);
            auto found = hints_.find(key);
            if (found != hints_.end()) {
                auto& pending = found->second;
                if (pending.expires <= now) { hints_.erase(found); continue; }
                if (pending.answered) {
                    if (pending.decision != Decision::Pending &&
                        std::chrono::steady_clock::now() - pending.answeredAt < reuseWindow_) {
                        if (reused) *reused = true;
                        return pending.decision == Decision::Tunnel;
                    }
                    hints_.erase(found);
                    continue;
                }
                if (pending.tunnel) {
                    pending.decision = Decision::Tunnel;
                    return true;
                }
                if (pending.decision == Decision::Tunnel) return true;
                if (pending.decision == Decision::Direct) return false;
                if (pending.direct) {
                    pending.decision = Decision::Direct;
                    return false;
                }
            }
            if (changed_.wait_until(lock, deadline) == std::cv_status::timeout) return std::nullopt;
        }
    }

    void complete(const std::wstring& name, uint16_t type) {
        std::lock_guard lock(mutex_);
        auto found = hints_.find(makeKey(name, type));
        if (found != hints_.end()) {
            found->second.answered = true;
            found->second.answeredAt = std::chrono::steady_clock::now();
        }
    }

private:
    enum class Decision { Pending, Direct, Tunnel };

    struct Pending {
        bool tunnel{};
        bool direct{};
        bool unknown{};
        bool answered{};
        Decision decision{Decision::Pending};
        std::chrono::steady_clock::time_point expires{};
        std::chrono::steady_clock::time_point answeredAt{};
    };

    static std::wstring makeKey(const std::wstring& name, uint16_t type) {
        return normalizeName(name) + L"#" + std::to_wstring(type);
    }

    void expire(std::chrono::steady_clock::time_point now) {
        // At most one bounded scan per second, even under sustained event traffic.
        if (now < nextExpiry_) return;
        nextExpiry_ = now + std::chrono::seconds(1);
        for (auto it = hints_.begin(); it != hints_.end();) {
            if (it->second.expires <= now) it = hints_.erase(it);
            else ++it;
        }
    }

    std::chrono::steady_clock::time_point nextExpiry_{};
    std::chrono::steady_clock::time_point overloadedUntil_{};
    std::unordered_set<std::wstring> included_;
    std::chrono::milliseconds reuseWindow_;
    std::mutex mutex_;
    std::condition_variable changed_;
    std::unordered_map<std::wstring, Pending> hints_;
};

