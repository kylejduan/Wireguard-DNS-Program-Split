// SPDX-License-Identifier: GPL-3.0-or-later
// Private implementation fragment of dns-dispatcher.cpp.
class Hints {
public:
    static constexpr size_t kMaxHints = 4096;
    // A repeated query for a name and type answered within reuseWindow, carrying no
    // newer attribution event, reuses that answer's route: the Windows DNS Client
    // retransmits and falls back to TCP without raising a new query event.
    explicit Hints(std::unordered_set<std::wstring> included,
                   std::chrono::milliseconds reuseWindow = std::chrono::milliseconds(3000),
                   std::chrono::milliseconds barrierTimeout = std::chrono::milliseconds(500))
        : included_(std::make_shared<const std::unordered_set<std::wstring>>(std::move(included))),
          reuseWindow_(reuseWindow), barrierTimeout_(barrierTimeout) {}

    // A reload swaps the whole set; a lookup in progress keeps the set it started with.
    void setIncluded(std::unordered_set<std::wstring> included) {
        auto replacement = std::make_shared<const std::unordered_set<std::wstring>>(std::move(included));
        std::lock_guard lock(includedMutex_);
        included_ = std::move(replacement);
    }

    bool isIncluded(const std::wstring& lowerPath) const {
        std::shared_ptr<const std::unordered_set<std::wstring>> included;
        {
            std::lock_guard lock(includedMutex_);
            included = included_;
        }
        return included->count(lowerPath) != 0;
    }

    void add(const std::wstring& name, uint16_t type, DWORD pid, long long eventQpc,
             long long deliveryMilliseconds, USHORT eventId) {
        const std::wstring path = lower(processPath(pid));
        const bool selected = !path.empty() && isIncluded(path);
        addResolved(name, type, path);
        logLine(L"HINT " + normalizeName(name) + L" type=" + std::to_wstring(type) +
                L" pid=" + std::to_wstring(pid) + L" selected=" +
                std::to_wstring(selected ? 1 : 0) + L" delivery=" +
                std::to_wstring(deliveryMilliseconds) + L"ms event=" + std::to_wstring(eventId) +
                L" event-qpc=" + std::to_wstring(eventQpc) + L" path=" + path);
    }

    bool addResolved(const std::wstring& name, uint16_t type, const std::wstring& path) {
        const bool selected = !path.empty() && isIncluded(lower(path));
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
            if (pending.expires <= now) pending = {};
            else if (pending.answered) retire(pending, now);
            pending.generation = ++generations_;
            pending.selected = pending.selected || selected;
            pending.tunnel = pending.tunnel || selected;
            pending.direct = pending.direct || (!path.empty() && !selected);
            // A process that exited before its event was read may have been a selected one. No direct route
            // or direct answer for the name until this event's attribution lifetime ends; tunnel evidence
            // still routes to the tunnel.
            if (path.empty()) pending.unknownUntil = now + std::chrono::seconds(10);
            pending.expires = std::max(pending.expires, now + std::chrono::seconds(10));
        }
        changed_.notify_all();
        return true;
    }

    // ETW dropped events or buffers: a selected hint may be among them. Forget every entry without
    // tunnel evidence and refuse direct routes for a full attribution lifetime, so neither an earlier
    // nor a later same-name direct hint can stand in for the lost one. Tunnel decisions continue.
    // Repairs keep the payload filters and NRPT rule, so a failed health probe meanwhile is not a leak.
    void lostEvents() {
        {
            std::lock_guard lock(mutex_);
            const auto now = std::chrono::steady_clock::now();
            std::erase_if(hints_, [now](const auto& entry) { return !entry.second.tunnel && now >= entry.second.unknownUntil; });
            directBlockedUntil_ = now + std::chrono::seconds(10);
        }
        changed_.notify_all();
    }

    // The ordering barrier. Microsoft-Windows-DNS-Client logs its query event in the calling process before
    // the query reaches the DNS Client service and is sent here, and the session writes every event to one
    // buffer sequence in logging order (EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING). A sentinel event written
    // after a packet arrived is therefore delivered after the query event of that packet, if one exists.
    using SentinelWriter = std::function<bool(unsigned long long sequence)>;
    void setSentinelWriter(SentinelWriter writer) {
        std::lock_guard lock(mutex_);
        writer_ = std::move(writer);
    }

    // The consumer processed the sentinel carrying this sequence, and so every event logged before it.
    // Sequences are assigned before their sentinels are written, so a later one covers every earlier one.
    void sentinelProcessed(unsigned long long sequence) {
        {
            std::lock_guard lock(mutex_);
            processed_ = std::max(processed_, sequence);
        }
        changed_.notify_all();
    }

    // A flush that started once this sequence had been assigned has checked the session for lost events.
    void flushChecked(unsigned long long sequence) {
        {
            std::lock_guard lock(mutex_);
            checked_ = std::max(checked_, sequence);
        }
        changed_.notify_all();
    }

    unsigned long long lastSequence() const { return sequence_.load(); }

    // Tunnel evidence routes at once. Any other decision (a fresh or reused direct route, or no hint) waits
    // for the barrier, so the query event of this very packet has been seen, then is final: tunnel evidence,
    // else direct evidence, else refusal. A barrier that does not complete in time refuses.
    // generation identifies the evidence the decision was made on, for complete().
    std::optional<bool> take(const std::wstring& name, uint16_t type, bool* reused = nullptr,
                             unsigned long long* generation = nullptr) {
        const auto key = makeKey(name, type);
        if (reused) *reused = false;
        const auto decided = [&](bool tunnel) {
            if (generation) *generation = hints_.at(key).generation;
            return std::optional<bool>(tunnel);
        };
        std::unique_lock lock(mutex_);
        if (std::chrono::steady_clock::now() < overloadedUntil_) return std::nullopt;
        if (decide(key, reused, false) == std::optional<bool>(true)) return decided(true);
        if (!barrier(lock) || std::chrono::steady_clock::now() < overloadedUntil_) return std::nullopt;
        const auto route = decide(key, reused, true);
        return route ? decided(*route) : route;
    }

    // Asked before a direct answer is delivered. The Windows DNS Client merges a lookup into an identical
    // one already in flight, so a selected application that asks for the name meanwhile sends no packet of
    // its own and would receive this answer. Once its query event has been seen (the barrier again), the
    // answer is withheld and refused, and the retried lookups go to the tunnel.
    bool directAnswerUnsafe(const std::wstring& name, uint16_t type) {
        const auto key = makeKey(name, type);
        std::unique_lock lock(mutex_);
        if (!barrier(lock)) return true;
        // Lost events or an overflow may have dropped exactly that selected event: withhold meanwhile too.
        const auto now = std::chrono::steady_clock::now();
        if (now < directBlockedUntil_ || now < overloadedUntil_) return true;
        const auto found = hints_.find(key);
        return found != hints_.end() && (found->second.tunnel || now < found->second.unknownUntil);
    }

    static constexpr unsigned long long kLatestGeneration = ~0ULL;

    // The exchange decided on generation's evidence was answered. Evidence that arrived meanwhile is not
    // finalized by it: the entry stays unanswered, so that evidence is decided on by its own packet.
    void complete(const std::wstring& name, uint16_t type, unsigned long long generation = kLatestGeneration) {
        std::lock_guard lock(mutex_);
        auto found = hints_.find(makeKey(name, type));
        if (found == hints_.end()) return;
        auto& pending = found->second;
        const auto now = std::chrono::steady_clock::now();
        if (pending.decision == Decision::Tunnel && pending.selected) {
            pending.selectedAnswered = true;
            pending.selectedAnsweredAt = now;
            // The entry outlives the window in which this exchange's tunnel provenance applies.
            pending.expires = std::max(pending.expires, now + reuseWindow_);
        }
        if (generation != kLatestGeneration && generation != pending.generation) return;
        pending.answered = true;
        pending.answeredAt = now;
    }

private:
    enum class Decision { Pending, Direct, Tunnel };

    struct Pending {
        bool tunnel{};
        // A selected application's own event, as opposed to tunnel evidence carried over from an earlier exchange.
        bool selected{};
        bool selectedAnswered{};
        unsigned long long generation{};
        bool direct{};
        std::chrono::steady_clock::time_point unknownUntil{};
        bool answered{};
        Decision decision{Decision::Pending};
        std::chrono::steady_clock::time_point expires{};
        std::chrono::steady_clock::time_point answeredAt{};
        std::chrono::steady_clock::time_point selectedAnsweredAt{};
    };

    // Waits until every event logged before the call has been processed and checked for loss, or the barrier
    // timeout passes. Called and returns with the lock held.
    bool barrier(std::unique_lock<std::mutex>& lock) {
        struct Waiting {
            Waiting() { gHintWaiters.fetch_add(1); }
            ~Waiting() { gHintWaiters.fetch_sub(1); }
        } waiting;
        const auto deadline = std::chrono::steady_clock::now() + barrierTimeout_;
        const unsigned long long sequence = ++sequence_;
        const SentinelWriter writer = writer_;
        lock.unlock();
        const bool written = writer && writer(sequence);
        if (const HANDLE flush = gTraceFlushRequested.load()) SetEvent(flush);
        lock.lock();
        if (written && changed_.wait_until(lock, deadline, [&] { return processed_ >= sequence && checked_ >= sequence; })) return true;
        logLine(L"BARRIER INCOMPLETE sequence=" + std::to_wstring(sequence) + L" written=" + std::to_wstring(written) +
                L" processed=" + std::to_wstring(processed_) + L" checked=" + std::to_wstring(checked_), true);
        return false;
    }

    // The route the hints give now, or none. Without allowDirect only tunnel evidence decides.
    std::optional<bool> decide(const std::wstring& key, bool* reused, bool allowDirect) {
        const auto now = std::chrono::steady_clock::now();
        expire(now);
        const auto found = hints_.find(key);
        if (found == hints_.end()) return std::nullopt;
        auto& pending = found->second;
        if (pending.expires <= now) {
            hints_.erase(found);
            return std::nullopt;
        }
        const bool directAllowed = allowDirect && now >= directBlockedUntil_ && now >= pending.unknownUntil;
        if (pending.answered) {
            // Selected evidence newer than the answered direct decision takes precedence over route
            // reuse: a completed direct query must not finalize a later hint.
            if (pending.tunnel && pending.decision != Decision::Tunnel) {
                pending.answered = false;
                pending.decision = Decision::Tunnel;
                return true;
            }
            if (pending.decision == Decision::Pending || now - pending.answeredAt >= reuseWindow_) {
                // The reusable route has expired, but not the evidence that outlives it: unclaimed or recent
                // selected evidence and the unknown-attribution quarantine stay for their own lifetimes.
                retire(pending, now);
                if (!pending.tunnel && now >= pending.unknownUntil) {
                    hints_.erase(found);
                    return std::nullopt;
                }
                if (pending.tunnel) {
                    pending.decision = Decision::Tunnel;
                    return true;
                }
                return std::nullopt;
            }
            if (pending.decision == Decision::Tunnel || directAllowed) {
                if (reused) *reused = true;
                return pending.decision == Decision::Tunnel;
            }
            return std::nullopt;
        }
        if (pending.tunnel || pending.decision == Decision::Tunnel) {
            pending.decision = Decision::Tunnel;
            return true;
        }
        if (directAllowed && (pending.direct || pending.decision == Decision::Direct)) {
            pending.decision = Decision::Direct;
            return false;
        }
        return std::nullopt;
    }

    // Ends an answered entry's reusable route, keeping what must outlive it: selected evidence no decision has
    // claimed, the provenance of a selected exchange answered within the reuse window, the unknown-attribution
    // quarantine, and the entry's lifetime.
    void retire(Pending& pending, std::chrono::steady_clock::time_point now) {
        Pending next;
        const bool unclaimedTunnel = pending.tunnel && pending.decision != Decision::Tunnel;
        const bool recentSelected = pending.selectedAnswered && now - pending.selectedAnsweredAt < reuseWindow_;
        next.tunnel = unclaimedTunnel || recentSelected;
        next.selected = unclaimedTunnel && pending.selected;
        next.selectedAnswered = recentSelected;
        next.selectedAnsweredAt = pending.selectedAnsweredAt;
        next.unknownUntil = pending.unknownUntil;
        next.generation = pending.generation;
        next.expires = pending.expires;
        pending = next;
    }

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
    std::chrono::steady_clock::time_point directBlockedUntil_{};
    mutable std::mutex includedMutex_;
    std::shared_ptr<const std::unordered_set<std::wstring>> included_;
    std::chrono::milliseconds reuseWindow_;
    std::chrono::milliseconds barrierTimeout_;
    SentinelWriter writer_;
    std::atomic<unsigned long long> sequence_{};
    unsigned long long processed_{};
    unsigned long long checked_{};
    unsigned long long generations_{};
    std::mutex mutex_;
    std::condition_variable changed_;
    std::unordered_map<std::wstring, Pending> hints_;
};

