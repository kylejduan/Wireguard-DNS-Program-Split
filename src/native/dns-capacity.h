// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <atomic>

// The reservation is held only while an upstream exchange is outstanding, not
// while reading a TCP client or classifying a query. Excess work fails promptly.
// This isolates slow tunnel exchanges; global ingress admission remains shared.
class ExchangeLimit {
public:
    explicit ExchangeLimit(unsigned maximum) : maximum_(maximum) {}
    ExchangeLimit(const ExchangeLimit&) = delete;
    ExchangeLimit& operator=(const ExchangeLimit&) = delete;

    class Lease {
    public:
        explicit Lease(ExchangeLimit* limit) : limit_(limit) {
            if (!limit_) { allowed_ = true; return; }
            unsigned active = limit_->active_.load(std::memory_order_relaxed);
            while (active < limit_->maximum_) {
                if (limit_->active_.compare_exchange_weak(active, active + 1, std::memory_order_relaxed)) {
                    allowed_ = true;
                    return;
                }
            }
        }
        ~Lease() {
            if (limit_ && allowed_) limit_->active_.fetch_sub(1, std::memory_order_relaxed);
        }
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        explicit operator bool() const { return allowed_; }
    private:
        ExchangeLimit* limit_;
        bool allowed_{};
    };

    unsigned active() const { return active_.load(std::memory_order_relaxed); }

private:
    const unsigned maximum_;
    std::atomic_uint active_{};
};
