#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <unordered_map>

#include "rules.hpp"

using Clock = std::chrono::steady_clock;

// Classic token bucket: holds up to `burst` tokens, refills at `rate` per
// second, and each new flow costs one token. Allows short bursts while
// capping the sustained rate.
struct TokenBucket {
    double tokens = -1;  // < 0 means "not started yet": begin full
    Clock::time_point last;

    bool take(double rate, double burst, Clock::time_point now) {
        if (tokens < 0) {
            tokens = burst;
        } else {
            const double elapsed = std::chrono::duration<double>(now - last).count();
            tokens = std::min(burst, tokens + elapsed * rate);
        }
        last = now;
        if (tokens < 1) return false;
        tokens -= 1;
        return true;
    }
};

// Per-source-IP new-flow limiter. A source that keeps hitting the limit
// (`ban_after` rejected attempts) is reported as one to ban.
class RateLimiter {
public:
    enum class Result { Allowed, Limited, Ban };

    Result check(uint32_t src_ip, const RateLimit& cfg, Clock::time_point now) {
        Source& s = sources_[src_ip];
        if (s.bucket.take(cfg.new_flows_per_sec, cfg.burst, now)) return Result::Allowed;
        if (++s.strikes >= cfg.ban_after) {
            s.strikes = 0;
            return Result::Ban;
        }
        return Result::Limited;
    }

    // Forget sources that have been quiet long enough to have a full bucket again.
    void gc(Clock::time_point now, std::chrono::seconds idle) {
        for (auto it = sources_.begin(); it != sources_.end();) {
            if (now - it->second.bucket.last > idle) it = sources_.erase(it);
            else ++it;
        }
    }

    size_t size() const { return sources_.size(); }

private:
    struct Source {
        TokenBucket bucket;
        int strikes = 0;
    };
    std::unordered_map<uint32_t, Source> sources_;
};
