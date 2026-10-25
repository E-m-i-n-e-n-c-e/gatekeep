#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include <nlohmann/json.hpp>

#include "packet.hpp"
#include "ratelimit.hpp"
#include "rules.hpp"
#include "verdict.hpp"

struct Decision {
    Verdict verdict = Verdict::DropPacket;
    std::string reason;   // policy, domain_blocked, rate_limited, banned, inspecting, ...
    std::string rule_id;  // rule that matched, or "default"
    std::string app;      // tls / http / dns / unknown, once known
    std::string host;     // SNI / Host header / DNS name, once known
    bool log = true;      // false for the many "keep inspecting" packets
    int ban_seconds = 0;  // > 0: this decision banned the source; tell the kernel
};

// Connection identity in the original direction. Replies are accepted by the
// kernel (ct direction reply), so the engine only ever sees this direction.
struct FlowKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t proto;
    bool operator==(const FlowKey& o) const {
        return src_ip == o.src_ip && dst_ip == o.dst_ip && src_port == o.src_port &&
               dst_port == o.dst_port && proto == o.proto;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        uint64_t a = (uint64_t(k.src_ip) << 32) | k.dst_ip;
        uint64_t b = (uint64_t(k.src_port) << 24) | (uint64_t(k.dst_port) << 8) | k.proto;
        return std::hash<uint64_t>()(a ^ (b * 0x9e3779b97f4a7c15ULL));
    }
};

// A flow the engine is still looking at: allowed by the L3/L4 rules but
// waiting for its first payload (TLS ClientHello / HTTP request) or, for
// DNS, inspected packet by packet. Once a flow gets a flow verdict it is
// removed from here and lives only in the kernel.
struct PendingFlow {
    Clock::time_point first_seen, last_seen;
    uint32_t packets = 0;
    std::string rule_id;
    std::string app;
    std::string host;
    bool inspected = false;   // first payload has been classified
    bool per_packet = false;  // DNS: every packet is inspected, never offloaded
};

// The decision engine (slow path). Thread-safe: the packet loop calls
// decide(), the REST API calls everything else.
class Engine {
public:
    explicit Engine(Policy policy);

    Decision decide(const Packet& p);
    void count_malformed();

    // Control plane. Policy changes clear the pending-flow table; the caller
    // must also flush kernel conntrack so cached flow verdicts are re-evaluated.
    nlohmann::json policy_json();
    void replace_policy(Policy p);
    void add_rule(Rule r, std::optional<size_t> position);  // throws on duplicate id
    bool remove_rule(const std::string& id);
    void add_domain(const std::string& domain);
    bool remove_domain(const std::string& domain);

    bool fast_path() const { return fast_path_; }
    void set_fast_path(bool on);

    bool unban(uint32_t ip);
    nlohmann::json bans();
    nlohmann::json pending_flows();
    nlohmann::json events(size_t limit);
    nlohmann::json stats();
    std::string prometheus_metrics();

    // Expire idle pending flows, bans and rate-limiter state.
    void gc();

private:
    Decision decide_new(const Packet& p, const FlowKey& key, Clock::time_point now);
    Decision decide_pending(const Packet& p, const FlowKey& key, PendingFlow& f);
    Decision inspect_dns(const Packet& p, const PendingFlow& f);
    Decision release(const FlowKey& key, PendingFlow& f, const std::string& reason);
    void record(const Packet& p, const Decision& d);
    void policy_changed();

    std::mutex mu_;
    Policy policy_;
    RateLimiter limiter_;
    std::unordered_map<FlowKey, PendingFlow, FlowKeyHash> pending_;
    std::unordered_map<uint32_t, Clock::time_point> bans_;  // ip -> expiry
    std::deque<nlohmann::json> events_;
    std::map<std::string, uint64_t> decisions_;  // "verdict|reason" -> count
    uint64_t packets_ = 0;
    uint64_t new_flows_ = 0;
    uint64_t malformed_ = 0;
    std::atomic<bool> fast_path_{true};

    static constexpr size_t kMaxPending = 65536;
    static constexpr size_t kMaxEvents = 256;
};
