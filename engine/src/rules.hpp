#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "packet.hpp"

enum class Action { Allow, Drop, Reject };

const char* action_name(Action a);

struct Cidr {
    uint32_t network = 0;
    uint32_t mask = 0;
    int prefix = 0;

    bool contains(uint32_t ip) const { return (ip & mask) == network; }
    std::string str() const;
    static Cidr parse(const std::string& text);  // "10.0.0.0/8" or "10.1.2.3"
};

struct PortRange {
    uint16_t lo = 0;
    uint16_t hi = 0;
    bool contains(uint16_t port) const { return port >= lo && port <= hi; }
};

// "80", "8000-8100", "80,443,8000-8100"
std::vector<PortRange> parse_ports(const std::string& spec);
std::string ports_to_string(const std::vector<PortRange>& ports);

// One line of the rule table. Unset fields match anything.
struct Rule {
    std::string id;
    Action action = Action::Drop;
    uint8_t proto = 0;  // 0 = any
    std::optional<Cidr> src;
    std::optional<Cidr> dst;
    std::vector<PortRange> dst_ports;  // empty = any; only matches TCP/UDP when set
    uint64_t hits = 0;

    bool matches(const Packet& p) const;
};

struct RateLimit {
    double new_flows_per_sec = 50;  // token refill rate, per source IP
    double burst = 100;             // bucket size
    int ban_after = 200;            // rate-limited packets before the source is banned
    int ban_seconds = 30;
};

struct Policy {
    Action default_action = Action::Drop;
    std::vector<Rule> rules;                  // evaluated top to bottom, first match wins
    std::vector<std::string> blocked_domains;  // matched against SNI, HTTP Host, DNS queries
    RateLimit rate_limit;
    int max_inspect_packets = 8;  // give up waiting for a TCP payload after this many packets

    // First matching rule, or nullptr (then default_action applies).
    Rule* match(const Packet& p);
    bool domain_blocked(const std::string& host) const;
};

// JSON <-> policy. Parsing throws std::runtime_error with a readable message,
// including for unknown keys, so a typo in a rule is an error, not a silent no-op.
Policy policy_from_json(const nlohmann::json& j);
Rule rule_from_json(const nlohmann::json& j);
nlohmann::json policy_to_json(const Policy& p);
nlohmann::json rule_to_json(const Rule& r);
Policy load_policy_file(const std::string& path);
