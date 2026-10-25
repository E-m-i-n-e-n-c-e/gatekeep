#include "engine.hpp"

#include <algorithm>
#include <ctime>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include "inspect.hpp"

using nlohmann::json;

namespace {

Decision make(Verdict v, std::string reason, std::string rule_id = "", std::string app = "",
              std::string host = "") {
    Decision d;
    d.verdict = v;
    d.reason = std::move(reason);
    d.rule_id = std::move(rule_id);
    d.app = std::move(app);
    d.host = std::move(host);
    return d;
}

std::string utc_timestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S", &tm);
    char out[40];
    std::snprintf(out, sizeof out, "%s.%03dZ", buf, int(ms));
    return out;
}

constexpr auto kPendingIdle = std::chrono::seconds(60);

}  // namespace

Engine::Engine(Policy policy) : policy_(std::move(policy)) {}

// ─── Data plane (slow path) ──────────────────────────────────────────────────

Decision Engine::decide(const Packet& p) {
    const auto now = Clock::now();
    std::lock_guard<std::mutex> lock(mu_);
    packets_++;

    const FlowKey key{p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.proto};
    Decision d;
    auto it = pending_.find(key);
    if (it == pending_.end()) {
        d = decide_new(p, key, now);
    } else {
        it->second.last_seen = now;
        d = decide_pending(p, key, it->second);
    }

    decisions_[std::string(verdict_name(d.verdict)) + "|" + d.reason]++;
    if (d.log) record(p, d);
    return d;
}

// First packet the engine sees for a connection.
Decision Engine::decide_new(const Packet& p, const FlowKey& key, Clock::time_point now) {
    new_flows_++;

    // 1. Banned sources. The kernel drops these via the @banned set; this
    //    catches the packets already queued when the ban was added.
    auto ban = bans_.find(p.src_ip);
    if (ban != bans_.end() && ban->second > now) {
        Decision d = make(Verdict::DropPacket, "banned");
        d.log = false;
        return d;
    }

    // 2. Per-source rate limit on new flows. Drop the packet without caching
    //    anything, so the client's retry is judged again later.
    switch (limiter_.check(p.src_ip, policy_.rate_limit, now)) {
        case RateLimiter::Result::Allowed:
            break;
        case RateLimiter::Result::Limited: {
            Decision d = make(Verdict::DropPacket, "rate_limited");
            d.log = false;  // could be thousands per second during a flood
            return d;
        }
        case RateLimiter::Result::Ban: {
            bans_[p.src_ip] = now + std::chrono::seconds(policy_.rate_limit.ban_seconds);
            Decision d = make(Verdict::DropPacket, "rate_limit_ban");
            d.ban_seconds = policy_.rate_limit.ban_seconds;
            return d;
        }
    }

    // 3. L3/L4 rules, first match wins.
    Rule* rule = policy_.match(p);
    const Action action = rule ? rule->action : policy_.default_action;
    const std::string rule_id = rule ? rule->id : "default";
    if (rule) rule->hits++;
    if (action == Action::Drop) return make(Verdict::DropFlow, "policy", rule_id);
    if (action == Action::Reject) return make(Verdict::RejectFlow, "policy", rule_id);

    // 4. Allowed. Decide whether the flow needs L7 inspection before it can
    //    be offloaded: DNS is checked per query, TCP waits for its first
    //    payload when there are domains to block. Everything else goes
    //    straight to the fast path.
    const bool dns = p.proto == ipproto::UDP && p.dst_port == 53;
    const bool inspect_tcp = p.proto == ipproto::TCP && !policy_.blocked_domains.empty();
    if (!dns && !inspect_tcp && fast_path_) return make(Verdict::AllowFlow, "policy", rule_id);

    // Fail closed if an attacker fills the table with flows that never send data.
    if (pending_.size() >= kMaxPending) return make(Verdict::DropPacket, "flow_table_full", rule_id);

    PendingFlow& f = pending_[key];
    f.first_seen = f.last_seen = now;
    f.rule_id = rule_id;
    f.per_packet = dns;
    f.app = dns ? "dns" : "";
    f.inspected = !dns && !inspect_tcp;  // nothing to inspect; only reached with the fast path off
    return decide_pending(p, key, f);
}

// A packet of a flow that is still being inspected.
Decision Engine::decide_pending(const Packet& p, const FlowKey& key, PendingFlow& f) {
    f.packets++;
    if (f.per_packet) return inspect_dns(p, f);
    if (f.inspected) return release(key, f, "policy");

    // Closed before sending any data (e.g. a port scan): stop tracking it.
    if (p.payload_len == 0 && (p.tcp_flags & (tcpflag::RST | tcpflag::FIN))) {
        pending_.erase(key);
        Decision d = make(Verdict::AllowPacket, "closed");
        d.log = false;
        return d;
    }

    // TCP handshake packets carry no payload: let them through and wait.
    if (p.payload_len > 0) {
        f.inspected = true;
        const AppInfo info = inspect_tcp_payload(p.payload, p.payload_len);
        f.app = app_name(info.app);
        f.host = info.host;
        if (!f.host.empty() && policy_.domain_blocked(f.host)) {
            Decision d = make(Verdict::RejectFlow, "domain_blocked", f.rule_id, f.app, f.host);
            pending_.erase(key);  // `f` is gone after this line
            return d;
        }
        return release(key, f, "inspected");
    }
    if (f.packets >= uint32_t(policy_.max_inspect_packets)) {
        f.inspected = true;
        return release(key, f, "inspect_limit");
    }
    Decision d = make(Verdict::AllowPacket, "inspecting", f.rule_id);
    d.log = false;
    return d;
}

Decision Engine::inspect_dns(const Packet& p, const PendingFlow& f) {
    const std::string name = dns_query_name(p.payload, p.payload_len);
    if (!name.empty() && policy_.domain_blocked(name))
        return make(Verdict::RejectPacket, "domain_blocked", f.rule_id, "dns", name);
    return make(Verdict::AllowPacket, "policy", f.rule_id, "dns", name);
}

// The flow passed inspection. With the fast path on, hand it to the kernel
// for good; with it off (benchmark mode), keep accepting packet by packet.
Decision Engine::release(const FlowKey& key, PendingFlow& f, const std::string& reason) {
    Decision d = make(fast_path_ ? Verdict::AllowFlow : Verdict::AllowPacket, reason, f.rule_id, f.app, f.host);
    if (fast_path_) {
        pending_.erase(key);
    } else {
        d.log = f.packets == 1 || reason != "policy";  // log once, not every packet
    }
    return d;
}

void Engine::count_malformed() {
    std::lock_guard<std::mutex> lock(mu_);
    packets_++;
    malformed_++;
    decisions_["drop_packet|malformed"]++;
}

void Engine::record(const Packet& p, const Decision& d) {
    json e{
        {"ts", utc_timestamp()},
        {"verdict", verdict_name(d.verdict)},
        {"reason", d.reason},
        {"proto", proto_name(p.proto)},
        {"src", ip_to_string(p.src_ip)},
        {"dst", ip_to_string(p.dst_ip)},
    };
    if (p.proto == ipproto::TCP || p.proto == ipproto::UDP) {
        e["src_port"] = p.src_port;
        e["dst_port"] = p.dst_port;
    }
    if (!d.rule_id.empty()) e["rule"] = d.rule_id;
    if (!d.app.empty()) e["app"] = d.app;
    if (!d.host.empty()) e["host"] = d.host;
    if (d.ban_seconds) e["ban_seconds"] = d.ban_seconds;

    std::cout << e.dump() << '\n';
    events_.push_back(std::move(e));
    if (events_.size() > kMaxEvents) events_.pop_front();
}

// ─── Control plane ───────────────────────────────────────────────────────────

void Engine::policy_changed() { pending_.clear(); }

json Engine::policy_json() {
    std::lock_guard<std::mutex> lock(mu_);
    return policy_to_json(policy_);
}

void Engine::replace_policy(Policy p) {
    std::lock_guard<std::mutex> lock(mu_);
    policy_ = std::move(p);
    policy_changed();
}

void Engine::add_rule(Rule r, std::optional<size_t> position) {
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto& existing : policy_.rules)
        if (existing.id == r.id) throw std::runtime_error("rule id '" + r.id + "' already exists");
    const size_t at = std::min(position.value_or(policy_.rules.size()), policy_.rules.size());
    policy_.rules.insert(policy_.rules.begin() + long(at), std::move(r));
    policy_changed();
}

bool Engine::remove_rule(const std::string& id) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = std::find_if(policy_.rules.begin(), policy_.rules.end(), [&](const Rule& r) { return r.id == id; });
    if (it == policy_.rules.end()) return false;
    policy_.rules.erase(it);
    policy_changed();
    return true;
}

void Engine::add_domain(const std::string& domain) {
    const std::string d = normalize_host(domain);
    if (d.empty()) throw std::runtime_error("domain is empty");
    std::lock_guard<std::mutex> lock(mu_);
    auto& list = policy_.blocked_domains;
    if (std::find(list.begin(), list.end(), d) == list.end()) list.push_back(d);
    policy_changed();
}

bool Engine::remove_domain(const std::string& domain) {
    const std::string d = normalize_host(domain);
    std::lock_guard<std::mutex> lock(mu_);
    auto& list = policy_.blocked_domains;
    auto it = std::find(list.begin(), list.end(), d);
    if (it == list.end()) return false;
    list.erase(it);
    policy_changed();
    return true;
}

void Engine::set_fast_path(bool on) {
    std::lock_guard<std::mutex> lock(mu_);
    fast_path_ = on;
    policy_changed();
}

bool Engine::unban(uint32_t ip) {
    std::lock_guard<std::mutex> lock(mu_);
    return bans_.erase(ip) > 0;
}

json Engine::bans() {
    const auto now = Clock::now();
    std::lock_guard<std::mutex> lock(mu_);
    json out = json::array();
    for (const auto& [ip, expiry] : bans_) {
        if (expiry <= now) continue;
        out.push_back({{"ip", ip_to_string(ip)},
                       {"expires_in_s", std::chrono::duration_cast<std::chrono::seconds>(expiry - now).count()}});
    }
    return out;
}

json Engine::pending_flows() {
    const auto now = Clock::now();
    std::lock_guard<std::mutex> lock(mu_);
    json out = json::array();
    for (const auto& [k, f] : pending_) {
        out.push_back({{"proto", proto_name(k.proto)},
                       {"src", ip_to_string(k.src_ip) + ":" + std::to_string(k.src_port)},
                       {"dst", ip_to_string(k.dst_ip) + ":" + std::to_string(k.dst_port)},
                       {"packets", f.packets},
                       {"app", f.app},
                       {"host", f.host},
                       {"rule", f.rule_id},
                       {"age_s", std::chrono::duration_cast<std::chrono::seconds>(now - f.first_seen).count()}});
    }
    return out;
}

json Engine::events(size_t limit) {
    std::lock_guard<std::mutex> lock(mu_);
    const size_t n = std::min(limit, events_.size());
    return json(std::vector<json>(events_.end() - long(n), events_.end()));
}

json Engine::stats() {
    std::lock_guard<std::mutex> lock(mu_);
    json decisions = json::object();
    for (const auto& [key, count] : decisions_) decisions[key] = count;
    json hits = json::object();
    for (const auto& r : policy_.rules) hits[r.id] = r.hits;
    return {
        {"fast_path", fast_path_.load()},
        {"packets_inspected", packets_},
        {"new_flows", new_flows_},
        {"malformed", malformed_},
        {"pending_flows", pending_.size()},
        {"active_bans", bans_.size()},
        {"tracked_sources", limiter_.size()},
        {"decisions", decisions},
        {"rule_hits", hits},
    };
}

std::string Engine::prometheus_metrics() {
    std::lock_guard<std::mutex> lock(mu_);
    std::ostringstream m;
    auto metric = [&](const char* name, const char* type, const char* help) {
        m << "# HELP " << name << ' ' << help << "\n# TYPE " << name << ' ' << type << '\n';
    };

    metric("gatekeep_packets_inspected_total", "counter", "Packets delivered to the userspace engine.");
    m << "gatekeep_packets_inspected_total " << packets_ << '\n';
    metric("gatekeep_new_flows_total", "counter", "Connections seen for the first time.");
    m << "gatekeep_new_flows_total " << new_flows_ << '\n';
    metric("gatekeep_decisions_total", "counter", "Verdicts by type and reason.");
    for (const auto& [key, count] : decisions_) {
        const size_t bar = key.find('|');
        m << "gatekeep_decisions_total{verdict=\"" << key.substr(0, bar) << "\",reason=\""
          << key.substr(bar + 1) << "\"} " << count << '\n';
    }
    metric("gatekeep_rule_hits_total", "counter", "New flows matched per rule.");
    for (const auto& r : policy_.rules) m << "gatekeep_rule_hits_total{rule=\"" << r.id << "\"} " << r.hits << '\n';
    metric("gatekeep_pending_flows", "gauge", "Flows waiting for L7 inspection.");
    m << "gatekeep_pending_flows " << pending_.size() << '\n';
    metric("gatekeep_active_bans", "gauge", "Source IPs currently banned.");
    m << "gatekeep_active_bans " << bans_.size() << '\n';
    metric("gatekeep_fast_path_enabled", "gauge", "1 if allowed flows are offloaded to the kernel.");
    m << "gatekeep_fast_path_enabled " << (fast_path_ ? 1 : 0) << '\n';
    return m.str();
}

void Engine::gc() {
    const auto now = Clock::now();
    std::lock_guard<std::mutex> lock(mu_);
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (now - it->second.last_seen > kPendingIdle) it = pending_.erase(it);
        else ++it;
    }
    for (auto it = bans_.begin(); it != bans_.end();) {
        if (it->second <= now) it = bans_.erase(it);
        else ++it;
    }
    limiter_.gc(now, std::chrono::seconds(60));
}
