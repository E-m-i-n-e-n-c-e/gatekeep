#include "rules.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>

#include "inspect.hpp"

using nlohmann::json;

namespace {

[[noreturn]] void fail(const std::string& msg) { throw std::runtime_error(msg); }

// Strict unsigned parse: the whole string must be digits and <= max.
unsigned long parse_uint(const std::string& text, unsigned long max, const std::string& what) {
    if (text.empty() || !std::all_of(text.begin(), text.end(), ::isdigit) || text.size() > 10)
        fail("invalid " + what + ": '" + text + "'");
    const unsigned long value = std::stoul(text);
    if (value > max) fail(what + " out of range: " + text);
    return value;
}

std::string trim(const std::string& s) {
    const size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return "";
    const size_t b = s.find_last_not_of(" \t");
    return s.substr(a, b - a + 1);
}

Action parse_action(const std::string& s) {
    if (s == "allow") return Action::Allow;
    if (s == "drop") return Action::Drop;
    if (s == "reject") return Action::Reject;
    fail("action must be allow, drop or reject, got '" + s + "'");
}

uint8_t parse_proto(const std::string& s) {
    if (s == "any") return 0;
    if (s == "tcp") return ipproto::TCP;
    if (s == "udp") return ipproto::UDP;
    if (s == "icmp") return ipproto::ICMP;
    fail("proto must be tcp, udp, icmp or any, got '" + s + "'");
}

void reject_unknown_keys(const json& j, const std::set<std::string>& allowed, const std::string& where) {
    if (!j.is_object()) fail(where + " must be a JSON object");
    for (const auto& item : j.items())
        if (!allowed.count(item.key())) fail("unknown key '" + item.key() + "' in " + where);
}

std::string get_string(const json& j, const char* key) {
    if (!j.at(key).is_string()) fail(std::string("'") + key + "' must be a string");
    return j.at(key).get<std::string>();
}

}  // namespace

const char* action_name(Action a) {
    switch (a) {
        case Action::Allow: return "allow";
        case Action::Drop: return "drop";
        default: return "reject";
    }
}

Cidr Cidr::parse(const std::string& text) {
    const size_t slash = text.find('/');
    const std::string ip_part = text.substr(0, slash);
    const int prefix = slash == std::string::npos
                           ? 32
                           : int(parse_uint(text.substr(slash + 1), 32, "CIDR prefix"));
    uint32_t ip = 0;
    if (!parse_ip(ip_part, ip)) fail("invalid IPv4 address: '" + text + "'");

    Cidr c;
    c.prefix = prefix;
    c.mask = prefix == 0 ? 0 : 0xffffffffu << (32 - prefix);  // shifting by 32 is undefined
    c.network = ip & c.mask;
    return c;
}

std::string Cidr::str() const { return ip_to_string(network) + "/" + std::to_string(prefix); }

std::vector<PortRange> parse_ports(const std::string& spec) {
    std::vector<PortRange> out;
    std::stringstream ss(spec);
    std::string part;
    while (std::getline(ss, part, ',')) {
        part = trim(part);
        const size_t dash = part.find('-');
        PortRange r;
        if (dash == std::string::npos) {
            r.lo = r.hi = uint16_t(parse_uint(part, 65535, "port"));
        } else {
            r.lo = uint16_t(parse_uint(trim(part.substr(0, dash)), 65535, "port"));
            r.hi = uint16_t(parse_uint(trim(part.substr(dash + 1)), 65535, "port"));
            if (r.lo > r.hi) fail("port range is backwards: " + part);
        }
        out.push_back(r);
    }
    if (out.empty()) fail("empty port list");
    return out;
}

std::string ports_to_string(const std::vector<PortRange>& ports) {
    std::string s;
    for (const auto& r : ports) {
        if (!s.empty()) s += ",";
        s += std::to_string(r.lo);
        if (r.hi != r.lo) s += "-" + std::to_string(r.hi);
    }
    return s;
}

bool Rule::matches(const Packet& p) const {
    if (proto != 0 && p.proto != proto) return false;
    if (src && !src->contains(p.src_ip)) return false;
    if (dst && !dst->contains(p.dst_ip)) return false;
    if (!dst_ports.empty()) {
        if (p.proto != ipproto::TCP && p.proto != ipproto::UDP) return false;
        const bool hit = std::any_of(dst_ports.begin(), dst_ports.end(),
                                     [&](const PortRange& r) { return r.contains(p.dst_port); });
        if (!hit) return false;
    }
    return true;
}

Rule* Policy::match(const Packet& p) {
    for (auto& rule : rules)
        if (rule.matches(p)) return &rule;
    return nullptr;
}

bool Policy::domain_blocked(const std::string& host) const {
    return std::any_of(blocked_domains.begin(), blocked_domains.end(),
                       [&](const std::string& d) { return domain_matches(host, d); });
}

Rule rule_from_json(const json& j) {
    reject_unknown_keys(j, {"id", "action", "proto", "src", "dst", "dst_ports", "hits"}, "rule");
    if (!j.contains("id") || !j.contains("action")) fail("a rule needs 'id' and 'action'");

    Rule r;
    r.id = get_string(j, "id");
    if (r.id.empty() || r.id.size() > 64 ||
        !std::all_of(r.id.begin(), r.id.end(), [](char c) { return std::isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.'; }))
        fail("rule id must be 1-64 chars of [A-Za-z0-9._-]");
    r.action = parse_action(get_string(j, "action"));
    if (j.contains("proto")) r.proto = parse_proto(get_string(j, "proto"));
    if (j.contains("src")) r.src = Cidr::parse(get_string(j, "src"));
    if (j.contains("dst")) r.dst = Cidr::parse(get_string(j, "dst"));
    if (j.contains("dst_ports")) {
        const json& ports = j.at("dst_ports");
        r.dst_ports = parse_ports(ports.is_number_integer() ? std::to_string(ports.get<int>())
                                                            : get_string(j, "dst_ports"));
        if (r.proto != ipproto::TCP && r.proto != ipproto::UDP)
            fail("rule '" + r.id + "': dst_ports needs proto tcp or udp");
    }
    return r;
}

Policy policy_from_json(const json& j) {
    reject_unknown_keys(j, {"default_action", "rules", "blocked_domains", "rate_limit", "max_inspect_packets"},
                        "policy");
    Policy p;
    if (j.contains("default_action")) p.default_action = parse_action(get_string(j, "default_action"));

    if (j.contains("rules")) {
        if (!j.at("rules").is_array()) fail("'rules' must be an array");
        std::set<std::string> ids;
        for (const auto& rj : j.at("rules")) {
            Rule r = rule_from_json(rj);
            if (!ids.insert(r.id).second) fail("duplicate rule id '" + r.id + "'");
            p.rules.push_back(std::move(r));
        }
    }

    if (j.contains("blocked_domains")) {
        if (!j.at("blocked_domains").is_array()) fail("'blocked_domains' must be an array");
        for (const auto& d : j.at("blocked_domains")) {
            if (!d.is_string()) fail("blocked domains must be strings");
            const std::string domain = normalize_host(d.get<std::string>());
            if (domain.empty()) fail("empty blocked domain");
            p.blocked_domains.push_back(domain);
        }
    }

    if (j.contains("rate_limit")) {
        const json& rl = j.at("rate_limit");
        reject_unknown_keys(rl, {"new_flows_per_sec", "burst", "ban_after", "ban_seconds"}, "rate_limit");
        p.rate_limit.new_flows_per_sec = rl.value("new_flows_per_sec", p.rate_limit.new_flows_per_sec);
        p.rate_limit.burst = rl.value("burst", p.rate_limit.burst);
        p.rate_limit.ban_after = rl.value("ban_after", p.rate_limit.ban_after);
        p.rate_limit.ban_seconds = rl.value("ban_seconds", p.rate_limit.ban_seconds);
        if (p.rate_limit.new_flows_per_sec <= 0 || p.rate_limit.burst < 1 || p.rate_limit.ban_after < 1 ||
            p.rate_limit.ban_seconds < 1)
            fail("rate_limit values must be positive");
    }

    p.max_inspect_packets = j.value("max_inspect_packets", p.max_inspect_packets);
    if (p.max_inspect_packets < 1) fail("max_inspect_packets must be >= 1");
    return p;
}

json rule_to_json(const Rule& r) {
    json j{{"id", r.id}, {"action", action_name(r.action)}, {"hits", r.hits}};
    if (r.proto) j["proto"] = proto_name(r.proto);
    if (r.src) j["src"] = r.src->str();
    if (r.dst) j["dst"] = r.dst->str();
    if (!r.dst_ports.empty()) j["dst_ports"] = ports_to_string(r.dst_ports);
    return j;
}

json policy_to_json(const Policy& p) {
    json rules = json::array();
    for (const auto& r : p.rules) rules.push_back(rule_to_json(r));
    return {
        {"default_action", action_name(p.default_action)},
        {"rules", rules},
        {"blocked_domains", p.blocked_domains},
        {"rate_limit",
         {{"new_flows_per_sec", p.rate_limit.new_flows_per_sec},
          {"burst", p.rate_limit.burst},
          {"ban_after", p.rate_limit.ban_after},
          {"ban_seconds", p.rate_limit.ban_seconds}}},
        {"max_inspect_packets", p.max_inspect_packets},
    };
}

Policy load_policy_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) fail("cannot open policy file " + path);
    json j;
    try {
        in >> j;
    } catch (const json::exception& e) {
        fail("policy file " + path + " is not valid JSON: " + e.what());
    }
    return policy_from_json(j);
}
