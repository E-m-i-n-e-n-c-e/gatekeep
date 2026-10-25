// Unit tests for the parsers, rules and decision engine. No framework: each
// CHECK prints a failure and the binary exits non-zero if any failed.
// Run as part of the Docker build, so a broken engine never gets an image.

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "engine.hpp"
#include "inspect.hpp"
#include "packet.hpp"
#include "rules.hpp"

namespace {

int failures = 0;
int checks = 0;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        checks++;                                                                      \
        if (!(cond)) {                                                                 \
            failures++;                                                                \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond "\n"; \
        }                                                                              \
    } while (0)

using Bytes = std::vector<uint8_t>;

void put16(Bytes& b, uint16_t v) {
    b.push_back(uint8_t(v >> 8));
    b.push_back(uint8_t(v));
}
void put32(Bytes& b, uint32_t v) {
    put16(b, uint16_t(v >> 16));
    put16(b, uint16_t(v));
}
void append(Bytes& b, const Bytes& more) { b.insert(b.end(), more.begin(), more.end()); }
void append(Bytes& b, const std::string& s) { b.insert(b.end(), s.begin(), s.end()); }

uint32_t ip(const char* text) {
    uint32_t v = 0;
    parse_ip(text, v);
    return v;
}

// Builds a raw IPv4 packet the way it arrives from NFQUEUE.
Bytes ipv4(uint8_t proto, const char* src, const char* dst, uint16_t sport, uint16_t dport,
           uint8_t tcp_flags = 0, const Bytes& payload = {}) {
    Bytes l4;
    if (proto == ipproto::TCP) {
        put16(l4, sport);
        put16(l4, dport);
        put32(l4, 1);  // seq
        put32(l4, 0);  // ack
        l4.push_back(5 << 4);  // data offset = 5 words
        l4.push_back(tcp_flags);
        put16(l4, 65535);  // window
        put32(l4, 0);      // checksum + urgent pointer
    } else if (proto == ipproto::UDP) {
        put16(l4, sport);
        put16(l4, dport);
        put16(l4, uint16_t(8 + payload.size()));
        put16(l4, 0);
    }
    append(l4, payload);

    Bytes p;
    p.push_back(0x45);  // version 4, IHL 5
    p.push_back(0);
    put16(p, uint16_t(20 + l4.size()));
    put32(p, 0);  // id, flags, fragment offset
    p.push_back(64);
    p.push_back(proto);
    put16(p, 0);
    put32(p, ip(src));
    put32(p, ip(dst));
    append(p, l4);
    return p;
}

Bytes client_hello(const std::string& sni) {
    Bytes body;
    put16(body, 0x0303);                   // legacy_version
    body.insert(body.end(), 32, 0xab);     // random
    body.push_back(32);                    // session id
    body.insert(body.end(), 32, 0xcd);
    put16(body, 4);                        // cipher suites
    put16(body, 0x1301);
    put16(body, 0x1302);
    body.push_back(1);                     // compression methods
    body.push_back(0);

    Bytes ext;
    put16(ext, 0x002b);  // supported_versions first, so the parser must skip it
    put16(ext, 3);
    ext.push_back(2);
    put16(ext, 0x0304);
    Bytes sn;
    put16(sn, uint16_t(sni.size() + 3));
    sn.push_back(0);  // host_name
    put16(sn, uint16_t(sni.size()));
    append(sn, sni);
    put16(ext, 0x0000);  // server_name
    put16(ext, uint16_t(sn.size()));
    append(ext, sn);
    put16(body, uint16_t(ext.size()));
    append(body, ext);

    Bytes hs{0x01, uint8_t(body.size() >> 16), uint8_t(body.size() >> 8), uint8_t(body.size())};
    append(hs, body);
    Bytes rec{0x16, 0x03, 0x01};
    put16(rec, uint16_t(hs.size()));
    append(rec, hs);
    return rec;
}

Bytes dns_query(const std::string& name) {
    Bytes q;
    put16(q, 0x1234);  // id
    put16(q, 0x0100);  // flags: standard query, recursion desired
    put16(q, 1);       // qdcount
    put16(q, 0);
    put16(q, 0);
    put16(q, 0);
    size_t start = 0;
    while (start <= name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) dot = name.size();
        q.push_back(uint8_t(dot - start));
        append(q, name.substr(start, dot - start));
        start = dot + 1;
    }
    q.push_back(0);
    put16(q, 1);  // A
    put16(q, 1);  // IN
    return q;
}

Packet parse(const Bytes& b) {
    Packet p;
    if (!parse_ipv4(b.data(), b.size(), p)) throw std::runtime_error("test packet did not parse");
    return p;
}

Policy test_policy() {
    return policy_from_json(nlohmann::json::parse(R"({
        "default_action": "drop",
        "rules": [
            {"id": "block-host", "action": "drop", "src": "10.0.1.66"},
            {"id": "reject-telnet", "action": "reject", "proto": "tcp", "dst_ports": "23"},
            {"id": "allow-dns", "action": "allow", "proto": "udp", "dst_ports": 53},
            {"id": "allow-web", "action": "allow", "proto": "tcp", "dst": "10.0.2.0/24", "dst_ports": "80,443,8000-8100"},
            {"id": "allow-ping", "action": "allow", "proto": "icmp"}
        ],
        "blocked_domains": ["evil.test"],
        "rate_limit": {"new_flows_per_sec": 1, "burst": 3, "ban_after": 2, "ban_seconds": 10}
    })"));
}

// Same policy with a rate limit high enough not to interfere.
Policy relaxed_policy() {
    Policy p = test_policy();
    p.rate_limit.burst = 1000;
    return p;
}

void test_packet_parsing() {
    const Bytes raw = ipv4(ipproto::TCP, "10.0.1.10", "10.0.2.10", 40000, 443, tcpflag::SYN);
    Packet p = parse(raw);
    CHECK(p.proto == ipproto::TCP);
    CHECK(p.src_ip == ip("10.0.1.10"));
    CHECK(p.dst_port == 443);
    CHECK(p.tcp_flags == tcpflag::SYN);
    CHECK(p.payload_len == 0);

    Packet q;
    CHECK(!parse_ipv4(raw.data(), 10, q));  // shorter than an IP header
    Bytes bad_version = raw;
    bad_version[0] = 0x65;
    CHECK(!parse_ipv4(bad_version.data(), bad_version.size(), q));
    Bytes fragment = raw;
    fragment[7] = 0x10;  // fragment offset != 0
    CHECK(!parse_ipv4(fragment.data(), fragment.size(), q));
    Bytes bad_offset = raw;
    bad_offset[20 + 12] = 0xf0;  // TCP data offset 60 > packet
    CHECK(!parse_ipv4(bad_offset.data(), bad_offset.size(), q));

    // Truncated copy (kernel copied fewer bytes than the IP total length).
    const Bytes big = ipv4(ipproto::TCP, "10.0.1.10", "10.0.2.10", 1, 2, tcpflag::ACK, Bytes(3000, 'x'));
    CHECK(parse_ipv4(big.data(), 1000, q));
    CHECK(q.payload_len == 1000 - 40);
}

void test_tls_sni() {
    const Bytes hello = client_hello("Shop.Example.TEST");
    CHECK(tls_sni(hello.data(), hello.size()) == "shop.example.test");

    // Cut off after the SNI: still found. Cut inside the name: not found.
    const size_t sni_end = hello.size();
    CHECK(tls_sni(hello.data(), sni_end) == "shop.example.test");
    CHECK(tls_sni(hello.data(), sni_end - 3).empty());
    CHECK(tls_sni(hello.data(), 20).empty());

    const Bytes not_tls{0x17, 0x03, 0x03, 0x00, 0x10};
    CHECK(tls_sni(not_tls.data(), not_tls.size()).empty());

    const AppInfo info = inspect_tcp_payload(hello.data(), hello.size());
    CHECK(info.app == App::TLS);
    CHECK(info.host == "shop.example.test");
}

void test_http_and_dns() {
    const std::string req = "GET /x HTTP/1.1\r\nUser-Agent: t\r\nhost:  Evil.test:8080 \r\n\r\n";
    CHECK(http_host(reinterpret_cast<const uint8_t*>(req.data()), req.size()) == "evil.test");
    const std::string no_host = "GET / HTTP/1.0\r\n\r\n";
    const AppInfo info = inspect_tcp_payload(reinterpret_cast<const uint8_t*>(no_host.data()), no_host.size());
    CHECK(info.app == App::HTTP);
    CHECK(info.host.empty());
    const std::string ssh = "SSH-2.0-OpenSSH_9.6\r\n";
    CHECK(inspect_tcp_payload(reinterpret_cast<const uint8_t*>(ssh.data()), ssh.size()).app == App::Unknown);

    const Bytes q = dns_query("ads.Tracker.test");
    CHECK(dns_query_name(q.data(), q.size()) == "ads.tracker.test");
    Bytes response = q;
    response[2] |= 0x80;  // QR = response
    CHECK(dns_query_name(response.data(), response.size()).empty());
    Bytes truncated(q.begin(), q.begin() + 16);
    CHECK(dns_query_name(truncated.data(), truncated.size()).empty());

    CHECK(domain_matches("evil.test", "evil.test"));
    CHECK(domain_matches("a.b.evil.test", "evil.test"));
    CHECK(!domain_matches("notevil.test", "evil.test"));
    CHECK(!domain_matches("test", "evil.test"));
}

void test_rules() {
    const Cidr c = Cidr::parse("10.0.2.77/24");
    CHECK(c.str() == "10.0.2.0/24");
    CHECK(c.contains(ip("10.0.2.1")));
    CHECK(!c.contains(ip("10.0.3.1")));
    CHECK(Cidr::parse("0.0.0.0/0").contains(ip("8.8.8.8")));

    const auto ports = parse_ports("80, 443,8000-8100");
    CHECK(ports.size() == 3);
    CHECK(ports_to_string(ports) == "80,443,8000-8100");

    auto throws = [](const char* text) {
        try {
            policy_from_json(nlohmann::json::parse(text));
        } catch (const std::runtime_error&) {
            return true;
        }
        return false;
    };
    CHECK(throws(R"({"rules": [{"id": "x", "action": "allow", "dport": "80"}]})"));  // typo'd key
    CHECK(throws(R"({"rules": [{"id": "x", "action": "maybe"}]})"));
    CHECK(throws(R"({"rules": [{"id": "x", "action": "allow", "src": "10.0.0.0/33"}]})"));
    CHECK(throws(R"({"rules": [{"id": "x", "action": "allow", "proto": "tcp", "dst_ports": "90-80"}]})"));
    CHECK(throws(R"({"rules": [{"id": "x", "action": "allow", "dst_ports": "80"}]})"));  // ports without proto
    CHECK(throws(R"({"rules": [{"id": "x", "action": "allow"}, {"id": "x", "action": "drop"}]})"));

    Policy p = test_policy();
    CHECK(p.match(parse(ipv4(ipproto::TCP, "10.0.1.66", "10.0.2.10", 1, 80)))->id == "block-host");
    CHECK(p.match(parse(ipv4(ipproto::TCP, "10.0.1.10", "10.0.2.10", 1, 8050)))->id == "allow-web");
    CHECK(p.match(parse(ipv4(ipproto::TCP, "10.0.1.10", "10.0.9.10", 1, 80))) == nullptr);
    CHECK(p.match(parse(ipv4(ipproto::ICMP, "10.0.1.10", "10.0.2.10", 0, 0)))->id == "allow-ping");

    // Round trip through JSON keeps the policy the same.
    const auto j = policy_to_json(p);
    CHECK(policy_to_json(policy_from_json(j)) == j);
}

void test_engine_l4() {
    Engine e(relaxed_policy());
    Decision d = e.decide(parse(ipv4(ipproto::TCP, "10.0.1.10", "10.0.2.10", 40001, 23, tcpflag::SYN)));
    CHECK(d.verdict == Verdict::RejectFlow);
    CHECK(d.rule_id == "reject-telnet");

    d = e.decide(parse(ipv4(ipproto::TCP, "10.0.1.66", "10.0.2.10", 40002, 80, tcpflag::SYN)));
    CHECK(d.verdict == Verdict::DropFlow);

    d = e.decide(parse(ipv4(ipproto::UDP, "10.0.1.10", "10.0.2.10", 40003, 9999)));
    CHECK(d.verdict == Verdict::DropFlow);
    CHECK(d.rule_id == "default");

    d = e.decide(parse(ipv4(ipproto::ICMP, "10.0.1.11", "10.0.2.10", 0, 0)));
    CHECK(d.verdict == Verdict::AllowFlow);
}

void test_engine_inspection() {
    Engine e(relaxed_policy());
    const char* client = "10.0.1.10";

    // Allowed web flow to a good domain: handshake packets are let through
    // one by one, the ClientHello decides, then the flow is offloaded.
    Decision d = e.decide(parse(ipv4(ipproto::TCP, client, "10.0.2.10", 50000, 443, tcpflag::SYN)));
    CHECK(d.verdict == Verdict::AllowPacket);
    d = e.decide(parse(ipv4(ipproto::TCP, client, "10.0.2.10", 50000, 443, tcpflag::ACK)));
    CHECK(d.verdict == Verdict::AllowPacket);
    d = e.decide(parse(ipv4(ipproto::TCP, client, "10.0.2.10", 50000, 443, tcpflag::ACK | tcpflag::PSH,
                            client_hello("shop.test"))));
    CHECK(d.verdict == Verdict::AllowFlow);
    CHECK(d.app == "tls");
    CHECK(d.host == "shop.test");
    CHECK(e.stats()["pending_flows"] == 0);

    // Same thing to a blocked domain (subdomain match), on a non-standard
    // port: identified as TLS by its bytes, not by port 443.
    e.decide(parse(ipv4(ipproto::TCP, client, "10.0.2.10", 50001, 8050, tcpflag::SYN)));
    d = e.decide(parse(ipv4(ipproto::TCP, client, "10.0.2.10", 50001, 8050, tcpflag::ACK | tcpflag::PSH,
                            client_hello("cdn.evil.test"))));
    CHECK(d.verdict == Verdict::RejectFlow);
    CHECK(d.reason == "domain_blocked");

    // HTTP Host header.
    const std::string get = "GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n";
    e.decide(parse(ipv4(ipproto::TCP, client, "10.0.2.10", 50002, 80, tcpflag::SYN)));
    d = e.decide(parse(ipv4(ipproto::TCP, client, "10.0.2.10", 50002, 80, tcpflag::ACK,
                            Bytes(get.begin(), get.end()))));
    CHECK(d.verdict == Verdict::RejectFlow);
    CHECK(d.app == "http");

    // A flow that never sends data is released after max_inspect_packets.
    for (int i = 0; i < 7; i++) e.decide(parse(ipv4(ipproto::TCP, client, "10.0.2.10", 50003, 80, tcpflag::ACK)));
    d = e.decide(parse(ipv4(ipproto::TCP, client, "10.0.2.10", 50003, 80, tcpflag::ACK)));
    CHECK(d.verdict == Verdict::AllowFlow);
    CHECK(d.reason == "inspect_limit");

    // A flow reset before sending data leaves the pending table.
    e.decide(parse(ipv4(ipproto::TCP, client, "10.0.2.10", 50004, 80, tcpflag::SYN)));
    CHECK(e.stats()["pending_flows"] == 1);
    d = e.decide(parse(ipv4(ipproto::TCP, client, "10.0.2.10", 50004, 80, tcpflag::RST)));
    CHECK(d.verdict == Verdict::AllowPacket);
    CHECK(e.stats()["pending_flows"] == 0);

    // DNS: each query is checked, the flow is never offloaded.
    d = e.decide(parse(ipv4(ipproto::UDP, "10.0.1.20", "10.0.2.10", 5353, 53, 0, dns_query("shop.test"))));
    CHECK(d.verdict == Verdict::AllowPacket);
    d = e.decide(parse(ipv4(ipproto::UDP, "10.0.1.20", "10.0.2.10", 5353, 53, 0, dns_query("www.evil.test"))));
    CHECK(d.verdict == Verdict::RejectPacket);
    CHECK(d.host == "www.evil.test");
}

void test_engine_rate_limit_and_ban() {
    Engine e(test_policy());  // burst 3, 1/s, ban after 2 limited attempts
    auto syn = [&](uint16_t sport) {
        return e.decide(parse(ipv4(ipproto::ICMP, "10.0.1.99", "10.0.2.10", sport, 0)));
    };
    CHECK(syn(1).verdict == Verdict::AllowFlow);
    CHECK(syn(2).verdict == Verdict::AllowFlow);
    CHECK(syn(3).verdict == Verdict::AllowFlow);
    Decision d = syn(4);
    CHECK(d.verdict == Verdict::DropPacket);
    CHECK(d.reason == "rate_limited");
    d = syn(5);
    CHECK(d.reason == "rate_limit_ban");
    CHECK(d.ban_seconds == 10);
    CHECK(syn(6).reason == "banned");
    CHECK(e.bans().size() == 1);
    CHECK(e.unban(ip("10.0.1.99")));
    CHECK(e.bans().empty());
}

void test_engine_slow_path_mode() {
    Engine e(test_policy());
    e.replace_policy([] {
        Policy p = test_policy();
        p.blocked_domains.clear();
        return p;
    }());
    e.set_fast_path(false);
    for (int i = 0; i < 5; i++) {
        const Decision d = e.decide(parse(ipv4(ipproto::TCP, "10.0.1.10", "10.0.2.10", 60000, 80, tcpflag::ACK)));
        CHECK(d.verdict == Verdict::AllowPacket);
        CHECK(d.log == (i == 0));
    }
    e.set_fast_path(true);
    CHECK(e.decide(parse(ipv4(ipproto::TCP, "10.0.1.10", "10.0.2.10", 60000, 80, tcpflag::ACK))).verdict ==
          Verdict::AllowFlow);
}

}  // namespace

int main() {
    std::cout.setstate(std::ios::failbit);  // silence the engine's JSON event log
    test_packet_parsing();
    test_tls_sni();
    test_http_and_dns();
    test_rules();
    test_engine_l4();
    test_engine_inspection();
    test_engine_rate_limit_and_ban();
    test_engine_slow_path_mode();
    std::cout.clear();
    std::cout << checks - failures << "/" << checks << " checks passed\n";
    return failures == 0 ? 0 : 1;
}
