#include "packet.hpp"

#include <arpa/inet.h>

bool parse_ipv4(const uint8_t* d, size_t len, Packet& out) {
    // IPv4 header: version+IHL (1), TOS (1), total length (2), id (2),
    // flags+fragment offset (2), TTL (1), protocol (1), checksum (2),
    // source (4), destination (4), then options (IHL > 5).
    if (len < 20) return false;
    const uint8_t version = d[0] >> 4;
    const size_t ihl = size_t(d[0] & 0x0f) * 4;
    if (version != 4 || ihl < 20 || ihl > len) return false;

    const size_t total_len = read_u16(d + 2);
    if (total_len < ihl) return false;
    const size_t available = total_len < len ? total_len : len;

    // Conntrack reassembles fragments before the forward hook, so a
    // non-first fragment here means something odd is going on: refuse it.
    const uint16_t frag_offset = read_u16(d + 6) & 0x1fff;
    if (frag_offset != 0) return false;

    out = Packet{};
    out.proto = d[9];
    out.src_ip = read_u32(d + 12);
    out.dst_ip = read_u32(d + 16);

    const uint8_t* l4 = d + ihl;
    const size_t l4_len = available - ihl;

    if (out.proto == ipproto::TCP) {
        // TCP header: src port (2), dst port (2), seq (4), ack (4),
        // data offset (4 bits) + reserved, flags (1), window (2), ...
        if (l4_len < 20) return false;
        const size_t data_offset = size_t(l4[12] >> 4) * 4;
        if (data_offset < 20 || data_offset > l4_len) return false;
        out.src_port = read_u16(l4);
        out.dst_port = read_u16(l4 + 2);
        out.tcp_flags = l4[13];
        out.payload = l4 + data_offset;
        out.payload_len = l4_len - data_offset;
    } else if (out.proto == ipproto::UDP) {
        // UDP header: src port (2), dst port (2), length (2), checksum (2).
        if (l4_len < 8) return false;
        out.src_port = read_u16(l4);
        out.dst_port = read_u16(l4 + 2);
        out.payload = l4 + 8;
        out.payload_len = l4_len - 8;
    }
    return true;
}

std::string ip_to_string(uint32_t ip) {
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 0xff) + "." +
           std::to_string((ip >> 8) & 0xff) + "." + std::to_string(ip & 0xff);
}

bool parse_ip(const std::string& text, uint32_t& out) {
    in_addr addr{};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1) return false;
    out = ntohl(addr.s_addr);
    return true;
}

std::string proto_name(uint8_t proto) {
    switch (proto) {
        case ipproto::TCP: return "tcp";
        case ipproto::UDP: return "udp";
        case ipproto::ICMP: return "icmp";
        default: return std::to_string(proto);
    }
}
