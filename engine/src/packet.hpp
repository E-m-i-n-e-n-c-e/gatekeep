#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// IP protocol numbers (the "protocol" byte of the IPv4 header).
namespace ipproto {
constexpr uint8_t ICMP = 1;
constexpr uint8_t TCP = 6;
constexpr uint8_t UDP = 17;
}  // namespace ipproto

// TCP flag bits (byte 13 of the TCP header).
namespace tcpflag {
constexpr uint8_t FIN = 0x01;
constexpr uint8_t SYN = 0x02;
constexpr uint8_t RST = 0x04;
constexpr uint8_t PSH = 0x08;
constexpr uint8_t ACK = 0x10;
}  // namespace tcpflag

// The fields of a packet the firewall cares about. Addresses and ports are in
// host byte order. `payload` points into the original buffer (no copy).
struct Packet {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t proto = 0;
    uint8_t tcp_flags = 0;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
};

// Parses an IPv4 packet with its TCP/UDP header. Returns false for anything
// malformed. `len` may be shorter than the IP total length when the kernel
// only copied the first N bytes to userspace; the payload is then truncated.
bool parse_ipv4(const uint8_t* data, size_t len, Packet& out);

std::string ip_to_string(uint32_t ip);
bool parse_ip(const std::string& text, uint32_t& out);
std::string proto_name(uint8_t proto);

// Big-endian ("network order") reads.
inline uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
inline uint32_t read_u32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
