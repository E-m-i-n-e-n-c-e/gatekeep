#include "inspect.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "packet.hpp"

namespace {

// Bounds-checked cursor over a byte buffer. Every read fails (returns false)
// instead of running past the end, which is what keeps the parsers safe on
// hostile or truncated input.
struct Reader {
    const uint8_t* data;
    size_t len;
    size_t pos = 0;

    size_t remaining() const { return len - pos; }
    bool skip(size_t n) {
        if (remaining() < n) return false;
        pos += n;
        return true;
    }
    bool u8(uint8_t& v) {
        if (remaining() < 1) return false;
        v = data[pos++];
        return true;
    }
    bool u16(uint16_t& v) {
        if (remaining() < 2) return false;
        v = read_u16(data + pos);
        pos += 2;
        return true;
    }
    bool u24(uint32_t& v) {
        if (remaining() < 3) return false;
        v = (uint32_t(data[pos]) << 16) | (uint32_t(data[pos + 1]) << 8) | data[pos + 2];
        pos += 3;
        return true;
    }
};

bool is_hostname_char(unsigned char c) {
    return std::isalnum(c) || c == '-' || c == '.' || c == '_';
}

bool is_http_request(const uint8_t* data, size_t len) {
    static const char* const methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
                                          "OPTIONS ", "PATCH ", "CONNECT "};
    return std::any_of(std::begin(methods), std::end(methods), [&](const char* m) {
        const size_t n = std::strlen(m);
        return len >= n && std::memcmp(data, m, n) == 0;
    });
}

bool valid_hostname(const std::string& host) {
    return !host.empty() && host.size() <= 253 &&
           std::all_of(host.begin(), host.end(), [](char c) { return is_hostname_char(c); });
}

}  // namespace

const char* app_name(App app) {
    switch (app) {
        case App::TLS: return "tls";
        case App::HTTP: return "http";
        case App::DNS: return "dns";
        default: return "unknown";
    }
}

std::string normalize_host(std::string host) {
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (!host.empty() && host.back() == '.') host.pop_back();
    return host;
}

bool domain_matches(const std::string& host, const std::string& domain) {
    if (host == domain) return true;
    if (host.size() <= domain.size()) return false;
    const size_t start = host.size() - domain.size();
    return host[start - 1] == '.' && host.compare(start, domain.size(), domain) == 0;
}

std::string tls_sni(const uint8_t* data, size_t len) {
    Reader r{data, len};

    // TLS record header: content type 22 = handshake, version 3.x, length.
    uint8_t content_type = 0, major = 0, minor = 0;
    uint16_t record_len = 0;
    if (!r.u8(content_type) || content_type != 0x16) return "";
    if (!r.u8(major) || major != 0x03 || !r.u8(minor) || !r.u16(record_len)) return "";

    // Handshake header: type 1 = ClientHello, 24-bit length.
    uint8_t hs_type = 0;
    uint32_t hs_len = 0;
    if (!r.u8(hs_type) || hs_type != 0x01 || !r.u24(hs_len)) return "";

    // ClientHello body. Skip the fields before the extensions:
    // legacy_version (2) + random (32), session_id, cipher_suites, compression.
    uint8_t session_id_len = 0, compression_len = 0;
    uint16_t cipher_suites_len = 0, extensions_len = 0;
    if (!r.skip(2 + 32)) return "";
    if (!r.u8(session_id_len) || !r.skip(session_id_len)) return "";
    if (!r.u16(cipher_suites_len) || !r.skip(cipher_suites_len)) return "";
    if (!r.u8(compression_len) || !r.skip(compression_len)) return "";
    if (!r.u16(extensions_len)) return "";

    // Walk the extensions: type (2), length (2), data. Stop at server_name (0).
    const size_t extensions_end = r.pos + extensions_len;
    while (r.pos + 4 <= extensions_end) {
        uint16_t ext_type = 0, ext_len = 0;
        if (!r.u16(ext_type) || !r.u16(ext_len)) return "";
        if (ext_type != 0x0000) {
            if (!r.skip(ext_len)) return "";  // truncated before we reached SNI
            continue;
        }
        // server_name extension: list length (2), then entries of
        // name_type (1, 0 = host_name), name length (2), name.
        uint16_t list_len = 0, name_len = 0;
        uint8_t name_type = 0;
        if (!r.u16(list_len) || !r.u8(name_type) || name_type != 0) return "";
        if (!r.u16(name_len) || r.remaining() < name_len) return "";
        std::string host(reinterpret_cast<const char*>(data + r.pos), name_len);
        host = normalize_host(host);
        return valid_hostname(host) ? host : "";
    }
    return "";
}

std::string http_host(const uint8_t* data, size_t len) {
    if (!is_http_request(data, len)) return "";
    const std::string text(reinterpret_cast<const char*>(data), std::min<size_t>(len, 4096));

    // Find "\r\nHost:" case-insensitively.
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const size_t at = lower.find("\r\nhost:");
    if (at == std::string::npos) return "";

    size_t start = at + 7;
    while (start < text.size() && (text[start] == ' ' || text[start] == '\t')) start++;
    size_t end = text.find("\r\n", start);
    if (end == std::string::npos) end = text.size();

    std::string host = text.substr(start, end - start);
    while (!host.empty() && (host.back() == ' ' || host.back() == '\t')) host.pop_back();
    const size_t colon = host.find(':');  // strip ":port"
    if (colon != std::string::npos) host.resize(colon);
    host = normalize_host(host);
    return valid_hostname(host) ? host : "";
}

std::string dns_query_name(const uint8_t* data, size_t len) {
    // DNS header (12 bytes): id, flags, qdcount, ancount, nscount, arcount.
    if (len < 12) return "";
    const bool is_response = data[2] & 0x80;  // QR bit
    const uint16_t qdcount = read_u16(data + 4);
    if (is_response || qdcount == 0) return "";

    // Question name: a sequence of length-prefixed labels ending in a zero byte.
    Reader r{data, len, 12};
    std::string name;
    for (;;) {
        uint8_t label_len = 0;
        if (!r.u8(label_len)) return "";
        if (label_len == 0) break;
        if (label_len > 63 || r.remaining() < label_len) return "";  // > 63 = compression pointer
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(data + r.pos), label_len);
        r.skip(label_len);
        if (name.size() > 253) return "";
    }
    name = normalize_host(name);
    return valid_hostname(name) ? name : "";
}

AppInfo inspect_tcp_payload(const uint8_t* data, size_t len) {
    AppInfo info;
    if (len == 0) return info;
    if (data[0] == 0x16) {
        info.app = App::TLS;
        info.host = tls_sni(data, len);
        return info;
    }
    if (is_http_request(data, len)) {
        info.app = App::HTTP;
        info.host = http_host(data, len);
    }
    return info;
}
