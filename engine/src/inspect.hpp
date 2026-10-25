#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// Layer-7 inspection: work out which application a flow is (by looking at its
// bytes, not its port) and which hostname it is trying to reach.

enum class App { Unknown, TLS, HTTP, DNS };

struct AppInfo {
    App app = App::Unknown;
    std::string host;  // lowercase, no port, no trailing dot; empty if unknown
};

const char* app_name(App app);

// Classifies the first payload segment of a TCP flow. TLS is recognised by a
// ClientHello record (host = SNI), HTTP by a request line (host = Host header).
AppInfo inspect_tcp_payload(const uint8_t* data, size_t len);

// Returns the server_name from a TLS ClientHello, or "" if there is none.
// Tolerates a ClientHello cut short (e.g. split across TCP segments) as long
// as the SNI extension itself is complete.
std::string tls_sni(const uint8_t* data, size_t len);

// Returns the Host header of an HTTP/1.x request, or "".
std::string http_host(const uint8_t* data, size_t len);

// Returns the name in the first question of a DNS query, or "".
std::string dns_query_name(const uint8_t* data, size_t len);

// Lowercases and strips a trailing dot.
std::string normalize_host(std::string host);

// True if `host` is `domain` or a subdomain of it ("a.evil.test" matches "evil.test").
bool domain_matches(const std::string& host, const std::string& domain);
