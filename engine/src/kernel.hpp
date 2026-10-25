#pragma once

#include <cstdint>

#include <nlohmann/json.hpp>

// Side effects on and reads of the kernel's state, done by running the nft and
// conntrack tools. Arguments come only from the engine's own data (parsed IPs),
// never from request text. Kept apart from the engine so the engine stays pure
// logic and can be unit-tested anywhere.

// Add the IP to the nftables @banned set; the kernel then drops its packets
// before they reach the queue and expires the entry by itself.
void kernel_ban(uint32_t ip, int seconds);
void kernel_unban(uint32_t ip);

// Delete conntrack entries, which also deletes their cached verdicts (ct mark).
// The next packet of each connection is queued and judged again.
void kernel_flush_conntrack();
void kernel_flush_conntrack_from(uint32_t src_ip);

// Packet counts from the nftables chain: {"fast": allowed connections handled
// in the kernel, "slow": packets queued to the engine, "banned_drops": ...}.
nlohmann::json kernel_counters();
