#pragma once

#include <cstdint>

// What the engine tells the kernel to do with a queued packet.
//
// "Flow" verdicts are cached on the kernel's conntrack entry (ct mark), so
// the rest of the connection is handled in the kernel and never reaches the
// engine again: that is the fast path. "Packet" verdicts apply to this one
// packet only, and the next packet of the flow is queued again.
//
// The engine hands the verdict back as a packet mark with NF_REPEAT; the
// nftables rules in nft/gatekeep.nft translate the mark (see there).
enum class Verdict {
    AllowFlow,     // mark 1: accept, offload the connection to the fast path
    DropFlow,      // mark 2: drop this and every later packet of the connection
    AllowPacket,   // mark 3: accept this packet, keep inspecting the flow
    RejectFlow,    // mark 4: reject (TCP RST / ICMP) and cache that for the connection
    RejectPacket,  // mark 5: reject just this packet
    DropPacket,    // NF_DROP, no mark: nothing cached, a retry is re-evaluated
};

inline uint32_t verdict_mark(Verdict v) {
    switch (v) {
        case Verdict::AllowFlow: return 1;
        case Verdict::DropFlow: return 2;
        case Verdict::AllowPacket: return 3;
        case Verdict::RejectFlow: return 4;
        case Verdict::RejectPacket: return 5;
        default: return 0;
    }
}

inline const char* verdict_name(Verdict v) {
    switch (v) {
        case Verdict::AllowFlow: return "allow_flow";
        case Verdict::DropFlow: return "drop_flow";
        case Verdict::AllowPacket: return "allow_packet";
        case Verdict::RejectFlow: return "reject_flow";
        case Verdict::RejectPacket: return "reject_packet";
        default: return "drop_packet";
    }
}
