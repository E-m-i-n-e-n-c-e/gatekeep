#include "nfq.hpp"

#include <arpa/inet.h>
#include <linux/netfilter.h>  // NF_DROP, NF_REPEAT
#include <sys/socket.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
}

namespace {

// Copy only the first 4 KB of each packet to userspace: enough for the IP and
// TCP/UDP headers plus the start of a ClientHello or HTTP request.
constexpr uint32_t kCopyBytes = 4096;
constexpr uint32_t kQueueMaxLen = 4096;            // packets waiting in the kernel
constexpr int kSocketBuffer = 8 * 1024 * 1024;      // netlink receive buffer

int on_packet(nfq_q_handle* qh, nfgenmsg*, nfq_data* nfa, void* data) {
    auto& handler = *static_cast<NfqRunner::Handler*>(data);

    uint32_t id = 0;
    if (nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa)) id = ntohl(ph->packet_id);

    unsigned char* payload = nullptr;
    const int len = nfq_get_payload(nfa, &payload);
    const Verdict v = len > 0 ? handler(payload, size_t(len)) : Verdict::DropPacket;

    if (v == Verdict::DropPacket) return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);

    // NF_REPEAT sends the packet through the nftables chain again with the
    // verdict as its mark; the "meta mark" rules then act on it and cache it.
    return nfq_set_verdict2(qh, id, NF_REPEAT, verdict_mark(v), 0, nullptr);
}

[[noreturn]] void fail(const std::string& what) {
    throw std::runtime_error("nfqueue: " + what + ": " + std::strerror(errno));
}

}  // namespace

void NfqRunner::run() {
    nfq_handle* h = nfq_open();
    if (!h) fail("nfq_open (is CAP_NET_ADMIN granted?)");
    nfq_bind_pf(h, AF_INET);  // no-op on modern kernels, needed on old ones

    nfq_q_handle* qh = nfq_create_queue(h, queue_num_, &on_packet, &handler_);
    if (!qh) fail("cannot bind queue " + std::to_string(queue_num_) + " (another process on it?)");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, kCopyBytes) < 0) fail("nfq_set_mode");
    nfq_set_queue_maxlen(qh, kQueueMaxLen);
    // Accept GSO super-packets as they are instead of making the kernel split them.
    nfq_set_queue_flags(qh, NFQA_CFG_F_GSO, NFQA_CFG_F_GSO);
    nfnl_rcvbufsiz(nfq_nfnlh(h), kSocketBuffer);

    const int fd = nfq_fd(h);
    std::vector<char> buf(256 * 1024);
    std::cerr << "gatekeep: listening on NFQUEUE " << queue_num_ << '\n';

    for (;;) {
        const ssize_t n = recv(fd, buf.data(), buf.size(), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) {  // we fell behind; the kernel dropped some packets (fail closed)
                std::cerr << "gatekeep: queue overrun, packets dropped\n";
                continue;
            }
            fail("recv");
        }
        nfq_handle_packet(h, buf.data(), int(n));
    }
}
