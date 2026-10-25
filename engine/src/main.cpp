// gatekeep: a stateful L3-L7 firewall engine behind Linux NFQUEUE.
//
//   nftables (kernel) ──first packets of new flows──► this process ──verdict──► kernel
//
// See ../../README.md for the architecture and ../../WALKTHROUGH.md for a tour of the code.

#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#include "api.hpp"
#include "engine.hpp"
#include "kernel.hpp"
#include "nfq.hpp"

namespace {

struct Options {
    std::string policy_path = "/etc/gatekeep/policy.json";
    uint16_t queue = 0;
    std::string api_host = "0.0.0.0";
    int api_port = 8080;
    std::vector<std::string> cors_origins;  // besides localhost, which is always allowed
};

[[noreturn]] void usage() {
    std::cerr << "usage: gatekeep [--policy FILE] [--queue N] [--api-host HOST] [--api-port PORT]\n"
                 "                [--cors-origin ORIGIN[,ORIGIN...]]\n";
    std::exit(2);
}

Options parse_args(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; i++) {
        const std::string arg = argv[i];
        if (i + 1 >= argc) usage();
        const std::string value = argv[++i];
        if (arg == "--policy") o.policy_path = value;
        else if (arg == "--queue") o.queue = uint16_t(std::stoi(value));
        else if (arg == "--api-host") o.api_host = value;
        else if (arg == "--api-port") o.api_port = std::stoi(value);
        else if (arg == "--cors-origin") {
            std::stringstream list(value);
            for (std::string origin; std::getline(list, origin, ',');)
                if (!origin.empty()) o.cors_origins.push_back(origin);
        }
        else usage();
    }
    return o;
}

}  // namespace

int main(int argc, char** argv) {
    std::cout.setf(std::ios::unitbuf);  // one JSON log line per decision, unbuffered for `docker logs`
    const Options opt = parse_args(argc, argv);

    Policy policy;
    try {
        policy = load_policy_file(opt.policy_path);
    } catch (const std::exception& e) {
        std::cerr << "gatekeep: " << e.what() << '\n';
        return 1;
    }
    std::cerr << "gatekeep: loaded " << policy.rules.size() << " rules, " << policy.blocked_domains.size()
              << " blocked domains from " << opt.policy_path << '\n';

    Engine engine(std::move(policy));

    std::thread([&] { run_api(engine, opt.api_host, opt.api_port, opt.policy_path, opt.cors_origins); }).detach();
    std::thread([&] {
        for (;;) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            engine.gc();
        }
    }).detach();

    // Start from a clean slate: verdicts cached by a previous run are discarded.
    kernel_flush_conntrack();

    NfqRunner runner(opt.queue, [&](const uint8_t* data, size_t len) {
        Packet p;
        if (!parse_ipv4(data, len, p)) {
            engine.count_malformed();
            return Verdict::DropPacket;
        }
        const Decision d = engine.decide(p);
        if (d.ban_seconds > 0) kernel_ban(p.src_ip, d.ban_seconds);
        return d.verdict;
    });

    try {
        runner.run();
    } catch (const std::exception& e) {
        std::cerr << "gatekeep: " << e.what() << '\n';
        return 1;
    }
}
