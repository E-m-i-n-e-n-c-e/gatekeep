#include "kernel.hpp"

#include <spawn.h>
#include <sys/wait.h>

#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "packet.hpp"

extern char** environ;

namespace {

int run(std::vector<std::string> args) {
    std::vector<char*> argv;
    for (auto& a : args) argv.push_back(a.data());
    argv.push_back(nullptr);

    pid_t pid = 0;
    if (posix_spawnp(&pid, argv[0], nullptr, nullptr, argv.data(), environ) != 0) {
        std::cerr << "gatekeep: failed to run " << args[0] << '\n';
        return -1;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

}  // namespace

void kernel_ban(uint32_t ip, int seconds) {
    run({"nft", "add", "element", "inet", "gatekeep", "banned",
         "{ " + ip_to_string(ip) + " timeout " + std::to_string(seconds) + "s }"});
    kernel_flush_conntrack_from(ip);  // also cut its already-allowed connections
}

void kernel_unban(uint32_t ip) {
    run({"nft", "delete", "element", "inet", "gatekeep", "banned", "{ " + ip_to_string(ip) + " }"});
}

void kernel_flush_conntrack() { run({"conntrack", "-F"}); }

void kernel_flush_conntrack_from(uint32_t src_ip) { run({"conntrack", "-D", "-s", ip_to_string(src_ip)}); }

nlohmann::json kernel_counters() {
    // A fixed command, nothing from the request goes into it.
    FILE* pipe = popen("nft list chain inet gatekeep forward 2>/dev/null", "r");
    if (!pipe) return {{"error", "cannot run nft"}};
    std::string out;
    char buf[4096];
    while (size_t n = fread(buf, 1, sizeof buf, pipe)) out.append(buf, n);
    pclose(pipe);

    nlohmann::json counts = {{"fast", 0}, {"slow", 0}, {"banned_drops", 0}};
    std::istringstream lines(out);
    std::string line;
    while (std::getline(lines, line)) {
        const size_t at = line.find("packets ");
        if (at == std::string::npos) continue;
        const uint64_t packets = std::strtoull(line.c_str() + at + 8, nullptr, 10);
        if (line.find("comment \"fast path") != std::string::npos) counts["fast"] = packets;
        else if (line.find("comment \"slow path") != std::string::npos) counts["slow"] = packets;
        else if (line.find("@banned") != std::string::npos) counts["banned_drops"] = packets;
    }
    return counts;
}
