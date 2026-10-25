#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

#include "verdict.hpp"

// Receives packets from an NFQUEUE and returns a verdict for each one.
class NfqRunner {
public:
    using Handler = std::function<Verdict(const uint8_t* data, size_t len)>;

    NfqRunner(uint16_t queue_num, Handler handler) : queue_num_(queue_num), handler_(std::move(handler)) {}

    // Binds to the queue and processes packets forever. Throws on setup errors.
    [[noreturn]] void run();

private:
    uint16_t queue_num_;
    Handler handler_;
};
