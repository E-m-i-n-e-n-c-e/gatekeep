#pragma once

#include <string>

#include "engine.hpp"

// REST control plane. Blocks; run it on its own thread.
void run_api(Engine& engine, const std::string& host, int port, const std::string& policy_path);
