#pragma once

#include <string>
#include <vector>

#include "engine.hpp"

// REST control plane. Blocks; run it on its own thread. Browser pages on
// localhost may call it; `cors_origins` adds others (e.g. a hosted website).
void run_api(Engine& engine, const std::string& host, int port, const std::string& policy_path,
             const std::vector<std::string>& cors_origins);
